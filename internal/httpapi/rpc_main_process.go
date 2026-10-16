package httpapi

import (
	"context"
	"strings"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *compatRPCAdapter) ReportMainProcessExit(ctx context.Context, req *compatv1.ReportMainProcessExitRequest) (*compatv1.ReportMainProcessExitResponse, error) {
	if req == nil || strings.TrimSpace(req.GetSandboxId()) == "" || strings.TrimSpace(req.GetInstanceId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id and instance_id are required")
	}
	principal := PrincipalFrom(ctx)
	if principal.Kind != PrincipalSandbox {
		return nil, status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
	}
	if s.runtime == nil || s.runtime.st == nil || s.runtime.relay == nil {
		return nil, status.Error(codes.Unavailable, "sandbox supervisor service is not initialized")
	}
	sandbox, ok := s.runtime.st.GetSandboxByID(req.GetSandboxId())
	if !ok {
		sandbox, ok = s.runtime.st.GetSandbox(req.GetSandboxId())
	}
	if !ok {
		// OpenShell acknowledges reports for sandboxes already removed by cleanup.
		if principal.Sandbox != req.GetSandboxId() {
			return nil, status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
		}
		return &compatv1.ReportMainProcessExitResponse{}, nil
	}
	if principal.Sandbox != sandbox.Name && principal.Sandbox != sandbox.ID {
		return nil, status.Error(codes.PermissionDenied, "sandbox supervisor cannot report another sandbox")
	}
	activeInstance, connected := s.runtime.relay.SupervisorInstance(sandbox.Name)
	if (sandbox.SupervisorInstanceID != "" && sandbox.SupervisorInstanceID != req.GetInstanceId()) || (connected && activeInstance != req.GetInstanceId()) {
		// A late report from a superseded supervisor must not overwrite a newer run.
		return &compatv1.ReportMainProcessExitResponse{}, nil
	}
	if lifecycleStopping(sandbox.Status) {
		return &compatv1.ReportMainProcessExitResponse{}, nil
	}
	_, err := s.runtime.st.RecordMainProcessExit(sandbox.Name, req.GetInstanceId(), req.GetExitCode())
	if err != nil {
		return nil, status.Error(codes.Internal, "could not persist main process exit")
	}
	return &compatv1.ReportMainProcessExitResponse{}, nil
}

func (s *compatRPCAdapter) FinalizeMainProcessExit(ctx context.Context, req *compatv1.FinalizeMainProcessExitRequest) (*compatv1.FinalizeMainProcessExitResponse, error) {
	if req == nil || strings.TrimSpace(req.GetSandboxId()) == "" || strings.TrimSpace(req.GetInstanceId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id and instance_id are required")
	}
	principal := PrincipalFrom(ctx)
	if principal.Kind != PrincipalSandbox {
		return nil, status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
	}
	if s.runtime == nil || s.runtime.st == nil || s.runtime.relay == nil {
		return nil, status.Error(codes.Unavailable, "sandbox supervisor service is not initialized")
	}
	sandbox, ok := s.runtime.st.GetSandboxByID(req.GetSandboxId())
	if !ok {
		sandbox, ok = s.runtime.st.GetSandbox(req.GetSandboxId())
	}
	if ok && principal.Sandbox != sandbox.Name && principal.Sandbox != sandbox.ID {
		return nil, status.Error(codes.PermissionDenied, "sandbox supervisor cannot finalize another sandbox")
	}
	if !ok && principal.Sandbox != req.GetSandboxId() {
		return nil, status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
	}
	sandboxName := req.GetSandboxId()
	if ok {
		sandboxName = sandbox.Name
	}
	activeInstance, connected := s.runtime.relay.SupervisorInstance(sandboxName)
	if connected {
		if activeInstance != req.GetInstanceId() {
			return nil, status.Error(codes.FailedPrecondition, "supervisor session is not connected for this instance")
		}
	} else if ok && sandbox.SupervisorInstanceID != req.GetInstanceId() {
		// Finalize is the second half of a durable two-step lifecycle. The
		// supervisor may lose its stream immediately after ReportMainProcessExit
		// is acknowledged (container teardown, gateway restart, or relay race).
		// The persisted instance binding plus the store's reported-exit check are
		// sufficient authorization for an idempotent finalize in that window.
		return nil, status.Error(codes.FailedPrecondition, "supervisor session is not connected for this instance")
	}
	if !ok {
		return &compatv1.FinalizeMainProcessExitResponse{}, nil
	}
	if !lifecycleStopping(sandbox.Status) {
		if _, err := s.runtime.st.FinalizeMainProcessExit(sandbox.Name, req.GetInstanceId()); err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
	}
	return &compatv1.FinalizeMainProcessExitResponse{}, nil
}

func lifecycleStopping(statusValue string) bool {
	switch strings.ToLower(strings.TrimSpace(statusValue)) {
	case "deleting", "stopping", "stopped":
		return true
	default:
		return false
	}
}
