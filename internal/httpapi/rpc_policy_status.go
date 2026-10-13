package httpapi

import (
	"context"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *openShellRPC) ReportPolicyStatus(ctx context.Context, req *openshellv1.ReportPolicyStatusRequest) (*openshellv1.ReportPolicyStatusResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "policy store is not initialized")
	}
	if req == nil || req.GetSandboxId() == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id is required")
	}
	if req.GetVersion() == 0 {
		return nil, status.Error(codes.InvalidArgument, "version is required")
	}
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalSandbox {
		return nil, status.Error(codes.Unauthenticated, "sandbox principal required")
	}
	sandbox, ok := s.runtime.st.GetSandboxByID(req.GetSandboxId())
	if !ok {
		sandbox, ok = s.runtime.st.GetSandbox(req.GetSandboxId())
	}
	if !ok {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	if p.Sandbox != sandbox.Name && p.Sandbox != sandbox.ID {
		return nil, status.Error(codes.PermissionDenied, "sandbox principal cannot report another sandbox policy")
	}
	var policyStatus string
	switch req.GetStatus() {
	case openshellv1.PolicyStatus_POLICY_STATUS_LOADED:
		policyStatus = store.PolicyStatusLoaded
	case openshellv1.PolicyStatus_POLICY_STATUS_FAILED:
		policyStatus = store.PolicyStatusFailed
	default:
		return nil, status.Error(codes.InvalidArgument, "status must be LOADED or FAILED")
	}
	if _, err := s.runtime.st.GetPolicyRevision(sandbox.Name, int(req.GetVersion())); err != nil {
		return nil, status.Error(codes.NotFound, "policy revision not found")
	}
	loadedAt := time.Time{}
	loadError := ""
	if policyStatus == store.PolicyStatusLoaded {
		loadedAt = time.Now().UTC()
	} else {
		loadError = req.GetLoadError()
	}
	sandboxID := sandbox.ID
	if sandboxID == "" {
		sandboxID = sandbox.Name
	}
	if err := s.runtime.st.ReportPolicyStatus(sandboxID, int(req.GetVersion()), policyStatus, loadError, loadedAt); err != nil {
		return nil, status.Error(codes.Internal, "could not record policy load status")
	}
	return &openshellv1.ReportPolicyStatusResponse{}, nil
}
