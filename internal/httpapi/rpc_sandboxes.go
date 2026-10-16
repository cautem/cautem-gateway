package httpapi

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultSandboxPageSize uint32 = 100
	maxSandboxPageSize     uint32 = 1000
)

func (s *compatRPCAdapter) GetSandbox(ctx context.Context, req *compatv1.GetSandboxRequest) (*compatv1.SandboxResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	workspace := requestWorkspace(req.GetWorkspaceScope())
	if workspace == "" {
		workspace = "default"
	}
	if err := s.requireSandboxReadWorkspace(ctx, workspace); err != nil {
		return nil, err
	}
	sandbox, ok := s.runtime.st.GetSandbox(req.GetName())
	if !ok || sandbox.Workspace != workspace {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	result, err := sandboxRecordToProto(sandbox)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "stored sandbox spec is invalid")
	}
	return &compatv1.SandboxResponse{Sandbox: result}, nil
}

func (s *compatRPCAdapter) ListSandboxes(ctx context.Context, req *compatv1.ListSandboxesRequest) (*compatv1.ListSandboxesResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	workspace := strings.TrimSpace(requestWorkspace(req.GetWorkspaceScope()))
	if scopeAllWorkspaces(req.GetWorkspaceScope()) {
		if workspace != "" {
			return nil, status.Error(codes.InvalidArgument, "all_workspaces and workspace are mutually exclusive")
		}
		if !isConfigAdmin(PrincipalFrom(ctx), s.options.OIDC.AdminRole) {
			return nil, status.Error(codes.PermissionDenied, "platform admin role required for all-workspace listing")
		}
	} else {
		if workspace == "" {
			workspace = "default"
		}
		if err := s.requireSandboxReadWorkspace(ctx, workspace); err != nil {
			return nil, err
		}
	}
	selector, err := parseSandboxLabelSelector(req.GetLabelSelector())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	filtered := make([]store.Sandbox, 0)
	for _, sandbox := range s.runtime.st.ListSandboxes() {
		if !scopeAllWorkspaces(req.GetWorkspaceScope()) && sandbox.Workspace != workspace {
			continue
		}
		matches := true
		for key, value := range selector {
			if sandbox.Labels[key] != value {
				matches = false
				break
			}
		}
		if matches {
			filtered = append(filtered, sandbox)
		}
	}
	limit := uint32(req.GetPageSize())
	if limit == 0 {
		limit = defaultSandboxPageSize
	}
	if limit > maxSandboxPageSize {
		limit = maxSandboxPageSize
	}
	start := uint64(0)
	if token := strings.TrimSpace(req.GetPageToken()); token != "" {
		parsed, parseErr := strconv.ParseUint(token, 10, 64)
		if parseErr != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid page_token")
		}
		start = parsed
	}
	if start >= uint64(len(filtered)) {
		return &compatv1.ListSandboxesResponse{}, nil
	}
	end := start + uint64(limit)
	if end > uint64(len(filtered)) {
		end = uint64(len(filtered))
	}
	response := &compatv1.ListSandboxesResponse{Sandboxes: make([]*compatv1.Sandbox, 0, end-start)}
	for _, sandbox := range filtered[start:end] {
		result, err := sandboxRecordToProto(sandbox)
		if err != nil {
			return nil, status.Error(codes.FailedPrecondition, "stored sandbox spec is invalid")
		}
		response.Sandboxes = append(response.Sandboxes, result)
	}
	if end < uint64(len(filtered)) {
		response.NextPageToken = strconv.FormatUint(end, 10)
	}
	return response, nil
}

func (s *compatRPCAdapter) requireSandboxReadWorkspace(ctx context.Context, workspace string) error {
	return requireSandboxReadWorkspace(ctx, s.runtime.st, workspace)
}

func requireSandboxReadWorkspace(ctx context.Context, st *store.Store, workspace string) error {
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalUser {
		return status.Error(codes.Unauthenticated, "authenticated user required")
	}
	if p.IDP == "local" || p.IDP == "local_dev" {
		return nil
	}
	if !containsString(p.Scopes, "sandbox:read") && !containsString(p.Scopes, "openshell:all") {
		return status.Error(codes.PermissionDenied, "sandbox:read scope required")
	}
	ws, ok := st.GetWorkspace(workspace)
	if !ok {
		return status.Error(codes.NotFound, "workspace not found")
	}
	for _, member := range ws.Members {
		if member.Subject == p.Subject {
			switch strings.ToLower(strings.TrimSpace(member.Role)) {
			case "owner", "admin", "user", "member", "reader", "viewer":
				return nil
			}
		}
	}
	return status.Error(codes.PermissionDenied, "workspace sandbox read access required")
}

func parseSandboxLabelSelector(raw string) (map[string]string, error) {
	selector := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return selector, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(pair), "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !found || key == "" || value == "" {
			return nil, fmt.Errorf("label_selector supports non-empty key=value pairs separated by commas")
		}
		if _, duplicate := selector[key]; duplicate {
			return nil, fmt.Errorf("label_selector repeats key %q", key)
		}
		selector[key] = value
	}
	return selector, nil
}

func sandboxRecordToProto(record store.Sandbox) (*compatv1.Sandbox, error) {
	createdAt := record.CreatedAt
	if createdAt.IsZero() {
		createdAt = record.UpdatedAt
	}
	metadata := &datamodelv1.ObjectMeta{Id: record.ID, Name: record.Name, Labels: record.Labels, Annotations: record.Annotations, Workspace: record.Workspace, ResourceVersion: record.ResourceVersion}
	if !createdAt.IsZero() {
		metadata.CreatedTime = timestamppb.New(createdAt)
	}
	spec := &compatv1.SandboxSpec{Template: &compatv1.SandboxTemplate{Image: record.Image}, Providers: append([]string(nil), record.AttachedProviders...)}
	if record.SpecJSON != "" {
		if err := protojson.Unmarshal([]byte(record.SpecJSON), spec); err != nil {
			return nil, err
		}
	}
	// The registry's provider attachment field is the canonical mutation source
	// when present. Keep legacy records that only have providers in SpecJSON
	// readable until their first CAS mutation projects the registry field.
	if record.AttachedProviders != nil {
		spec.Providers = append([]string(nil), record.AttachedProviders...)
	}
	phase := compatv1.SandboxPhase_SANDBOX_PHASE_UNKNOWN
	switch strings.ToLower(strings.TrimSpace(record.Status)) {
	case "provisioning":
		phase = compatv1.SandboxPhase_SANDBOX_PHASE_PROVISIONING
	case "running", "ready":
		phase = compatv1.SandboxPhase_SANDBOX_PHASE_READY
	case "starting":
		phase = compatv1.SandboxPhase_SANDBOX_PHASE_STARTING
	case "stopping":
		phase = compatv1.SandboxPhase_SANDBOX_PHASE_STOPPING
	case "stopped":
		phase = compatv1.SandboxPhase_SANDBOX_PHASE_STOPPED
	case "error", "failed":
		phase = compatv1.SandboxPhase_SANDBOX_PHASE_ERROR
	case "completed":
		phase = compatv1.SandboxPhase_SANDBOX_PHASE_COMPLETED
	case "deleting":
		phase = compatv1.SandboxPhase_SANDBOX_PHASE_DELETING
	}
	status := &compatv1.SandboxStatus{Phase: phase, CurrentPolicyVersion: record.ActivePolicyVersion, MainProcessInstanceId: record.MainProcessInstanceID}
	if record.MainProcessExitCode != nil {
		code := *record.MainProcessExitCode
		status.ExitCode = &code
	}
	return &compatv1.Sandbox{Metadata: metadata, Spec: spec, Status: status}, nil
}
