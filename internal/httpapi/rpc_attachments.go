package httpapi

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maxSandboxProviders = 32

func (s *compatRPCAdapter) ListSandboxProviders(ctx context.Context, req *compatv1.ListSandboxProvidersRequest) (*compatv1.ListSandboxProvidersResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	if req == nil || strings.TrimSpace(req.GetSandbox()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox is required")
	}
	workspace := defaultWorkspace(requestWorkspace(req.GetWorkspaceScope()))
	if err := s.requireSandboxReadWorkspace(ctx, workspace); err != nil {
		return nil, err
	}
	sandbox, ok := s.runtime.st.GetSandbox(req.GetSandbox())
	if !ok || defaultWorkspace(sandbox.Workspace) != workspace {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	sandboxProto, err := sandboxRecordToProto(sandbox)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "stored sandbox spec is invalid")
	}
	providerNames := sandboxProto.GetSpec().GetProviders()
	providers := make([]*datamodelv1.Provider, 0, len(providerNames))
	for _, name := range providerNames {
		record, ok := s.runtime.st.GetProvider(name)
		if !ok || !providerInWorkspace(record, workspace) {
			return nil, status.Errorf(codes.FailedPrecondition, "provider %q not found", name)
		}
		providers = append(providers, providerAttachmentToProto(record))
	}
	return &compatv1.ListSandboxProvidersResponse{Providers: providers}, nil
}

func (s *compatRPCAdapter) AttachSandboxProvider(ctx context.Context, req *compatv1.AttachSandboxProviderRequest) (*compatv1.AttachSandboxProviderResponse, error) {
	if req == nil || strings.TrimSpace(req.GetSandbox()) == "" || strings.TrimSpace(req.GetProvider()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox and provider are required")
	}
	if len(req.GetProvider()) > 253 {
		return nil, status.Error(codes.InvalidArgument, "provider_name exceeds maximum length (253)")
	}
	workspace, sandbox, err := s.providerAttachmentTarget(ctx, requestWorkspace(req.GetWorkspaceScope()), req.GetSandbox(), true, true)
	if err != nil {
		return nil, err
	}
	record, ok := s.runtime.st.GetProvider(req.GetProvider())
	if !ok || !providerInWorkspace(record, workspace) {
		return nil, status.Errorf(codes.FailedPrecondition, "provider %q not found", req.GetProvider())
	}
	if !containsString(sandbox.AttachedProviders, req.GetProvider()) && len(sandbox.AttachedProviders) >= maxSandboxProviders {
		return nil, status.Errorf(codes.InvalidArgument, "providers list exceeds maximum (%d)", maxSandboxProviders)
	}
	updated, attached, err := s.runtime.st.ApplySandboxProvider(sandbox.Name, req.GetExpectedResourceVersion(), req.GetProvider(), true)
	if err != nil {
		return nil, sandboxProviderMutationError(err, "attach sandbox provider")
	}
	response, err := sandboxRecordToProto(updated)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "stored sandbox spec is invalid")
	}
	return &compatv1.AttachSandboxProviderResponse{Sandbox: response, Attached: attached}, nil
}

func (s *compatRPCAdapter) DetachSandboxProvider(ctx context.Context, req *compatv1.DetachSandboxProviderRequest) (*compatv1.DetachSandboxProviderResponse, error) {
	if req == nil || strings.TrimSpace(req.GetSandbox()) == "" || strings.TrimSpace(req.GetProvider()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox and provider are required")
	}
	if len(req.GetProvider()) > 253 {
		return nil, status.Error(codes.InvalidArgument, "provider_name exceeds maximum length (253)")
	}
	_, sandbox, err := s.providerAttachmentTarget(ctx, requestWorkspace(req.GetWorkspaceScope()), req.GetSandbox(), true, false)
	if err != nil {
		return nil, err
	}
	updated, detached, err := s.runtime.st.ApplySandboxProvider(sandbox.Name, req.GetExpectedResourceVersion(), req.GetProvider(), false)
	if err != nil {
		return nil, sandboxProviderMutationError(err, "detach sandbox provider")
	}
	response, err := sandboxRecordToProto(updated)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "stored sandbox spec is invalid")
	}
	return &compatv1.DetachSandboxProviderResponse{Sandbox: response, Detached: detached}, nil
}

func (s *compatRPCAdapter) providerAttachmentTarget(ctx context.Context, rawWorkspace, sandboxName string, write, requireActive bool) (string, store.Sandbox, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return "", store.Sandbox{}, status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	workspace := defaultWorkspace(rawWorkspace)
	if write {
		if PrincipalFrom(ctx).Kind != PrincipalUser {
			return "", store.Sandbox{}, status.Error(codes.Unauthenticated, "authenticated user required")
		}
		if err := s.requireSandboxWrite(ctx, workspace); err != nil {
			return "", store.Sandbox{}, err
		}
		if requireActive {
			if err := s.requireWorkspaceActive(workspace); err != nil {
				return "", store.Sandbox{}, err
			}
		}
	} else if err := s.requireSandboxReadWorkspace(ctx, workspace); err != nil {
		return "", store.Sandbox{}, err
	}
	sandbox, ok := s.runtime.st.GetSandbox(sandboxName)
	if !ok || defaultWorkspace(sandbox.Workspace) != workspace {
		return "", store.Sandbox{}, status.Error(codes.NotFound, "sandbox not found")
	}
	return workspace, sandbox, nil
}

func providerAttachmentToProto(record store.ProviderRecord) *datamodelv1.Provider {
	credentials := make(map[string]string, len(record.EnvVars))
	for _, key := range record.EnvVars {
		credentials[key] = "REDACTED"
	}
	expires := make(map[string]*timestamppb.Timestamp, len(record.CredentialExpiresAtMS))
	for key, value := range record.CredentialExpiresAtMS {
		expires[key] = timestamppb.New(time.UnixMilli(value))
	}
	return &datamodelv1.Provider{
		Metadata: &datamodelv1.ObjectMeta{
			Id: record.Name, Name: record.Name, Workspace: record.Workspace,
			Labels:      cloneStringMap(record.Labels),
			Annotations: map[string]string{"cautem.io/runtime-credentials": strconv.FormatBool(record.RuntimeCredentials)},
		},
		Type: record.Type, Credentials: credentials, Config: cloneStringMap(record.Config),
		CredentialExpirationTimes: expires, ProfileWorkspace: record.Workspace,
	}
}

func sandboxProviderMutationError(err error, operation string) error {
	switch {
	case errors.Is(err, store.ErrResourceVersionConflict):
		return status.Error(codes.Aborted, "sandbox was concurrently modified, please retry")
	case errors.Is(err, store.ErrSandboxProviderLimit):
		return status.Errorf(codes.InvalidArgument, "providers list exceeds maximum (%d)", maxSandboxProviders)
	default:
		return status.Errorf(codes.Internal, "%s failed", operation)
	}
}
