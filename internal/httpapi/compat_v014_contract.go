package httpapi

import (
	"context"
	"strings"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetSandboxProviderStatus keeps authorization and existence checks in place,
// then reports the missing durable readiness store as typed Unsupported.
func (s *compatRPCAdapter) GetSandboxProviderStatus(ctx context.Context, req *compatv1.GetSandboxProviderStatusRequest) (*compatv1.GetSandboxProviderStatusResponse, error) {
	if req == nil || strings.TrimSpace(req.GetSandbox()) == "" || strings.TrimSpace(req.GetProvider()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox and provider are required")
	}
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	sandbox, ok := s.runtime.st.GetSandbox(req.GetSandbox())
	workspace := defaultWorkspace(requestWorkspace(req.GetWorkspaceScope()))
	if !ok || defaultWorkspace(sandbox.Workspace) != workspace || !containsString(sandbox.AttachedProviders, req.GetProvider()) {
		return nil, status.Error(codes.NotFound, "sandbox provider not found")
	}
	if err := s.requireSandboxReadWorkspace(ctx, workspace); err != nil {
		return nil, err
	}
	return nil, providerReadinessGapError()
}

func (s *compatRPCAdapter) ReportProviderReadiness(ctx context.Context, req *compatv1.ReportProviderReadinessRequest) (*compatv1.ReportProviderReadinessResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "provider readiness report is required")
	}
	if err := requireAuthenticatedSandbox(ctx, req.GetSandboxId()); err != nil {
		return nil, err
	}
	return nil, providerReadinessGapError()
}

func (s *compatRPCAdapter) ReportEndpointStatus(ctx context.Context, req *compatv1.ReportEndpointStatusRequest) (*compatv1.ReportEndpointStatusResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "endpoint status report is required")
	}
	if err := requireAuthenticatedSandbox(ctx, req.GetSandboxId()); err != nil {
		return nil, err
	}
	return nil, providerReadinessGapError()
}

func (s *compatRPCAdapter) ReportSandboxConfiguration(ctx context.Context, req *compatv1.ReportSandboxConfigurationRequest) (*compatv1.ReportSandboxConfigurationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "sandbox configuration report is required")
	}
	if err := requireAuthenticatedSandbox(ctx, req.GetSandboxId()); err != nil {
		return nil, err
	}
	return nil, providerReadinessGapError()
}

func (s *compatRPCAdapter) PeerReportProviderReadiness(context.Context, *compatv1.ReportProviderReadinessRequest) (*compatv1.ReportProviderReadinessResponse, error) {
	return nil, peerRelayGapError()
}

func (s *compatRPCAdapter) PeerReportEndpointStatus(context.Context, *compatv1.ReportEndpointStatusRequest) (*compatv1.ReportEndpointStatusResponse, error) {
	return nil, peerRelayGapError()
}

func (s *compatRPCAdapter) PeerGetSandboxProviderStatus(context.Context, *compatv1.GetSandboxProviderStatusRequest) (*compatv1.GetSandboxProviderStatusResponse, error) {
	return nil, peerRelayGapError()
}

func (s *compatRPCAdapter) PeerRelay(grpc.BidiStreamingServer[compatv1.PeerRelayFrame, compatv1.PeerRelayFrame]) error {
	return peerRelayGapError()
}

func requireAuthenticatedSandbox(ctx context.Context, sandbox string) error {
	principal := PrincipalFrom(ctx)
	if principal.Kind != PrincipalSandbox || principal.Sandbox == "" || principal.Sandbox != sandbox {
		return status.Error(codes.PermissionDenied, "authenticated sandbox identity required")
	}
	return nil
}

func providerReadinessGapError() error {
	return status.Error(codes.Unimplemented, "provider readiness reporting is unsupported by this gateway")
}

func peerRelayGapError() error {
	return status.Error(codes.Unimplemented, "peer relay transport is unsupported by this gateway")
}
