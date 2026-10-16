package httpapi

import (
	"context"
	"testing"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCompatV014ReportRPCsValidateRequestsAndExposeKnownGaps(t *testing.T) {
	rpc := &compatRPCAdapter{}
	tests := []struct {
		name        string
		call        func(context.Context) error
		invalid     func() error
		unsupported string
	}{
		{"provider readiness", func(ctx context.Context) error {
			_, err := rpc.ReportProviderReadiness(ctx, &compatv1.ReportProviderReadinessRequest{SandboxId: "sandbox"})
			return err
		}, func() error { _, err := rpc.ReportProviderReadiness(context.Background(), nil); return err }, "provider readiness reporting is unsupported by this gateway"},
		{"endpoint status", func(ctx context.Context) error {
			_, err := rpc.ReportEndpointStatus(ctx, &compatv1.ReportEndpointStatusRequest{SandboxId: "sandbox"})
			return err
		}, func() error { _, err := rpc.ReportEndpointStatus(context.Background(), nil); return err }, "provider readiness reporting is unsupported by this gateway"},
		{"sandbox configuration", func(ctx context.Context) error {
			_, err := rpc.ReportSandboxConfiguration(ctx, &compatv1.ReportSandboxConfigurationRequest{SandboxId: "sandbox"})
			return err
		}, func() error { _, err := rpc.ReportSandboxConfiguration(context.Background(), nil); return err }, "provider readiness reporting is unsupported by this gateway"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := status.Code(tt.invalid()); got != codes.InvalidArgument {
				t.Fatalf("nil request status=%s; want %s", got, codes.InvalidArgument)
			}
			for _, principal := range []Principal{
				{},
				{Kind: PrincipalUser, Subject: "user"},
				{Kind: PrincipalSandbox, Sandbox: "other"},
			} {
				ctx := withPrincipal(context.Background(), principal)
				if got := status.Code(tt.call(ctx)); got != codes.PermissionDenied {
					t.Errorf("principal %+v status=%s; want %s", principal, got, codes.PermissionDenied)
				}
			}
			ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "sandbox"})
			err := tt.call(ctx)
			if got := status.Code(err); got != codes.Unimplemented {
				t.Fatalf("authenticated report status=%s; want typed unsupported %s", got, codes.Unimplemented)
			}
			if got := status.Convert(err).Message(); got != tt.unsupported {
				t.Fatalf("unsupported report message=%q; want %q", got, tt.unsupported)
			}
		})
	}

	peerCalls := []struct {
		name string
		call func() error
	}{
		{"readiness report", func() error {
			_, err := rpc.PeerReportProviderReadiness(context.Background(), &compatv1.ReportProviderReadinessRequest{})
			return err
		}},
		{"endpoint report", func() error {
			_, err := rpc.PeerReportEndpointStatus(context.Background(), &compatv1.ReportEndpointStatusRequest{})
			return err
		}},
		{"provider status", func() error {
			_, err := rpc.PeerGetSandboxProviderStatus(context.Background(), &compatv1.GetSandboxProviderStatusRequest{})
			return err
		}},
		{"relay stream", func() error { return rpc.PeerRelay(nil) }},
	}
	for _, tt := range peerCalls {
		t.Run("peer "+tt.name, func(t *testing.T) {
			err := tt.call()
			if got := status.Code(err); got != codes.Unimplemented {
				t.Fatalf("peer RPC status=%s; want typed unsupported %s", got, codes.Unimplemented)
			}
			if got, want := status.Convert(err).Message(), "peer relay transport is unsupported by this gateway"; got != want {
				t.Fatalf("peer RPC message=%q; want %q", got, want)
			}
		})
	}
}

func TestGetSandboxProviderStatusFailsClosedWithoutReadinessStore(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-provider-status")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "sandbox", ID: "sandbox", AttachedProviders: []string{"provider"}}); err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st}}
	req := &compatv1.GetSandboxProviderStatusRequest{Sandbox: "sandbox", Provider: "provider"}
	if _, err := rpc.GetSandboxProviderStatus(context.Background(), req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated query status=%s; want %s", status.Code(err), codes.Unauthenticated)
	}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	if response, err := rpc.GetSandboxProviderStatus(ctx, req); status.Code(err) != codes.Unimplemented || response != nil {
		t.Fatalf("query response=%v error=%v; want typed Unsupported", response, err)
	}
}
