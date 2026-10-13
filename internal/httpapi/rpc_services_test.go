package httpapi

import (
	"context"
	"testing"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
)

func TestOpenShellServiceEndpointLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir(), "services")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-demo", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})

	exposed, err := rpc.ExposeService(ctx, &openshellv1.ExposeServiceRequest{Sandbox: "demo", Service: "web", TargetPort: 8080, Domain: true})
	if err != nil {
		t.Fatal(err)
	}
	if exposed.GetEndpoint().GetSandboxId() != "sandbox-demo" || exposed.GetEndpoint().GetTargetPort() != 8080 || exposed.GetUrl() != "http://web.openshell.localhost" {
		t.Fatalf("exposed endpoint=%v", exposed)
	}

	got, err := rpc.GetService(ctx, &openshellv1.GetServiceRequest{Sandbox: "demo", Service: "web"})
	if err != nil || got.GetEndpoint().GetServiceName() != "web" {
		t.Fatalf("GetService=%v err=%v", got, err)
	}
	listed, err := rpc.ListServices(ctx, &openshellv1.ListServicesRequest{})
	if err != nil || len(listed.GetServices()) != 1 {
		t.Fatalf("ListServices=%v err=%v", listed, err)
	}
	deleted, err := rpc.DeleteService(ctx, &openshellv1.DeleteServiceRequest{Sandbox: "demo", Service: "web"})
	if err != nil || !deleted.GetDeleted() {
		t.Fatalf("DeleteService=%v err=%v", deleted, err)
	}
	if _, err := rpc.GetService(ctx, &openshellv1.GetServiceRequest{Sandbox: "demo", Service: "web"}); err == nil {
		t.Fatal("deleted service still returned")
	}
}

func TestOpenShellSandboxTokenRotation(t *testing.T) {
	st, err := store.Open(t.TempDir(), "tokens")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-demo"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "demo"})
	first, err := rpc.IssueSandboxToken(ctx, &openshellv1.IssueSandboxTokenRequest{})
	if err != nil || first.GetToken() == "" {
		t.Fatalf("IssueSandboxToken=%v err=%v", first, err)
	}
	second, err := rpc.RefreshSandboxToken(ctx, &openshellv1.RefreshSandboxTokenRequest{})
	if err != nil || second.GetToken() == "" || second.GetToken() == first.GetToken() {
		t.Fatalf("RefreshSandboxToken=%v err=%v", second, err)
	}
	if sandbox, ok := st.SandboxForToken(second.GetToken()); !ok || sandbox != "demo" {
		t.Fatalf("refreshed token lookup=%q ok=%v", sandbox, ok)
	}
	if _, ok := st.SandboxForToken(first.GetToken()); ok {
		t.Fatal("rotated token remained valid")
	}
}
