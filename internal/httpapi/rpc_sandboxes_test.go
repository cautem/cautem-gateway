package httpapi

import (
	"context"
	"testing"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetAndListSandboxesReturnStoredSpecAndMetadata(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-sandbox-read")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "id-demo", Workspace: "default", Status: "running", ResourceVersion: 7, Labels: map[string]string{"team": "infra"}, SpecJSON: `{"template":{"image":"alpine:3"},"providers":["github"]}`}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	got, err := rpc.GetSandbox(ctx, &openshellv1.GetSandboxRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetSandbox().GetSpec().GetTemplate().GetImage() != "alpine:3" || got.GetSandbox().GetMetadata().GetResourceVersion() != 7 || got.GetSandbox().GetStatus().GetPhase() != openshellv1.SandboxPhase_SANDBOX_PHASE_READY {
		t.Fatalf("GetSandbox returned incomplete record: %v", got)
	}
	list, err := rpc.ListSandboxes(ctx, &openshellv1.ListSandboxesRequest{LabelSelector: "team=infra", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetSandboxes()) != 1 || list.GetSandboxes()[0].GetMetadata().GetName() != "demo" {
		t.Fatalf("ListSandboxes=%v", list)
	}
}

func TestSandboxReadAuthorizationValidationAndPagination(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-sandbox-read-auth")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if err := st.UpsertSandbox(store.Sandbox{Name: name, Workspace: "team", Labels: map[string]string{"group": "x"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team", Members: []store.WorkspaceMember{{Subject: "reader", Role: "reader"}}}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	reader := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "reader", Scopes: []string{"sandbox:read"}})
	page, err := rpc.ListSandboxes(reader, &openshellv1.ListSandboxesRequest{Workspace: "team", LabelSelector: "group=x", Limit: 1, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.GetSandboxes()) != 1 || page.GetSandboxes()[0].GetMetadata().GetName() != "b" {
		t.Fatalf("page=%v", page)
	}
	if _, err := rpc.GetSandbox(reader, &openshellv1.GetSandboxRequest{Name: "a", Workspace: "default"}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-workspace GetSandbox error=%v", err)
	}
	if _, err := rpc.ListSandboxes(reader, &openshellv1.ListSandboxesRequest{AllWorkspaces: true}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("all-workspace error=%v", err)
	}
	if _, err := rpc.ListSandboxes(reader, &openshellv1.ListSandboxesRequest{Workspace: "team", AllWorkspaces: true}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("conflicting scope error=%v", err)
	}
	if _, err := rpc.ListSandboxes(reader, &openshellv1.ListSandboxesRequest{Workspace: "team", LabelSelector: "group"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad selector error=%v", err)
	}
}

func TestSandboxReadRejectsCorruptStoredSpec(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-sandbox-bad-spec")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "broken", Workspace: "default", SpecJSON: "{"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	if _, err := rpc.GetSandbox(ctx, &openshellv1.GetSandboxRequest{Name: "broken"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("corrupt spec error=%v", err)
	}
}
