package httpapi

import (
	"context"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSandboxPolicyHistoryStatusAndPagination(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-policy-history")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBasePolicy("demo", "version: 1\n"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBasePolicy("demo", "version: 1\nnetwork_policies: {}\n"); err != nil {
		t.Fatal(err)
	}
	if err := st.ReportPolicyStatus("demo", 2, store.PolicyStatusLoaded, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	statusResponse, err := rpc.GetSandboxPolicyStatus(ctx, &openshellv1.GetSandboxPolicyStatusRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if statusResponse.GetRevision().GetVersion() != 2 || statusResponse.GetActiveVersion() != 2 || statusResponse.GetRevision().GetPolicy() == nil {
		t.Fatalf("status response=%v", statusResponse)
	}
	list, err := rpc.ListSandboxPolicies(ctx, &openshellv1.ListSandboxPoliciesRequest{Name: "demo", Limit: 1, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetRevisions()) != 1 || list.GetRevisions()[0].GetVersion() != 1 || list.GetRevisions()[0].GetPolicy() != nil {
		t.Fatalf("list response=%v", list)
	}
	if _, err := rpc.GetSandboxPolicyStatus(ctx, &openshellv1.GetSandboxPolicyStatusRequest{Name: "demo", Version: 99}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing version error=%v; want NotFound", err)
	}
}

func TestSandboxPolicyHistoryRejectsCrossWorkspaceAndInvalidPolicy(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-policy-history-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBasePolicy("demo", "version: 1\n"); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "reader", Scopes: []string{"sandbox:read"}})
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team", Members: []store.WorkspaceMember{{Subject: "reader", Role: "reader"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := rpc.GetSandboxPolicyStatus(ctx, &openshellv1.GetSandboxPolicyStatusRequest{Name: "demo", Workspace: "default"}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-workspace status error=%v; want NotFound", err)
	}
	if _, err := rpc.GetSandboxPolicyStatus(ctx, &openshellv1.GetSandboxPolicyStatusRequest{Name: "demo", Workspace: "team"}); err != nil {
		t.Fatal(err)
	}
}

func TestGlobalPolicyHistoryIsAdminOnlyAndPaginatedNewestFirst(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-global-policy-history")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetGlobalPolicy("version: 1\n"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetGlobalPolicy("version: 1\nnetwork_policies: {}\n"); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	admin := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	list, err := rpc.ListSandboxPolicies(admin, &openshellv1.ListSandboxPoliciesRequest{Global: true, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetRevisions()) != 1 || list.GetRevisions()[0].GetVersion() != 2 {
		t.Fatalf("global policy list=%v", list)
	}
	statusResponse, err := rpc.GetSandboxPolicyStatus(admin, &openshellv1.GetSandboxPolicyStatusRequest{Global: true, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if statusResponse.GetRevision().GetVersion() != 1 || statusResponse.GetRevision().GetPolicy() == nil {
		t.Fatalf("global policy status=%v", statusResponse)
	}
	user := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "viewer", Scopes: []string{"sandbox:read"}})
	if _, err := rpc.ListSandboxPolicies(user, &openshellv1.ListSandboxPoliciesRequest{Global: true}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("global policy list auth error=%v", err)
	}
}
