package httpapi

import (
	"context"
	"errors"
	"net"
	"testing"

	sdkv1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestOpenShellWorkspaceRPCs(t *testing.T) {
	st, err := store.Open(t.TempDir(), "workspace-rpc")
	if err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev", Subject: "operator"})
	created, err := rpc.CreateWorkspace(ctx, &openshellv1.CreateWorkspaceRequest{Name: "team-a", Labels: map[string]string{"env": "test"}})
	if err != nil {
		t.Fatal(err)
	}
	if created.GetWorkspace().GetMetadata().GetLabels()["env"] != "test" {
		t.Fatalf("workspace=%v", created.GetWorkspace())
	}
	if created.GetWorkspace().GetMetadata().GetId() == "" || created.GetWorkspace().GetMetadata().GetResourceVersion() == 0 {
		t.Fatalf("workspace metadata=%v", created.GetWorkspace().GetMetadata())
	}
	if _, err = rpc.CreateWorkspace(ctx, &openshellv1.CreateWorkspaceRequest{Name: "team-a"}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate create err=%v", err)
	}
	if _, err = rpc.AddWorkspaceMember(ctx, &openshellv1.AddWorkspaceMemberRequest{Workspace: "team-a", PrincipalSubject: "alice", Role: openshellv1.WorkspaceRole_WORKSPACE_ROLE_USER}); err != nil {
		t.Fatal(err)
	}
	adminCtx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	added, err := rpc.AddWorkspaceMember(adminCtx, &openshellv1.AddWorkspaceMemberRequest{Workspace: "team-a", PrincipalSubject: "alice", Role: openshellv1.WorkspaceRole_WORKSPACE_ROLE_USER})
	if status.Code(err) != codes.AlreadyExists || added != nil {
		t.Fatalf("duplicate member add=%v err=%v", added, err)
	}
	readCtx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "alice", Scopes: []string{"workspace:read"}})
	got, err := rpc.GetWorkspace(readCtx, &openshellv1.GetWorkspaceRequest{Name: "team-a"})
	if err != nil || got.GetWorkspace().GetMetadata().GetName() != "team-a" {
		t.Fatalf("get=%v err=%v", got, err)
	}
	listed, err := rpc.ListWorkspaces(readCtx, &openshellv1.ListWorkspacesRequest{LabelSelector: "env=test"})
	if err != nil || len(listed.GetWorkspaces()) != 1 {
		t.Fatalf("list=%v err=%v", listed, err)
	}
	members, err := rpc.ListWorkspaceMembers(readCtx, &openshellv1.ListWorkspaceMembersRequest{Workspace: "team-a"})
	if err != nil || len(members.GetMembers()) != 1 || members.GetMembers()[0].GetPrincipalSubject() != "alice" {
		t.Fatalf("members=%v err=%v", members, err)
	}
	if members.GetMembers()[0].GetMetadata().GetId() == "" || members.GetMembers()[0].GetMetadata().GetResourceVersion() == 0 {
		t.Fatalf("member metadata=%v", members.GetMembers()[0].GetMetadata())
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "busy", Workspace: "team-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err = rpc.DeleteWorkspace(ctx, &openshellv1.DeleteWorkspaceRequest{Name: "team-a"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("non-empty delete err=%v", err)
	}
	terminating, err := rpc.GetWorkspace(ctx, &openshellv1.GetWorkspaceRequest{Name: "team-a"})
	if err != nil || terminating.GetWorkspace().GetStatus().GetPhase() != datamodelv1.WorkspacePhase_WORKSPACE_PHASE_TERMINATING {
		t.Fatalf("terminating workspace=%v err=%v", terminating, err)
	}
	if _, err := rpc.AddWorkspaceMember(ctx, &openshellv1.AddWorkspaceMemberRequest{Workspace: "team-a", PrincipalSubject: "blocked", Role: openshellv1.WorkspaceRole_WORKSPACE_ROLE_USER}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("member create in terminating workspace err=%v", err)
	}
	if err := st.DeleteSandbox("busy"); err != nil {
		t.Fatal(err)
	}
	removed, err := rpc.RemoveWorkspaceMember(ctx, &openshellv1.RemoveWorkspaceMemberRequest{Workspace: "team-a", PrincipalSubject: "alice"})
	if err != nil || !removed.GetRemoved() {
		t.Fatalf("remove=%v err=%v", removed, err)
	}
	if err := st.DeleteSandbox("busy"); err != nil {
		t.Fatal(err)
	}
	deleted, err := rpc.DeleteWorkspace(ctx, &openshellv1.DeleteWorkspaceRequest{Name: "team-a"})
	if err != nil || !deleted.GetDeleted() {
		t.Fatalf("delete=%v err=%v", deleted, err)
	}
}

func TestPinnedOpenShellGoSDKWorkspaceConformance(t *testing.T) {
	st, err := store.Open(t.TempDir(), "workspace-sdk-conformance")
	if err != nil {
		t.Fatal(err)
	}
	runtime := &grpcRuntime{st: st}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpcAuthServerOptions(Options{grpcRuntime: runtime, AllowUnauthenticated: true})...)
	registerOpenShellRPCWithOptions(server, Options{grpcRuntime: runtime, AllowUnauthenticated: true})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	client, err := sdkv1.NewClient(sdkv1.Config{Address: "http://" + listener.Addr().String(), Auth: sdkv1.NoAuth()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	created, err := client.Workspaces().Create(ctx, "sdk-team", map[string]string{"team": "sdk"})
	if err != nil || created.Name != "sdk-team" || created.ID == "" || created.ResourceVersion == 0 || created.Labels["team"] != "sdk" {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	if _, err := client.Workspaces().Create(ctx, "sdk-team", nil); !sdkv1.IsAlreadyExists(err) {
		t.Fatalf("duplicate SDK create err=%v", err)
	}
	got, err := client.Workspaces().Get(ctx, "sdk-team")
	if err != nil || got.Name != "sdk-team" {
		t.Fatalf("get=%+v err=%v", got, err)
	}
	listed, err := client.Workspaces().List(ctx, sdkv1.ListOptions{Limit: 10})
	if err != nil || len(listed) != 1 || listed[0].Name != "sdk-team" {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	member, err := client.Workspaces().AddMember(ctx, "sdk-team", "sdk-user", sdkv1.WorkspaceRoleUser)
	if err != nil || member.PrincipalSubject != "sdk-user" || member.Role != sdkv1.WorkspaceRoleUser || member.ID == "" || member.ResourceVersion == 0 {
		t.Fatalf("add member=%+v err=%v", member, err)
	}
	members, err := client.Workspaces().ListMembers(ctx, "sdk-team")
	if err != nil || len(members) != 1 || members[0].PrincipalSubject != "sdk-user" {
		t.Fatalf("members=%+v err=%v", members, err)
	}
	if err := client.Workspaces().RemoveMember(ctx, "sdk-team", "sdk-user"); err != nil {
		t.Fatal(err)
	}
	if err := client.Workspaces().Delete(ctx, "sdk-team"); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceRPCAuthorizationAndValidation(t *testing.T) {
	st, err := store.Open(t.TempDir(), "workspace-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "team-a", Members: []store.WorkspaceMember{{Subject: "alice", Role: "user"}}}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	outsider := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "bob", Scopes: []string{"workspace:read"}})
	if _, err := rpc.GetWorkspace(outsider, &openshellv1.GetWorkspaceRequest{Name: "team-a"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-member read err=%v", err)
	}
	member := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "alice", Scopes: []string{"workspace:write"}})
	if _, err := rpc.AddWorkspaceMember(member, &openshellv1.AddWorkspaceMemberRequest{Workspace: "team-a", PrincipalSubject: "bob", Role: openshellv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("admin grant err=%v", err)
	}
	local := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	if _, err := rpc.CreateWorkspace(local, &openshellv1.CreateWorkspaceRequest{Name: "Not DNS"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid name err=%v", err)
	}
	if _, err := rpc.DeleteWorkspace(local, &openshellv1.DeleteWorkspaceRequest{Name: "default"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("default delete err=%v", err)
	}
}

func TestDeleteWorkspaceChecksAllGatewayOwnedWorkspaceResources(t *testing.T) {
	st, err := store.Open(t.TempDir(), "workspace-resource-blockers")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "team-a"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProfileScoped("workspace", "team-a", "team-profile", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteWorkspace("team-a"); !errors.Is(err, store.ErrWorkspaceNotEmpty) {
		t.Fatalf("profile blocker err=%v", err)
	}
	if err := st.DeleteProfileScoped("workspace", "team-a", "team-profile"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "team-provider", Workspace: "team-a"}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteWorkspace("team-a"); !errors.Is(err, store.ErrWorkspaceNotEmpty) {
		t.Fatalf("provider blocker err=%v", err)
	}
	if err := st.DeleteProvider("team-provider"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteWorkspace("team-a"); err != nil {
		t.Fatalf("empty workspace delete err=%v", err)
	}
}

func TestWorkspaceDeleteCASProtectsRecreatedRecord(t *testing.T) {
	st, err := store.Open(t.TempDir(), "workspace-delete-cas")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "cas-team", ID: "original"}); err != nil {
		t.Fatal(err)
	}
	terminating, err := st.MarkWorkspaceTerminating("cas-team")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteWorkspace("cas-team"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "cas-team", ID: "replacement"}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteWorkspaceCAS("cas-team", terminating.ID, terminating.ResourceVersion); !errors.Is(err, store.ErrWorkspaceConflict) {
		t.Fatalf("stale delete err=%v", err)
	}
	if ws, ok := st.GetWorkspace("cas-team"); !ok || ws.ID != "replacement" {
		t.Fatalf("replacement workspace=%+v exists=%v", ws, ok)
	}
}
