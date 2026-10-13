package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestOpenShellSandboxProviderAttachmentLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir(), "provider-attachments")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{
		Name: "demo", ID: "sandbox-demo", Workspace: "default", ResourceVersion: 7,
		AttachedProviders: []string{"github"},
		SpecJSON:          `{"template":{"image":"alpine:3"},"providers":["stale"]}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{
		Name: "openai", Type: "openai", Workspace: "default", EnvVars: []string{"OPENAI_API_KEY"},
		Config:                map[string]string{"organization": "team"},
		CredentialExpiresAtMS: map[string]int64{"OPENAI_API_KEY": 1234},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "github", Type: "github", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev", Subject: "alice"})

	list, err := rpc.ListSandboxProviders(ctx, &openshellv1.ListSandboxProvidersRequest{SandboxName: "demo"})
	if err != nil || len(list.GetProviders()) != 1 || list.GetProviders()[0].GetType() != "github" {
		t.Fatalf("ListSandboxProviders=%v err=%v", list, err)
	}
	if len(list.GetProviders()[0].GetCredentials()) != 0 {
		t.Fatalf("ListSandboxProviders exposed credentials: %v", list.GetProviders()[0].GetCredentials())
	}

	attached, err := rpc.AttachSandboxProvider(ctx, &openshellv1.AttachSandboxProviderRequest{SandboxName: "demo", ProviderName: "openai", ExpectedResourceVersion: 7})
	if err != nil || !attached.GetAttached() {
		t.Fatalf("AttachSandboxProvider=%v err=%v", attached, err)
	}
	if got := attached.GetSandbox().GetMetadata().GetResourceVersion(); got != 8 {
		t.Fatalf("attached resource_version=%d, want 8", got)
	}
	if got := attached.GetSandbox().GetSpec().GetProviders(); len(got) != 2 || got[0] != "github" || got[1] != "openai" {
		t.Fatalf("attached spec providers=%v", got)
	}
	var savedSpec map[string]any
	if err := json.Unmarshal([]byte(st.Snapshot().Sandboxes["demo"].SpecJSON), &savedSpec); err != nil {
		t.Fatal(err)
	}
	if got := savedSpec["providers"].([]any); len(got) != 2 || got[0] != "github" || got[1] != "openai" {
		t.Fatalf("persisted spec providers=%v", got)
	}

	list, err = rpc.ListSandboxProviders(ctx, &openshellv1.ListSandboxProvidersRequest{SandboxName: "demo"})
	if err != nil || len(list.GetProviders()) != 2 {
		t.Fatalf("ListSandboxProviders after attach=%v err=%v", list, err)
	}
	var foundOpenAI bool
	for _, provider := range list.GetProviders() {
		if provider.GetType() == "openai" {
			foundOpenAI = true
			if provider.GetCredentials()["OPENAI_API_KEY"] != "REDACTED" || provider.GetConfig()["organization"] != "team" || provider.GetCredentialExpiresAtMs()["OPENAI_API_KEY"] != 1234 {
				t.Fatalf("redacted provider projection=%v", provider)
			}
		}
	}
	if !foundOpenAI {
		t.Fatal("attached provider missing from ListSandboxProviders")
	}

	idempotent, err := rpc.AttachSandboxProvider(ctx, &openshellv1.AttachSandboxProviderRequest{SandboxName: "demo", ProviderName: "openai", ExpectedResourceVersion: 8})
	if err != nil || idempotent.GetAttached() || idempotent.GetSandbox().GetMetadata().GetResourceVersion() != 8 {
		t.Fatalf("idempotent attach=%v err=%v", idempotent, err)
	}
	detached, err := rpc.DetachSandboxProvider(ctx, &openshellv1.DetachSandboxProviderRequest{SandboxName: "demo", ProviderName: "github", ExpectedResourceVersion: 8})
	if err != nil || !detached.GetDetached() || detached.GetSandbox().GetMetadata().GetResourceVersion() != 9 {
		t.Fatalf("DetachSandboxProvider=%v err=%v", detached, err)
	}
	if got := detached.GetSandbox().GetSpec().GetProviders(); len(got) != 1 || got[0] != "openai" {
		t.Fatalf("detached spec providers=%v", got)
	}
	missing, err := rpc.DetachSandboxProvider(ctx, &openshellv1.DetachSandboxProviderRequest{SandboxName: "demo", ProviderName: "github", ExpectedResourceVersion: 9})
	if err != nil || missing.GetDetached() || missing.GetSandbox().GetMetadata().GetResourceVersion() != 9 {
		t.Fatalf("idempotent detach=%v err=%v", missing, err)
	}
}

func TestOpenShellSandboxProviderAttachmentAuthorizationAndCAS(t *testing.T) {
	st, err := store.Open(t.TempDir(), "provider-attachments-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team", Members: []store.WorkspaceMember{{Subject: "alice", Role: "user"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-team", Workspace: "team", ResourceVersion: 3, SpecJSON: `{"providers":[]}`}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "openai", Type: "openai", Workspace: "team"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	alice := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "alice", Scopes: []string{"sandbox:read", "sandbox:write"}})
	bob := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "bob", Scopes: []string{"sandbox:read", "sandbox:write"}})
	if _, err := rpc.AttachSandboxProvider(bob, &openshellv1.AttachSandboxProviderRequest{SandboxName: "demo", Workspace: "team", ProviderName: "openai"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-workspace attach code=%s err=%v", status.Code(err), err)
	}
	if _, err := rpc.AttachSandboxProvider(alice, &openshellv1.AttachSandboxProviderRequest{SandboxName: "demo", Workspace: "team", ProviderName: "missing"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("missing provider attach code=%s err=%v", status.Code(err), err)
	}
	if _, err := rpc.AttachSandboxProvider(alice, &openshellv1.AttachSandboxProviderRequest{SandboxName: "demo", Workspace: "team", ProviderName: "openai", ExpectedResourceVersion: 2}); status.Code(err) != codes.Aborted {
		t.Fatalf("stale attach code=%s err=%v", status.Code(err), err)
	}
	current, _ := st.GetSandbox("demo")
	if current.ResourceVersion != 3 || len(current.AttachedProviders) != 0 {
		t.Fatalf("rejected mutation changed sandbox: %+v", current)
	}
	if _, err := rpc.AttachSandboxProvider(alice, &openshellv1.AttachSandboxProviderRequest{SandboxName: "demo", Workspace: "team", ProviderName: "openai", ExpectedResourceVersion: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := rpc.DetachSandboxProvider(alice, &openshellv1.DetachSandboxProviderRequest{SandboxName: "demo", Workspace: "team", ProviderName: "openai", ExpectedResourceVersion: 3}); status.Code(err) != codes.Aborted {
		t.Fatalf("stale detach code=%s err=%v", status.Code(err), err)
	}
}

func TestOpenShellSandboxProviderAttachmentLimit(t *testing.T) {
	st, err := store.Open(t.TempDir(), "provider-attachments-limit")
	if err != nil {
		t.Fatal(err)
	}
	attached := make([]string, maxSandboxProviders)
	for i := range attached {
		attached[i] = fmt.Sprintf("provider-%02d", i)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "full", Workspace: "default", ResourceVersion: 5, AttachedProviders: attached}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "extra", Type: "test", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	if _, err := rpc.AttachSandboxProvider(ctx, &openshellv1.AttachSandboxProviderRequest{SandboxName: "full", ProviderName: "extra"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("provider limit code=%s err=%v", status.Code(err), err)
	}
	current, _ := st.GetSandbox("full")
	if current.ResourceVersion != 5 || len(current.AttachedProviders) != maxSandboxProviders {
		t.Fatalf("provider limit rejection mutated sandbox: rv=%d providers=%d", current.ResourceVersion, len(current.AttachedProviders))
	}
}
