package httpapi

import (
	"context"
	"errors"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestOpenShellGRPCSSHSessionLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir(), "ssh-grpc")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sb-demo", Workspace: "default", ComputeDriver: "docker"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	relay := sshrelay.NewHub()
	remove := relay.RegisterOpenShellSupervisor("demo", "instance-demo", func(string, string) error { return nil }, done, nil)
	defer func() { close(done); remove() }()
	rpc := &openShellRPC{options: Options{Listen: "127.0.0.1:7443"}, runtime: &grpcRuntime{
		st: st, relay: relay, sshSessionTTL: 0,
		compute: &computeRegistry{configured: map[string]map[string]any{"docker": {"grpc_endpoint": "https://gateway.example:8443"}}},
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev", Subject: "alice"})
	created, err := rpc.CreateSshSession(ctx, &openshellv1.CreateSshSessionRequest{SandboxId: "sb-demo"})
	if err != nil {
		t.Fatal(err)
	}
	if created.GetSandboxId() != "demo" || created.GetGatewayHost() != "gateway.example" || created.GetGatewayPort() != 8443 || created.GetGatewayScheme() != "https" || created.GetToken() == "" || created.GetExpiresAtMs() == 0 {
		t.Fatalf("CreateSshSession returned incomplete response: %v", created)
	}
	if _, err := st.ValidateSSHSession(created.GetToken(), "demo", time.Now()); err != nil {
		t.Fatalf("issued session token does not validate: %v", err)
	}
	revoked, err := rpc.RevokeSshSession(ctx, &openshellv1.RevokeSshSessionRequest{Token: created.GetToken()})
	if err != nil || !revoked.GetRevoked() {
		t.Fatalf("RevokeSshSession=%v err=%v", revoked, err)
	}
	if _, err := st.ValidateSSHSession(created.GetToken(), "demo", time.Now()); !errors.Is(err, store.ErrSessionRevoked) {
		t.Fatalf("revoked session validation error=%v", err)
	}
	revoked, err = rpc.RevokeSshSession(ctx, &openshellv1.RevokeSshSessionRequest{Token: created.GetToken()})
	if err != nil || revoked.GetRevoked() {
		t.Fatalf("repeated revoke=%v err=%v; want false, nil", revoked, err)
	}
}

func TestOpenShellGRPCSSHSessionRequiresRelayAndScopedOwner(t *testing.T) {
	st, err := store.Open(t.TempDir(), "ssh-grpc-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team", Members: []store.WorkspaceMember{{Subject: "alice", Role: "user"}}}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{options: Options{Listen: "127.0.0.1:7443"}, runtime: &grpcRuntime{st: st, relay: sshrelay.NewHub()}}
	alice := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "alice", Scopes: []string{"sandbox:write"}})
	if _, err := rpc.CreateSshSession(alice, &openshellv1.CreateSshSessionRequest{SandboxId: "demo"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("not-ready CreateSshSession code=%s err=%v", status.Code(err), err)
	}
	_, token, err := st.CreateSSHSession("demo", "alice", 0)
	if err != nil {
		t.Fatal(err)
	}
	bob := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "bob", Scopes: []string{"sandbox:write"}})
	if _, err := rpc.RevokeSshSession(bob, &openshellv1.RevokeSshSessionRequest{Token: token}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-workspace RevokeSshSession code=%s err=%v", status.Code(err), err)
	}
	if _, err := st.ValidateSSHSession(token, "demo", time.Now()); err != nil {
		t.Fatalf("unauthorized revoke changed session state: %v", err)
	}
}

func TestOpenShellGRPCSSHSessionExpiresAndCannotBeValidated(t *testing.T) {
	st, err := store.Open(t.TempDir(), "ssh-expiry")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sb-demo", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	relay := sshrelay.NewHub()
	remove := relay.RegisterOpenShellSupervisor("demo", "instance", func(string, string) error { return nil }, done, nil)
	t.Cleanup(func() { close(done); remove() })
	rpc := &openShellRPC{options: Options{Listen: "127.0.0.1:7443"}, runtime: &grpcRuntime{
		st: st, relay: relay, sshSessionTTL: time.Millisecond,
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev", Subject: "alice"})
	created, err := rpc.CreateSshSession(ctx, &openshellv1.CreateSshSessionRequest{SandboxId: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := st.ValidateSSHSession(created.GetToken(), "demo", time.Now()); !errors.Is(err, store.ErrSessionExpired) {
		t.Fatalf("expired session validation error=%v, want ErrSessionExpired", err)
	}
}

func TestParsePublicGatewayURLRejectsShellMetacharacters(t *testing.T) {
	for _, raw := range []string{"http://gateway.example;touch" + ":7443", "http://bad%24host:7443", "http://0.0.0.0:7443"} {
		if _, err := parsePublicGatewayURL(raw); err == nil {
			t.Errorf("parsePublicGatewayURL(%q) unexpectedly succeeded", raw)
		}
	}
	for _, raw := range []string{"http://gateway.example:7443", "https://[2001:db8::1]:8443"} {
		if _, err := parsePublicGatewayURL(raw); err != nil {
			t.Errorf("parsePublicGatewayURL(%q) failed: %v", raw, err)
		}
	}
}
