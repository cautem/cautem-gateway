package httpapi

import (
	"context"
	"errors"
	"testing"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type execEventStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s execEventStream) Context() context.Context                 { return s.ctx }
func (s execEventStream) Send(*openshellv1.ExecSandboxEvent) error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestMapRelayExecErrorTreatsTransportTimeoutAsDeadline(t *testing.T) {
	if got := status.Code(mapRelayExecError(timeoutError{})); got != codes.DeadlineExceeded {
		t.Fatalf("transport timeout mapped to %s; want DeadlineExceeded", got)
	}
	if got := status.Code(mapRelayExecError(errors.New("relay disconnected"))); got != codes.Unavailable {
		t.Fatalf("relay disconnect mapped to %s; want Unavailable", got)
	}
}

func TestOpenShellExecSandboxRequiresWorkspaceWrite(t *testing.T) {
	st, err := store.Open(t.TempDir(), "exec-rpc-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team", Members: []store.WorkspaceMember{{Subject: "alice", Role: "user"}}}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, relay: sshrelay.NewHub()}}
	req := &openshellv1.ExecSandboxRequest{SandboxId: "demo", Command: []string{"id"}}
	stream := execEventStream{ctx: withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "bob", Scopes: []string{"sandbox:write"}})}
	if err := rpc.ExecSandbox(req, stream); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-workspace exec code=%s err=%v; want PermissionDenied", status.Code(err), err)
	}
	stream.ctx = withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "alice", Scopes: []string{"sandbox:write"}})
	if err := rpc.ExecSandbox(req, stream); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("exec without supervisor relay code=%s err=%v; want FailedPrecondition", status.Code(err), err)
	}
}

func TestOpenShellExecSandboxRejectsUnapprovedEnvironment(t *testing.T) {
	st, err := store.Open(t.TempDir(), "exec-rpc-env")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, relay: sshrelay.NewHub()}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev", Subject: "local-dev"})
	err = rpc.ExecSandbox(&openshellv1.ExecSandboxRequest{SandboxId: "demo", Command: []string{"id"}, Environment: map[string]string{"LD_PRELOAD": "payload"}}, execEventStream{ctx: ctx})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unapproved environment code=%s err=%v; want InvalidArgument", status.Code(err), err)
	}
}
