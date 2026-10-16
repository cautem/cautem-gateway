//go:build linux

package integration

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/quarshell-core/relayproto"
	"github.com/cautem/quarshell-gateway/internal/httpapi"
	controlv1 "github.com/cautem/quarshell-proto/gen/go/cautem/control/v1"
	"github.com/cautem/quarshell-runtime/relayclient"
	"github.com/cautem/quarshell-runtime/sshserver"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// startSupervisor runs a real sshserver on a Unix socket and a relayclient
// dialing out to the gateway, like the proxy sidecar does.
func (g *testGateway) startSupervisor(name, token string) {
	g.t.Helper()
	initPath := filepath.Join(g.t.TempDir(), "cautem-init")
	if err := os.WriteFile(initPath, []byte("#!/bin/sh\n[ \"$1\" = \"--\" ] || exit 99\nshift\nexec \"$@\"\n"), 0o700); err != nil {
		g.t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := sshserver.New(sshserver.Config{
		Shell:    "/bin/sh",
		InitPath: initPath,
		Env:      []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + g.t.TempDir()},
		Log:      quiet,
	})
	if err != nil {
		g.t.Fatal(err)
	}
	sock := filepath.Join(g.t.TempDir(), "ssh", "sshd.sock")
	ln, err := sshserver.ListenUnix(sock)
	if err != nil {
		g.t.Fatal(err)
	}
	g.t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = srv.Serve(ln) }()

	ctx, cancel := context.WithCancel(context.Background())
	g.t.Cleanup(cancel)
	connected := make(chan struct{}, 1)
	go func() {
		_ = relayclient.Run(ctx, relayclient.Config{
			GatewayURL: g.srv.URL,
			Sandbox:    name,
			Token:      token,
			SSHSocket:  sock,
			Log:        quiet,
			MinBackoff: 20 * time.Millisecond,
			MaxBackoff: 100 * time.Millisecond,
			OnConnected: func() {
				select {
				case connected <- struct{}{}:
				default:
				}
			},
		})
	}()
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		g.t.Fatal("supervisor did not connect")
	}
}

type sshSessionResp struct {
	SessionID string `json:"session_id"`
	SandboxID string `json:"sandbox_id"`
	Token     string `json:"token"`
	Scheme    string `json:"gateway_scheme"`
	Host      string `json:"gateway_host"`
	Port      int    `json:"gateway_port"`
	ExpiresAt int64  `json:"expires_at_ms"`
}

func (g *testGateway) sshSession(name string) sshSessionResp {
	g.t.Helper()
	client, _ := g.openShellClient()
	ctx := g.rpcContext(context.Background(), g.token)
	deadline := time.Now().Add(2 * time.Second)
	var session *compatv1.CreateSshSessionResponse
	var err error
	for {
		session, err = client.CreateSshSession(ctx, &compatv1.CreateSshSessionRequest{Sandbox: name})
		if err == nil {
			break
		}
		if status.Code(err) != codes.FailedPrecondition || time.Now().After(deadline) {
			g.t.Fatalf("create SSH session over OpenShell RPC: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	var expiresAt int64
	if expiration := session.GetExpirationTime(); expiration != nil {
		expiresAt = expiration.AsTime().UnixMilli()
	}
	return sshSessionResp{SandboxID: session.GetSandboxId(), Token: session.GetToken(), Scheme: session.GetGatewayScheme(), Host: session.GetGatewayHost(), Port: int(session.GetGatewayPort()), ExpiresAt: expiresAt}
}

func (g *testGateway) dialSSH(sandbox, sessionToken string) (*ssh.Client, error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+sessionToken)
	h.Set(relayproto.HeaderSandboxID, sandbox)
	conn, err := relayproto.Dial(context.Background(), g.srv.URL, relayproto.PathSSHConnect, relayproto.DialOptions{Header: h})
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, "sandbox", &ssh.ClientConfig{
		User:            "sandbox",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func statusOf(err error) int {
	var se *relayproto.StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

func TestRelaySSHSessionEndToEnd(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	g.startSupervisor("demo", g.sandboxToken("demo"))

	s := g.sshSession("demo")
	if s.Token == "" || s.SandboxID != "demo" || s.Scheme != "http" || s.Port == 0 || s.ExpiresAt == 0 {
		t.Fatalf("session response = %+v", s)
	}
	client, err := g.dialSSH("demo", s.Token)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("echo relay-ok")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "relay-ok" {
		t.Fatalf("out = %q", out)
	}
	_ = client.Close()

	rpcClient, _ := g.openShellClient()
	revoked, err := rpcClient.RevokeSshSession(g.rpcContext(context.Background(), g.token), &compatv1.RevokeSshSessionRequest{Token: s.Token})
	if err != nil || revoked.GetOutcome() != compatv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED {
		t.Fatalf("revoke SSH session over OpenShell RPC: response=%v err=%v", revoked, err)
	}
	if _, err := g.dialSSH("demo", s.Token); statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("revoked session dial = %v, want 401", err)
	}
}

func TestRelaySSHConnectRejections(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	g.createSandbox("other")
	g.startSupervisor("demo", g.sandboxToken("demo"))
	s := g.sshSession("demo")

	cases := map[string]struct{ sandbox, token string }{
		"no token":        {"demo", ""},
		"user token":      {"demo", g.token},
		"wrong sandbox":   {"other", s.Token},
		"unknown sandbox": {"ghost", s.Token},
		"garbage token":   {"demo", "deadbeef"},
	}
	for name, c := range cases {
		if _, err := g.dialSSH(c.sandbox, c.token); statusOf(err) != http.StatusUnauthorized {
			t.Errorf("%s: err = %v, want 401", name, err)
		}
	}
}

func TestRelaySessionExpires(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{SSHSessionTTL: 300 * time.Millisecond})
	g.createSandbox("demo")
	g.startSupervisor("demo", g.sandboxToken("demo"))
	s := g.sshSession("demo")
	time.Sleep(400 * time.Millisecond)
	if _, err := g.dialSSH("demo", s.Token); statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("expired session dial = %v, want 401", err)
	}
}

func TestRelayNotReady(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("cold")
	client, _ := g.openShellClient()
	ctx := g.rpcContext(context.Background(), g.token)
	if _, err := client.CreateSshSession(ctx, &compatv1.CreateSshSessionRequest{Sandbox: "cold"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("CreateSshSession without supervisor code=%s err=%v", status.Code(err), err)
	}
	if _, err := client.CreateSshSession(ctx, &compatv1.CreateSshSessionRequest{Sandbox: "ghost"}); status.Code(err) != codes.NotFound {
		t.Fatalf("CreateSshSession for missing sandbox code=%s err=%v", status.Code(err), err)
	}
	exec, err := client.ExecSandbox(ctx, &compatv1.ExecSandboxRequest{Sandbox: "cold", Command: []string{"true"}})
	if err == nil {
		_, err = exec.Recv()
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ExecSandbox without supervisor code=%s err=%v", status.Code(err), err)
	}
}

func TestRelayExec(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	g.syncSandbox(&controlv1.SyncManagedSandboxRequest{Workspace: "default", Name: "demo", Status: "running"})
	g.startSupervisor("demo", g.sandboxToken("demo"))

	client, _ := g.openShellClient()
	ctx := g.rpcContext(context.Background(), g.token)
	stream, err := client.ExecSandbox(ctx, &compatv1.ExecSandboxRequest{Sandbox: "demo", Command: []string{"sh", "-c", `echo "it's fine"; exit 4`}})
	if err != nil {
		t.Fatalf("ExecSandbox: %v", err)
	}
	var stdout strings.Builder
	var exitCode int32
	for {
		event, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			t.Fatalf("ExecSandbox stream: %v", recvErr)
		}
		if data := event.GetStdout(); data != nil {
			stdout.Write(data.GetData())
		}
		if result := event.GetExit(); result != nil {
			exitCode = result.GetExitCode()
		}
	}
	if exitCode != 4 || strings.TrimSpace(stdout.String()) != "it's fine" {
		t.Fatalf("ExecSandbox exit=%d output=%q", exitCode, stdout.String())
	}
	for _, path := range []string{"/v1/sandboxes/demo/exec", "/v1/relay/demo/exec", "/v1/relay/demo/poll", "/v1/relay/demo/result"} {
		if code, _ := g.do(http.MethodPost, path, g.token, map[string]any{"argv": []string{"echo", "legacy"}}); code != http.StatusNotFound {
			t.Errorf("removed REST exec route %s = %d, want 404", path, code)
		}
	}
}

func TestSupervisorTokenRotationKicksOldSupervisor(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	old := g.sandboxToken("demo")
	g.sandboxToken("demo")
	if code, _ := g.do(http.MethodGet, "/v1/whoami", old, nil); code != http.StatusUnauthorized {
		t.Fatalf("rotated supervisor token = %d, want 401", code)
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+old)
	_, err := relayproto.Dial(context.Background(), g.srv.URL, relayproto.PathSupervisorConnect+"?sandbox=demo", relayproto.DialOptions{Header: h})
	if statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("old supervisor connect = %v, want 401", err)
	}
}

func TestSandboxDeleteRevokesRelay(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	sbTok := g.sandboxToken("demo")
	g.startSupervisor("demo", sbTok)
	s := g.sshSession("demo")
	g.deleteSandbox("demo")
	if _, err := g.dialSSH("demo", s.Token); statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("session after delete = %v, want 401", err)
	}
	if code, _ := g.do(http.MethodGet, "/v1/whoami", sbTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("sandbox token after delete = %d, want 401", code)
	}
}

func TestUserTokenCannotActAsSupervisor(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	h := http.Header{}
	h.Set("Authorization", "Bearer "+g.token)
	_, err := relayproto.Dial(context.Background(), g.srv.URL, relayproto.PathSupervisorConnect+"?sandbox=demo", relayproto.DialOptions{Header: h})
	if statusOf(err) != http.StatusForbidden {
		t.Fatalf("user token supervisor connect = %v, want 403", err)
	}
}
