package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestBrowserTerminalRouteRelaysInteractivePTY(t *testing.T) {
	st, err := store.Open(t.TempDir(), "browser-terminal-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	token, err := st.EnsureAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	runtime := &grpcRuntime{st: st, relay: sshrelay.NewHub()}
	done := make(chan struct{})
	remove := runtime.relay.RegisterSupervisor("demo", "terminal-test", func(channel, _ string) error {
		relayConn, err := runtime.relay.AcceptRelay("demo", channel)
		if err != nil {
			return err
		}
		supervisorSide, serviceSide := forwardTCPPair(t)
		go sshrelay.Bridge(relayConn, supervisorSide)
		go serveTerminalTestSSH(t, serviceSide)
		return nil
	}, done, nil)
	t.Cleanup(func() { close(done); remove() })
	mux := http.NewServeMux()
	mountBrowserTerminal(mux, context.Background(), st, runtime, Options{}, AuthOptions{})
	server := httptest.NewServer(withAuth(mux, st, AuthOptions{}))
	t.Cleanup(server.Close)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/sandboxes/demo/terminal"

	badOrigin := http.Header{"Origin": []string{"http://attacker.example"}}
	if conn, _, err := websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{HTTPHeader: badOrigin}); err == nil {
		_ = conn.CloseNow()
		t.Fatal("cross-origin WebSocket was accepted")
	}

	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	if err := wsjson.Write(context.Background(), conn, browserTerminalFrame{Type: "auth", Token: token, Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}

	readFrame := func() browserTerminalEvent {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		var event browserTerminalEvent
		if err := wsjson.Read(ctx, conn, &event); err != nil {
			t.Fatal(err)
		}
		return event
	}
	if event := readFrame(); event.Type != "ready" {
		t.Fatalf("first terminal event=%+v, want ready", event)
	}
	if event := readFrame(); event.Type != "stdout" || !terminalEventContains(t, event, "terminal-ready") {
		t.Fatalf("first PTY output=%+v, want terminal-ready", event)
	}
	if err := wsjson.Write(context.Background(), conn, browserTerminalFrame{Type: "stdin", Data: "interactive-input\r"}); err != nil {
		t.Fatal(err)
	}
	if event := readFrame(); event.Type != "stdout" || !terminalEventContains(t, event, "interactive-input") {
		t.Fatalf("PTY response=%+v, want echoed terminal input", event)
	}
}

func serveTerminalTestSSH(t *testing.T, conn net.Conn) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("generate test SSH host key: %v", err)
		_ = conn.Close()
		return
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Errorf("create test SSH signer: %v", err)
		_ = conn.Close()
		return
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			t.Errorf("accept terminal SSH client: %v", err)
		}
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	defer serverConn.Close()
	go ssh.DiscardRequests(requests)
	for request := range channels {
		if request.ChannelType() != "session" {
			_ = request.Reject(ssh.UnknownChannelType, "session channel required")
			continue
		}
		channel, channelRequests, err := request.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for channelRequest := range channelRequests {
				switch channelRequest.Type {
				case "pty-req", "window-change":
					if channelRequest.WantReply {
						_ = channelRequest.Reply(true, nil)
					}
				case "exec":
					if channelRequest.WantReply {
						_ = channelRequest.Reply(true, nil)
					}
					_, _ = channel.Write([]byte("terminal-ready\r\n"))
					_, _ = io.Copy(channel, channel)
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
					return
				default:
					if channelRequest.WantReply {
						_ = channelRequest.Reply(false, nil)
					}
				}
			}
		}()
	}
}

func terminalEventContains(t *testing.T, event browserTerminalEvent, text string) bool {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(event.Data)
	if err != nil {
		t.Fatalf("decode terminal event data: %v", err)
	}
	return bytes.Contains(data, []byte(text))
}

func TestBrowserTerminalAccessIsRecheckedForMembershipAndLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir(), "browser-terminal-recheck")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team-a", Members: []store.WorkspaceMember{{Subject: "alice", Role: "user"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team-a", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	runtime := &grpcRuntime{st: st, relay: sshrelay.NewHub()}
	principal := Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "alice", Scopes: []string{"sandbox:write"}}
	start := &compatv1.ExecSandboxRequest{Sandbox: "demo", WorkspaceScope: workspaceScope("team-a"), Command: []string{"/bin/sh"}, Tty: true, Cols: 80, Rows: 24}
	if err := validateBrowserTerminalAccess(context.Background(), principal, "demo", st, runtime, Options{}, start); err != nil {
		t.Fatalf("authorized terminal was denied: %v", err)
	}

	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team-a"}); err != nil {
		t.Fatal(err)
	}
	if err := validateBrowserTerminalAccess(context.Background(), principal, "demo", st, runtime, Options{}, start); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("removed workspace member access code=%s err=%v; want PermissionDenied", status.Code(err), err)
	}

	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team-a", Members: []store.WorkspaceMember{{Subject: "alice", Role: "user"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team-a", Status: "stopped"}); err != nil {
		t.Fatal(err)
	}
	if err := validateBrowserTerminalAccess(context.Background(), principal, "demo", st, runtime, Options{}, start); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stopped sandbox access code=%s err=%v; want FailedPrecondition", status.Code(err), err)
	}
}

func TestTerminalPrincipalChecksWorkspaceRolePolicy(t *testing.T) {
	tests := []struct {
		name     string
		roles    []string
		settings OIDCOptions
		want     bool
	}{
		{name: "no role mapping", want: true},
		{name: "workspace user", roles: []string{"cautem-user"}, settings: OIDCOptions{UserRole: "cautem-user", AdminRole: "cautem-admin"}, want: true},
		{name: "platform admin", roles: []string{"cautem-admin"}, settings: OIDCOptions{UserRole: "cautem-user", AdminRole: "cautem-admin"}, want: true},
		{name: "unmapped role", roles: []string{"other"}, settings: OIDCOptions{UserRole: "cautem-user", AdminRole: "cautem-admin"}, want: false},
		{name: "incomplete mapping", roles: []string{"cautem-user"}, settings: OIDCOptions{UserRole: "cautem-user"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := oidcUserRoleAllowed(Principal{Roles: tt.roles}, tt.settings)
			if got != tt.want {
				t.Fatalf("oidcUserRoleAllowed()=%t, want %t", got, tt.want)
			}
		})
	}
}

func TestBrowserTerminalPathIsPublicOnlyForTerminalRoute(t *testing.T) {
	if !isPublicRoute("/v1/sandboxes/demo/terminal") {
		t.Fatal("terminal websocket must authenticate its first frame")
	}
	if !isBrowserServiceProxyPath("/v1/sandboxes/demo/services/web/proxy/api/v1/items") || !isPublicRoute("/v1/sandboxes/demo/services/web/proxy/api/v1/items") {
		t.Fatal("service proxy must authenticate its scoped cookie session")
	}
	if isPublicRoute("/v1/sandboxes/demo/services/web/session") || oidcRouteScope(http.MethodPost, "/v1/sandboxes/demo/services/web/session") != "sandbox:read" {
		t.Fatal("service session creation must use an authenticated read-scoped request")
	}
	for _, path := range []string{"/v1/sandboxes/demo", "/v1/sandboxes/demo/terminal/extra", "/v1/sandboxes/.hidden/terminal"} {
		if isPublicRoute(path) {
			t.Errorf("route %q unexpectedly bypasses bearer middleware", path)
		}
	}
}

func TestTerminalDimensionsDefaultAndCap(t *testing.T) {
	if cols, rows := terminalDimensions(0, 0); cols != terminalDefaultCols || rows != terminalDefaultRows {
		t.Fatalf("default dimensions=%dx%d", cols, rows)
	}
	if cols, rows := terminalDimensions(5000, 5000); cols != terminalMaxCols || rows != terminalMaxRows {
		t.Fatalf("capped dimensions=%dx%d", cols, rows)
	}
}

func TestBrowserTerminalErrorMappingHidesBackendDetails(t *testing.T) {
	err := status.Error(codes.PermissionDenied, "alice does not have access to team-a")
	if got := terminalErrorMessage(err); got != "Your workspace role does not allow terminal access." {
		t.Fatalf("terminal error message=%q", got)
	}
	if got := terminalErrorMessage(errors.New("secret backend detail")); strings.Contains(got, "secret") {
		t.Fatalf("internal error detail leaked to browser: %q", got)
	}
}
