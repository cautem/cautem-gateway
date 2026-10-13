package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	terminalFrameLimit      = 16 << 10
	terminalAuthTimeout     = 5 * time.Second
	terminalRecheckInterval = time.Second
	terminalConcurrentLimit = 64
	terminalDefaultCols     = 80
	terminalDefaultRows     = 24
	terminalMaxCols         = 500
	terminalMaxRows         = 200
)

type browserTerminalFrame struct {
	Type  string `json:"type"`
	Token string `json:"token,omitempty"`
	Data  string `json:"data,omitempty"`
	Cols  uint32 `json:"cols,omitempty"`
	Rows  uint32 `json:"rows,omitempty"`
}

type browserTerminalEvent struct {
	Type     string `json:"type"`
	Data     string `json:"data,omitempty"`
	ExitCode int32  `json:"exitCode,omitempty"`
	Message  string `json:"message,omitempty"`
}

type browserTerminalStream struct {
	ctx   context.Context
	conn  *websocket.Conn
	start *openshellv1.ExecSandboxInput
	mu    sync.Mutex
}

func mountBrowserTerminal(mux *http.ServeMux, appCtx context.Context, st *store.Store, runtime *grpcRuntime, opt Options, auth AuthOptions) {
	slots := make(chan struct{}, terminalConcurrentLimit)
	mux.HandleFunc("GET /v1/sandboxes/{sandbox}/terminal", func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "terminal capacity reached", http.StatusServiceUnavailable)
			return
		}
		serveBrowserTerminal(w, r, appCtx, st, runtime, opt, auth)
	})
}

func isBrowserTerminalPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 4 && parts[0] == "v1" && parts[1] == "sandboxes" && validDNSLabel(parts[2]) && parts[3] == "terminal"
}

func serveBrowserTerminal(w http.ResponseWriter, r *http.Request, appCtx context.Context, st *store.Store, runtime *grpcRuntime, opt Options, auth AuthOptions) {
	if runtime == nil || runtime.relay == nil || st == nil {
		http.Error(w, "terminal service is unavailable", http.StatusServiceUnavailable)
		return
	}
	name := r.PathValue("sandbox")
	if !validDNSLabel(name) {
		http.NotFound(w, r)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(terminalFrameLimit)

	frame := browserTerminalFrame{}
	token := bearerToken(r)
	if token == "" {
		ctx, cancel := context.WithTimeout(appCtx, terminalAuthTimeout)
		err = wsjson.Read(ctx, conn, &frame)
		cancel()
		if err != nil || frame.Type != "auth" {
			writeTerminalError(appCtx, conn, "terminal authentication required")
			_ = conn.Close(websocket.StatusPolicyViolation, "authentication required")
			return
		}
		token = strings.TrimSpace(frame.Token)
	}

	authRequest := r.Clone(appCtx)
	authRequest.Header = r.Header.Clone()
	if token != "" {
		authRequest.Header.Set("Authorization", "Bearer "+token)
	}
	principal, valid := terminalPrincipal(authRequest, st, auth)
	if !valid || principal.Kind != PrincipalUser {
		writeTerminalError(appCtx, conn, "terminal authentication failed")
		_ = conn.Close(websocket.StatusPolicyViolation, "authentication failed")
		return
	}

	cols, rows := terminalDimensions(frame.Cols, frame.Rows)
	start := &openshellv1.ExecSandboxRequest{SandboxId: name, Command: []string{"/bin/sh"}, Tty: true, Cols: cols, Rows: rows}
	rpc := &openShellRPC{options: opt, runtime: runtime}
	principalCtx := withPrincipal(appCtx, principal)
	if err := validateBrowserTerminalAccess(principalCtx, principal, name, st, runtime, opt, start); err != nil {
		writeTerminalError(appCtx, conn, terminalErrorMessage(err))
		_ = conn.Close(websocket.StatusPolicyViolation, "terminal access denied")
		return
	}

	if err := wsjson.Write(appCtx, conn, browserTerminalEvent{Type: "ready"}); err != nil {
		return
	}
	sessionCtx, cancel := context.WithCancel(principalCtx)
	defer cancel()
	go monitorBrowserTerminal(sessionCtx, cancel, conn, authRequest, token, principal, name, st, runtime, opt, auth, start)

	stream := &browserTerminalStream{
		ctx:   sessionCtx,
		conn:  conn,
		start: &openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Start{Start: start}},
	}
	if err := rpc.ExecSandboxInteractive(stream); err != nil && !errors.Is(err, context.Canceled) {
		_ = wsjson.Write(sessionCtx, conn, browserTerminalEvent{Type: "error", Message: terminalErrorMessage(err)})
	}
	_ = conn.Close(websocket.StatusNormalClosure, "terminal closed")
}

func terminalPrincipal(r *http.Request, st *store.Store, auth AuthOptions) (Principal, bool) {
	principal, valid := resolvePrincipal(r, st, auth.OIDC, auth.OIDCSettings)
	if !valid {
		return Principal{}, false
	}
	if principal.Kind == PrincipalNone && auth.EnableMTLSAuth {
		principal = mtlsPrincipal(r)
	}
	if principal.Kind == PrincipalNone && auth.AllowUnauthenticated {
		principal = Principal{Kind: PrincipalUser, Subject: "local-dev", IDP: "local_dev", Roles: []string{"platform_admin", "platform-admin", "user"}}
	}
	if principal.Kind == PrincipalUser && (principal.IDP == "oidc" || principal.IDP == "mtls") && !oidcUserRoleAllowed(principal, auth.OIDCSettings) {
		return Principal{}, false
	}
	return principal, principal.Kind == PrincipalUser
}

func oidcUserRoleAllowed(principal Principal, settings OIDCOptions) bool {
	adminConfigured, userConfigured := settings.AdminRole != "", settings.UserRole != ""
	if !adminConfigured && !userConfigured {
		return true
	}
	if !adminConfigured || !userConfigured {
		return false
	}
	return containsString(principal.Roles, settings.UserRole) || containsString(principal.Roles, settings.AdminRole)
}

func monitorBrowserTerminal(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, authRequest *http.Request, token string, initial Principal, sandboxName string, st *store.Store, runtime *grpcRuntime, opt Options, auth AuthOptions, start *openshellv1.ExecSandboxRequest) {
	ticker := time.NewTicker(terminalRecheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			request := authRequest.Clone(ctx)
			request.Header = authRequest.Header.Clone()
			if token != "" {
				request.Header.Set("Authorization", "Bearer "+token)
			}
			principal, valid := terminalPrincipal(request, st, auth)
			if !valid || principal.Subject != initial.Subject || principal.IDP != initial.IDP {
				cancel()
				_ = conn.CloseNow()
				return
			}
			if err := validateBrowserTerminalAccess(ctx, principal, sandboxName, st, runtime, opt, start); err != nil {
				cancel()
				_ = conn.CloseNow()
				return
			}
		}
	}
}

func validateBrowserTerminalAccess(ctx context.Context, principal Principal, sandboxName string, st *store.Store, runtime *grpcRuntime, opt Options, start *openshellv1.ExecSandboxRequest) error {
	if runtime == nil || st == nil {
		return status.Error(codes.Unavailable, "terminal service unavailable")
	}
	if principal.Kind != PrincipalUser {
		return status.Error(codes.Unauthenticated, "authenticated user required")
	}
	sandbox, err := (&openShellRPC{options: opt, runtime: runtime}).validateExecSandboxRequest(withPrincipal(ctx, principal), start)
	if err != nil {
		return err
	}
	if sandbox.Name != sandboxName {
		return status.Error(codes.NotFound, "sandbox not found")
	}
	return nil
}

func terminalDimensions(cols, rows uint32) (uint32, uint32) {
	if cols == 0 {
		cols = terminalDefaultCols
	}
	if rows == 0 {
		rows = terminalDefaultRows
	}
	if cols > terminalMaxCols {
		cols = terminalMaxCols
	}
	if rows > terminalMaxRows {
		rows = terminalMaxRows
	}
	return cols, rows
}

func terminalErrorMessage(err error) string {
	switch status.Code(err) {
	case codes.Unauthenticated:
		return "Sign in is required to use the terminal."
	case codes.PermissionDenied:
		return "Your workspace role does not allow terminal access."
	case codes.NotFound:
		return "Sandbox not found."
	case codes.FailedPrecondition:
		return "Sandbox is not ready for a terminal session."
	case codes.Unavailable:
		return "Sandbox terminal relay is unavailable."
	default:
		return "Terminal session could not be started."
	}
}

func writeTerminalError(ctx context.Context, conn *websocket.Conn, message string) {
	_ = wsjson.Write(ctx, conn, browserTerminalEvent{Type: "error", Message: message})
}

func (s *browserTerminalStream) Context() context.Context     { return s.ctx }
func (s *browserTerminalStream) SetHeader(metadata.MD) error  { return nil }
func (s *browserTerminalStream) SendHeader(metadata.MD) error { return nil }
func (s *browserTerminalStream) SetTrailer(metadata.MD)       {}
func (s *browserTerminalStream) SendMsg(any) error {
	return status.Error(codes.Unimplemented, "SendMsg is unsupported")
}
func (s *browserTerminalStream) RecvMsg(any) error {
	return status.Error(codes.Unimplemented, "RecvMsg is unsupported")
}

func (s *browserTerminalStream) Recv() (*openshellv1.ExecSandboxInput, error) {
	s.mu.Lock()
	if s.start != nil {
		start := s.start
		s.start = nil
		s.mu.Unlock()
		return start, nil
	}
	s.mu.Unlock()
	frame := browserTerminalFrame{}
	if err := wsjson.Read(s.ctx, s.conn, &frame); err != nil {
		return nil, err
	}
	switch frame.Type {
	case "stdin":
		return &openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Stdin{Stdin: []byte(frame.Data)}}, nil
	case "resize":
		cols, rows := terminalDimensions(frame.Cols, frame.Rows)
		return &openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Resize{Resize: &openshellv1.ExecSandboxWindowResize{Cols: cols, Rows: rows}}}, nil
	case "close":
		return nil, io.EOF
	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported browser terminal frame")
	}
}

func (s *browserTerminalStream) Send(event *openshellv1.ExecSandboxEvent) error {
	if event == nil {
		return status.Error(codes.InvalidArgument, "empty terminal event")
	}
	frame := browserTerminalEvent{}
	switch payload := event.GetPayload().(type) {
	case *openshellv1.ExecSandboxEvent_Stdout:
		frame.Type = "stdout"
		frame.Data = base64.StdEncoding.EncodeToString(payload.Stdout.GetData())
	case *openshellv1.ExecSandboxEvent_Stderr:
		frame.Type = "stderr"
		frame.Data = base64.StdEncoding.EncodeToString(payload.Stderr.GetData())
	case *openshellv1.ExecSandboxEvent_Exit:
		frame.Type = "exit"
		frame.ExitCode = payload.Exit.GetExitCode()
	default:
		return status.Error(codes.InvalidArgument, "unsupported terminal event")
	}
	return wsjson.Write(s.ctx, s.conn, frame)
}

var _ interface {
	Context() context.Context
	SetHeader(metadata.MD) error
	SendHeader(metadata.MD) error
	SetTrailer(metadata.MD)
	Recv() (*openshellv1.ExecSandboxInput, error)
	Send(*openshellv1.ExecSandboxEvent) error
} = (*browserTerminalStream)(nil)
