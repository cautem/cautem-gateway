package httpapi

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestHTTPAndGRPCShareCleartextListener(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	grpcStarted := make(chan struct{})
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- listenAndServe(ctx, Options{
			Listen: addr,
			RegisterGRPC: func(server *grpc.Server) {
				healthpb.RegisterHealthServer(server, health.NewServer())
				registerCompatRPC(server)
				close(grpcStarted)
			},
		}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/rest-probe" && r.URL.Path != controlAPIPathPrefix+"ConsoleService/GetViewer" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
	}()
	select {
	case <-grpcStarted:
	case err := <-serveErr:
		t.Fatalf("listener exited before startup: %v", err)
	case <-time.After(time.Second):
		t.Fatal("gRPC service registration did not run")
	}

	deadline := time.Now().Add(3 * time.Second)
	var httpResp *http.Response
	for time.Now().Before(deadline) {
		reqCtx, reqCancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+addr+"/rest-probe", nil)
		httpResp, err = http.DefaultClient.Do(req)
		reqCancel()
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("REST request did not connect: %v", err)
	}
	_ = httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusNoContent {
		t.Fatalf("REST status = %d, want %d", httpResp.StatusCode, http.StatusNoContent)
	}
	// The control service's native gRPC requests must reach its Connect
	// handler; OpenShell's grpc-go server owns other gRPC paths.
	h2client := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}}
	controlReq, err := http.NewRequest(http.MethodPost, "http://"+addr+controlAPIPathPrefix+"ConsoleService/GetViewer", nil)
	if err != nil {
		t.Fatal(err)
	}
	controlReq.Header.Set("Content-Type", "application/grpc")
	controlResp, err := h2client.Do(controlReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = controlResp.Body.Close()
	if controlResp.StatusCode != http.StatusNoContent {
		t.Fatalf("control gRPC path status = %d, want 204", controlResp.StatusCode)
	}

	callCtx, callCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer callCancel()
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	response, err := healthpb.NewHealthClient(conn).Check(callCtx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("gRPC health Check failed: %v", err)
	}
	if response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("gRPC health status = %s", fmt.Sprint(response.GetStatus()))
	}
	compatHealth, err := compatv1.NewOpenShellClient(conn).Health(callCtx, &compatv1.HealthRequest{})
	if err != nil || compatHealth.GetStatus() != compatv1.ServiceStatus_SERVICE_STATUS_HEALTHY {
		t.Fatalf("OpenShell Health response=%v err=%v", compatHealth, err)
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("listener shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not stop after context cancellation")
	}
}

func TestCompatGRPCExternalClientAuthentication(t *testing.T) {
	state, err := store.Open(t.TempDir(), "grpc-auth-test")
	if err != nil {
		t.Fatal(err)
	}
	token, err := state.EnsureAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	if err := state.UpsertSandbox(store.Sandbox{Name: "sandbox-a", ID: "sandbox-id-a", Workspace: "default", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	sandboxToken, err := state.IssueSandboxToken("sandbox-a")
	if err != nil {
		t.Fatal(err)
	}
	relayHub := sshrelay.NewHub()
	runtime := &grpcRuntime{st: state, relay: relayHub}
	opt := Options{Listen: addr, grpcRuntime: runtime, RegisterGRPC: func(server *grpc.Server) {
		registerCompatRPCWithOptions(server, Options{grpcRuntime: runtime})
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- listenAndServe(ctx, opt, http.NotFoundHandler()) }()
	readyBy := time.Now().Add(3 * time.Second)
	for {
		probe, err := net.DialTimeout("tcp", addr, 20*time.Millisecond)
		if err == nil {
			_ = probe.Close()
			break
		}
		if time.Now().After(readyBy) {
			t.Fatalf("gRPC server did not start listening: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := compatv1.NewOpenShellClient(conn)
	callCtx, callCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer callCancel()
	if _, err := client.GetCurrentUser(callCtx, &compatv1.GetCurrentUserRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated GetCurrentUser error=%v, want Unauthenticated", err)
	}
	authed := metadata.AppendToOutgoingContext(callCtx, "authorization", "Bearer "+token)
	user, err := client.GetCurrentUser(authed, &compatv1.GetCurrentUserRequest{})
	if err != nil || user.GetSubject() != "local-dev" {
		t.Fatalf("authenticated GetCurrentUser response=%v err=%v", user, err)
	}
	if _, err := client.Health(callCtx, &compatv1.HealthRequest{}); err != nil {
		t.Fatalf("public OpenShell Health failed: %v", err)
	}
	stream, err := client.ExecSandbox(callCtx, &compatv1.ExecSandboxRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated streaming RPC error=%v, want Unauthenticated", err)
	}
	supervisorStream, err := client.ConnectSupervisor(authed)
	if err == nil {
		_, err = supervisorStream.Recv()
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator token opened supervisor-only stream: err=%v, want PermissionDenied", err)
	}
	wrongSupervisorCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+sandboxToken)
	wrongSupervisor, err := client.ConnectSupervisor(wrongSupervisorCtx)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongSupervisor.Send(&compatv1.SupervisorMessage{Payload: &compatv1.SupervisorMessage_Hello{Hello: &compatv1.SupervisorHello{SandboxId: "another-sandbox", InstanceId: "wrong-instance"}}}); err != nil {
		t.Fatal(err)
	}
	rejected, err := wrongSupervisor.Recv()
	if err != nil || rejected.GetSessionRejected() == nil {
		t.Fatalf("cross-sandbox supervisor rejection=%v err=%v; want SessionRejected", rejected, err)
	}
	if _, err := wrongSupervisor.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-sandbox supervisor Hello error=%v; want PermissionDenied", err)
	}
	supervisorCtx, stopSupervisor := context.WithCancel(metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+sandboxToken))
	supervisor, err := client.ConnectSupervisor(supervisorCtx)
	if err != nil {
		t.Fatalf("open supervisor stream: %v", err)
	}
	if err := supervisor.Send(&compatv1.SupervisorMessage{Payload: &compatv1.SupervisorMessage_Hello{Hello: &compatv1.SupervisorHello{SandboxId: "sandbox-id-a", InstanceId: "test-instance"}}}); err != nil {
		t.Fatal(err)
	}
	accepted, err := supervisor.Recv()
	if err != nil || accepted.GetSessionAccepted() == nil {
		t.Fatalf("supervisor session response=%v err=%v", accepted, err)
	}
	if !relayHub.Connected("sandbox-a") {
		t.Fatal("authenticated OpenShell supervisor was not registered")
	}
	if rec, ok := state.GetSandbox("sandbox-a"); !ok || rec.SupervisorInstanceID != "test-instance" {
		t.Fatalf("persisted supervisor instance=%q present=%v; want test-instance", rec.SupervisorInstanceID, ok)
	}
	type openedChannel struct {
		conn net.Conn
		err  error
	}
	opened := make(chan openedChannel, 1)
	go func() { c, e := relayHub.OpenChannel(supervisorCtx, "sandbox-a", "ssh"); opened <- openedChannel{c, e} }()
	openRequest, err := supervisor.Recv()
	if err != nil || openRequest.GetRelayOpen() == nil {
		t.Fatalf("supervisor RelayOpen=%v err=%v", openRequest, err)
	}
	dataStream, err := client.RelayStream(supervisorCtx)
	if err != nil {
		t.Fatalf("open RelayStream: %v", err)
	}
	channelID := openRequest.GetRelayOpen().GetChannelId()
	if err := dataStream.Send(&compatv1.RelayFrame{Payload: &compatv1.RelayFrame_Init{Init: &compatv1.RelayInit{ChannelId: channelID}}}); err != nil {
		t.Fatal(err)
	}
	var upstream net.Conn
	select {
	case result := <-opened:
		if result.err != nil {
			t.Fatalf("open pending relay: %v", result.err)
		}
		upstream = result.conn
	case <-time.After(time.Second):
		t.Fatal("RelayStream did not claim the pending OpenChannel")
	}
	defer upstream.Close()
	if _, err := upstream.Write([]byte("from-gateway")); err != nil {
		t.Fatal(err)
	}
	frame, err := dataStream.Recv()
	if err != nil || string(frame.GetData()) != "from-gateway" {
		t.Fatalf("supervisor received relay frame=%v err=%v", frame, err)
	}
	if err := dataStream.Send(&compatv1.RelayFrame{Payload: &compatv1.RelayFrame_Data{Data: []byte("request-body")}}); err != nil {
		t.Fatal(err)
	}
	if err := dataStream.CloseSend(); err != nil {
		t.Fatalf("half-close supervisor request direction: %v", err)
	}
	_ = upstream.SetReadDeadline(time.Now().Add(time.Second))
	request := make([]byte, len("request-body"))
	if _, err := io.ReadFull(upstream, request); err != nil || string(request) != "request-body" {
		t.Fatalf("gateway target request bytes=%q err=%v", request, err)
	}
	if _, err := upstream.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("gateway target did not receive request EOF: err=%v", err)
	}
	if _, err := upstream.Write([]byte("response-after-eof")); err != nil {
		t.Fatalf("write target response after caller EOF: %v", err)
	}
	response, err := dataStream.Recv()
	if err != nil || string(response.GetData()) != "response-after-eof" {
		t.Fatalf("supervisor response after request EOF=%v err=%v", response, err)
	}
	if err := upstream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("half-close gateway response direction: %v", err)
	}
	if _, err := dataStream.Recv(); err != io.EOF {
		t.Fatalf("gateway response stream EOF=%v; want EOF", err)
	}
	if _, err := client.ReportMainProcessExit(supervisorCtx, &compatv1.ReportMainProcessExitRequest{SandboxId: "sandbox-id-a", InstanceId: "test-instance", ExitCode: 0}); err != nil {
		t.Fatalf("external OpenShell SDK ReportMainProcessExit: %v", err)
	}
	if _, err := client.FinalizeMainProcessExit(supervisorCtx, &compatv1.FinalizeMainProcessExitRequest{SandboxId: "sandbox-id-a", InstanceId: "test-instance"}); err != nil {
		t.Fatalf("external OpenShell SDK FinalizeMainProcessExit: %v", err)
	}
	if rec, ok := state.GetSandbox("sandbox-a"); !ok || rec.Status != "completed" || rec.MainProcessExitCode == nil || *rec.MainProcessExitCode != 0 || !rec.MainProcessFinalized {
		t.Fatalf("external lifecycle RPC state=%+v present=%v", rec, ok)
	}
	stopSupervisor()
	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("listener shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not stop after context cancellation")
	}
}

func TestCompatGRPCAuthMapsMethodsToCompatibilityScopes(t *testing.T) {
	tests := []struct {
		method, wantMethod, wantPath string
	}{
		{"/openshell.v1.OpenShell/GetCurrentUser", "GET", "/v1/whoami"},
		{"/openshell.v1.OpenShell/ListProviders", "GET", "/v1/providers"},
		{"/openshell.v1.OpenShell/RotateProviderCredential", "POST", "/v1/providers"},
		{"/openshell.v1.OpenShell/ListSandboxes", "GET", "/v1/sandboxes"},
		{"/openshell.v1.OpenShell/CreateSandbox", "POST", "/v1/sandboxes"},
		{"/openshell.v1.OpenShell/ListWorkspaces", "GET", "/v1/workspaces/read"},
		{"/openshell.v1.OpenShell/CreateWorkspace", "POST", "/v1/workspaces/admin"},
		{"/openshell.v1.OpenShell/AddWorkspaceMember", "POST", "/v1/workspaces/write"},
		{"/openshell.v1.OpenShell/UnknownSensitiveMethod", "", ""},
	}
	for _, tt := range tests {
		gotMethod, gotPath := grpcAuthRoute(tt.method)
		if gotMethod != tt.wantMethod || gotPath != tt.wantPath {
			t.Errorf("grpcAuthRoute(%q)=(%q,%q), want (%q,%q)", tt.method, gotMethod, gotPath, tt.wantMethod, tt.wantPath)
		}
	}
}

func TestWorkspaceMemberMutationAllowsWorkspaceScopedUserRole(t *testing.T) {
	p := Principal{Kind: PrincipalUser, IDP: "oidc", Roles: []string{"openshell-user"}, Scopes: []string{"workspace:write"}}
	settings := OIDCOptions{AdminRole: "openshell-admin", UserRole: "openshell-user", ScopesClaim: "scope"}
	if !oidcRouteAuthorized(p, "POST", &url.URL{Path: "/v1/workspaces/write"}, settings) {
		t.Fatal("workspace-scoped member mutation should be authorized for the handler to enforce workspace admin membership")
	}
	if oidcRouteAuthorized(p, "POST", &url.URL{Path: "/v1/workspaces/admin"}, settings) {
		t.Fatal("workspace creation and deletion must remain platform-admin-only")
	}
}
