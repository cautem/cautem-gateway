package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-core/relayproto"
	"github.com/cautem/cautem-gateway/internal/httpapi"
	credentialsv1 "github.com/cautem/cautem-gateway/internal/upstreamproto/credentialsv1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type e2ECredentialDriver struct {
	credentialsv1.UnimplementedCredentialDriverServer
	mu       sync.Mutex
	values   map[string]string
	stores   int
	resolves int
	deletes  int
}

func startPolicyProbeServer(t *testing.T, parent context.Context, client openshellv1.OpenShellClient, sandboxID string) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	stream, err := client.ExecSandboxInteractive(ctx)
	if err != nil {
		cancel()
		t.Fatalf("open policy probe server ExecSandbox: %v", err)
	}
	if err := stream.Send(&openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Start{Start: &openshellv1.ExecSandboxRequest{
		SandboxId: sandboxID, Command: []string{"/usr/local/bin/cautem-tcp-echo", "serve-tcp", "0.0.0.0:17777"}, NoLoginShell: true, TimeoutSeconds: 90,
	}}}); err != nil {
		cancel()
		t.Fatalf("start policy probe server: %v", err)
	}
	ready := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		readySent := false
		for {
			event, recvErr := stream.Recv()
			if recvErr != nil {
				if !readySent {
					ready <- recvErr
				}
				return
			}
			if stdout := event.GetStdout(); stdout != nil && strings.Contains(string(stdout.GetData()), "READY tcp") && !readySent {
				readySent = true
				ready <- nil
			}
			if exit := event.GetExit(); exit != nil && !readySent {
				ready <- fmt.Errorf("probe server exited with code %d", exit.GetExitCode())
				return
			}
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			cancel()
			t.Fatalf("policy probe server failed before ready: %v", err)
		}
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("policy probe server did not become ready")
	case <-ctx.Done():
		t.Fatalf("policy probe server context ended before ready: %v", ctx.Err())
	}
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("policy probe server did not stop after stream cancellation")
		}
	}
}

func runPolicyConnectProbe(t *testing.T, ctx context.Context, client openshellv1.OpenShellClient, sandboxID, target, wantStatus string) {
	t.Helper()
	streamCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stream, err := client.ExecSandbox(streamCtx, &openshellv1.ExecSandboxRequest{
		SandboxId: sandboxID, Command: []string{"/usr/local/bin/cautem-tcp-echo", "probe-connect-status", target, wantStatus}, NoLoginShell: true, TimeoutSeconds: 10,
	})
	if err != nil {
		t.Fatalf("run policy CONNECT probe for %s: %v", target, err)
	}
	var exit *openshellv1.ExecSandboxExit
	for {
		event, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			t.Fatalf("receive policy CONNECT probe for %s: %v", target, recvErr)
		}
		if event.GetExit() != nil {
			exit = event.GetExit()
		}
	}
	if exit == nil || exit.GetExitCode() != 0 {
		t.Fatalf("policy CONNECT probe for %s returned exit=%v; want proxy status %s", target, exit, wantStatus)
	}
}

func (d *e2ECredentialDriver) GetCapabilities(context.Context, *credentialsv1.GetCredentialDriverCapabilitiesRequest) (*credentialsv1.GetCredentialDriverCapabilitiesResponse, error) {
	return &credentialsv1.GetCredentialDriverCapabilitiesResponse{
		DriverName: "docker-podman-e2e-credentials", BackendKind: "e2e", SupportsExpiresAt: true,
	}, nil
}

func (d *e2ECredentialDriver) StoreCredential(_ context.Context, request *credentialsv1.StoreCredentialRequest) (*credentialsv1.StoreCredentialResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	handle := request.GetProviderName() + "/" + request.GetCredentialKey()
	d.values[handle] = request.GetValue()
	d.stores++
	return &credentialsv1.StoreCredentialResponse{Handle: &datamodelv1.CredentialHandle{Driver: "docker-podman-e2e-credentials", Handle: handle}}, nil
}

func (d *e2ECredentialDriver) ResolveCredentials(_ context.Context, request *credentialsv1.ResolveCredentialsRequest) (*credentialsv1.ResolveCredentialsResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resolves++
	response := &credentialsv1.ResolveCredentialsResponse{}
	for _, item := range request.GetCredentials() {
		response.Credentials = append(response.Credentials, &credentialsv1.ResolvedCredential{
			RequestId: item.GetRequestId(), Value: d.values[item.GetHandle().GetHandle()],
		})
	}
	return response, nil
}

func (d *e2ECredentialDriver) DeleteCredential(_ context.Context, request *credentialsv1.DeleteCredentialRequest) (*credentialsv1.DeleteCredentialResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.values, request.GetHandle().GetHandle())
	d.deletes++
	return &credentialsv1.DeleteCredentialResponse{}, nil
}

// TestEngineGatewayConnectE2E invokes the gateway CreateSandbox handler against
// a real Docker-compatible Engine API, waits for the outbound supervisor relay,
// then runs the public SSH-session/relay handshake and executes a command. The
// Docker and Podman harnesses live under tools/e2e/.
func TestEngineGatewayConnectE2E(t *testing.T) {
	if os.Getenv("CAUTEM_ENGINE_E2E") != "1" {
		t.Skip("set CAUTEM_ENGINE_E2E=1 to run against a disposable Docker-compatible Engine")
	}
	driverName := strings.TrimSpace(os.Getenv("CAUTEM_E2E_DRIVER"))
	if driverName == "" {
		driverName = "docker"
	}
	if driverName != "docker" && driverName != "podman" {
		t.Fatalf("unsupported CAUTEM_E2E_DRIVER %q: want docker or podman", driverName)
	}
	endpoint := strings.TrimSpace(os.Getenv("CAUTEM_E2E_GATEWAY_URL"))
	if endpoint == "" {
		t.Fatal("CAUTEM_E2E_GATEWAY_URL must be reachable from sandbox containers")
	}
	helperDir := strings.TrimSpace(os.Getenv("CAUTEM_HELPERS_DIR"))
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if st, err := os.Stat(filepath.Join(helperDir, name)); err != nil || st.IsDir() {
			t.Fatalf("Linux helper %s missing in %s: %v", name, helperDir, err)
		}
	}
	url, err := url.Parse(endpoint)
	if err != nil || url.Scheme != "http" || url.Host == "" {
		t.Fatalf("invalid E2E gateway URL %q", endpoint)
	}
	relayEndpoint := strings.TrimSpace(os.Getenv("CAUTEM_E2E_RELAY_ENDPOINT"))
	if relayEndpoint == "" {
		relayEndpoint = endpoint
	}
	if relayURL, parseErr := url.Parse(relayEndpoint); parseErr != nil || relayURL.Scheme != "http" || relayURL.Host == "" {
		t.Fatalf("invalid E2E relay URL %q", relayEndpoint)
	}
	listenAddr := strings.TrimSpace(os.Getenv("CAUTEM_E2E_LISTEN_ADDR"))
	if listenAddr == "" {
		listenAddr = url.Host
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	credentialListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	credentialDriver := &e2ECredentialDriver{values: map[string]string{}}
	credentialServer := grpc.NewServer()
	credentialsv1.RegisterCredentialDriverServer(credentialServer, credentialDriver)
	go func() { _ = credentialServer.Serve(credentialListener) }()
	t.Cleanup(func() {
		credentialServer.Stop()
		_ = credentialListener.Close()
	})
	runtime := httpapi.NewE2ERuntime()
	networkName := "cautem-" + driverName + "-connect-e2e"
	opt := httpapi.Options{
		Listen: listenAddr, DataDir: t.TempDir(),
		ComputeDriverNames:      []string{driverName},
		CredentialDriverNames:   []string{"docker-podman-e2e-credentials"},
		DefaultCredentialDriver: "docker-podman-e2e-credentials",
		CredentialDriverConfigs: map[string]map[string]any{"docker-podman-e2e-credentials": {
			"grpc_endpoint": "http://" + credentialListener.Addr().String(), "allow_insecure_transport": true,
		}},
		ComputeDriverConfigs: map[string]map[string]any{driverName: {
			"image_pull_policy": "missing",
			"grpc_endpoint":     relayEndpoint, "network_name": networkName,
		}},
	}
	runtime.Attach(&opt)
	workspaceRoot := filepath.Join(opt.DataDir, "workspaces", "default")
	if err := os.MkdirAll(workspaceRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(workspaceRoot, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	handler, err := httpapi.NewHandler(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, serveCancel := context.WithCancel(ctx)
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpapi.ServeE2E(serveCtx, opt, handler) }()
	defer func() {
		if serveCancel != nil {
			serveCancel()
		}
		if serveErr == nil {
			return
		}
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("gateway listener shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("gateway listener did not stop")
		}
	}()
	grpcConn, err := grpc.NewClient("passthrough:///"+url.Host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer grpcConn.Close()
	grpcClient := openshellv1.NewOpenShellClient(grpcConn)
	userCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+runtime.AuthToken())
	var healthErr error
	readyBy := time.Now().Add(10 * time.Second)
	for time.Now().Before(readyBy) {
		probeCtx, probeCancel := context.WithTimeout(userCtx, 500*time.Millisecond)
		_, healthErr = grpcClient.Health(probeCtx, &openshellv1.HealthRequest{})
		probeCancel()
		if healthErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if healthErr != nil {
		t.Fatalf("external OpenShell gRPC Health: %v", healthErr)
	}
	if user, err := grpcClient.GetCurrentUser(userCtx, &openshellv1.GetCurrentUserRequest{}); err != nil || user.GetSubject() != "local-dev" {
		t.Fatalf("external OpenShell gRPC GetCurrentUser=%v err=%v", user, err)
	}

	name := driverName + "-connect-e2e"
	image := strings.TrimSpace(os.Getenv("CAUTEM_E2E_SANDBOX_IMAGE"))
	if image == "" {
		image = "localhost/cautem-connect-e2e:latest"
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		_, _ = grpcClient.DeleteSandbox(metadata.AppendToOutgoingContext(cleanupCtx, "authorization", "Bearer "+runtime.AuthToken()), &openshellv1.DeleteSandboxRequest{Name: name, Workspace: "default"})
	}()
	_, err = grpcClient.CreateSandbox(userCtx, &openshellv1.CreateSandboxRequest{
		Name: name, Workspace: "default",
		Spec: &openshellv1.SandboxSpec{
			Policy:   &sandboxv1.SandboxPolicy{Version: 1},
			Template: &openshellv1.SandboxTemplate{Image: image},
			Command:  []string{"sh", "-c", `rm -f /tmp/cautem-process-event-trigger; mkfifo /tmp/cautem-process-event-trigger; IFS= read -r _ < /tmp/cautem-process-event-trigger; i=0; while [ "$i" -lt 24 ]; do (sleep 2 &) ; i=$((i + 1)); done; exec sleep infinity`},
		},
	})
	if err != nil {
		if driverName == "podman" && strings.Contains(strings.ToLower(err.Error()), "host-gateway isolation requires podman 6.0") {
			t.Skipf("Podman proxy-backed sandboxes require blackhole routes for host-gateway isolation: %v", err)
		}
		t.Fatalf("external OpenShell gRPC CreateSandbox: %v", err)
	}
	if !runtime.Connected(name) {
		t.Fatal("CreateSandbox returned before the supervisor relay connected")
	}
	measureSupervisorProcessEventDelivery(t, userCtx, grpcClient, name)
	policyUpdate, err := grpcClient.UpdateConfig(userCtx, &openshellv1.UpdateConfigRequest{
		Name: name, Workspace: "default",
		Policy: &sandboxv1.SandboxPolicy{Version: 1, NetworkPolicies: map[string]*sandboxv1.NetworkPolicyRule{
			"api": {Name: "api", Endpoints: []*sandboxv1.NetworkEndpoint{{Host: "api.example.com", Port: 443}}},
		}},
	})
	if err != nil {
		t.Fatalf("external OpenShell gRPC UpdateConfig with runtime acknowledgement: %v", err)
	}
	policyStatus, err := grpcClient.GetSandboxPolicyStatus(userCtx, &openshellv1.GetSandboxPolicyStatusRequest{Name: name})
	if err != nil || policyStatus.GetActiveVersion() != policyUpdate.GetVersion() || policyStatus.GetRevision().GetStatus() != openshellv1.PolicyStatus_POLICY_STATUS_LOADED {
		t.Fatalf("UpdateConfig policy status=%v err=%v; want loaded active version %d", policyStatus, err, policyUpdate.GetVersion())
	}
	globalPolicyUpdate, err := grpcClient.UpdateConfig(userCtx, &openshellv1.UpdateConfigRequest{
		Global: true,
		Policy: &sandboxv1.SandboxPolicy{Version: 1, NetworkPolicies: map[string]*sandboxv1.NetworkPolicyRule{
			"live-proxy-probe": {Name: "live-proxy-probe", Endpoints: []*sandboxv1.NetworkEndpoint{{
				Host: "cautem-" + name, Port: 17777, AllowedIps: []string{"10.0.0.0/8", "172.16.0.0/12"},
			}}},
		}},
	})
	if err != nil {
		t.Fatalf("global UpdateConfig with runtime acknowledgement: %v", err)
	}
	globalPolicyStatus, err := grpcClient.GetSandboxPolicyStatus(userCtx, &openshellv1.GetSandboxPolicyStatusRequest{Name: name})
	if err != nil || globalPolicyStatus.GetRevision().GetStatus() != openshellv1.PolicyStatus_POLICY_STATUS_LOADED {
		t.Fatalf("global UpdateConfig policy status=%v err=%v; want loaded policy", globalPolicyStatus, err)
	}
	effectiveConfig, err := grpcClient.GetSandboxConfig(userCtx, &sandboxv1.GetSandboxConfigRequest{SandboxId: name})
	if err != nil || effectiveConfig.GetGlobalPolicyVersion() != globalPolicyUpdate.GetVersion() {
		t.Fatalf("effective sandbox config=%v err=%v; want global policy revision %d", effectiveConfig, err, globalPolicyUpdate.GetVersion())
	}
	execCtx, execCancel := context.WithTimeout(userCtx, 30*time.Second)
	execStream, err := grpcClient.ExecSandbox(execCtx, &openshellv1.ExecSandboxRequest{
		SandboxId: name, Command: []string{"id", "-un"}, TimeoutSeconds: 20, NoLoginShell: true,
	})
	if err != nil {
		execCancel()
		t.Fatalf("external OpenShell gRPC ExecSandbox: %v", err)
	}
	var execOutput strings.Builder
	var execExit *openshellv1.ExecSandboxExit
	for {
		event, recvErr := execStream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			execCancel()
			t.Fatalf("receive ExecSandbox event: %v", recvErr)
		}
		if stdout := event.GetStdout(); stdout != nil {
			execOutput.Write(stdout.GetData())
		}
		if event.GetStderr() != nil {
			t.Errorf("ExecSandbox stderr=%q", event.GetStderr().GetData())
		}
		if event.GetExit() != nil {
			execExit = event.GetExit()
		}
	}
	execCancel()
	if execExit == nil || execExit.GetExitCode() != 0 || strings.TrimSpace(execOutput.String()) != "sandbox" {
		t.Fatalf("ExecSandbox output=%q exit=%v; want sandbox/0", execOutput.String(), execExit)
	}
	inputCtx, inputCancel := context.WithTimeout(userCtx, 30*time.Second)
	inputStream, err := grpcClient.ExecSandbox(inputCtx, &openshellv1.ExecSandboxRequest{
		SandboxId: name,
		Command:   []string{"sh", "-c", `printf '%s:%s:%s' "$PWD" "$LANG" "$(cat)"`},
		Workdir:   "/tmp", Environment: map[string]string{"LANG": "C.UTF-8"}, Stdin: []byte("stdin-ok"), TimeoutSeconds: 20,
	})
	if err != nil {
		inputCancel()
		t.Fatalf("external OpenShell gRPC ExecSandbox with stdin/env/workdir: %v", err)
	}
	var inputOutput strings.Builder
	var inputExit *openshellv1.ExecSandboxExit
	for {
		event, recvErr := inputStream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			inputCancel()
			t.Fatalf("receive ExecSandbox stdin/env/workdir event: %v", recvErr)
		}
		if stdout := event.GetStdout(); stdout != nil {
			inputOutput.Write(stdout.GetData())
		}
		if event.GetExit() != nil {
			inputExit = event.GetExit()
		}
	}
	inputCancel()
	if inputExit == nil || inputExit.GetExitCode() != 0 || inputOutput.String() != "/tmp:C.UTF-8:stdin-ok" {
		t.Fatalf("ExecSandbox stdin/env/workdir output=%q exit=%v; want /tmp:C.UTF-8:stdin-ok/0", inputOutput.String(), inputExit)
	}
	interactiveCtx, interactiveCancel := context.WithTimeout(userCtx, 30*time.Second)
	interactive, err := grpcClient.ExecSandboxInteractive(interactiveCtx)
	if err != nil {
		interactiveCancel()
		t.Fatalf("open interactive ExecSandbox: %v", err)
	}
	if err := interactive.Send(&openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Start{Start: &openshellv1.ExecSandboxRequest{
		SandboxId: name, Command: []string{"sh", "-c", `read line; printf '%s:' "$line"; stty size`}, Tty: true,
		Cols: 80, Rows: 24, NoLoginShell: true, TimeoutSeconds: 20,
	}}}); err != nil {
		interactiveCancel()
		t.Fatalf("start interactive ExecSandbox: %v", err)
	}
	if err := interactive.Send(&openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Resize{Resize: &openshellv1.ExecSandboxWindowResize{Cols: 132, Rows: 43}}}); err != nil {
		interactiveCancel()
		t.Fatalf("resize interactive ExecSandbox: %v", err)
	}
	if err := interactive.Send(&openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Stdin{Stdin: []byte("interactive-ok\n")}}); err != nil {
		interactiveCancel()
		t.Fatalf("send interactive ExecSandbox stdin: %v", err)
	}
	if err := interactive.CloseSend(); err != nil {
		interactiveCancel()
		t.Fatalf("close interactive ExecSandbox stdin: %v", err)
	}
	var interactiveOutput strings.Builder
	var interactiveExit *openshellv1.ExecSandboxExit
	for {
		event, recvErr := interactive.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			interactiveCancel()
			t.Fatalf("receive interactive ExecSandbox event: %v", recvErr)
		}
		if stdout := event.GetStdout(); stdout != nil {
			interactiveOutput.Write(stdout.GetData())
		}
		if event.GetExit() != nil {
			interactiveExit = event.GetExit()
		}
	}
	interactiveCancel()
	if interactiveExit == nil || interactiveExit.GetExitCode() != 0 || !strings.Contains(interactiveOutput.String(), "interactive-ok:43 132") {
		t.Fatalf("interactive ExecSandbox output=%q exit=%v; want resized PTY and exit 0", interactiveOutput.String(), interactiveExit)
	}
	cancelCtx, cancelExec := context.WithCancel(userCtx)
	cancelStream, err := grpcClient.ExecSandboxInteractive(cancelCtx)
	if err != nil {
		cancelExec()
		t.Fatalf("open cancellable interactive ExecSandbox: %v", err)
	}
	cancelPIDFile := "/tmp/cautem-cancel-child-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := cancelStream.Send(&openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Start{Start: &openshellv1.ExecSandboxRequest{
		SandboxId: name, Command: []string{"sh", "-c", "sleep 30 & echo $! > " + cancelPIDFile + "; test -s " + cancelPIDFile + " || exit 99; echo ready; wait"}, NoLoginShell: true, TimeoutSeconds: 60,
	}}}); err != nil {
		cancelExec()
		t.Fatalf("start cancellable interactive ExecSandbox: %v", err)
	}
	var cancelOutput strings.Builder
	for !strings.Contains(cancelOutput.String(), "ready") {
		readyEvent, recvErr := cancelStream.Recv()
		if recvErr != nil {
			cancelExec()
			t.Fatalf("cancellable interactive ExecSandbox readiness output=%q event=%v err=%v", cancelOutput.String(), readyEvent, recvErr)
		}
		if stdout := readyEvent.GetStdout(); stdout != nil {
			cancelOutput.Write(stdout.GetData())
		}
	}
	cancelExec()
	var cancelErr error
	var cancelExit *openshellv1.ExecSandboxExit
	for {
		event, recvErr := cancelStream.Recv()
		cancelErr = recvErr
		if cancelErr != nil {
			break
		}
		if event.GetExit() != nil {
			cancelExit = event.GetExit()
		}
	}
	// grpc-go may surface a locally cancelled bidi stream as io.EOF after the
	// server has closed the relay; both forms mean the cancellation completed
	// without leaving a running child behind.
	if status.Code(cancelErr) != codes.Canceled && cancelExit == nil && !errors.Is(cancelErr, io.EOF) {
		t.Fatalf("interactive ExecSandbox cancel error=%v code=%s exit=%v; want Canceled or a terminal process exit", cancelErr, status.Code(cancelErr), cancelExit)
	}
	orphanCtx, orphanCancel := context.WithTimeout(userCtx, 15*time.Second)
	orphanStream, err := grpcClient.ExecSandbox(orphanCtx, &openshellv1.ExecSandboxRequest{
		SandboxId:      name,
		Command:        []string{"sh", "-c", "pid=$(cat " + cancelPIDFile + "); i=0; while kill -0 \"$pid\" 2>/dev/null; do i=$((i+1)); [ \"$i\" -ge 40 ] && exit 1; sleep .1; done; rm -f " + cancelPIDFile + "; echo reaped"},
		TimeoutSeconds: 10, NoLoginShell: true,
	})
	if err != nil {
		orphanCancel()
		t.Fatalf("check cancelled exec child cleanup: %v", err)
	}
	var orphanOutput strings.Builder
	var orphanExit *openshellv1.ExecSandboxExit
	for {
		event, recvErr := orphanStream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			orphanCancel()
			t.Fatalf("receive cancelled exec child cleanup result: %v", recvErr)
		}
		if stdout := event.GetStdout(); stdout != nil {
			orphanOutput.Write(stdout.GetData())
		}
		if event.GetExit() != nil {
			orphanExit = event.GetExit()
		}
	}
	orphanCancel()
	if orphanExit == nil || orphanExit.GetExitCode() != 0 || !strings.Contains(orphanOutput.String(), "reaped") {
		t.Fatalf("cancelled exec child cleanup output=%q exit=%v; want reaped/0", orphanOutput.String(), orphanExit)
	}
	exitStream, err := grpcClient.ExecSandbox(userCtx, &openshellv1.ExecSandboxRequest{
		SandboxId: name, Command: []string{"sh", "-c", "echo stdout; echo stderr >&2; exit 7"}, NoLoginShell: true, TimeoutSeconds: 20,
	})
	if err != nil {
		t.Fatalf("start stderr/nonzero ExecSandbox: %v", err)
	}
	var exitStdout, exitStderr strings.Builder
	var nonzeroExit *openshellv1.ExecSandboxExit
	for {
		event, recvErr := exitStream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			t.Fatalf("receive stderr/nonzero ExecSandbox event: %v", recvErr)
		}
		if stdout := event.GetStdout(); stdout != nil {
			exitStdout.Write(stdout.GetData())
		}
		if stderr := event.GetStderr(); stderr != nil {
			exitStderr.Write(stderr.GetData())
		}
		if event.GetExit() != nil {
			nonzeroExit = event.GetExit()
		}
	}
	if nonzeroExit == nil || nonzeroExit.GetExitCode() != 7 || !strings.Contains(exitStdout.String(), "stdout") || !strings.Contains(exitStderr.String(), "stderr") {
		t.Fatalf("ExecSandbox stdout=%q stderr=%q exit=%v; want separate streams and exit 7", exitStdout.String(), exitStderr.String(), nonzeroExit)
	}
	timeoutCtx, timeoutCancel := context.WithTimeout(userCtx, 30*time.Second)
	timeoutStream, err := grpcClient.ExecSandbox(timeoutCtx, &openshellv1.ExecSandboxRequest{
		SandboxId: name, Command: []string{"sleep", "15"}, TimeoutSeconds: 5, NoLoginShell: true,
	})
	if err != nil {
		timeoutCancel()
		t.Fatalf("start timeout ExecSandbox: %v", err)
	}
	var timeoutExit *openshellv1.ExecSandboxExit
	for {
		event, recvErr := timeoutStream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			timeoutCancel()
			t.Fatalf("receive ExecSandbox timeout event: %v", recvErr)
		}
		if event.GetExit() != nil {
			timeoutExit = event.GetExit()
		}
	}
	timeoutCancel()
	if timeoutExit == nil || timeoutExit.GetExitCode() != 124 {
		t.Fatalf("ExecSandbox timeout exit=%v; want exit code 124", timeoutExit)
	}
	interactiveTimeoutCtx, interactiveTimeoutCancel := context.WithTimeout(userCtx, 30*time.Second)
	interactiveTimeout, err := grpcClient.ExecSandboxInteractive(interactiveTimeoutCtx)
	if err != nil {
		interactiveTimeoutCancel()
		t.Fatalf("open interactive ExecSandbox timeout: %v", err)
	}
	if err := interactiveTimeout.Send(&openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Start{Start: &openshellv1.ExecSandboxRequest{
		SandboxId: name, Command: []string{"sleep", "15"}, TimeoutSeconds: 5, NoLoginShell: true,
	}}}); err != nil {
		interactiveTimeoutCancel()
		t.Fatalf("start interactive ExecSandbox timeout: %v", err)
	}
	var interactiveTimeoutExit *openshellv1.ExecSandboxExit
	for {
		event, recvErr := interactiveTimeout.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			interactiveTimeoutCancel()
			t.Fatalf("receive interactive ExecSandbox timeout event: %v", recvErr)
		}
		if event.GetExit() != nil {
			interactiveTimeoutExit = event.GetExit()
		}
	}
	interactiveTimeoutCancel()
	if interactiveTimeoutExit == nil || interactiveTimeoutExit.GetExitCode() != 124 {
		t.Fatalf("interactive ExecSandbox timeout exit=%v; want exit code 124", interactiveTimeoutExit)
	}
	if os.Getenv("CAUTEM_E2E_FORWARD_TCP") == "1" {
		forwardEchoCtx, forwardEchoCancel := context.WithCancel(userCtx)
		forwardEcho, err := grpcClient.ExecSandboxInteractive(forwardEchoCtx)
		if err != nil {
			forwardEchoCancel()
			t.Fatalf("open TCP echo server ExecSandbox: %v", err)
		}
		if err := forwardEcho.Send(&openshellv1.ExecSandboxInput{Payload: &openshellv1.ExecSandboxInput_Start{Start: &openshellv1.ExecSandboxRequest{
			SandboxId: name, Command: []string{"/usr/local/bin/cautem-tcp-echo", "127.0.0.1:17777"}, NoLoginShell: true, TimeoutSeconds: 90,
		}}}); err != nil {
			forwardEchoCancel()
			t.Fatalf("start TCP echo server in sandbox: %v", err)
		}
		echoReady := make(chan error, 1)
		echoDone := make(chan error, 1)
		go func() {
			ready := false
			for {
				event, recvErr := forwardEcho.Recv()
				if recvErr != nil {
					if !ready {
						echoReady <- recvErr
					}
					echoDone <- recvErr
					return
				}
				if stdout := event.GetStdout(); stdout != nil && strings.Contains(string(stdout.GetData()), "READY") && !ready {
					ready = true
					echoReady <- nil
				}
			}
		}()
		select {
		case err := <-echoReady:
			if err != nil {
				forwardEchoCancel()
				t.Fatalf("TCP echo server failed before ready: %v", err)
			}
		case <-time.After(10 * time.Second):
			forwardEchoCancel()
			t.Fatal("TCP echo server did not become ready")
		}
		forwardSession, err := grpcClient.CreateSshSession(userCtx, &openshellv1.CreateSshSessionRequest{SandboxId: name})
		if err != nil {
			forwardEchoCancel()
			t.Fatalf("create authorization for ForwardTcp E2E: %v", err)
		}
		// A caller must not turn the sandbox loopback relay into an arbitrary
		// outbound tunnel. Verify the public RPC rejects a non-loopback target
		// against a live backend sandbox before opening any relay channel.
		deniedCtx, deniedCancel := context.WithTimeout(userCtx, 5*time.Second)
		deniedStream, deniedErr := grpcClient.ForwardTcp(deniedCtx)
		if deniedErr == nil {
			deniedErr = deniedStream.Send(&openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Init{Init: &openshellv1.TcpForwardInit{
				SandboxId: name, AuthorizationToken: forwardSession.GetToken(), ServiceId: "e2e-denied-public-target",
				Target: &openshellv1.TcpForwardInit_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: "1.1.1.1", Port: 443}},
			}}})
		}
		if deniedErr == nil {
			_, deniedErr = deniedStream.Recv()
		}
		deniedCancel()
		if status.Code(deniedErr) != codes.InvalidArgument {
			forwardEchoCancel()
			t.Fatalf("ForwardTcp accepted public target or returned wrong status: err=%v code=%s; want InvalidArgument", deniedErr, status.Code(deniedErr))
		}
		forwardCtx, forwardCancel := context.WithTimeout(userCtx, 15*time.Second)
		forwardStream, err := grpcClient.ForwardTcp(forwardCtx)
		if err == nil {
			err = forwardStream.Send(&openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Init{Init: &openshellv1.TcpForwardInit{
				SandboxId: name, AuthorizationToken: forwardSession.GetToken(), ServiceId: "e2e-loopback",
				Target: &openshellv1.TcpForwardInit_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: "localhost", Port: 17777}},
			}}})
		}
		const forwardPayload = "docker-podman-forward-roundtrip"
		if err == nil {
			err = forwardStream.Send(&openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Data{Data: []byte(forwardPayload)}})
		}
		var forwarded *openshellv1.TcpForwardFrame
		if err == nil {
			forwarded, err = forwardStream.Recv()
		}
		if err != nil || string(forwarded.GetData()) != forwardPayload {
			forwardCancel()
			forwardEchoCancel()
			t.Fatalf("external OpenShell gRPC ForwardTcp payload=%v err=%v; want echoed %q", forwarded, err, forwardPayload)
		}
		forwardCancel()
		_, _ = grpcClient.RevokeSshSession(userCtx, &openshellv1.RevokeSshSessionRequest{Token: forwardSession.GetToken()})
		forwardEchoCancel()
		select {
		case <-echoDone:
		case <-time.After(10 * time.Second):
			t.Error("TCP echo server exec did not stop after stream cancellation")
		}
	}
	if _, err = grpcClient.StopSandbox(userCtx, &openshellv1.StopSandboxRequest{Name: name, Workspace: "default"}); err != nil {
		t.Fatalf("external OpenShell gRPC StopSandbox: %v", err)
	}
	if runtime.Connected(name) {
		t.Fatal("StopSandbox returned while the old supervisor relay remained connected")
	}
	if _, err = grpcClient.StartSandbox(userCtx, &openshellv1.StartSandboxRequest{Name: name, Workspace: "default"}); err != nil {
		t.Fatalf("external OpenShell gRPC StartSandbox: %v", err)
	}
	if !runtime.Connected(name) {
		t.Fatal("StartSandbox returned before the supervisor relay reconnected")
	}

	sshCtx, sshCancel := context.WithTimeout(ctx, 30*time.Second)
	defer sshCancel()
	sshSession, err := grpcClient.CreateSshSession(userCtx, &openshellv1.CreateSshSessionRequest{SandboxId: name})
	if err != nil {
		t.Fatalf("create user SSH session through OpenShell gRPC: %v", err)
	}
	defer func() {
		_, _ = grpcClient.RevokeSshSession(context.Background(), &openshellv1.RevokeSshSessionRequest{Token: sshSession.GetToken()})
	}()
	sshHeaders := http.Header{}
	sshHeaders.Set("Authorization", "Bearer "+sshSession.GetToken())
	sshHeaders.Set(relayproto.HeaderSandboxID, sshSession.GetSandboxId())
	conn, err := relayproto.Dial(sshCtx, endpoint, relayproto.PathSSHConnect, relayproto.DialOptions{Header: sshHeaders})
	if err != nil {
		t.Fatalf("open user SSH relay connection: %v", err)
	}
	defer conn.Close()
	sshConn, channels, requests, err := ssh.NewClientConn(conn, "sandbox", &ssh.ClientConfig{
		User: "sandbox", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 15 * time.Second, //nolint:gosec
	})
	if err != nil {
		t.Fatalf("SSH handshake over user relay: %v", err)
	}
	sshClient := ssh.NewClient(sshConn, channels, requests)
	defer sshClient.Close()
	command, err := sshClient.NewSession()
	if err != nil {
		t.Fatalf("open SSH command session: %v", err)
	}
	defer command.Close()
	output, err := command.Output("id -un")
	if err != nil {
		t.Fatalf("run SSH command: %v; output=%q", err, output)
	}
	if strings.TrimSpace(string(output)) != "sandbox" {
		t.Fatalf("SSH command output=%q, want sandbox", output)
	}
	supervisorSession, err := sshClient.NewSession()
	if err != nil {
		t.Fatalf("open supervisor process inspection session: %v", err)
	}
	defer supervisorSession.Close()
	supervisorOutput, err := supervisorSession.Output("tr '\\0' ' ' </proc/1/cmdline")
	if err != nil || !strings.Contains(string(supervisorOutput), "/cautem/cautem-supervisor") {
		if os.Getenv("CAUTEM_E2E_ROOTLESS_PODMAN") != "1" {
			t.Fatalf("PID 1=%q err=%v, want Go sandbox supervisor", supervisorOutput, err)
		}
		t.Logf("rootless Podman-in-Docker does not provide an isolated PID namespace: PID 1=%q err=%v", supervisorOutput, err)
	}
	// Exercise the workload PID 1 → proxy sidecar → pinned gateway lifecycle
	// RPC path on the real Docker/Podman backend, including the persisted status.
	exitName := driverName + "-main-exit"
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		_, _ = grpcClient.DeleteSandbox(metadata.AppendToOutgoingContext(cleanupCtx, "authorization", "Bearer "+runtime.AuthToken()), &openshellv1.DeleteSandboxRequest{Name: exitName, Workspace: "default"})
	}()
	_, err = grpcClient.CreateSandbox(userCtx, &openshellv1.CreateSandboxRequest{
		Name: exitName, Workspace: "default",
		Spec: &openshellv1.SandboxSpec{
			Policy:   &sandboxv1.SandboxPolicy{Version: 1},
			Template: &openshellv1.SandboxTemplate{Image: image},
			Command:  []string{"/bin/sh", "-c", "sleep 3; exit 7"},
		},
	})
	if err != nil {
		t.Fatalf("create short-lived main-process sandbox: %v", err)
	}
	exitCtx, exitCancel := context.WithTimeout(userCtx, 30*time.Second)
	defer exitCancel()
	var exited *openshellv1.Sandbox
	finalized := false
	for {
		response, getErr := grpcClient.GetSandbox(exitCtx, &openshellv1.GetSandboxRequest{Name: exitName, Workspace: "default"})
		if getErr == nil {
			exited = response.GetSandbox()
			phase := exited.GetStatus().GetPhase()
			if phase == openshellv1.SandboxPhase_SANDBOX_PHASE_COMPLETED || phase == openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR {
				if record, ok := runtime.Sandbox(exitName); ok && record.MainProcessFinalized {
					finalized = true
					break
				}
			}
		}
		select {
		case <-exitCtx.Done():
			logs, logsErr := runtime.EngineLogs(context.Background(), exitName)
			t.Fatalf("short-lived sandbox did not finalize main process: sandbox=%v getErr=%v logs=%q logsErr=%v: %v", exited, getErr, logs, logsErr, exitCtx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if code := exited.GetStatus().ExitCode; code == nil || *code != 7 {
		t.Fatalf("completed main-process exit code=%v; want 7", code)
	}
	record, ok := runtime.Sandbox(exitName)
	if !finalized || !ok || !record.MainProcessFinalized {
		t.Fatalf("main-process exit was not finalized in gateway store: record=%+v found=%v", record, ok)
	}
	// Preserve the active supervisor bearer across the gateway restart below.
	// RefreshSandboxToken must accept this current token after state is reopened,
	// without requiring plaintext bearer persistence.
	supervisorToken, ok := runtime.CurrentSandboxToken(name)
	if !ok || supervisorToken == "" {
		t.Fatal("current supervisor token was not available before gateway restart")
	}

	// Restart the gateway process state while Docker/Podman workloads remain
	// alive. The sidecar must reconnect and the persisted sandbox remains usable.
	serveCancel()
	select {
	case shutdownErr := <-serveErr:
		if shutdownErr != nil {
			t.Fatalf("stop gateway before restart: %v", shutdownErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not stop before restart")
	}
	serveErr = nil
	serveCancel = func() {}
	runtime = httpapi.NewE2ERuntime()
	runtime.Attach(&opt)
	handler, err = httpapi.NewHandler(ctx, opt)
	if err != nil {
		t.Fatalf("reopen gateway state for restart E2E: %v", err)
	}
	restartCtx, restartCancel := context.WithCancel(ctx)
	restartErr := make(chan error, 1)
	go func() { restartErr <- httpapi.ServeE2E(restartCtx, opt, handler) }()
	serveErr = restartErr
	serveCancel = restartCancel
	restartDeadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(restartDeadline) {
		healthCtx, healthCancel := context.WithTimeout(userCtx, time.Second)
		_, healthErr = grpcClient.Health(healthCtx, &openshellv1.HealthRequest{})
		healthCancel()
		if healthErr == nil && runtime.Connected(name) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if healthErr != nil || !runtime.Connected(name) {
		t.Fatalf("gateway restart did not restore client and supervisor relay: health=%v relay_connected=%v", healthErr, runtime.Connected(name))
	}
	restartedPolicyStatus, err := grpcClient.GetSandboxPolicyStatus(userCtx, &openshellv1.GetSandboxPolicyStatusRequest{Name: name})
	if err != nil || restartedPolicyStatus.GetRevision().GetStatus() != openshellv1.PolicyStatus_POLICY_STATUS_LOADED {
		t.Fatalf("global policy after gateway restart status=%v err=%v; want loaded policy", restartedPolicyStatus, err)
	}
	restartedConfig, err := grpcClient.GetSandboxConfig(userCtx, &sandboxv1.GetSandboxConfigRequest{SandboxId: name})
	if err != nil || restartedConfig.GetGlobalPolicyVersion() != globalPolicyUpdate.GetVersion() {
		t.Fatalf("effective sandbox config after gateway restart=%v err=%v; want global policy revision %d", restartedConfig, err, globalPolicyUpdate.GetVersion())
	}
	stopPolicyProbeServer := startPolicyProbeServer(t, userCtx, grpcClient, name)
	defer stopPolicyProbeServer()
	runPolicyConnectProbe(t, userCtx, grpcClient, name, "cautem-"+name+":17777", "200")
	runPolicyConnectProbe(t, userCtx, grpcClient, name, "blocked.invalid:443", "403")
	stopPolicyProbeServer()
	refreshCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+supervisorToken)
	refreshed, err := grpcClient.RefreshSandboxToken(refreshCtx, &openshellv1.RefreshSandboxTokenRequest{})
	if err != nil || refreshed.GetToken() != supervisorToken {
		t.Fatalf("supervisor token refresh after gateway restart=%q err=%v; want persisted current token", refreshed.GetToken(), err)
	}
	restored, err := grpcClient.GetSandbox(userCtx, &openshellv1.GetSandboxRequest{Name: exitName, Workspace: "default"})
	if err != nil || restored.GetSandbox().GetStatus().GetExitCode() != 7 {
		t.Fatalf("gateway restart lost main-process result: sandbox=%v err=%v", restored, err)
	}

	// Drop only the active supervisor stream while leaving gateway and workload
	// alive. The sidecar must reconnect, and a subsequent exec must cross the
	// replacement relay rather than a stale session.
	runtime.Disconnect(name)
	if runtime.Connected(name) {
		t.Fatal("forced relay disconnect left the supervisor session registered")
	}
	relayDeadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(relayDeadline) {
		if runtime.Connected(name) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !runtime.Connected(name) {
		t.Fatal("supervisor relay did not reconnect after an isolated relay loss")
	}
	relayCtx, relayCancel := context.WithTimeout(userCtx, 30*time.Second)
	relayStream, err := grpcClient.ExecSandbox(relayCtx, &openshellv1.ExecSandboxRequest{
		SandboxId: name, Command: []string{"printf", "relay-recovered"}, TimeoutSeconds: 20, NoLoginShell: true,
	})
	if err != nil {
		relayCancel()
		t.Fatalf("ExecSandbox after relay recovery: %v", err)
	}
	var relayOutput strings.Builder
	var relayExit *openshellv1.ExecSandboxExit
	for {
		event, recvErr := relayStream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			relayCancel()
			t.Fatalf("receive ExecSandbox after relay recovery: %v", recvErr)
		}
		if stdout := event.GetStdout(); stdout != nil {
			relayOutput.Write(stdout.GetData())
		}
		if event.GetExit() != nil {
			relayExit = event.GetExit()
		}
	}
	relayCancel()
	if relayExit == nil || relayExit.GetExitCode() != 0 || relayOutput.String() != "relay-recovered" {
		t.Fatalf("ExecSandbox after relay recovery output=%q exit=%v; want relay-recovered/0", relayOutput.String(), relayExit)
	}
	// Exercise the public SSH session expiry boundary against the real relay.
	runtime.SetSSHSessionTTL(time.Millisecond)
	expiringSession, err := grpcClient.CreateSshSession(userCtx, &openshellv1.CreateSshSessionRequest{SandboxId: name})
	if err != nil {
		t.Fatalf("create expiring SSH session: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	expiringHeaders := http.Header{}
	expiringHeaders.Set("Authorization", "Bearer "+expiringSession.GetToken())
	expiringHeaders.Set(relayproto.HeaderSandboxID, expiringSession.GetSandboxId())
	expiringCtx, expiringCancel := context.WithTimeout(userCtx, 5*time.Second)
	_, expiryErr := relayproto.Dial(expiringCtx, endpoint, relayproto.PathSSHConnect, relayproto.DialOptions{Header: expiringHeaders})
	expiringCancel()
	if expiryErr == nil {
		t.Fatal("expired SSH session unexpectedly opened a relay")
	}
	createdProvider, err := grpcClient.CreateProvider(userCtx, &openshellv1.CreateProviderRequest{
		Workspace: "default",
		Provider: &datamodelv1.Provider{
			Metadata: &datamodelv1.ObjectMeta{Name: "e2e-provider"},
			Type:     "e2e", Credentials: map[string]string{"API_TOKEN": "docker-podman-e2e-secret"},
		},
	})
	if err != nil || createdProvider.GetProvider().GetMetadata().GetName() != "e2e-provider" {
		t.Fatalf("external OpenShell gRPC CreateProvider=%v err=%v", createdProvider, err)
	}
	attached, err := grpcClient.AttachSandboxProvider(userCtx, &openshellv1.AttachSandboxProviderRequest{SandboxName: name, ProviderName: "e2e-provider"})
	if err != nil || !attached.GetAttached() {
		t.Fatalf("external OpenShell gRPC AttachSandboxProvider=%v err=%v", attached, err)
	}
	listed, err := grpcClient.ListSandboxProviders(userCtx, &openshellv1.ListSandboxProvidersRequest{SandboxName: name, Workspace: "default"})
	if err != nil || len(listed.GetProviders()) != 1 || listed.GetProviders()[0].GetType() != "e2e" {
		t.Fatalf("external OpenShell gRPC ListSandboxProviders=%v err=%v", listed, err)
	}
	sandboxToken, err := runtime.IssueSandboxToken(name)
	if err != nil {
		t.Fatal(err)
	}
	sandboxCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+sandboxToken)
	providerEnvironment, err := grpcClient.GetSandboxProviderEnvironment(sandboxCtx, &openshellv1.GetSandboxProviderEnvironmentRequest{SandboxId: name})
	if err != nil || providerEnvironment.GetEnvironment()["API_TOKEN"] != "docker-podman-e2e-secret" {
		t.Fatalf("sandbox provider environment=%v err=%v", providerEnvironment, err)
	}
	detached, err := grpcClient.DetachSandboxProvider(userCtx, &openshellv1.DetachSandboxProviderRequest{
		SandboxName: name, ProviderName: "e2e-provider", ExpectedResourceVersion: attached.GetSandbox().GetMetadata().GetResourceVersion(),
	})
	if err != nil || !detached.GetDetached() || len(detached.GetSandbox().GetSpec().GetProviders()) != 0 {
		t.Fatalf("external OpenShell gRPC DetachSandboxProvider=%v err=%v", detached, err)
	}
	deletedProvider, err := grpcClient.DeleteProvider(userCtx, &openshellv1.DeleteProviderRequest{Name: "e2e-provider", Workspace: "default"})
	if err != nil || !deletedProvider.GetDeleted() {
		t.Fatalf("external OpenShell gRPC DeleteProvider=%v err=%v", deletedProvider, err)
	}
	credentialDriver.mu.Lock()
	stores, resolves, deletes, remaining := credentialDriver.stores, credentialDriver.resolves, credentialDriver.deletes, len(credentialDriver.values)
	credentialDriver.mu.Unlock()
	if stores == 0 || resolves == 0 || deletes == 0 || remaining != 0 {
		t.Fatalf("external credential driver lifecycle store=%d resolve=%d delete=%d remaining=%d", stores, resolves, deletes, remaining)
	}
}

func measureSupervisorProcessEventDelivery(t *testing.T, ctx context.Context, client openshellv1.OpenShellClient, sandbox string) {
	t.Helper()
	baseline, err := client.GetSandboxLogs(ctx, &openshellv1.GetSandboxLogsRequest{SandboxId: sandbox, Lines: 1000, Sources: []string{"sandbox"}})
	if err != nil {
		t.Fatalf("read initial supervisor process events from gateway: %v", err)
	}
	t.Logf("gateway initially has %d sandbox log lines for process-event probe", len(baseline.GetLogs()))
	for _, line := range baseline.GetLogs() {
		if line.GetFields()["activity"] != "" {
			t.Logf("initial supervisor process event: activity=%s pid=%s executable=%s", line.GetFields()["activity"], line.GetFields()["pid"], line.GetFields()["executable"])
		}
	}

	rtts := make([]time.Duration, 20)
	for i := range rtts {
		started := time.Now()
		if _, err := client.Health(ctx, &openshellv1.HealthRequest{}); err != nil {
			t.Fatalf("gateway Health RTT sample %d: %v", i+1, err)
		}
		rtts[i] = time.Since(started)
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	t.Logf("gateway Health RPC round-trip on the E2E gateway host (20 samples): p50=%s p95=%s max=%s", durationPercentile(rtts, 0.50), durationPercentile(rtts, 0.95), rtts[len(rtts)-1])

	const expectedExits = 8
	startedAt := time.Now()
	probeCtx, probeCancel := context.WithTimeout(ctx, 30*time.Second)
	defer probeCancel()
	probe, err := client.ExecSandbox(probeCtx, &openshellv1.ExecSandboxRequest{
		SandboxId:      sandbox,
		Command:        []string{"sh", "-c", `test -p /tmp/cautem-process-event-trigger && printf 'start' > /tmp/cautem-process-event-trigger`},
		TimeoutSeconds: 20, NoLoginShell: true,
	})
	if err != nil {
		t.Fatalf("trigger adopted-child process event probes: %v", err)
	}
	var probeExit *openshellv1.ExecSandboxExit
	for {
		event, recvErr := probe.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			t.Fatalf("receive adopted-child process event probe result: %v", recvErr)
		}
		if event.GetExit() != nil {
			probeExit = event.GetExit()
		}
	}
	if probeExit == nil || probeExit.GetExitCode() != 0 {
		t.Fatalf("process event probe trigger exit=%v; want exit 0", probeExit)
	}

	marker := startedAt.UnixMilli()
	latencies := make(map[string]time.Duration, expectedExits)
	deadline := time.Now().Add(20 * time.Second)
	for len(latencies) < expectedExits && time.Now().Before(deadline) {
		response, err := client.GetSandboxLogs(probeCtx, &openshellv1.GetSandboxLogsRequest{
			SandboxId: sandbox, SinceMs: marker, Lines: 1000, Sources: []string{"sandbox"},
		})
		if err != nil {
			t.Fatalf("read process event probe logs from gateway: %v", err)
		}
		observedAt := time.Now()
		for _, line := range response.GetLogs() {
			fields := line.GetFields()
			if fields["activity"] != "EXIT" {
				continue
			}
			pid := fields["pid"]
			if pid == "" || line.GetTimestampMs() < marker {
				continue
			}
			if _, seen := latencies[pid]; !seen {
				latencies[pid] = observedAt.Sub(time.UnixMilli(line.GetTimestampMs()))
			}
		}
		if len(latencies) < expectedExits {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if len(latencies) < expectedExits {
		all, readErr := client.GetSandboxLogs(ctx, &openshellv1.GetSandboxLogsRequest{SandboxId: sandbox, Lines: 1000, Sources: []string{"sandbox"}})
		if readErr != nil {
			t.Fatalf("gateway received %d/%d adopted-child EXIT events; diagnostic log query: %v", len(latencies), expectedExits, readErr)
		}
		var events []string
		for _, line := range all.GetLogs() {
			fields := line.GetFields()
			if fields["activity"] != "" {
				events = append(events, fields["activity"]+":"+fields["executable"]+":"+fields["pid"])
			}
		}
		t.Fatalf("gateway received %d/%d adopted-child EXIT events; process logs=%v", len(latencies), expectedExits, events)
	}
	processLatencies := make([]time.Duration, 0, len(latencies))
	for _, latency := range latencies {
		if latency < 0 {
			t.Fatalf("gateway observed process exit before its event timestamp: %s", latency)
		}
		processLatencies = append(processLatencies, latency)
	}
	sort.Slice(processLatencies, func(i, j int) bool { return processLatencies[i] < processLatencies[j] })
	t.Logf("supervisor detected-exit -> gateway log query observed (sandbox %s, %d samples): p50=%s p95=%s max=%s", sandbox, len(processLatencies), durationPercentile(processLatencies, 0.50), durationPercentile(processLatencies, 0.95), processLatencies[len(processLatencies)-1])
}

func durationPercentile(sorted []time.Duration, percentile float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted))*percentile+0.999999) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
