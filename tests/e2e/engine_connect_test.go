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
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/quarshell-core/relayproto"
	"github.com/cautem/quarshell-gateway/internal/httpapi"
	credentialsv1 "github.com/cautem/quarshell-gateway/internal/upstreamproto/credentialsv1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type e2ECredentialDriver struct {
	credentialsv1.UnimplementedCredentialDriverServer
	mu       sync.Mutex
	values   map[string]string
	stores   int
	resolves int
	deletes  int
}

func e2eWorkspaceScope() *datamodelv1.WorkspaceSelector {
	return &datamodelv1.WorkspaceSelector{Selection: &datamodelv1.WorkspaceSelector_Workspace{Workspace: "default"}}
}

func startPolicyProbeServer(t *testing.T, parent context.Context, client compatv1.OpenShellClient, sandboxID string) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	stream, err := client.ExecSandboxInteractive(ctx)
	if err != nil {
		cancel()
		t.Fatalf("open policy probe server ExecSandbox: %v", err)
	}
	if err := stream.Send(&compatv1.ExecSandboxInput{Payload: &compatv1.ExecSandboxInput_Start{Start: &compatv1.ExecSandboxRequest{
		Sandbox: sandboxID, Command: []string{"/usr/local/bin/cautem-tcp-echo", "serve-tcp", "0.0.0.0:17777"}, NoLoginShell: true, ExecutionTimeout: durationpb.New(90 * time.Second),
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

func runPolicyConnectProbe(t *testing.T, ctx context.Context, client compatv1.OpenShellClient, runtime *httpapi.E2ERuntime, sandboxID, target, wantStatus string) {
	t.Helper()
	streamCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stream, err := client.ExecSandbox(streamCtx, &compatv1.ExecSandboxRequest{
		Sandbox: sandboxID, Command: []string{"/usr/local/bin/cautem-tcp-echo", "probe-connect-status", target, wantStatus}, NoLoginShell: true, ExecutionTimeout: durationpb.New(10 * time.Second),
	})
	if err != nil {
		t.Fatalf("run policy CONNECT probe for %s: %v", target, err)
	}
	var exit *compatv1.ExecSandboxExit
	var output, errorsOutput strings.Builder
	for {
		event, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			t.Fatalf("receive policy CONNECT probe for %s: %v", target, recvErr)
		}
		if stdout := event.GetStdout(); stdout != nil {
			_, _ = output.Write(stdout.GetData())
		}
		if stderr := event.GetStderr(); stderr != nil {
			_, _ = errorsOutput.Write(stderr.GetData())
		}
		if event.GetExit() != nil {
			exit = event.GetExit()
		}
	}
	if exit == nil || exit.GetExitCode() != 0 {
		workloadIP, workloadIPErr := runtime.EngineContainerIP(ctx, sandboxID, "cautem-"+sandboxID)
		proxyIP, proxyIPErr := runtime.EngineContainerIP(ctx, sandboxID, "cautem-proxy-"+sandboxID)
		networkState, networkStateErr := sandboxNetworkDiagnostic(ctx, client, sandboxID)
		t.Fatalf("policy CONNECT probe for %s returned exit=%v; want proxy status %s (stdout=%q stderr=%q workload_ip=%q workload_ip_err=%v proxy_ip=%q proxy_ip_err=%v network=%q network_err=%v)", target, exit, wantStatus, output.String(), errorsOutput.String(), workloadIP, workloadIPErr, proxyIP, proxyIPErr, networkState, networkStateErr)
	}
}

func sandboxNetworkDiagnostic(ctx context.Context, client compatv1.OpenShellClient, sandboxID string) (string, error) {
	diagCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stream, err := client.ExecSandbox(diagCtx, &compatv1.ExecSandboxRequest{
		Sandbox: sandboxID, Command: []string{"sh", "-c", "cat /etc/resolv.conf; cat /proc/net/route; cat /proc/net/fib_trie"}, NoLoginShell: true,
		ExecutionTimeout: durationpb.New(4 * time.Second),
	})
	if err != nil {
		return "", err
	}
	var output strings.Builder
	for {
		event, recvErr := stream.Recv()
		if recvErr == io.EOF {
			return output.String(), nil
		}
		if recvErr != nil {
			return output.String(), recvErr
		}
		if stdout := event.GetStdout(); stdout != nil {
			_, _ = output.Write(stdout.GetData())
		}
		if stderr := event.GetStderr(); stderr != nil {
			_, _ = output.Write(stderr.GetData())
		}
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
	handle := request.GetProvider() + "/" + request.GetCredentialKey()
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
		// Docker Desktop bind mounts do not always allow host-side chown.
		// This is a disposable fixture, so grant the sandbox UID access instead.
		if chmodErr := os.Chmod(workspaceRoot, 0o777); chmodErr != nil {
			t.Fatalf("prepare E2E workspace ownership: chown: %v; chmod: %v", err, chmodErr)
		}
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
	grpcClient := compatv1.NewOpenShellClient(grpcConn)
	userCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+runtime.AuthToken())
	var healthErr error
	readyBy := time.Now().Add(10 * time.Second)
	for time.Now().Before(readyBy) {
		probeCtx, probeCancel := context.WithTimeout(userCtx, 500*time.Millisecond)
		_, healthErr = grpcClient.Health(probeCtx, &compatv1.HealthRequest{})
		probeCancel()
		if healthErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if healthErr != nil {
		t.Fatalf("external OpenShell gRPC Health: %v", healthErr)
	}
	if user, err := grpcClient.GetCurrentUser(userCtx, &compatv1.GetCurrentUserRequest{}); err != nil || user.GetSubject() != "local-dev" {
		t.Fatalf("external OpenShell gRPC GetCurrentUser=%v err=%v", user, err)
	}

	name := driverName + "-connect-e2e"
	recoveryName := driverName + "-recover-e2e"
	image := strings.TrimSpace(os.Getenv("CAUTEM_E2E_SANDBOX_IMAGE"))
	if image == "" {
		image = "localhost/cautem-connect-e2e:latest"
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		_, _ = grpcClient.DeleteSandbox(metadata.AppendToOutgoingContext(cleanupCtx, "authorization", "Bearer "+runtime.AuthToken()), &compatv1.DeleteSandboxRequest{Name: name, WorkspaceScope: e2eWorkspaceScope()})
	}()
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		_, _ = grpcClient.DeleteSandbox(metadata.AppendToOutgoingContext(cleanupCtx, "authorization", "Bearer "+runtime.AuthToken()), &compatv1.DeleteSandboxRequest{Name: recoveryName, WorkspaceScope: e2eWorkspaceScope()})
	}()
	_, err = grpcClient.CreateSandbox(userCtx, &compatv1.CreateSandboxRequest{
		Name: name, WorkspaceScope: e2eWorkspaceScope(),
		Spec: &compatv1.SandboxSpec{
			Policy:   &sandboxv1.SandboxPolicy{Version: 1},
			Template: &compatv1.SandboxTemplate{Image: image},
			Command:  []string{"sh", "-c", `rm -f /tmp/cautem-process-event-trigger /tmp/cautem-process-event-child-pids || { echo process-event-fixture-rm-failed; exit 11; }; mkfifo /tmp/cautem-process-event-trigger || { echo process-event-fixture-mkfifo-failed; exit 12; }; IFS= read -r _ < /tmp/cautem-process-event-trigger; /usr/local/bin/cautem-tcp-echo spawn-orphans 24 15 || exit 14; exec sleep infinity`},
		},
	})
	if err != nil {
		if driverName == "podman" && strings.Contains(strings.ToLower(err.Error()), "host-gateway isolation requires podman 6.0") {
			t.Skipf("Podman proxy-backed sandboxes require blackhole routes for host-gateway isolation: %v", err)
		}
		logs, _ := runtime.EngineLogs(ctx, name)
		t.Fatalf("external OpenShell gRPC CreateSandbox: %v\ncontainer logs:\n%s", err, logs)
	}
	if !runtime.Connected(name) {
		t.Fatal("CreateSandbox returned before the supervisor relay connected")
	}
	_, err = grpcClient.CreateSandbox(userCtx, &compatv1.CreateSandboxRequest{
		Name: recoveryName, WorkspaceScope: e2eWorkspaceScope(),
		Spec: &compatv1.SandboxSpec{
			Policy:   &sandboxv1.SandboxPolicy{Version: 1},
			Template: &compatv1.SandboxTemplate{Image: image},
			Command:  []string{"sleep", "infinity"},
		},
	})
	if err != nil {
		t.Fatalf("create sandbox for missing-runtime recovery: %v", err)
	}
	if !runtime.Connected(recoveryName) {
		t.Fatal("recovery sandbox relay did not connect after create")
	}
	if err := os.MkdirAll(workspaceRoot, 0o700); err != nil {
		t.Fatalf("create recovery workspace fixture: %v", err)
	}
	const recoveryMarker = ".cautem-gateway-recovery-marker"
	if err := os.WriteFile(filepath.Join(workspaceRoot, recoveryMarker), []byte("workspace-survived-runtime-loss\n"), 0o644); err != nil {
		t.Fatalf("write recovery workspace marker: %v", err)
	}
	measureSupervisorProcessEventDelivery(t, userCtx, grpcClient, runtime, name)
	policyUpdate, err := grpcClient.UpdateConfig(userCtx, &compatv1.UpdateConfigRequest{
		Sandbox: name, WorkspaceScope: e2eWorkspaceScope(),
		Policy: &sandboxv1.SandboxPolicy{Version: 1, NetworkPolicies: map[string]*sandboxv1.NetworkPolicyRule{
			"api": {Name: "api", Endpoints: []*sandboxv1.NetworkEndpoint{{Host: "api.example.com", Port: 443}}},
		}},
	})
	if err != nil {
		t.Fatalf("external OpenShell gRPC UpdateConfig with runtime acknowledgement: %v", err)
	}
	policyStatus, err := grpcClient.GetSandboxPolicyStatus(userCtx, &compatv1.GetSandboxPolicyStatusRequest{Sandbox: name})
	if err != nil || policyStatus.GetActiveVersion() != policyUpdate.GetVersion() || policyStatus.GetRevision().GetStatus() != compatv1.PolicyStatus_POLICY_STATUS_LOADED {
		t.Fatalf("UpdateConfig policy status=%v err=%v; want loaded active version %d", policyStatus, err, policyUpdate.GetVersion())
	}
	globalPolicyUpdate, err := grpcClient.UpdateConfig(userCtx, &compatv1.UpdateConfigRequest{
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
	globalPolicyStatus, err := grpcClient.GetSandboxPolicyStatus(userCtx, &compatv1.GetSandboxPolicyStatusRequest{Sandbox: name})
	if err != nil || globalPolicyStatus.GetRevision().GetStatus() != compatv1.PolicyStatus_POLICY_STATUS_LOADED {
		t.Fatalf("global UpdateConfig policy status=%v err=%v; want loaded policy", globalPolicyStatus, err)
	}
	effectiveConfig, err := grpcClient.GetSandboxConfig(userCtx, &sandboxv1.GetSandboxConfigRequest{Name: name})
	if err != nil || effectiveConfig.GetGlobalPolicyVersion() != globalPolicyUpdate.GetVersion() {
		t.Fatalf("effective sandbox config=%v err=%v; want global policy revision %d", effectiveConfig, err, globalPolicyUpdate.GetVersion())
	}
	execCtx, execCancel := context.WithTimeout(userCtx, 30*time.Second)
	execStream, err := grpcClient.ExecSandbox(execCtx, &compatv1.ExecSandboxRequest{
		Sandbox: name, Command: []string{"id", "-un"}, ExecutionTimeout: durationpb.New(20 * time.Second), NoLoginShell: true,
	})
	if err != nil {
		execCancel()
		t.Fatalf("external OpenShell gRPC ExecSandbox: %v", err)
	}
	var execOutput strings.Builder
	var execExit *compatv1.ExecSandboxExit
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
	inputStream, err := grpcClient.ExecSandbox(inputCtx, &compatv1.ExecSandboxRequest{
		Sandbox: name,
		Command: []string{"sh", "-c", `printf '%s:%s:%s' "$PWD" "$LANG" "$(cat)"`},
		Workdir: "/tmp", Environment: map[string]string{"LANG": "C.UTF-8"}, Stdin: []byte("stdin-ok"), ExecutionTimeout: durationpb.New(20 * time.Second),
	})
	if err != nil {
		inputCancel()
		t.Fatalf("external OpenShell gRPC ExecSandbox with stdin/env/workdir: %v", err)
	}
	var inputOutput strings.Builder
	var inputExit *compatv1.ExecSandboxExit
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
	if err := interactive.Send(&compatv1.ExecSandboxInput{Payload: &compatv1.ExecSandboxInput_Start{Start: &compatv1.ExecSandboxRequest{
		Sandbox: name, Command: []string{"sh", "-c", `read line; printf '%s:' "$line"; stty size`}, Tty: true,
		Cols: 80, Rows: 24, NoLoginShell: true, ExecutionTimeout: durationpb.New(20 * time.Second),
	}}}); err != nil {
		interactiveCancel()
		t.Fatalf("start interactive ExecSandbox: %v", err)
	}
	if err := interactive.Send(&compatv1.ExecSandboxInput{Payload: &compatv1.ExecSandboxInput_Resize{Resize: &compatv1.ExecSandboxWindowResize{Cols: 132, Rows: 43}}}); err != nil {
		interactiveCancel()
		t.Fatalf("resize interactive ExecSandbox: %v", err)
	}
	if err := interactive.Send(&compatv1.ExecSandboxInput{Payload: &compatv1.ExecSandboxInput_Stdin{Stdin: []byte("interactive-ok\n")}}); err != nil {
		interactiveCancel()
		t.Fatalf("send interactive ExecSandbox stdin: %v", err)
	}
	if err := interactive.CloseSend(); err != nil {
		interactiveCancel()
		t.Fatalf("close interactive ExecSandbox stdin: %v", err)
	}
	var interactiveOutput strings.Builder
	var interactiveExit *compatv1.ExecSandboxExit
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
	if err := cancelStream.Send(&compatv1.ExecSandboxInput{Payload: &compatv1.ExecSandboxInput_Start{Start: &compatv1.ExecSandboxRequest{
		Sandbox: name, Command: []string{"sh", "-c", "sleep 30 & echo $! > " + cancelPIDFile + "; test -s " + cancelPIDFile + " || exit 99; echo ready; wait"}, NoLoginShell: true, ExecutionTimeout: durationpb.New(60 * time.Second),
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
	var cancelExit *compatv1.ExecSandboxExit
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
	orphanStream, err := grpcClient.ExecSandbox(orphanCtx, &compatv1.ExecSandboxRequest{
		Sandbox:          name,
		Command:          []string{"sh", "-c", "pid=$(cat " + cancelPIDFile + "); i=0; while kill -0 \"$pid\" 2>/dev/null; do i=$((i+1)); [ \"$i\" -ge 40 ] && exit 1; sleep .1; done; rm -f " + cancelPIDFile + "; echo reaped"},
		ExecutionTimeout: durationpb.New(10 * time.Second), NoLoginShell: true,
	})
	if err != nil {
		orphanCancel()
		t.Fatalf("check cancelled exec child cleanup: %v", err)
	}
	var orphanOutput strings.Builder
	var orphanExit *compatv1.ExecSandboxExit
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
	exitStream, err := grpcClient.ExecSandbox(userCtx, &compatv1.ExecSandboxRequest{
		Sandbox: name, Command: []string{"sh", "-c", "echo stdout; echo stderr >&2; exit 7"}, NoLoginShell: true, ExecutionTimeout: durationpb.New(20 * time.Second),
	})
	if err != nil {
		t.Fatalf("start stderr/nonzero ExecSandbox: %v", err)
	}
	var exitStdout, exitStderr strings.Builder
	var nonzeroExit *compatv1.ExecSandboxExit
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
	timeoutPIDFile := "/tmp/cautem-exec-timeout-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	timeoutExitFile := timeoutPIDFile + ".exit"
	timeoutCtx, timeoutCancel := context.WithTimeout(userCtx, 30*time.Second)
	timeoutStream, err := grpcClient.ExecSandbox(timeoutCtx, &compatv1.ExecSandboxRequest{
		Sandbox: name, Command: []string{"/usr/local/bin/cautem-tcp-echo", "spawn-child", timeoutPIDFile, timeoutExitFile, "30"}, ExecutionTimeout: durationpb.New(5 * time.Second), NoLoginShell: true,
	})
	if err != nil {
		timeoutCancel()
		t.Fatalf("start timeout ExecSandbox: %v", err)
	}
	var timeoutExit *compatv1.ExecSandboxExit
	var timeoutStdout, timeoutStderr strings.Builder
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
		if output := event.GetStdout(); output != nil {
			_, _ = timeoutStdout.Write(output.GetData())
		}
		if output := event.GetStderr(); output != nil {
			_, _ = timeoutStderr.Write(output.GetData())
		}
	}
	timeoutCancel()
	if timeoutExit == nil || timeoutExit.GetExitCode() != 124 {
		t.Fatalf("ExecSandbox timeout stdout=%q stderr=%q exit=%v; want exit code 124", timeoutStdout.String(), timeoutStderr.String(), timeoutExit)
	}
	orphanCheckCtx, orphanCheckCancel := context.WithTimeout(userCtx, 15*time.Second)
	orphanCheck, err := grpcClient.ExecSandbox(orphanCheckCtx, &compatv1.ExecSandboxRequest{
		Sandbox: name, Command: []string{"sh", "-c", "pid=$(cat " + timeoutPIDFile + ") || exit 2; i=0; while [ ! -s " + timeoutExitFile + " ]; do i=$((i+1)); if [ \"$i\" -ge 80 ]; then [ -s " + timeoutExitFile + " ] && break; printf 'timed-out child did not receive termination pid=%s pidns=' \"$pid\"; readlink /proc/self/ns/pid; exit 1; fi; sleep .1; done; read exited_pid signal < " + timeoutExitFile + " || exit 2; [ \"$pid\" = \"$exited_pid\" ] && [ \"$signal\" = 'terminated' ] || { printf 'unexpected child termination pid=%s exited_pid=%s signal=%s\\n' \"$pid\" \"$exited_pid\" \"$signal\"; exit 1; }; rm -f " + timeoutPIDFile + " " + timeoutExitFile + "; echo reaped"},
		ExecutionTimeout: durationpb.New(10 * time.Second), NoLoginShell: true,
	})
	if err != nil {
		orphanCheckCancel()
		t.Fatalf("start timed out exec child cleanup check: %v", err)
	}
	var orphanCheckOutput strings.Builder
	var orphanCheckExit *compatv1.ExecSandboxExit
	for {
		event, recvErr := orphanCheck.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			orphanCheckCancel()
			t.Fatalf("receive timed out exec child cleanup result: %v", recvErr)
		}
		if stdout := event.GetStdout(); stdout != nil {
			orphanCheckOutput.Write(stdout.GetData())
		}
		if event.GetExit() != nil {
			orphanCheckExit = event.GetExit()
		}
	}
	orphanCheckCancel()
	if orphanCheckExit == nil || orphanCheckExit.GetExitCode() != 0 || !strings.Contains(orphanCheckOutput.String(), "reaped") {
		t.Fatalf("timed out exec child cleanup output=%q exit=%v; want reaped/0", orphanCheckOutput.String(), orphanCheckExit)
	}
	interactiveTimeoutCtx, interactiveTimeoutCancel := context.WithTimeout(userCtx, 30*time.Second)
	interactiveTimeout, err := grpcClient.ExecSandboxInteractive(interactiveTimeoutCtx)
	if err != nil {
		interactiveTimeoutCancel()
		t.Fatalf("open interactive ExecSandbox timeout: %v", err)
	}
	if err := interactiveTimeout.Send(&compatv1.ExecSandboxInput{Payload: &compatv1.ExecSandboxInput_Start{Start: &compatv1.ExecSandboxRequest{
		Sandbox: name, Command: []string{"sleep", "15"}, ExecutionTimeout: durationpb.New(5 * time.Second), NoLoginShell: true,
	}}}); err != nil {
		interactiveTimeoutCancel()
		t.Fatalf("start interactive ExecSandbox timeout: %v", err)
	}
	var interactiveTimeoutExit *compatv1.ExecSandboxExit
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
		if err := forwardEcho.Send(&compatv1.ExecSandboxInput{Payload: &compatv1.ExecSandboxInput_Start{Start: &compatv1.ExecSandboxRequest{
			Sandbox: name, Command: []string{"/usr/local/bin/cautem-tcp-echo", "127.0.0.1:17777"}, NoLoginShell: true, ExecutionTimeout: durationpb.New(90 * time.Second),
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
		forwardSession, err := grpcClient.CreateSshSession(userCtx, &compatv1.CreateSshSessionRequest{Sandbox: name})
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
			deniedErr = deniedStream.Send(&compatv1.TcpForwardFrame{Payload: &compatv1.TcpForwardFrame_Init{Init: &compatv1.TcpForwardInit{
				Sandbox: name, AuthorizationToken: forwardSession.GetToken(), ServiceId: "e2e-denied-public-target",
				Target: &compatv1.TcpForwardInit_Tcp{Tcp: &compatv1.TcpRelayTarget{Host: "1.1.1.1", Port: 443}},
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
			err = forwardStream.Send(&compatv1.TcpForwardFrame{Payload: &compatv1.TcpForwardFrame_Init{Init: &compatv1.TcpForwardInit{
				Sandbox: name, AuthorizationToken: forwardSession.GetToken(), ServiceId: "e2e-loopback",
				Target: &compatv1.TcpForwardInit_Tcp{Tcp: &compatv1.TcpRelayTarget{Host: "localhost", Port: 17777}},
			}}})
		}
		const forwardPayload = "docker-podman-forward-roundtrip"
		if err == nil {
			err = forwardStream.Send(&compatv1.TcpForwardFrame{Payload: &compatv1.TcpForwardFrame_Data{Data: []byte(forwardPayload)}})
		}
		var forwarded *compatv1.TcpForwardFrame
		if err == nil {
			forwarded, err = forwardStream.Recv()
		}
		if err != nil || string(forwarded.GetData()) != forwardPayload {
			forwardCancel()
			forwardEchoCancel()
			t.Fatalf("external OpenShell gRPC ForwardTcp payload=%v err=%v; want echoed %q", forwarded, err, forwardPayload)
		}
		forwardCancel()
		_, _ = grpcClient.RevokeSshSession(userCtx, &compatv1.RevokeSshSessionRequest{Token: forwardSession.GetToken()})
		forwardEchoCancel()
		select {
		case <-echoDone:
		case <-time.After(10 * time.Second):
			t.Error("TCP echo server exec did not stop after stream cancellation")
		}
	}
	if _, err = grpcClient.StopSandbox(userCtx, &compatv1.StopSandboxRequest{Name: name, WorkspaceScope: e2eWorkspaceScope()}); err != nil {
		t.Fatalf("external OpenShell gRPC StopSandbox: %v", err)
	}
	if runtime.Connected(name) {
		t.Fatal("StopSandbox returned while the old supervisor relay remained connected")
	}
	if _, err = grpcClient.StartSandbox(userCtx, &compatv1.StartSandboxRequest{Name: name, WorkspaceScope: e2eWorkspaceScope()}); err != nil {
		t.Fatalf("external OpenShell gRPC StartSandbox: %v", err)
	}
	if !runtime.Connected(name) {
		t.Fatal("StartSandbox returned before the supervisor relay reconnected")
	}

	sshCtx, sshCancel := context.WithTimeout(ctx, 30*time.Second)
	defer sshCancel()
	sshSession, err := grpcClient.CreateSshSession(userCtx, &compatv1.CreateSshSessionRequest{Sandbox: name})
	if err != nil {
		t.Fatalf("create user SSH session through OpenShell gRPC: %v", err)
	}
	defer func() {
		_, _ = grpcClient.RevokeSshSession(context.Background(), &compatv1.RevokeSshSessionRequest{Token: sshSession.GetToken()})
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
	if err != nil {
		t.Logf("workload cannot inspect /proc/1/cmdline under its sandbox policy: %v", err)
	} else if !strings.Contains(string(supervisorOutput), "/cautem/cautem-supervisor") {
		if os.Getenv("CAUTEM_E2E_ROOTLESS_PODMAN") == "1" {
			t.Logf("rootless Podman-in-Docker does not provide an isolated PID namespace: PID 1=%q", supervisorOutput)
		} else {
			t.Fatalf("PID 1=%q, want Go sandbox supervisor", supervisorOutput)
		}
	}
	// Exercise the workload PID 1 → proxy sidecar → pinned gateway lifecycle
	// RPC path on the real Docker/Podman backend, including the persisted status.
	exitName := driverName + "-main-exit"
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		_, _ = grpcClient.DeleteSandbox(metadata.AppendToOutgoingContext(cleanupCtx, "authorization", "Bearer "+runtime.AuthToken()), &compatv1.DeleteSandboxRequest{Name: exitName, WorkspaceScope: e2eWorkspaceScope()})
	}()
	_, err = grpcClient.CreateSandbox(userCtx, &compatv1.CreateSandboxRequest{
		Name: exitName, WorkspaceScope: e2eWorkspaceScope(),
		Spec: &compatv1.SandboxSpec{
			Policy:   &sandboxv1.SandboxPolicy{Version: 1},
			Template: &compatv1.SandboxTemplate{Image: image},
			Command:  []string{"/bin/sh", "-c", "sleep 3; exit 7"},
		},
	})
	if err != nil {
		t.Fatalf("create short-lived main-process sandbox: %v", err)
	}
	exitCtx, exitCancel := context.WithTimeout(userCtx, 30*time.Second)
	defer exitCancel()
	var exited *compatv1.Sandbox
	finalized := false
	for {
		response, getErr := grpcClient.GetSandbox(exitCtx, &compatv1.GetSandboxRequest{Name: exitName, WorkspaceScope: e2eWorkspaceScope()})
		if getErr == nil {
			exited = response.GetSandbox()
			phase := exited.GetStatus().GetPhase()
			if phase == compatv1.SandboxPhase_SANDBOX_PHASE_COMPLETED || phase == compatv1.SandboxPhase_SANDBOX_PHASE_ERROR {
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
	recoveryRuntimeBefore, ok := runtime.Sandbox(recoveryName)
	if !ok || recoveryRuntimeBefore.RuntimeID == "" {
		t.Fatalf("recovery sandbox has no durable runtime identity before simulated loss: %+v", recoveryRuntimeBefore)
	}
	oldRecoveryRuntimeID, err := runtime.DropSandboxRuntime(ctx, recoveryName)
	if err != nil {
		t.Fatalf("simulate backend runtime loss: %v", err)
	}
	if oldRecoveryRuntimeID != recoveryRuntimeBefore.RuntimeID {
		t.Fatalf("dropped runtime ID=%q, durable ID=%q", oldRecoveryRuntimeID, recoveryRuntimeBefore.RuntimeID)
	}
	if runtime.Connected(recoveryName) {
		t.Fatal("backend runtime deletion left the recovery supervisor relay connected")
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
		_, healthErr = grpcClient.Health(healthCtx, &compatv1.HealthRequest{})
		healthCancel()
		if healthErr == nil && runtime.Connected(name) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if healthErr != nil || !runtime.Connected(name) {
		t.Fatalf("gateway restart did not restore client and supervisor relay: health=%v relay_connected=%v", healthErr, runtime.Connected(name))
	}
	recoveryReadyBy := time.Now().Add(20 * time.Second)
	var missingRecoveryStatus, missingRecoveryRuntimeID string
	var recoveryRecordFound bool
	for time.Now().Before(recoveryReadyBy) {
		missingRecoveryRecord, found := runtime.Sandbox(recoveryName)
		recoveryRecordFound = found
		if found {
			missingRecoveryStatus, missingRecoveryRuntimeID = missingRecoveryRecord.Status, missingRecoveryRecord.RuntimeID
		}
		if found && missingRecoveryStatus == "error" && missingRecoveryRuntimeID == "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !recoveryRecordFound || missingRecoveryStatus != "error" || missingRecoveryRuntimeID != "" {
		t.Fatalf("gateway startup reconciliation did not mark the missing runtime for recovery: status=%q runtime_id=%q found=%v", missingRecoveryStatus, missingRecoveryRuntimeID, recoveryRecordFound)
	}
	recoveredResponse, err := grpcClient.StartSandbox(userCtx, &compatv1.StartSandboxRequest{Name: recoveryName, WorkspaceScope: e2eWorkspaceScope()})
	if err != nil || recoveredResponse.GetSandbox().GetStatus().GetPhase() != compatv1.SandboxPhase_SANDBOX_PHASE_READY {
		t.Fatalf("StartSandbox did not recreate the missing backend runtime: response=%v err=%v", recoveredResponse, err)
	}
	if !runtime.Connected(recoveryName) {
		t.Fatal("replacement runtime did not reconnect its supervisor relay")
	}
	recoveredRecord, ok := runtime.Sandbox(recoveryName)
	if !ok || recoveredRecord.RuntimeID == "" || recoveredRecord.RuntimeID == oldRecoveryRuntimeID || recoveredRecord.Status != "running" {
		t.Fatalf("recovered runtime record=%+v found=%v; want a new running backend identity", recoveredRecord, ok)
	}
	recoveryExecCtx, recoveryExecCancel := context.WithTimeout(userCtx, 30*time.Second)
	recoveryExec, err := grpcClient.ExecSandbox(recoveryExecCtx, &compatv1.ExecSandboxRequest{
		Sandbox: recoveryName, Command: []string{"cat", "/workspace/" + recoveryMarker}, ExecutionTimeout: durationpb.New(20 * time.Second), NoLoginShell: true,
	})
	if err != nil {
		recoveryExecCancel()
		t.Fatalf("execute in recovered sandbox: %v", err)
	}
	var recoveredWorkspace strings.Builder
	var recoveryExit *compatv1.ExecSandboxExit
	for {
		event, recvErr := recoveryExec.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			recoveryExecCancel()
			t.Fatalf("receive recovered sandbox output: %v", recvErr)
		}
		if stdout := event.GetStdout(); stdout != nil {
			recoveredWorkspace.Write(stdout.GetData())
		}
		if event.GetExit() != nil {
			recoveryExit = event.GetExit()
		}
	}
	recoveryExecCancel()
	if recoveryExit == nil || recoveryExit.GetExitCode() != 0 || recoveredWorkspace.String() != "workspace-survived-runtime-loss\n" {
		t.Fatalf("recovered workspace content=%q exit=%v; workspace was not preserved", recoveredWorkspace.String(), recoveryExit)
	}
	restartedPolicyStatus, err := grpcClient.GetSandboxPolicyStatus(userCtx, &compatv1.GetSandboxPolicyStatusRequest{Sandbox: name})
	if err != nil || restartedPolicyStatus.GetRevision().GetStatus() != compatv1.PolicyStatus_POLICY_STATUS_LOADED {
		t.Fatalf("global policy after gateway restart status=%v err=%v; want loaded policy", restartedPolicyStatus, err)
	}
	restartedConfig, err := grpcClient.GetSandboxConfig(userCtx, &sandboxv1.GetSandboxConfigRequest{Name: name})
	if err != nil || restartedConfig.GetGlobalPolicyVersion() != globalPolicyUpdate.GetVersion() {
		t.Fatalf("effective sandbox config after gateway restart=%v err=%v; want global policy revision %d", restartedConfig, err, globalPolicyUpdate.GetVersion())
	}
	stopPolicyProbeServer := startPolicyProbeServer(t, userCtx, grpcClient, name)
	defer stopPolicyProbeServer()
	runPolicyConnectProbe(t, userCtx, grpcClient, runtime, name, "cautem-"+name+":17777", "200")
	runPolicyConnectProbe(t, userCtx, grpcClient, runtime, name, "blocked.invalid:443", "403")
	stopPolicyProbeServer()
	refreshCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+supervisorToken)
	refreshed, err := grpcClient.RefreshSandboxToken(refreshCtx, &compatv1.RefreshSandboxTokenRequest{})
	if err != nil || refreshed.GetToken() != supervisorToken {
		t.Fatalf("supervisor token refresh after gateway restart=%q err=%v; want persisted current token", refreshed.GetToken(), err)
	}
	restored, err := grpcClient.GetSandbox(userCtx, &compatv1.GetSandboxRequest{Name: exitName, WorkspaceScope: e2eWorkspaceScope()})
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
	relayStream, err := grpcClient.ExecSandbox(relayCtx, &compatv1.ExecSandboxRequest{
		Sandbox: name, Command: []string{"printf", "relay-recovered"}, ExecutionTimeout: durationpb.New(20 * time.Second), NoLoginShell: true,
	})
	if err != nil {
		relayCancel()
		t.Fatalf("ExecSandbox after relay recovery: %v", err)
	}
	var relayOutput strings.Builder
	var relayExit *compatv1.ExecSandboxExit
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
	expiringSession, err := grpcClient.CreateSshSession(userCtx, &compatv1.CreateSshSessionRequest{Sandbox: name})
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
	createdProvider, err := grpcClient.CreateProvider(userCtx, &compatv1.CreateProviderRequest{
		WorkspaceScope: e2eWorkspaceScope(),
		Provider: &datamodelv1.Provider{
			Metadata: &datamodelv1.ObjectMeta{Name: "e2e-provider"},
			Type:     "e2e", Credentials: map[string]string{"API_TOKEN": "docker-podman-e2e-secret"},
		},
	})
	if err != nil || createdProvider.GetProvider().GetMetadata().GetName() != "e2e-provider" {
		t.Fatalf("external OpenShell gRPC CreateProvider=%v err=%v", createdProvider, err)
	}
	attached, err := grpcClient.AttachSandboxProvider(userCtx, &compatv1.AttachSandboxProviderRequest{Sandbox: name, Provider: "e2e-provider"})
	if err != nil || !attached.GetAttached() {
		t.Fatalf("external OpenShell gRPC AttachSandboxProvider=%v err=%v", attached, err)
	}
	listed, err := grpcClient.ListSandboxProviders(userCtx, &compatv1.ListSandboxProvidersRequest{Sandbox: name, WorkspaceScope: e2eWorkspaceScope()})
	if err != nil || len(listed.GetProviders()) != 1 || listed.GetProviders()[0].GetType() != "e2e" {
		t.Fatalf("external OpenShell gRPC ListSandboxProviders=%v err=%v", listed, err)
	}
	sandboxToken, err := runtime.IssueSandboxToken(name)
	if err != nil {
		t.Fatal(err)
	}
	sandboxCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+sandboxToken)
	providerEnvironment, err := grpcClient.GetSandboxProviderEnvironment(sandboxCtx, &compatv1.GetSandboxProviderEnvironmentRequest{SandboxId: name})
	if err != nil || len(providerEnvironment.GetEnvironment()) != 0 || providerEnvironment.GetReadinessReason() != compatv1.ProviderReadinessReason_PROVIDER_READINESS_REASON_UNSUPPORTED_SUPERVISOR {
		t.Fatalf("sandbox provider environment must fail closed until endpoint bindings are supported: response=%v err=%v", providerEnvironment, err)
	}
	detached, err := grpcClient.DetachSandboxProvider(userCtx, &compatv1.DetachSandboxProviderRequest{
		Sandbox: name, Provider: "e2e-provider", ExpectedResourceVersion: attached.GetSandbox().GetMetadata().GetResourceVersion(),
	})
	if err != nil || !detached.GetDetached() || len(detached.GetSandbox().GetSpec().GetProviders()) != 0 {
		t.Fatalf("external OpenShell gRPC DetachSandboxProvider=%v err=%v", detached, err)
	}
	deletedProvider, err := grpcClient.DeleteProvider(userCtx, &compatv1.DeleteProviderRequest{Name: "e2e-provider", WorkspaceScope: e2eWorkspaceScope()})
	if err != nil || deletedProvider.GetOutcome() != compatv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED {
		t.Fatalf("external OpenShell gRPC DeleteProvider=%v err=%v", deletedProvider, err)
	}
	credentialDriver.mu.Lock()
	stores, resolves, deletes, remaining := credentialDriver.stores, credentialDriver.resolves, credentialDriver.deletes, len(credentialDriver.values)
	credentialDriver.mu.Unlock()
	if stores == 0 || resolves != 0 || deletes == 0 || remaining != 0 {
		t.Fatalf("external credential driver lifecycle must store and delete credentials while withholding unbound values: store=%d resolve=%d delete=%d remaining=%d", stores, resolves, deletes, remaining)
	}
}

func measureSupervisorProcessEventDelivery(t *testing.T, ctx context.Context, client compatv1.OpenShellClient, runtime *httpapi.E2ERuntime, sandbox string) {
	t.Helper()
	baseline, err := client.GetSandboxLogs(ctx, &compatv1.GetSandboxLogsRequest{Sandbox: sandbox, Lines: 1000, Sources: []string{"sandbox"}})
	if err != nil {
		t.Fatalf("read initial supervisor process events from gateway: %v", err)
	}
	initialProcessEvents := 0
	for _, line := range baseline.GetLogs() {
		if line.GetFields()["activity"] != "" {
			initialProcessEvents++
		}
	}
	t.Logf("gateway initially has %d sandbox log lines and %d process events", len(baseline.GetLogs()), initialProcessEvents)

	rtts := make([]time.Duration, 20)
	for i := range rtts {
		started := time.Now()
		if _, err := client.Health(ctx, &compatv1.HealthRequest{}); err != nil {
			t.Fatalf("gateway Health RTT sample %d: %v", i+1, err)
		}
		rtts[i] = time.Since(started)
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	t.Logf("gateway Health RPC round-trip on the E2E gateway host (20 samples): p50=%s p95=%s max=%s", durationPercentile(rtts, 0.50), durationPercentile(rtts, 0.95), rtts[len(rtts)-1])

	const expectedExits = 24
	startedAt := time.Now()
	probeCtx, probeCancel := context.WithTimeout(ctx, 30*time.Second)
	defer probeCancel()
	probe, err := client.ExecSandbox(probeCtx, &compatv1.ExecSandboxRequest{
		Sandbox:          sandbox,
		Command:          []string{"sh", "-c", `test -p /tmp/cautem-process-event-trigger && printf 'start' > /tmp/cautem-process-event-trigger && sleep .1 && cat /tmp/cautem-process-event-child-pids`},
		ExecutionTimeout: durationpb.New(20 * time.Second), NoLoginShell: true,
	})
	if err != nil {
		t.Fatalf("trigger adopted-child process event probes: %v", err)
	}
	var probeExit *compatv1.ExecSandboxExit
	var probeOutput strings.Builder
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
		if stdout := event.GetStdout(); stdout != nil {
			_, _ = probeOutput.Write(stdout.GetData())
		}
	}
	if probeExit == nil || probeExit.GetExitCode() != 0 {
		t.Fatalf("process event probe trigger exit=%v; want exit 0", probeExit)
	}
	childPIDs := make(map[string]struct{}, expectedExits)
	for _, rawPID := range strings.Fields(probeOutput.String()) {
		if _, err := strconv.Atoi(rawPID); err != nil {
			t.Fatalf("process event probe returned invalid child PID %q; output=%q", rawPID, probeOutput.String())
		}
		childPIDs[rawPID] = struct{}{}
	}
	if len(childPIDs) != expectedExits {
		t.Fatalf("process event probe returned %d child PIDs; want %d; output=%q", len(childPIDs), expectedExits, probeOutput.String())
	}
	marker := startedAt.UnixMilli()
	latencies := make(map[string]time.Duration, expectedExits)
	deadline := time.Now().Add(20 * time.Second)
	for len(latencies) < expectedExits && time.Now().Before(deadline) {
		response, err := client.GetSandboxLogs(probeCtx, &compatv1.GetSandboxLogsRequest{
			Sandbox: sandbox, SinceTime: timestamppb.New(time.UnixMilli(marker)), Lines: 1000, Sources: []string{"sandbox"},
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
			if _, expected := childPIDs[pid]; !expected || line.GetEventTime().AsTime().UnixMilli() < marker {
				continue
			}
			if _, seen := latencies[pid]; !seen {
				latencies[pid] = observedAt.Sub(time.UnixMilli(line.GetEventTime().AsTime().UnixMilli()))
			}
		}
		if len(latencies) < expectedExits {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if len(latencies) < expectedExits {
		var childDiagnostics string
		if os.Getenv("CAUTEM_E2E_ROOTLESS_PODMAN") == "1" {
			childDiagnostics, err = sandboxProcessDiagnostic(ctx, client, sandbox)
			if err != nil {
				t.Logf("rootless process-tree diagnostic failed: %v", err)
			}
		}
		all, readErr := client.GetSandboxLogs(ctx, &compatv1.GetSandboxLogsRequest{Sandbox: sandbox, Lines: 1000, Sources: []string{"sandbox"}})
		if readErr != nil {
			t.Fatalf("gateway received %d/%d adopted-child EXIT events; diagnostic log query: %v", len(latencies), expectedExits, readErr)
		}
		var events []string
		for _, line := range all.GetLogs() {
			fields := line.GetFields()
			if _, expected := childPIDs[fields["pid"]]; expected && fields["activity"] != "" {
				events = append(events, fields["activity"]+":"+fields["executable"]+":"+fields["pid"])
			}
		}
		engineLogs, engineLogsErr := runtime.EngineLogs(ctx, sandbox)
		t.Fatalf("gateway received %d/%d adopted-child EXIT events; process logs=%v; rootless process diagnostic=%q; container logs=%q; container logs error=%v", len(latencies), expectedExits, events, childDiagnostics, engineLogs, engineLogsErr)
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

func sandboxProcessDiagnostic(ctx context.Context, client compatv1.OpenShellClient, sandbox string) (string, error) {
	stream, err := client.ExecSandbox(ctx, &compatv1.ExecSandboxRequest{
		Sandbox:      sandbox,
		Command:      []string{"sh", "-c", `printf 'pidns-self='; readlink /proc/self/ns/pid; printf ' pidns-pid1='; readlink /proc/1/ns/pid; printf '\npid1='; tr '\0' ' ' </proc/1/cmdline; printf '\nself-status='; grep -E '^(Pid|PPid|NSpid):' /proc/self/status | tr '\n' ';'; printf '\npid1-status='; grep -E '^(Pid|PPid|NSpid):' /proc/1/status | tr '\n' ';'; while IFS= read -r pid; do printf '\nchild-pid=%s ' "$pid"; if [ -e "/proc/$pid/stat" ]; then cat "/proc/$pid/stat"; else printf 'missing'; fi; done </tmp/cautem-process-event-child-pids`},
		NoLoginShell: true, ExecutionTimeout: durationpb.New(5 * time.Second),
	})
	if err != nil {
		return "", err
	}
	var output strings.Builder
	var exit *compatv1.ExecSandboxExit
	for {
		event, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return output.String(), recvErr
		}
		if stdout := event.GetStdout(); stdout != nil {
			_, _ = output.Write(stdout.GetData())
		}
		if stderr := event.GetStderr(); stderr != nil {
			_, _ = output.Write(stderr.GetData())
		}
		if event.GetExit() != nil {
			exit = event.GetExit()
		}
	}
	if exit == nil || exit.GetExitCode() != 0 {
		return output.String(), fmt.Errorf("diagnostic exec exit=%v", exit)
	}
	return output.String(), nil
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
