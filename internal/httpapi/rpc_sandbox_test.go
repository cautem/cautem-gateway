package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-core/policy"
	"github.com/cautem/quarshell-driver/driver"
	"github.com/cautem/quarshell-gateway/internal/sshrelay"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

type nativeCreateRPCtestBackend struct {
	id        driver.BackendID
	validated driver.BackendCreateRequest
	created   driver.BackendCreateRequest
	starts    int
}

func (backend *nativeCreateRPCtestBackend) ID() driver.BackendID { return backend.id }

func (backend *nativeCreateRPCtestBackend) Capabilities(context.Context) (driver.BackendInfo, error) {
	return driver.BackendInfo{
		ID: backend.id,
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityProxyReadiness: {},
		},
	}, nil
}

func (backend *nativeCreateRPCtestBackend) ValidateCreate(_ context.Context, request driver.BackendCreateRequest) error {
	backend.validated = request
	return nil
}

func (backend *nativeCreateRPCtestBackend) Create(_ context.Context, request driver.BackendCreateRequest) (driver.Handle, error) {
	backend.created = request
	return driver.Handle{ID: core.ID(request.Name), Name: request.Name, Image: request.Workload.Image}, nil
}

func (backend *nativeCreateRPCtestBackend) Start(context.Context, core.ID) error {
	backend.starts++
	return nil
}

func (*nativeCreateRPCtestBackend) Stop(context.Context, core.ID) error         { return nil }
func (*nativeCreateRPCtestBackend) Delete(context.Context, core.ID) error       { return nil }
func (*nativeCreateRPCtestBackend) List(context.Context) ([]driver.Info, error) { return nil, nil }
func (*nativeCreateRPCtestBackend) Inspect(context.Context, string) (driver.Info, error) {
	return driver.Info{}, nil
}
func (*nativeCreateRPCtestBackend) WaitProxyReady(context.Context, string) error { return nil }

func TestCreateSandboxUsesNativeBackendDomainRequest(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)

	kind := fmt.Sprintf("native-create-test-%d", time.Now().UnixNano())
	backend := &nativeCreateRPCtestBackend{id: driver.CanonicalBackendID(kind)}
	if err := driver.RegisterBackendWithConfig(kind, func(map[string]any) (driver.Backend, error) {
		return backend, nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir(), "gw-native-create")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	registry := newComputeRegistry(Options{
		DataDir:              dataDir,
		ComputeDriverNames:   []string{kind},
		ComputeDriverConfigs: DriverConfigs{kind: {}},
	}, st.Snapshot().GatewayID)
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		st: st, opt: Options{DataDir: dataDir, Listen: "127.0.0.1:7443"}, compute: registry,
		waitSupervisorReady: func(context.Context, string) error { return nil },
	}}
	driverConfig, err := structpb.NewStruct(map[string]any{kind: map[string]any{"region": "test-region"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &compatv1.CreateSandboxRequest{
		Name: "native-demo", WorkspaceScope: workspaceScope("default"),
		Spec: &compatv1.SandboxSpec{
			Template: &compatv1.SandboxTemplate{Image: "alpine:3.22", DriverConfig: driverConfig},
			Command:  []string{"/bin/sh", "-lc", "true"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := backend.created
	if backend.starts != 1 || backend.validated.Name != "native-demo" || request.Name != "native-demo" || request.SandboxID != "native-demo" {
		t.Fatalf("native lifecycle starts=%d validated=%+v created=%+v", backend.starts, backend.validated, request)
	}
	if request.Workspace.ID != "default" || request.Workspace.HostPath != filepath.Join(dataDir, "workspaces", "default") || !request.Workspace.Persist {
		t.Fatalf("native workspace target = %+v", request.Workspace)
	}
	if request.Workload.Image != "alpine:3.22" || strings.Join(request.Workload.Command, " ") != "/bin/sh -lc true" {
		t.Fatalf("native workload = %+v", request.Workload)
	}
	config, ok := request.Config.(map[string]any)
	if !ok || config["region"] != "test-region" {
		t.Fatalf("native backend config = %#v", request.Config)
	}
	if request.Labels[driver.WorkspaceLabel] != "default" || request.Labels[driver.GatewayIDLabel] != st.Snapshot().GatewayID {
		t.Fatalf("native tenancy labels = %v", request.Labels)
	}
	if request.Network.Proxy == nil || request.Network.Proxy.PolicyPath == "" || !slices.ContainsFunc(request.Network.Proxy.Environment, func(value string) bool {
		return strings.HasPrefix(value, "CAUTEM_SANDBOX_TOKEN=")
	}) {
		t.Fatalf("native proxy and short-lived control bindings = %+v", request.Network.Proxy)
	}
}

func TestBuildGatewayBackendCreateRequestRestoresControlRuntimeOptions(t *testing.T) {
	count := uint32(2)
	req := &compatv1.CreateSandboxRequest{
		Annotations: map[string]string{
			annotationQuarshellPidsLimit:  "512",
			annotationQuarshellCDIDevices: `["nvidia.com/gpu=0","nvidia.com/gpu=1"]`,
		},
		Spec: &compatv1.SandboxSpec{
			Template:             &compatv1.SandboxTemplate{Image: "alpine:3.22"},
			ResourceRequirements: &compatv1.ResourceRequirements{Gpu: &compatv1.GpuResourceRequirements{Count: &count}},
		},
	}
	request, err := buildGatewayBackendCreateRequest(req, sandboxRuntimeInputs{}, "agent", "alpine:3.22", "", "/workspaces/team", "docker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if request.Resources.PIDs != 512 || request.Resources.GPUCount != 2 || !request.Resources.GPU || strings.Join(request.Resources.CDIDevices, ",") != "nvidia.com/gpu=0,nvidia.com/gpu=1" {
		t.Fatalf("restored runtime request=%+v", request.Resources)
	}
	if request.Config != nil {
		t.Fatalf("nil selected driver config became a typed nil: %#v", request.Config)
	}
}

func TestBuildGatewayBackendCreateRequestRejectsMalformedControlRuntimeOptions(t *testing.T) {
	for _, annotations := range []map[string]string{
		{annotationQuarshellPidsLimit: "-2"},
		{annotationQuarshellCDIDevices: `["","nvidia.com/gpu=0"]`},
		{annotationQuarshellCDIDevices: `["nvidia.com/gpu=0","nvidia.com/gpu=0"]`},
		{annotationQuarshellCDIDevices: `{}`},
		{annotationQuarshellCDIDevices: `null`},
		{annotationQuarshellCDIDevices: `[]`},
	} {
		_, err := buildGatewayBackendCreateRequest(&compatv1.CreateSandboxRequest{Annotations: annotations, Spec: &compatv1.SandboxSpec{Template: &compatv1.SandboxTemplate{Image: "alpine:3.22"}}}, sandboxRuntimeInputs{}, "agent", "alpine:3.22", "", "/workspaces/team", "docker", nil)
		if err == nil {
			t.Errorf("accepted invalid runtime annotations %v", annotations)
		}
	}
}

func TestBuildGatewayBackendCreateRequestUsesDomainFields(t *testing.T) {
	req := &compatv1.CreateSandboxRequest{
		Annotations: map[string]string{annotationQuarshellPidsLimit: "512"},
		Spec: &compatv1.SandboxSpec{
			Template: &compatv1.SandboxTemplate{Image: "alpine:3.22"},
			Command:  []string{"/bin/sh", "-lc", "true"},
		},
	}
	config := map[string]any{"mode": "isolated"}
	request, err := buildGatewayBackendCreateRequest(req, sandboxRuntimeInputs{gatewayID: "gateway-1"}, "agent", "alpine:3.22", "team-a", "/workspaces/team-a", "custom-vm", config)
	if err != nil {
		t.Fatal(err)
	}
	if request.Name != "agent" || request.SandboxID != "agent" || request.Workspace.ID != "team-a" || request.Workspace.HostPath != "/workspaces/team-a" {
		t.Fatalf("domain identity/workspace = %+v", request)
	}
	if request.Workload.Image != "alpine:3.22" || strings.Join(request.Workload.Command, " ") != "/bin/sh -lc true" || request.Resources.PIDs != 512 {
		t.Fatalf("domain workload/resources = %+v %+v", request.Workload, request.Resources)
	}
	if got, ok := request.Config.(map[string]any); !ok || got["mode"] != "isolated" {
		t.Fatalf("domain config = %#v", request.Config)
	}
}

type rpcTestEngine struct {
	created            driver.Spec
	deleted            bool
	started            int
	stopped            int
	createErr          error
	startErr           error
	stopErr            error
	deleteErr          error
	list               []driver.Info
	listErr            error
	mainLogsOpened     int
	mainWaitCode       int
	mainWaitCalls      atomic.Int32
	mainWaitFirstBlock chan struct{}
}

func (e *rpcTestEngine) OpenMainProcessLogs(context.Context, core.ID) (io.ReadCloser, error) {
	e.mainLogsOpened++
	return io.NopCloser(strings.NewReader("canonical-output\n")), nil
}

func (e *rpcTestEngine) WaitMainProcess(ctx context.Context, _ core.ID) (int, error) {
	if e.mainWaitCalls.Add(1) == 1 && e.mainWaitFirstBlock != nil {
		select {
		case <-e.mainWaitFirstBlock:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return e.mainWaitCode, nil
}

type tokenAwareRPCtestEngine struct {
	*rpcTestEngine
	token       string
	tokenStarts int
}

func (*tokenAwareRPCtestEngine) BackendCapabilityInfo() driver.BackendInfo {
	return driver.BackendInfo{
		ID: "kubernetes",
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityTokenAwareStart: {},
		},
	}
}

type gatewayRuntimeUnsupportedTestEngine struct {
	*rpcTestEngine
	validationErr error
}

func (*gatewayRuntimeUnsupportedTestEngine) BackendCapabilityInfo() driver.BackendInfo {
	return driver.BackendInfo{
		ID: "vm",
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityGatewayRuntimeValidation: {},
		},
	}
}

type launchSpecRestoringRPCtestEngine struct {
	*rpcTestEngine
	restoredSpec driver.Spec
	restoreCalls int
}

func (*launchSpecRestoringRPCtestEngine) BackendCapabilityInfo() driver.BackendInfo {
	return driver.BackendInfo{
		ID: "vm",
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityLaunchSpecRestore: {},
		},
	}
}

func (e *gatewayRuntimeUnsupportedTestEngine) ValidateGatewayRuntime() error {
	return e.validationErr
}

func (e *tokenAwareRPCtestEngine) StartWithToken(ctx context.Context, id core.ID, token string) error {
	e.token = token
	e.tokenStarts++
	return e.rpcTestEngine.Start(ctx, id)
}

func (e *launchSpecRestoringRPCtestEngine) RestoreLaunchSpec(_ context.Context, _ core.ID, spec driver.Spec) error {
	e.restoreCalls++
	e.restoredSpec = spec
	return nil
}

func (e *rpcTestEngine) Create(_ context.Context, s driver.Spec) (driver.Handle, error) {
	e.created = s
	if e.createErr != nil {
		return driver.Handle{}, e.createErr
	}
	return driver.Handle{ID: core.ID("runtime-1"), Name: s.Name, Image: s.Image}, nil
}
func (e *rpcTestEngine) Start(context.Context, core.ID) error {
	e.started++
	return e.startErr
}
func (e *rpcTestEngine) Stop(context.Context, core.ID) error { e.stopped++; return e.stopErr }
func (*rpcTestEngine) Exec(context.Context, core.ID, driver.ExecRequest) (driver.ExecResult, error) {
	return driver.ExecResult{}, nil
}
func (e *rpcTestEngine) Delete(context.Context, core.ID) error       { e.deleted = true; return e.deleteErr }
func (e *rpcTestEngine) List(context.Context) ([]driver.Info, error) { return e.list, e.listErr }
func (*rpcTestEngine) Inspect(context.Context, string) (driver.Info, error) {
	return driver.Info{Status: "running"}, nil
}
func (*rpcTestEngine) Logs(context.Context, core.ID, bool, io.Writer) error        { return nil }
func (*rpcTestEngine) CopyTo(context.Context, core.ID, string, string) error       { return nil }
func (*rpcTestEngine) CopyFrom(context.Context, core.ID, string, string) error     { return nil }
func (*rpcTestEngine) EnsureSSHDaemon(context.Context, core.ID) error              { return nil }
func (*rpcTestEngine) Health(context.Context) driver.Probe                         { return driver.Probe{OK: true} }
func (*rpcTestEngine) ImagePresent(context.Context, string) bool                   { return true }
func (*rpcTestEngine) RunProbe(context.Context, string) (string, error)            { return "", nil }
func (*rpcTestEngine) PolicyHostPath(context.Context, string) (string, error)      { return "", nil }
func (*rpcTestEngine) ContainerIP(context.Context, string, string) (string, error) { return "", nil }

func TestCreateSandboxRPCCreatesAndPersistsRuntime(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	st, err := store.Open(t.TempDir(), "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	readinessChecks := 0
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		st: st, opt: Options{DataDir: t.TempDir(), Listen: "127.0.0.1:7443"}, compute: registry,
		waitSupervisorReady: func(_ context.Context, sandbox string) error {
			readinessChecks++
			if sandbox != "demo" {
				t.Errorf("readiness checked for sandbox %q", sandbox)
			}
			return nil
		},
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	resp, err := rpc.CreateSandbox(ctx, &compatv1.CreateSandboxRequest{Name: "demo", WorkspaceScope: workspaceScope("default"), Labels: map[string]string{"team": "test", driver.WorkspaceLabel: "attacker-workspace", driver.GatewayIDLabel: "attacker-gateway"}, Spec: &compatv1.SandboxSpec{Policy: &sandboxv1.SandboxPolicy{Version: 1}, Template: &compatv1.SandboxTemplate{Image: "alpine:3.22", Environment: map[string]string{"FROM_TEMPLATE": "yes"}}, Environment: map[string]string{"FROM_SPEC": "yes"}, Command: []string{"sleep", "infinity"}}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSandbox().GetStatus().GetPhase() != compatv1.SandboxPhase_SANDBOX_PHASE_PROVISIONING {
		t.Fatalf("phase=%v", resp.GetSandbox().GetStatus().GetPhase())
	}
	envValues := map[string]string{}
	for _, entry := range engine.created.Env {
		k, v, ok := strings.Cut(entry, "=")
		if ok {
			envValues[k] = v
		}
	}
	if engine.created.Workspace == "" || engine.created.GatewayID != st.Snapshot().GatewayID || envValues["FROM_SPEC"] != "yes" || envValues["FROM_TEMPLATE"] != "yes" || engine.created.ProxyBin == "" || engine.created.InitBin == "" || engine.created.SSHBin == "" || !engine.created.EnableSSH || engine.created.SupervisorBin != filepath.Join(helperDir, "cautem-supervisor") {
		t.Fatalf("driver spec=%+v", engine.created)
	}
	if engine.created.Labels[driver.WorkspaceLabel] != "default" || engine.created.Labels[driver.GatewayIDLabel] != st.Snapshot().GatewayID || engine.created.Labels["team"] != "test" {
		t.Fatalf("compute labels=%v; Gateway tenancy labels must override untrusted input", engine.created.Labels)
	}
	proxyEnv := map[string]string{}
	for _, entry := range engine.created.ProxyEnv {
		k, v, ok := strings.Cut(entry, "=")
		if ok {
			proxyEnv[k] = v
		}
	}
	if proxyEnv["CAUTEM_GATEWAY_URL"] != "http://gateway:7443" || proxyEnv["CAUTEM_SANDBOX"] != "demo" || proxyEnv["CAUTEM_SANDBOX_TOKEN"] == "" {
		t.Fatalf("supervisor env=%v", proxyEnv)
	}
	rec, ok := st.GetSandbox("demo")
	if !ok || rec.RuntimeID != "runtime-1" || rec.ComputeDriver != "docker" || rec.Status != "running" {
		t.Fatalf("record=%+v ok=%v", rec, ok)
	}
	if _, err := rpc.StopSandbox(ctx, &compatv1.StopSandboxRequest{Name: "demo", WorkspaceScope: workspaceScope("default")}); err != nil {
		t.Fatal(err)
	}
	if _, err := rpc.StartSandbox(ctx, &compatv1.StartSandboxRequest{Name: "demo", WorkspaceScope: workspaceScope("default")}); err != nil {
		t.Fatal(err)
	}
	deleted, err := rpc.DeleteSandbox(ctx, &compatv1.DeleteSandboxRequest{Name: "demo", WorkspaceScope: workspaceScope("default")})
	if err != nil || deleted.GetOutcome() != compatv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED {
		t.Fatalf("deleted=%v err=%v", deleted, err)
	}
	if _, ok := st.GetSandbox("demo"); ok || engine.started != 2 || engine.stopped != 2 || !engine.deleted {
		t.Fatalf("registry/runtime lifecycle: exists=%v starts=%d stops=%d deleted=%v", ok, engine.started, engine.stopped, engine.deleted)
	}
	if readinessChecks != 2 {
		t.Fatalf("supervisor readiness checks = %d, want create and restart checks", readinessChecks)
	}
}

func TestStartSandboxRestoresProcessLocalLaunchSpecFromDurableRecord(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	st, err := store.Open(t.TempDir(), "gw-launch-restore")
	if err != nil {
		t.Fatal(err)
	}
	spec := &compatv1.SandboxSpec{
		Template: &compatv1.SandboxTemplate{Image: "alpine:3.22"},
		Command:  []string{"/bin/sh", "-c", "sleep infinity"},
	}
	specJSON, err := protojson.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{
		Name: "restore", ID: "stable-id", RuntimeID: "vm-runtime-1", ComputeDriver: "vm",
		Image: "alpine:3.22", Workspace: "default", Status: "stopped", SpecJSON: string(specJSON),
	}); err != nil {
		t.Fatal(err)
	}
	engine := &launchSpecRestoringRPCtestEngine{rpcTestEngine: &rpcTestEngine{}}
	registry := newComputeRegistry(Options{
		ComputeDriverNames:   []string{"vm"},
		ComputeDriverConfigs: map[string]map[string]any{"vm": {"grpc_endpoint": "http://gateway:7443"}},
	})
	registry.engines["vm"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		st: st, opt: Options{DataDir: t.TempDir(), Listen: "127.0.0.1:7443"}, compute: registry,
		waitSupervisorReady: func(context.Context, string) error { return nil },
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	if _, err := rpc.StartSandbox(ctx, &compatv1.StartSandboxRequest{Name: "restore", WorkspaceScope: workspaceScope("default")}); err != nil {
		t.Fatalf("StartSandbox() error = %v", err)
	}
	if engine.restoreCalls != 1 || strings.Join(engine.restoredSpec.Command, " ") != "/bin/sh -c sleep infinity" {
		t.Fatalf("restored launch spec calls=%d spec=%+v", engine.restoreCalls, engine.restoredSpec)
	}
	if engine.started != 1 {
		t.Fatalf("runtime starts=%d; want 1 after restoring launch spec", engine.started)
	}
}

func TestStartSandboxHydratesProcessLocalLaunchSpecForRunningVM(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	st, err := store.Open(t.TempDir(), "gw-launch-restore-running")
	if err != nil {
		t.Fatal(err)
	}
	spec := &compatv1.SandboxSpec{
		Template: &compatv1.SandboxTemplate{Image: "alpine:3.22"},
		Command:  []string{"/bin/sh", "-c", "sleep infinity"},
	}
	specJSON, err := protojson.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{
		Name: "running-vm", ID: "stable-id", RuntimeID: "vm-runtime-1", ComputeDriver: "vm",
		Image: "alpine:3.22", Workspace: "default", Status: "running", SpecJSON: string(specJSON),
	}); err != nil {
		t.Fatal(err)
	}
	engine := &launchSpecRestoringRPCtestEngine{rpcTestEngine: &rpcTestEngine{}}
	registry := newComputeRegistry(Options{
		ComputeDriverNames:   []string{"vm"},
		ComputeDriverConfigs: map[string]map[string]any{"vm": {"grpc_endpoint": "http://gateway:7443"}},
	})
	registry.engines["vm"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		st: st, opt: Options{DataDir: t.TempDir(), Listen: "127.0.0.1:7443"}, compute: registry,
		waitSupervisorReady: func(context.Context, string) error { return nil },
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	if _, err := rpc.StartSandbox(ctx, &compatv1.StartSandboxRequest{Name: "running-vm", WorkspaceScope: workspaceScope("default")}); err != nil {
		t.Fatalf("StartSandbox() on running VM error = %v", err)
	}
	if engine.restoreCalls != 1 || engine.started != 1 || strings.Join(engine.restoredSpec.Command, " ") != "/bin/sh -c sleep infinity" {
		t.Fatalf("running VM hydration calls=%d starts=%d spec=%+v", engine.restoreCalls, engine.started, engine.restoredSpec)
	}
}

func TestCreateSandboxRejectsUnsupportedGatewayRuntimeBeforeConsumingRootfsUpload(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	stagingPath := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(stagingPath, []byte("rootfs"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := &gatewayRuntimeUnsupportedTestEngine{
		rpcTestEngine: &rpcTestEngine{},
		validationErr: errors.New("VM workspace and supervisor integrations are unavailable"),
	}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"vm"}})
	registry.engines["vm"] = engine
	runtime := &grpcRuntime{
		st: st, opt: Options{DataDir: t.TempDir()}, compute: registry,
		rootfsStaging: map[string]rootfsTarStagingSlot{
			"single-use-token": {workspace: "default", driverName: "vm", path: stagingPath, maxBytes: 1024, expiresAt: time.Now().Add(time.Minute)},
		},
	}
	rpc := &compatRPCAdapter{runtime: runtime}
	driverConfig, err := structpb.NewStruct(map[string]any{"vm": map[string]any{"rootfs_tar_staging_token": "single-use-token"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &compatv1.CreateSandboxRequest{
		Name: "vm-sandbox", WorkspaceScope: workspaceScope("default"),
		Spec: &compatv1.SandboxSpec{Template: &compatv1.SandboxTemplate{Image: "fixture:latest", DriverConfig: driverConfig}},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot satisfy Gateway runtime requirements") {
		t.Fatalf("CreateSandbox() error = %v, want Gateway capability preflight failure", err)
	}
	if len(runtime.rootfsStaging) != 1 {
		t.Fatalf("rootfs staging slots = %d, want token preserved after preflight rejection", len(runtime.rootfsStaging))
	}
	if _, err := os.Stat(stagingPath); err != nil {
		t.Fatalf("rootfs upload was removed before backend preflight: %v", err)
	}
	if _, ok := st.GetSandbox("vm-sandbox"); ok {
		t.Fatal("Gateway persisted sandbox state before backend capability preflight")
	}
}

func TestStopSandboxRollsBackLifecycleStateWhenBackendStopFails(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-stop-rollback")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "stable-id", RuntimeID: "runtime-1", ComputeDriver: "docker", Workspace: "default", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{stopErr: errors.New("backend stop failed")}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	if _, err := rpc.StopSandbox(ctx, &compatv1.StopSandboxRequest{Name: "demo", WorkspaceScope: workspaceScope("default")}); err == nil {
		t.Fatal("backend stop failure unexpectedly succeeded")
	}
	record, ok := st.GetSandbox("demo")
	if !ok || record.Status != "running" {
		t.Fatalf("stop failure did not restore running state: %+v ok=%v", record, ok)
	}
}

func TestTokenAwareSandboxRestartRotatesAndStopRevokesBearer(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-token-aware-lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "stable-id", RuntimeID: "runtime-1", ComputeDriver: "kubernetes", Workspace: "default", Status: "stopped"}); err != nil {
		t.Fatal(err)
	}
	previous, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	engine := &tokenAwareRPCtestEngine{rpcTestEngine: &rpcTestEngine{}}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"kubernetes"}})
	registry.engines["kubernetes"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		st: st, compute: registry, waitSupervisorReady: func(context.Context, string) error { return nil },
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	if _, err := rpc.StartSandbox(ctx, &compatv1.StartSandboxRequest{Name: "demo", WorkspaceScope: workspaceScope("default")}); err != nil {
		t.Fatalf("StartSandbox() error = %v", err)
	}
	if engine.tokenStarts != 1 || engine.token == "" || engine.token == previous {
		t.Fatalf("token-aware starts/token = %d/%q; want fresh bearer", engine.tokenStarts, engine.token)
	}
	if _, ok := st.SandboxForToken(previous); ok {
		t.Fatal("previous bearer remained valid after restart rotation")
	}
	if name, ok := st.SandboxForToken(engine.token); !ok || name != "demo" {
		t.Fatal("replacement bearer was not activated")
	}
	if _, err := rpc.StopSandbox(ctx, &compatv1.StopSandboxRequest{Name: "demo", WorkspaceScope: workspaceScope("default")}); err != nil {
		t.Fatalf("StopSandbox() error = %v", err)
	}
	if _, ok := st.SandboxForToken(engine.token); ok {
		t.Fatal("supervisor bearer remained valid after token-aware runtime stop")
	}
	if _, ok := st.SandboxForRefreshToken(engine.token); ok {
		t.Fatal("stopped supervisor bearer remained refreshable")
	}
}

func TestStartSandboxRecreatesMissingRuntimeFromDurableSpec(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	st, err := store.Open(t.TempDir(), "gw-recovery")
	if err != nil {
		t.Fatal(err)
	}
	gpuCount := uint32(2)
	spec := &compatv1.SandboxSpec{
		Template: &compatv1.SandboxTemplate{Image: "alpine:3.22"}, Command: []string{"sleep", "infinity"},
		ResourceRequirements: &compatv1.ResourceRequirements{Gpu: &compatv1.GpuResourceRequirements{Count: &gpuCount}},
	}
	specJSON, err := protojson.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "recover", ID: "stable-id", ComputeDriver: "docker", Image: "alpine:3.22", Workspace: "default", Status: "error", SpecJSON: string(specJSON), Labels: map[string]string{"managed": "true"}, Annotations: map[string]string{annotationQuarshellPidsLimit: "512", annotationQuarshellCDIDevices: `["nvidia.com/gpu=0","nvidia.com/gpu=1"]`}}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		st: st, opt: Options{DataDir: t.TempDir(), Listen: "127.0.0.1:7443"}, compute: registry,
		waitSupervisorReady: func(context.Context, string) error { return nil },
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	response, err := rpc.StartSandbox(ctx, &compatv1.StartSandboxRequest{Name: "recover", WorkspaceScope: workspaceScope("default")})
	if err != nil {
		t.Fatalf("recovery start: %v", err)
	}
	if response.GetSandbox().GetStatus().GetPhase() != compatv1.SandboxPhase_SANDBOX_PHASE_READY {
		t.Fatalf("recovery phase=%v", response.GetSandbox().GetStatus().GetPhase())
	}
	recovered, ok := st.GetSandbox("recover")
	if !ok || recovered.ID != "stable-id" || recovered.RuntimeID != "runtime-1" || recovered.Status != "running" {
		t.Fatalf("recovered record=%+v ok=%v", recovered, ok)
	}
	if engine.started != 1 || engine.deleted || engine.stopped != 0 {
		t.Fatalf("recovery engine lifecycle started=%d stopped=%d deleted=%v", engine.started, engine.stopped, engine.deleted)
	}
	if engine.created.Labels[driver.WorkspaceLabel] != "default" || engine.created.Labels[driver.GatewayIDLabel] != st.Snapshot().GatewayID || engine.created.GatewayID != st.Snapshot().GatewayID {
		t.Fatalf("recovered compute tenancy gateway=%q labels=%v; want registry gateway ID and trusted workspace label", engine.created.GatewayID, engine.created.Labels)
	}
	if engine.created.PidsLimit != 512 || engine.created.GPUCount != 2 || strings.Join(engine.created.CDIDevices, ",") != "nvidia.com/gpu=0,nvidia.com/gpu=1" {
		t.Fatalf("recovery lost durable PID/CDI settings: %+v", engine.created)
	}
	if _, err := rpc.StartSandbox(ctx, &compatv1.StartSandboxRequest{Name: "recover", WorkspaceScope: workspaceScope("default")}); err != nil {
		t.Fatalf("normal restart after recovery: %v", err)
	}
	if engine.started != 2 {
		t.Fatalf("normal restart started=%d; want 2", engine.started)
	}
}

func TestStartSandboxRecoveryRollsBackPartialRuntime(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	st, err := store.Open(t.TempDir(), "gw-recovery-rollback")
	if err != nil {
		t.Fatal(err)
	}
	specJSON, err := protojson.Marshal(&compatv1.SandboxSpec{Template: &compatv1.SandboxTemplate{Image: "alpine:3.22"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "recover-fail", ID: "stable-id", ComputeDriver: "docker", Image: "alpine:3.22", Workspace: "default", Status: "error", SpecJSON: string(specJSON)}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{startErr: errors.New("backend start failed")}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, opt: Options{DataDir: t.TempDir(), Listen: "127.0.0.1:7443"}, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	if _, err := rpc.StartSandbox(ctx, &compatv1.StartSandboxRequest{Name: "recover-fail", WorkspaceScope: workspaceScope("default")}); err == nil {
		t.Fatal("failed backend recovery unexpectedly succeeded")
	}
	record, ok := st.GetSandbox("recover-fail")
	if !ok || record.RuntimeID != "" || record.Status != "error" || engine.stopped != 1 || !engine.deleted {
		t.Fatalf("rollback record=%+v ok=%v started=%d stopped=%d deleted=%v", record, ok, engine.started, engine.stopped, engine.deleted)
	}
}

func TestStartSandboxRecoveryRetainsRuntimeIdentityWhenRollbackDeleteFails(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	st, err := store.Open(t.TempDir(), "gw-recovery-cleanup-failure")
	if err != nil {
		t.Fatal(err)
	}
	specJSON, err := protojson.Marshal(&compatv1.SandboxSpec{Template: &compatv1.SandboxTemplate{Image: "alpine:3.22"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "recover-cleanup-fail", ID: "stable-id", ComputeDriver: "docker", Image: "alpine:3.22", Workspace: "default", Status: "error", SpecJSON: string(specJSON)}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{startErr: errors.New("backend start failed"), deleteErr: errors.New("backend delete failed")}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, opt: Options{DataDir: t.TempDir(), Listen: "127.0.0.1:7443"}, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.StartSandbox(ctx, &compatv1.StartSandboxRequest{Name: "recover-cleanup-fail", WorkspaceScope: workspaceScope("default")})
	if err == nil || !strings.Contains(err.Error(), "backend start failed") || !strings.Contains(err.Error(), "rollback cleanup failed") {
		t.Fatalf("StartSandbox error = %v, want start and cleanup failures", err)
	}
	record, ok := st.GetSandbox("recover-cleanup-fail")
	if !ok || record.RuntimeID != "runtime-1" || record.Status != "error" {
		t.Fatalf("failed recovery rollback lost runtime identity: record=%+v exists=%t", record, ok)
	}
	if engine.stopped != 1 || !engine.deleted {
		t.Fatalf("recovery cleanup: stopped=%d deleted=%v", engine.stopped, engine.deleted)
	}
}

func TestCreateSandboxRPCUsesRuntimeDefaultWithoutPersistingPolicy(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	dataDir := t.TempDir()
	st, err := store.Open(t.TempDir(), "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, opt: Options{DataDir: dataDir, Listen: "127.0.0.1:7443"}, compute: registry, waitSupervisorReady: func(context.Context, string) error { return nil }}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &compatv1.CreateSandboxRequest{
		Name: "default-policy", WorkspaceScope: workspaceScope("default"),
		Spec: &compatv1.SandboxSpec{Template: &compatv1.SandboxTemplate{Image: "alpine:3.22"}, Command: []string{"sleep", "infinity"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	record, ok := st.GetSandbox("default-policy")
	if !ok || record.BasePolicyYAML != "" || record.PolicyRev != 0 {
		t.Fatalf("runtime default was persisted as sandbox policy: %+v", record)
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "sandboxes", "default-policy", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	runtimePolicy, err := policy.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if runtimePolicy.Version != 1 || runtimePolicy.Landlock == nil || runtimePolicy.Landlock.Compatibility != "best_effort" || !containsString(runtimePolicy.FilesystemPolicy.ReadOnly, "/usr") || !containsString(runtimePolicy.FilesystemPolicy.ReadWrite, "/tmp") {
		t.Fatalf("runtime restrictive default = %+v", runtimePolicy)
	}
	config, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{Name: "default-policy"})
	if err != nil {
		t.Fatal(err)
	}
	if config.GetPolicy() != nil || config.GetPolicySource() != sandboxv1.PolicySource_POLICY_SOURCE_SANDBOX {
		t.Fatalf("runtime-only default leaked into config API: policy=%v source=%v", config.GetPolicy(), config.GetPolicySource())
	}
}

func TestPrepareSandboxRuntimeComposesAttachedProvidersWithRuntimeDefault(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	t.Setenv("API_TOKEN", "host-secret")
	st, err := store.Open(t.TempDir(), "gw-provider-default-policy")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProfile("test-provider", `id: test-provider
endpoints:
  - host: api.example.com
    port: 443
credentials:
  - name: api_token
    env_vars: [API_TOKEN]
`); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{
		Name: "provider", Type: "test-provider", Workspace: "default", EnvVars: []string{"API_TOKEN"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{
		Name: "sandbox", ID: "sandbox", Workspace: "default", AttachedProviders: []string{"provider"},
	}); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		st: st,
		opt: Options{
			DataDir: dataDir, Listen: "127.0.0.1:7443", ProviderProfileSources: []string{"user"},
		},
		compute: &computeRegistry{configured: DriverConfigs{"docker": {}}},
	}}
	request := &compatv1.CreateSandboxRequest{Spec: &compatv1.SandboxSpec{
		Template:  &compatv1.SandboxTemplate{Image: "alpine:3.22"},
		Providers: []string{"provider"},
	}}
	inputs, err := rpc.prepareSandboxRuntime(request, "docker", "sandbox", "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs.baseYAML) != 0 || len(inputs.attached) != 1 || inputs.attached[0] != "provider" {
		t.Fatalf("base policy or provider attachments changed: base=%q attached=%v", inputs.baseYAML, inputs.attached)
	}
	if !strings.Contains(string(inputs.effectiveYAML), "api.example.com") || !containsString(inputs.effectivePolicy.CredentialEnvKeys(), "API_TOKEN") {
		t.Fatalf("provider layer was not composed over restrictive runtime defaults: %s", inputs.effectiveYAML)
	}
	if !containsString(inputs.env, "API_TOKEN=cautem:resolve:env:API_TOKEN") {
		t.Fatalf("provider placeholder missing from guest environment: %v", inputs.env)
	}
}

func TestPrepareSandboxRuntimeUsesGlobalPolicyAsCompleteOverride(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	dataDir := t.TempDir()
	st, err := store.Open(t.TempDir(), "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetGlobalPolicy("version: 1\nfilesystem_policy:\n  include_workdir: true\n  read_write:\n    - /global-only\n"); err != nil {
		t.Fatal(err)
	}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, opt: Options{DataDir: dataDir, Listen: "127.0.0.1:7443"}, compute: registry}}
	inputs, err := rpc.prepareSandboxRuntime(&compatv1.CreateSandboxRequest{Spec: &compatv1.SandboxSpec{Policy: &sandboxv1.SandboxPolicy{Version: 1, Filesystem: &sandboxv1.FilesystemPolicy{IncludeWorkdir: true, ReadWrite: []string{"/sandbox-only"}}}}}, "docker", "global-override", "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs.attached) != 0 {
		t.Fatalf("unexpected provider layers: %v", inputs.attached)
	}
	if !strings.Contains(string(inputs.baseYAML), "/sandbox-only") || strings.Contains(string(inputs.baseYAML), "/global-only") {
		t.Fatalf("stored sandbox policy was replaced by global policy: %s", inputs.baseYAML)
	}
	runtimePolicy, err := policy.Parse(inputs.effectiveYAML)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(runtimePolicy.FilesystemPolicy.ReadWrite, "/global-only") || containsString(runtimePolicy.FilesystemPolicy.ReadWrite, "/sandbox-only") {
		t.Fatalf("global policy did not completely override sandbox policy: %+v", runtimePolicy.FilesystemPolicy)
	}
}

func TestCreateSandboxRejectsInvalidGlobalPolicyBeforeRuntimeSideEffects(t *testing.T) {
	dataDir := t.TempDir()
	st, err := store.Open(t.TempDir(), "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetGlobalPolicy("not: [valid"); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}})
	registry.engines["docker"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, opt: Options{DataDir: dataDir}, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &compatv1.CreateSandboxRequest{
		Name: "invalid-global", WorkspaceScope: workspaceScope("default"),
		Spec: &compatv1.SandboxSpec{Template: &compatv1.SandboxTemplate{Image: "alpine:3.22"}},
	})
	if err == nil || !strings.Contains(err.Error(), "global policy is invalid") {
		t.Fatalf("CreateSandbox error=%v, want invalid global policy", err)
	}
	if engine.created.Name != "" || engine.started != 0 {
		t.Fatalf("compute runtime was touched: %+v", engine)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "workspaces")); !os.IsNotExist(err) {
		t.Fatalf("workspace storage was created before policy validation: stat error=%v", err)
	}
	if _, ok := st.GetSandbox("invalid-global"); ok {
		t.Fatal("sandbox record was persisted despite invalid global policy")
	}
}

func TestCreateSandboxRPCRejectsWorkspacePathTraversal(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}})
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, opt: Options{DataDir: t.TempDir()}, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &compatv1.CreateSandboxRequest{WorkspaceScope: workspaceScope("../escape"), Spec: &compatv1.SandboxSpec{Policy: &sandboxv1.SandboxPolicy{Version: 1}, Template: &compatv1.SandboxTemplate{Image: "alpine"}}})
	if err == nil {
		t.Fatal("expected invalid workspace error")
	}
}

func TestCreateSandboxRPCCleansUpWhenSupervisorNeverConnects(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	dataDir := t.TempDir()
	st, err := store.Open(t.TempDir(), "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		st: st, opt: Options{DataDir: dataDir, Listen: "127.0.0.1:7443"}, compute: registry,
		waitSupervisorReady: func(context.Context, string) error { return sshrelay.ErrNotConnected },
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &compatv1.CreateSandboxRequest{
		Name: "relay-timeout", WorkspaceScope: workspaceScope("default"),
		Spec: &compatv1.SandboxSpec{
			Policy:   &sandboxv1.SandboxPolicy{Version: 1},
			Template: &compatv1.SandboxTemplate{Image: "alpine:3.22"},
			Command:  []string{"sleep", "infinity"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "supervisor relay did not become ready") {
		t.Fatalf("CreateSandbox error = %v, want supervisor readiness failure", err)
	}
	if !engine.deleted || engine.stopped != 1 {
		t.Fatalf("engine cleanup: stopped=%d deleted=%v", engine.stopped, engine.deleted)
	}
	if _, ok := st.GetSandbox("relay-timeout"); ok {
		t.Fatal("sandbox registry entry remained after readiness failure")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "sandboxes", "relay-timeout")); !os.IsNotExist(err) {
		t.Fatalf("runtime directory still exists: stat error = %v", err)
	}
}

func TestCreateSandboxRetainsRuntimeIdentityWhenRollbackDeleteFails(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	dataDir := t.TempDir()
	st, err := store.Open(t.TempDir(), "gw-test-rollback-failure")
	if err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{deleteErr: errors.New("engine delete failed")}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		st: st, opt: Options{DataDir: dataDir, Listen: "127.0.0.1:7443"}, compute: registry,
		waitSupervisorReady: func(context.Context, string) error { return sshrelay.ErrNotConnected },
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &compatv1.CreateSandboxRequest{
		Name: "relay-timeout", WorkspaceScope: workspaceScope("default"),
		Spec: &compatv1.SandboxSpec{
			Policy:   &sandboxv1.SandboxPolicy{Version: 1},
			Template: &compatv1.SandboxTemplate{Image: "alpine:3.22"},
			Command:  []string{"sleep", "infinity"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "rollback cleanup failed") || !strings.Contains(err.Error(), "engine delete failed") {
		t.Fatalf("CreateSandbox error = %v, want readiness and cleanup failure", err)
	}
	record, ok := st.GetSandbox("relay-timeout")
	if !ok || record.RuntimeID != "runtime-1" || record.Status != "error" {
		t.Fatalf("failed rollback lost runtime identity: record=%+v exists=%t", record, ok)
	}
	if engine.stopped != 1 || !engine.deleted {
		t.Fatalf("engine cleanup: stopped=%d deleted=%v", engine.stopped, engine.deleted)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "sandboxes", "relay-timeout")); err != nil {
		t.Fatalf("runtime recovery state was removed after failed backend cleanup: %v", err)
	}
}
