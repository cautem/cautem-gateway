package httpapi

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-core"
	"github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/protobuf/encoding/protojson"
)

type rpcTestEngine struct {
	created   driver.Spec
	deleted   bool
	started   int
	stopped   int
	createErr error
	startErr  error
	stopErr   error
	deleteErr error
	list      []driver.Info
	listErr   error
}

type tokenAwareRPCtestEngine struct {
	*rpcTestEngine
	token       string
	tokenStarts int
}

func (e *tokenAwareRPCtestEngine) StartWithToken(ctx context.Context, id core.ID, token string) error {
	e.token = token
	e.tokenStarts++
	return e.rpcTestEngine.Start(ctx, id)
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
	rpc := &openShellRPC{runtime: &grpcRuntime{
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
	resp, err := rpc.CreateSandbox(ctx, &openshellv1.CreateSandboxRequest{Name: "demo", Workspace: "default", Labels: map[string]string{"team": "test", driver.WorkspaceLabel: "attacker-workspace", driver.GatewayIDLabel: "attacker-gateway"}, Spec: &openshellv1.SandboxSpec{Policy: &sandboxv1.SandboxPolicy{Version: 1}, Template: &openshellv1.SandboxTemplate{Image: "alpine:3.22", Environment: map[string]string{"FROM_TEMPLATE": "yes"}}, Environment: map[string]string{"FROM_SPEC": "yes"}, Command: []string{"sleep", "infinity"}}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSandbox().GetStatus().GetPhase() != openshellv1.SandboxPhase_SANDBOX_PHASE_PROVISIONING {
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
	if _, err := rpc.StopSandbox(ctx, &openshellv1.StopSandboxRequest{Name: "demo", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	if _, err := rpc.StartSandbox(ctx, &openshellv1.StartSandboxRequest{Name: "demo", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	deleted, err := rpc.DeleteSandbox(ctx, &openshellv1.DeleteSandboxRequest{Name: "demo", Workspace: "default"})
	if err != nil || !deleted.GetDeleted() {
		t.Fatalf("deleted=%v err=%v", deleted, err)
	}
	if _, ok := st.GetSandbox("demo"); ok || engine.started != 2 || engine.stopped != 2 || !engine.deleted {
		t.Fatalf("registry/runtime lifecycle: exists=%v starts=%d stops=%d deleted=%v", ok, engine.started, engine.stopped, engine.deleted)
	}
	if readinessChecks != 2 {
		t.Fatalf("supervisor readiness checks = %d, want create and restart checks", readinessChecks)
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
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	if _, err := rpc.StopSandbox(ctx, &openshellv1.StopSandboxRequest{Name: "demo", Workspace: "default"}); err == nil {
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
	rpc := &openShellRPC{runtime: &grpcRuntime{
		st: st, compute: registry, waitSupervisorReady: func(context.Context, string) error { return nil },
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	if _, err := rpc.StartSandbox(ctx, &openshellv1.StartSandboxRequest{Name: "demo", Workspace: "default"}); err != nil {
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
	if _, err := rpc.StopSandbox(ctx, &openshellv1.StopSandboxRequest{Name: "demo", Workspace: "default"}); err != nil {
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
	spec := &openshellv1.SandboxSpec{Template: &openshellv1.SandboxTemplate{Image: "alpine:3.22"}, Command: []string{"sleep", "infinity"}}
	specJSON, err := protojson.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "recover", ID: "stable-id", ComputeDriver: "docker", Image: "alpine:3.22", Workspace: "default", Status: "error", SpecJSON: string(specJSON), Labels: map[string]string{"managed": "true"}}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &openShellRPC{runtime: &grpcRuntime{
		st: st, opt: Options{DataDir: t.TempDir(), Listen: "127.0.0.1:7443"}, compute: registry,
		waitSupervisorReady: func(context.Context, string) error { return nil },
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	response, err := rpc.StartSandbox(ctx, &openshellv1.StartSandboxRequest{Name: "recover", Workspace: "default"})
	if err != nil {
		t.Fatalf("recovery start: %v", err)
	}
	if response.GetSandbox().GetStatus().GetPhase() != openshellv1.SandboxPhase_SANDBOX_PHASE_READY {
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
	if _, err := rpc.StartSandbox(ctx, &openshellv1.StartSandboxRequest{Name: "recover", Workspace: "default"}); err != nil {
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
	specJSON, err := protojson.Marshal(&openshellv1.SandboxSpec{Template: &openshellv1.SandboxTemplate{Image: "alpine:3.22"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "recover-fail", ID: "stable-id", ComputeDriver: "docker", Image: "alpine:3.22", Workspace: "default", Status: "error", SpecJSON: string(specJSON)}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{startErr: errors.New("backend start failed")}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, opt: Options{DataDir: t.TempDir(), Listen: "127.0.0.1:7443"}, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	if _, err := rpc.StartSandbox(ctx, &openshellv1.StartSandboxRequest{Name: "recover-fail", Workspace: "default"}); err == nil {
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
	specJSON, err := protojson.Marshal(&openshellv1.SandboxSpec{Template: &openshellv1.SandboxTemplate{Image: "alpine:3.22"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "recover-cleanup-fail", ID: "stable-id", ComputeDriver: "docker", Image: "alpine:3.22", Workspace: "default", Status: "error", SpecJSON: string(specJSON)}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{startErr: errors.New("backend start failed"), deleteErr: errors.New("backend delete failed")}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, opt: Options{DataDir: t.TempDir(), Listen: "127.0.0.1:7443"}, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.StartSandbox(ctx, &openshellv1.StartSandboxRequest{Name: "recover-cleanup-fail", Workspace: "default"})
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
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, opt: Options{DataDir: dataDir, Listen: "127.0.0.1:7443"}, compute: registry, waitSupervisorReady: func(context.Context, string) error { return nil }}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &openshellv1.CreateSandboxRequest{
		Name: "default-policy", Workspace: "default",
		Spec: &openshellv1.SandboxSpec{Template: &openshellv1.SandboxTemplate{Image: "alpine:3.22"}, Command: []string{"sleep", "infinity"}},
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
	config, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{SandboxId: "default-policy"})
	if err != nil {
		t.Fatal(err)
	}
	if config.GetPolicy() != nil || config.GetPolicySource() != sandboxv1.PolicySource_POLICY_SOURCE_SANDBOX {
		t.Fatalf("runtime-only default leaked into config API: policy=%v source=%v", config.GetPolicy(), config.GetPolicySource())
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
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, opt: Options{DataDir: dataDir, Listen: "127.0.0.1:7443"}, compute: registry}}
	inputs, err := rpc.prepareSandboxRuntime(&openshellv1.CreateSandboxRequest{Spec: &openshellv1.SandboxSpec{Policy: &sandboxv1.SandboxPolicy{Version: 1, Filesystem: &sandboxv1.FilesystemPolicy{IncludeWorkdir: true, ReadWrite: []string{"/sandbox-only"}}}}}, "docker", "global-override", "default")
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
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, opt: Options{DataDir: dataDir}, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &openshellv1.CreateSandboxRequest{
		Name: "invalid-global", Workspace: "default",
		Spec: &openshellv1.SandboxSpec{Template: &openshellv1.SandboxTemplate{Image: "alpine:3.22"}},
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
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, opt: Options{DataDir: t.TempDir()}, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &openshellv1.CreateSandboxRequest{Workspace: "../escape", Spec: &openshellv1.SandboxSpec{Policy: &sandboxv1.SandboxPolicy{Version: 1}, Template: &openshellv1.SandboxTemplate{Image: "alpine"}}})
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
	rpc := &openShellRPC{runtime: &grpcRuntime{
		st: st, opt: Options{DataDir: dataDir, Listen: "127.0.0.1:7443"}, compute: registry,
		waitSupervisorReady: func(context.Context, string) error { return sshrelay.ErrNotConnected },
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &openshellv1.CreateSandboxRequest{
		Name: "relay-timeout", Workspace: "default",
		Spec: &openshellv1.SandboxSpec{
			Policy:   &sandboxv1.SandboxPolicy{Version: 1},
			Template: &openshellv1.SandboxTemplate{Image: "alpine:3.22"},
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
	rpc := &openShellRPC{runtime: &grpcRuntime{
		st: st, opt: Options{DataDir: dataDir, Listen: "127.0.0.1:7443"}, compute: registry,
		waitSupervisorReady: func(context.Context, string) error { return sshrelay.ErrNotConnected },
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateSandbox(ctx, &openshellv1.CreateSandboxRequest{
		Name: "relay-timeout", Workspace: "default",
		Spec: &openshellv1.SandboxSpec{
			Policy:   &sandboxv1.SandboxPolicy{Version: 1},
			Template: &openshellv1.SandboxTemplate{Image: "alpine:3.22"},
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
