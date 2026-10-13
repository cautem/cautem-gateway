package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestWorkspaceUsageAggregatesActiveRecordsByWorkspace(t *testing.T) {
	st, err := store.Open(t.TempDir(), "workspace-quota-usage")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"team", "other"} {
		if err := st.CreateWorkspace(store.WorkspaceRecord{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	for _, sandbox := range []store.Sandbox{
		{Name: "active-a", Workspace: "team", Status: "running", ResourceKnown: true, ResourceCPUMilli: 700, ResourceMemoryBytes: 2 << 30, ResourceGPUCount: 1},
		{Name: "stopped", Workspace: "team", Status: "stopped", ResourceKnown: true, ResourceCPUMilli: 9000, ResourceMemoryBytes: 9 << 30, ResourceGPUCount: 8},
		{Name: "other-team", Workspace: "other", Status: "running", ResourceKnown: true, ResourceCPUMilli: 5000, ResourceMemoryBytes: 5 << 30, ResourceGPUCount: 4},
		{Name: "unknown", Workspace: "team", ComputeDriver: "cli-managed", Status: "ready"},
	} {
		if err := st.UpsertSandbox(sandbox); err != nil {
			t.Fatal(err)
		}
	}

	usage := workspaceUsageFromState(st.Snapshot(), "team", 2)
	if usage.cpuMillicores != 700 || usage.memoryBytes != 2<<30 || usage.gpuCount != 1 || usage.activeSandboxes != 2 || usage.activeGUISessions != 2 || usage.unknownAllocations != 1 {
		t.Fatalf("workspace usage = %+v", usage)
	}
	quota := store.WorkspaceQuota{CPUMilliCores: 1000, ConcurrentSandboxes: 2}
	if reason := quotaExceeded(quota, usage, workspaceAllocation{cpuMillicores: 300, known: true}, true); reason != "workspace concurrent sandbox quota exceeded" {
		t.Fatalf("quota exceeded reason = %q, want concurrent sandbox cap", reason)
	}
	quota.ConcurrentSandboxes = 0
	if reason := quotaExceeded(quota, usage, workspaceAllocation{cpuMillicores: 300, known: true}, true); reason != "CPU quota cannot be enforced while active sandbox allocations are unknown" {
		t.Fatalf("quota with unknown active allocation reason = %q", reason)
	}
}

func TestWorkspaceQuotaUpdateRequiresWorkspaceAdminAndCAS(t *testing.T) {
	st, err := store.Open(t.TempDir(), "workspace-quota-api")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "team", Members: []store.WorkspaceMember{{Subject: "alice", Role: "admin"}, {Subject: "bob", Role: "user"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "box", Workspace: "team", Status: "running", ResourceKnown: true, ResourceCPUMilli: 700, ResourceMemoryBytes: 512 << 20, ResourceGPUCount: 1}); err != nil {
		t.Fatal(err)
	}
	api := &controlAPI{store: st}
	alice := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "alice", Scopes: []string{"workspace:write"}})
	bob := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "bob", Scopes: []string{"workspace:write"}})
	request := func(version uint64, cpu uint64) *connect.Request[controlv1.UpdateWorkspaceQuotaRequest] {
		return connect.NewRequest(&controlv1.UpdateWorkspaceQuotaRequest{
			Name: "team", ExpectedResourceVersion: version,
			Quota: &controlv1.WorkspaceQuota{CpuMillicores: cpu, MemoryBytes: 2 << 30, GpuCount: 1, ConcurrentSandboxes: 4, ConcurrentGuiSessions: 2},
		})
	}
	if _, err := api.UpdateWorkspaceQuota(bob, request(1, 2000)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("workspace member quota update code = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if _, err := api.UpdateWorkspaceQuota(alice, request(1, 500)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("quota below current usage code = %v, want FailedPrecondition", connect.CodeOf(err))
	}
	updated, err := api.UpdateWorkspaceQuota(alice, request(1, 2000))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Msg.GetWorkspace().GetResourceVersion() != 2 || updated.Msg.GetWorkspace().GetQuota().GetCpuMillicores() != 2000 || updated.Msg.GetWorkspace().GetUsage().GetGpuCount() != 1 || !updated.Msg.GetWorkspace().GetCanManageQuota() {
		t.Fatalf("quota update response = %+v", updated.Msg.GetWorkspace())
	}
	if _, err := api.UpdateWorkspaceQuota(alice, request(1, 3000)); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("stale quota update code = %v, want Aborted", connect.CodeOf(err))
	}
	if events := st.ListAuditEvents(0, 20); len(events) != 6 || events[0].Action != "workspace.quota.update" || events[1].Outcome != "failed" || events[3].Outcome != "succeeded" {
		t.Fatalf("quota audit events = %+v", events)
	}
}

func TestBrowserGUIQuotaAcquiresAndReleasesWorkspaceCapacity(t *testing.T) {
	st, err := store.Open(t.TempDir(), "workspace-gui-quota")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "team", Quota: store.WorkspaceQuota{ConcurrentGUISessions: 1}}); err != nil {
		t.Fatal(err)
	}
	sessions := newBrowserServiceSessions()
	release, ok := sessions.acquireGUI("team", st)
	if !ok {
		t.Fatal("first GUI connection was rejected")
	}
	if _, ok := sessions.acquireGUI("team", st); ok {
		t.Fatal("second GUI connection exceeded the workspace quota")
	}
	if sessions.activeGUICount("team") != 1 {
		t.Fatalf("active GUI count = %d, want 1", sessions.activeGUICount("team"))
	}
	release()
	if sessions.activeGUICount("team") != 0 {
		t.Fatalf("active GUI count after close = %d, want 0", sessions.activeGUICount("team"))
	}
	if _, ok := sessions.acquireGUI("team", st); !ok {
		t.Fatal("GUI capacity was not released when the connection closed")
	}
}

func TestBrowserGUIQuotaSerializesConcurrentConnections(t *testing.T) {
	st, err := store.Open(t.TempDir(), "workspace-gui-quota-race")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "team", Quota: store.WorkspaceQuota{ConcurrentGUISessions: 1}}); err != nil {
		t.Fatal(err)
	}
	sessions := newBrowserServiceSessions()
	const contenders = 32
	start := make(chan struct{})
	releases := make(chan func(), contenders)
	var workers sync.WaitGroup
	var accepted atomic.Int32
	for range contenders {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			release, ok := sessions.acquireGUI("team", st)
			if ok {
				accepted.Add(1)
				releases <- release
			}
		}()
	}
	close(start)
	workers.Wait()
	close(releases)
	for release := range releases {
		release()
	}
	if accepted.Load() != 1 {
		t.Fatalf("concurrent GUI connections accepted = %d, want exactly 1", accepted.Load())
	}
	if count := sessions.activeGUICount("team"); count != 0 {
		t.Fatalf("active GUI count after concurrent releases = %d, want 0", count)
	}
}

func TestWorkspaceQuotaRejectsAggregateMemoryOverage(t *testing.T) {
	quota := store.WorkspaceQuota{MemoryBytes: 3 << 30}
	usage := workspaceResourceUsage{memoryBytes: 2 << 30}
	if reason := quotaExceeded(quota, usage, workspaceAllocation{memoryBytes: 1<<30 + 1, known: true}, true); reason != "workspace memory quota exceeded" {
		t.Fatalf("memory quota result = %q, want memory overage", reason)
	}
	usage.unknownAllocations = 1
	if reason := quotaExceeded(quota, usage, workspaceAllocation{memoryBytes: 1, known: true}, true); reason != "memory quota cannot be enforced while active sandbox allocations are unknown" {
		t.Fatalf("memory quota with unknown allocation result = %q", reason)
	}
}

func TestGatewayMetricsExposeAggregateWorkspaceUsageWithoutTenantLabels(t *testing.T) {
	st, err := store.Open(t.TempDir(), "workspace-quota-metrics")
	if err != nil {
		t.Fatal(err)
	}
	for _, sandbox := range []store.Sandbox{
		{Name: "team-box", Workspace: "team-a", Status: "running", ResourceKnown: true, ResourceCPUMilli: 1200, ResourceMemoryBytes: 3 << 30, ResourceGPUCount: 1},
		{Name: "other-box", Workspace: "team-b", Status: "ready", ResourceKnown: true, ResourceCPUMilli: 800, ResourceMemoryBytes: 1 << 30},
		{Name: "stopped-box", Workspace: "team-b", Status: "stopped", ResourceKnown: true, ResourceCPUMilli: 9000},
	} {
		if err := st.UpsertSandbox(sandbox); err != nil {
			t.Fatal(err)
		}
	}
	sessions := newBrowserServiceSessions()
	for range 2 {
		if _, ok := sessions.acquireGUI("team-a", nil); !ok {
			t.Fatal("unexpected GUI session rejection")
		}
	}
	runtime := &grpcRuntime{st: st, browserServices: sessions}
	recorder := httptest.NewRecorder()
	gatewayMetricsHandler(runtime).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics := recorder.Body.String()
	for _, expected := range []string{
		"cautem_gateway_workspace_active_sandboxes 2",
		"cautem_gateway_workspace_cpu_millicores 2000",
		"cautem_gateway_workspace_memory_bytes 4294967296",
		"cautem_gateway_workspace_gpu_allocations 1",
		"cautem_gateway_workspace_gui_sessions 2",
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("metrics do not contain %q:\n%s", expected, metrics)
		}
	}
	if strings.Contains(metrics, "team-a") || strings.Contains(metrics, "team-b") {
		t.Fatalf("tenant names leaked into aggregate metrics:\n%s", metrics)
	}
}

func TestCreateSandboxEnforcesAggregateCPUQuotaBeforeRuntimeCreate(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	st, err := store.Open(t.TempDir(), "workspace-quota-create")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "team", Quota: store.WorkspaceQuota{CPUMilliCores: 1000}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "existing", Workspace: "team", Status: "running", ResourceKnown: true, ResourceCPUMilli: 800}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, opt: Options{DataDir: t.TempDir(), Listen: "127.0.0.1:7443"}, compute: registry}}
	resources, err := structpb.NewStruct(map[string]any{"limits": map[string]any{"cpu": "500m"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = rpc.CreateSandbox(withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"}), &openshellv1.CreateSandboxRequest{
		Workspace: "team", Name: "next", Spec: &openshellv1.SandboxSpec{Policy: &sandboxv1.SandboxPolicy{Version: 1}, Template: &openshellv1.SandboxTemplate{Image: "alpine:3.22", Resources: resources}},
	})
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("CreateSandbox error = %v, want ResourceExhausted", err)
	}
	if engine.created.Name != "" {
		t.Fatalf("runtime Create was called despite quota rejection: %+v", engine.created)
	}
	if _, exists := st.GetSandbox("next"); exists {
		t.Fatal("quota-rejected sandbox was persisted")
	}
}

func TestStartSandboxEnforcesWorkspaceGPUQuota(t *testing.T) {
	st, err := store.Open(t.TempDir(), "workspace-quota-start")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "team", Quota: store.WorkspaceQuota{GPUCount: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "active", Workspace: "team", Status: "running", ResourceKnown: true, ResourceGPUCount: 1}); err != nil {
		t.Fatal(err)
	}
	count := uint32(1)
	specJSON, err := protojson.Marshal(&openshellv1.SandboxSpec{
		Template:             &openshellv1.SandboxTemplate{Image: "alpine:3.22"},
		ResourceRequirements: &openshellv1.ResourceRequirements{Gpu: &openshellv1.GpuResourceRequirements{Count: &count}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "stopped", Workspace: "team", RuntimeID: "runtime-stopped", ComputeDriver: "docker", Status: "stopped", SpecJSON: string(specJSON)}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}})
	registry.engines["docker"] = engine
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, compute: registry}}
	_, err = rpc.StartSandbox(withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"}), &openshellv1.StartSandboxRequest{Workspace: "team", Name: "stopped"})
	if status.Code(err) != codes.ResourceExhausted && connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("StartSandbox error = %v, want ResourceExhausted", err)
	}
	if engine.started != 0 {
		t.Fatalf("runtime Start was called %d times despite quota rejection", engine.started)
	}
}
