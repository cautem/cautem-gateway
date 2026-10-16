package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/quarshell-gateway/internal/sshrelay"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

type policyDeliveryTestEngine struct {
	driver.Engine
	id     core.ID
	policy []byte
}

func (*policyDeliveryTestEngine) BackendCapabilityInfo() driver.BackendInfo {
	return driver.BackendInfo{
		ID: "kubernetes",
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityPolicyUpdate: {},
		},
	}
}

func TestWaitSandboxPolicyAppliedForDisconnectedKubernetesRuntime(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gateway-policy-ack")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{
		Name: "demo", ID: "sandbox-id", RuntimeID: "k8s:cautem-ws-123/demo/uid-123",
		ComputeDriver: "kubernetes", Workspace: "team", Status: "running",
		BasePolicyYAML: "version: 1\nnetwork_policies: {}\n",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBasePolicy("demo", "version: 1\nnetwork_policies: {}\n"); err != nil {
		t.Fatal(err)
	}
	engine := &policyDeliveryTestEngine{}
	runtime := &grpcRuntime{
		st: st, relay: sshrelay.NewHub(),
		compute:            &computeRegistry{engines: map[string]driver.Engine{"kubernetes": engine}},
		policyApplyTimeout: 20 * time.Millisecond,
	}
	err = (&compatRPCAdapter{runtime: runtime}).waitSandboxPolicyApplied(context.Background(), "demo", 1)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("waitSandboxPolicyApplied() error = %v; want timeout while disconnected", err)
	}
}

func (engine *policyDeliveryTestEngine) UpdateSandboxPolicy(_ context.Context, id core.ID, policy []byte) error {
	engine.id = id
	engine.policy = append([]byte(nil), policy...)
	return nil
}

func TestSyncSandboxRuntimePolicyDeliversToComputeDriverWithoutDataDir(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gateway-policy-delivery")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{
		Name: "demo", ID: "sandbox-id", RuntimeID: "k8s:cautem-ws-123/demo/uid-123",
		ComputeDriver: "kubernetes", Workspace: "team", Status: "running", PolicyRev: 3,
		BasePolicyYAML: "version: 1\nnetwork_policies: {}\n",
	}); err != nil {
		t.Fatal(err)
	}
	engine := &policyDeliveryTestEngine{}
	runtime := &grpcRuntime{
		st:      st,
		compute: &computeRegistry{engines: map[string]driver.Engine{"kubernetes": engine}},
		opt:     Options{},
	}
	rpc := &compatRPCAdapter{runtime: runtime}
	if err := rpc.syncSandboxRuntimePolicy(context.Background(), "demo", 3); err != nil {
		t.Fatalf("syncSandboxRuntimePolicy() error = %v", err)
	}
	if engine.id != core.ID("k8s:cautem-ws-123/demo/uid-123") {
		t.Fatalf("policy updater runtime ID = %q", engine.id)
	}
	if !strings.Contains(string(engine.policy), "cautem-policy-revision: 3") || !strings.Contains(string(engine.policy), "filesystem_policy:") {
		t.Fatalf("delivered policy did not contain the effective revision and document: %s", engine.policy)
	}
}
