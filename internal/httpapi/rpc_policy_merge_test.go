package httpapi

import (
	"context"
	"strings"
	"testing"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const mergeTestPolicy = `version: 1
network_policies:
  api:
    name: api
    binaries:
      - path: /usr/bin/agent
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        rules:
          - allow:
              method: GET
              path: /**
`

func TestUpdateConfigAppliesSandboxPolicyMergeOperationsAtomically(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-policy-merge")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-1", Workspace: "default", BasePolicyYAML: mergeTestPolicy}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBasePolicy("demo", mergeTestPolicy); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	addOps := []*openshellv1.PolicyMergeOperation{
		{Operation: &openshellv1.PolicyMergeOperation_AddAllowRules{AddAllowRules: &openshellv1.AddAllowRules{
			Host: "api.example.com", Port: 443,
			Rules: []*sandboxv1.L7Rule{{Allow: &sandboxv1.L7Allow{Method: "POST", Path: "/repos/**"}}},
		}}},
		{Operation: &openshellv1.PolicyMergeOperation_AddDenyRules{AddDenyRules: &openshellv1.AddDenyRules{
			Host: "api.example.com", Port: 443,
			DenyRules: []*sandboxv1.L7DenyRule{{Method: "DELETE", Path: "/repos/**"}},
		}}},
	}
	response, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{Name: "demo", Workspace: "default", MergeOperations: addOps, Annotations: map[string]string{"change": "reviewed"}})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetVersion() != 2 || response.GetPolicyHash() == "" || response.GetAnnotations()["change"] != "reviewed" {
		t.Fatalf("merge response=%+v", response)
	}
	record, _ := st.GetSandbox("demo")
	merged, err := policy.Parse([]byte(record.BasePolicyYAML))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := merged.NetworkPolicies["api"].Endpoints[0]
	if len(endpoint.Rules) != 2 || len(endpoint.DenyRules) != 1 {
		t.Fatalf("merged endpoint allows=%+v denies=%+v", endpoint.Rules, endpoint.DenyRules)
	}

	before := record.BasePolicyYAML
	bad := &openshellv1.UpdateConfigRequest{Name: "demo", Workspace: "default", MergeOperations: []*openshellv1.PolicyMergeOperation{
		{Operation: &openshellv1.PolicyMergeOperation_AddRule{AddRule: &openshellv1.AddNetworkRule{RuleName: "new-rule", Rule: &sandboxv1.NetworkPolicyRule{Endpoints: []*sandboxv1.NetworkEndpoint{{Host: "other.example.com", Port: 443}}}}}},
		{},
	}}
	if _, err := rpc.UpdateConfig(ctx, bad); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid batch error=%v; want InvalidArgument", err)
	}
	after, _ := st.GetSandbox("demo")
	if after.BasePolicyYAML != before || after.PolicyRev != record.PolicyRev {
		t.Fatalf("failed batch partially changed policy: before rev=%d after=%+v", record.PolicyRev, after)
	}
}

func TestUpdateConfigPolicyMergeEnforcesGlobalPolicyAndCAS(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-policy-merge-guards")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-1", Workspace: "default", BasePolicyYAML: mergeTestPolicy}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBasePolicy("demo", mergeTestPolicy); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	op := &openshellv1.PolicyMergeOperation{Operation: &openshellv1.PolicyMergeOperation_RemoveRule{RemoveRule: &openshellv1.RemoveNetworkRule{RuleName: "api"}}}
	if _, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{Name: "demo", ExpectedResourceVersion: 1, MergeOperations: []*openshellv1.PolicyMergeOperation{op}}); status.Code(err) != codes.Aborted {
		t.Fatalf("stale CAS error=%v; want Aborted", err)
	}
	if err := st.SetGlobalPolicy("version: 1\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{Name: "demo", MergeOperations: []*openshellv1.PolicyMergeOperation{op}}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("global policy merge error=%v; want FailedPrecondition", err)
	}
	if _, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{Global: true, MergeOperations: []*openshellv1.PolicyMergeOperation{op}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("global-scope merge error=%v; want InvalidArgument", err)
	}
}

func TestApplyOpenShellPolicyMergeRuleAndRemovalOperations(t *testing.T) {
	base, err := policy.Parse([]byte(mergeTestPolicy))
	if err != nil {
		t.Fatal(err)
	}
	newRule := &openshellv1.PolicyMergeOperation{Operation: &openshellv1.PolicyMergeOperation_AddRule{AddRule: &openshellv1.AddNetworkRule{
		RuleName: "docs",
		Rule:     &sandboxv1.NetworkPolicyRule{Endpoints: []*sandboxv1.NetworkEndpoint{{Host: "docs.example.com", Port: 443}}},
	}}}
	merged, err := applyOpenShellPolicyMerge(base, []*openshellv1.PolicyMergeOperation{newRule})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := merged.NetworkPolicies["docs"]; !ok {
		t.Fatalf("add_rule did not create named rule: %+v", merged.NetworkPolicies)
	}
	removeEndpoint := &openshellv1.PolicyMergeOperation{Operation: &openshellv1.PolicyMergeOperation_RemoveEndpoint{RemoveEndpoint: &openshellv1.RemoveNetworkEndpoint{RuleName: "api", Host: "api.example.com", Port: 443}}}
	withoutEndpoint, err := applyOpenShellPolicyMerge(merged, []*openshellv1.PolicyMergeOperation{removeEndpoint})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := withoutEndpoint.NetworkPolicies["api"]; ok {
		t.Fatalf("remove_endpoint left an empty rule behind: %+v", withoutEndpoint.NetworkPolicies["api"])
	}
	removeBinary := &openshellv1.PolicyMergeOperation{Operation: &openshellv1.PolicyMergeOperation_RemoveBinary{RemoveBinary: &openshellv1.RemoveNetworkBinary{RuleName: "api", BinaryPath: "/usr/bin/agent"}}}
	withoutBinary, err := applyOpenShellPolicyMerge(base, []*openshellv1.PolicyMergeOperation{removeBinary})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := withoutBinary.NetworkPolicies["api"]; ok {
		t.Fatalf("remove_binary did not delete the now-empty binary-scoped rule")
	}
	unsafeBinaryRemoval := &openshellv1.PolicyMergeOperation{Operation: &openshellv1.PolicyMergeOperation_RemoveBinary{RemoveBinary: &openshellv1.RemoveNetworkBinary{RuleName: "unrestricted", BinaryPath: "/usr/bin/agent"}}}
	base.NetworkPolicies["unrestricted"] = corePolicyAllBinaryRule()
	if _, err := applyOpenShellPolicyMerge(base, []*openshellv1.PolicyMergeOperation{unsafeBinaryRemoval}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("remove_binary from unrestricted scope error=%v; want FailedPrecondition", err)
	}
}

func TestUpdateConfigValidatesCredentialBindingsAgainstAttachedProviders(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-policy-merge-bindings")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProfile("database-credentials", `id: database-credentials
credentials:
  - name: db_token
    env_vars: [DB_TOKEN]
`); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "database", Type: "database-credentials", Workspace: "default", EnvVars: []string{"DB_TOKEN"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-bindings", Workspace: "default", BasePolicyYAML: "version: 1\nnetwork_policies: {}\n", AttachedProviders: []string{"database"}}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	addBinding := func(providerName string) *openshellv1.PolicyMergeOperation {
		return &openshellv1.PolicyMergeOperation{Operation: &openshellv1.PolicyMergeOperation_AddRule{AddRule: &openshellv1.AddNetworkRule{
			RuleName: "database",
			Rule: &sandboxv1.NetworkPolicyRule{Endpoints: []*sandboxv1.NetworkEndpoint{{
				Host: "db.example.com", Port: 5432,
				CredentialBinding: &sandboxv1.NetworkCredentialBinding{Provider: providerName},
			}}},
		}}}
	}
	if _, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{Name: "demo", Workspace: "default", MergeOperations: []*openshellv1.PolicyMergeOperation{addBinding("database")}}); err != nil {
		t.Fatalf("attached endpointless provider binding rejected: %v", err)
	}
	updated, _ := st.GetSandbox("demo")
	if !strings.Contains(updated.BasePolicyYAML, "credential_binding") || !strings.Contains(updated.BasePolicyYAML, "database") {
		t.Fatalf("stored policy lost credential binding: %s", updated.BasePolicyYAML)
	}

	before := updated.BasePolicyYAML
	if _, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{Name: "demo", Workspace: "default", MergeOperations: []*openshellv1.PolicyMergeOperation{addBinding("missing")}}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unattached binding error=%v; want FailedPrecondition", err)
	}
	after, _ := st.GetSandbox("demo")
	if after.BasePolicyYAML != before {
		t.Fatal("failed credential binding update mutated stored policy")
	}
}

func corePolicyAllBinaryRule() policy.NetworkPolicy {
	return policy.NetworkPolicy{Name: "unrestricted", Endpoints: []policy.AllowRule{{Host: "safe.example.com", Port: 443}}}
}
