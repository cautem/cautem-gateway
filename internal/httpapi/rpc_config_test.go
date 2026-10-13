package httpapi

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-runtime/secrets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestGetGatewayConfigReturnsRegisteredTypedSettingsAndRevision(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-config")
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"ocsf_json_enabled":              "true",
		"ocsf_schema_version":            "1.3",
		"agent_policy_proposals_enabled": "false",
		"proposal_approval_mode":         "manual",
		"unknown_setting":                "hidden",
		"policy":                         "hidden",
	} {
		if err := st.SetSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
	handler := &openShellRPC{runtime: &grpcRuntime{st: st}}
	resp, err := handler.GetGatewayConfig(context.Background(), &sandboxv1.GetGatewayConfigRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSettingsRevision() != 6 {
		t.Fatalf("settings revision=%d; want 6", resp.GetSettingsRevision())
	}
	if len(resp.GetSettings()) != 4 {
		t.Fatalf("returned settings=%v; want four registered settings", resp.GetSettings())
	}
	if got := resp.GetSettings()["ocsf_json_enabled"].GetBoolValue(); !got {
		t.Fatalf("ocsf_json_enabled=%v; want true", got)
	}
	if got := resp.GetSettings()["agent_policy_proposals_enabled"].GetBoolValue(); got {
		t.Fatalf("agent_policy_proposals_enabled=%v; want false", got)
	}
	if got := resp.GetSettings()["ocsf_schema_version"].GetStringValue(); got != "1.3" {
		t.Fatalf("ocsf_schema_version=%q", got)
	}
	if got := resp.GetSettings()["proposal_approval_mode"].GetStringValue(); got != "manual" {
		t.Fatalf("proposal_approval_mode=%q", got)
	}
	if _, ok := resp.GetSettings()["policy"]; ok {
		t.Fatal("reserved policy setting was returned")
	}
}

func TestGetSandboxConfigReturnsStablePolicySettingsAndWorkspace(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-sandbox-config")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-123", Workspace: "team", PolicyRev: 4, AttachedProviders: []string{"provider"}, BasePolicyYAML: "version: 1\nfilesystem_policy:\n  include_workdir: true\n  read_write:\n    - /workspace\n"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "provider", Type: "github", Workspace: "team", EnvVars: []string{"GITHUB_TOKEN"}, CredentialExpiresAtMS: map[string]int64{"GITHUB_TOKEN": 1000}}); err != nil {
		t.Fatal(err)
	}
	installConfigTestProfile(t, st, "team", "github")
	if err := st.SetSetting("ocsf_json_enabled", "on"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetSandboxSetting("demo", "ocsf_json_enabled", "false"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetSandboxSetting("demo", "proposal_approval_mode", "auto"); err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := sec.PutProviderCredentials(ctx, "provider", map[string]string{"GITHUB_TOKEN": "secret-one"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, sec: sec}}
	ctx = withPrincipal(ctx, Principal{Kind: PrincipalUser, IDP: "local_dev"})
	first, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{SandboxId: "sandbox-123"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{SandboxId: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if first.GetPolicy().GetVersion() != 1 || first.GetVersion() != 4 || first.GetPolicySource() != sandboxv1.PolicySource_POLICY_SOURCE_SANDBOX {
		t.Fatalf("policy response=%v version=%d source=%v", first.GetPolicy(), first.GetVersion(), first.GetPolicySource())
	}
	if first.GetPolicyHash() == "" || first.GetPolicyHash() != second.GetPolicyHash() || first.GetConfigRevision() == 0 || first.GetConfigRevision() != second.GetConfigRevision() {
		t.Fatalf("config identity is not stable: hash %q/%q revision %d/%d", first.GetPolicyHash(), second.GetPolicyHash(), first.GetConfigRevision(), second.GetConfigRevision())
	}
	if first.GetWorkspace() != "team" || !first.GetSettings()["ocsf_json_enabled"].GetValue().GetBoolValue() {
		t.Fatalf("workspace/settings missing: %v", first)
	}
	if first.GetProviderEnvRevision() == 0 || first.GetProviderEnvRevision() != second.GetProviderEnvRevision() {
		t.Fatalf("provider environment revision is not stable: %d/%d", first.GetProviderEnvRevision(), second.GetProviderEnvRevision())
	}
	if first.GetSettings()["ocsf_json_enabled"].GetScope() != sandboxv1.SettingScope_SETTING_SCOPE_GLOBAL {
		t.Fatalf("setting scope=%v", first.GetSettings()["ocsf_json_enabled"].GetScope())
	}
	if first.GetSettings()["proposal_approval_mode"].GetValue().GetStringValue() != "auto" || first.GetSettings()["proposal_approval_mode"].GetScope() != sandboxv1.SettingScope_SETTING_SCOPE_SANDBOX {
		t.Fatalf("sandbox setting was not resolved: %v", first.GetSettings()["proposal_approval_mode"])
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "provider", Type: "github", Workspace: "team", EnvVars: []string{"GITHUB_TOKEN"}, CredentialExpiresAtMS: map[string]int64{"GITHUB_TOKEN": 2000}}); err != nil {
		t.Fatal(err)
	}
	updated, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{SandboxId: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.GetProviderEnvRevision() == first.GetProviderEnvRevision() {
		t.Fatal("provider metadata update did not change provider environment revision")
	}
	if err := sec.PutProviderCredentials(ctx, "provider", map[string]string{"GITHUB_TOKEN": "secret-two"}); err != nil {
		t.Fatal(err)
	}
	credentialUpdated, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{SandboxId: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if credentialUpdated.GetProviderEnvRevision() == updated.GetProviderEnvRevision() {
		t.Fatal("credential rotation did not change provider environment revision")
	}
}

func installConfigTestProfile(t *testing.T, st *store.Store, workspace, id string) {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve config test source")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(source))))
	profile, err := os.ReadFile(filepath.Join(root, "cautem-cli", "providers", id+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProfileScoped("workspace", workspace, id, string(profile)); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateConfigMutatesGlobalAndSandboxSettings(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-update-config")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team", Members: []store.WorkspaceMember{{Subject: "admin", Role: "admin"}}}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	sandboxResp, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{
		Name: "demo", Workspace: "team", SettingKey: "proposal_approval_mode",
		SettingValue: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_StringValue{StringValue: "auto"}},
	})
	if err != nil || sandboxResp.GetSettingsRevision() != 1 {
		t.Fatalf("sandbox update resp=%v err=%v", sandboxResp, err)
	}
	globalResp, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{
		Global: true, SettingKey: "proposal_approval_mode",
		SettingValue: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_StringValue{StringValue: "manual"}},
	})
	if err != nil || globalResp.GetSettingsRevision() != 1 {
		t.Fatalf("global update resp=%v err=%v", globalResp, err)
	}
	config, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{SandboxId: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	setting := config.GetSettings()["proposal_approval_mode"]
	if setting.GetValue().GetStringValue() != "manual" || setting.GetScope() != sandboxv1.SettingScope_SETTING_SCOPE_GLOBAL {
		t.Fatalf("global setting did not override sandbox value: %v", setting)
	}
	deleted, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{Global: true, SettingKey: "proposal_approval_mode", DeleteSetting: true})
	if err != nil || !deleted.GetDeleted() || deleted.GetSettingsRevision() != 2 {
		t.Fatalf("global delete resp=%v err=%v", deleted, err)
	}
	config, err = rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{SandboxId: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	setting = config.GetSettings()["proposal_approval_mode"]
	if setting.GetValue().GetStringValue() != "auto" || setting.GetScope() != sandboxv1.SettingScope_SETTING_SCOPE_SANDBOX {
		t.Fatalf("sandbox setting did not resume after global delete: %v", setting)
	}
}

func TestUpdateConfigRejectsGlobalPolicyWithConnectedRuntime(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-global-policy-runtime")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	hub := sshrelay.NewHub()
	done := make(chan struct{})
	remove := hub.RegisterOpenShellSupervisor("demo", "instance-1", func(string, string) error { return nil }, done, nil)
	defer func() { close(done); remove() }()
	dataDir := t.TempDir()
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, relay: hub, opt: Options{DataDir: dataDir}, policyApplyTimeout: 20 * time.Millisecond}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	if _, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{
		Global: true, Policy: &sandboxv1.SandboxPolicy{Version: 1},
	}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("global policy update error=%v; want FailedPrecondition", err)
	}
	if policy, revision := st.GlobalPolicySnapshot(); policy != "" {
		t.Fatalf("global policy changed despite unavailable acknowledgement: %q", policy)
	} else if revision != 2 {
		t.Fatalf("global policy revision=%d after failed update and compensation; want monotonic revision 2", revision)
	}
	if sandbox, ok := st.GetSandbox("demo"); !ok || sandbox.PolicyRev != 2 {
		t.Fatalf("sandbox policy after compensation=%+v exists=%t; want restored policy at monotonic revision 2", sandbox, ok)
	}
	policyFile, err := os.ReadFile(filepath.Join(dataDir, "sandboxes", "demo", "policy.yaml"))
	if err != nil {
		t.Fatalf("read compensated runtime policy: %v", err)
	}
	if !strings.HasPrefix(string(policyFile), "# cautem-policy-revision: 2\n") {
		t.Fatalf("runtime policy after compensation does not contain revision 2: %q", policyFile)
	}
}

func TestUpdateConfigRejectsUnacknowledgedConnectedRuntime(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-policy-ack-timeout")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default", BasePolicyYAML: "version: 1\n"}); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	hub := sshrelay.NewHub()
	done := make(chan struct{})
	remove := hub.RegisterOpenShellSupervisor("demo", "instance-1", func(string, string) error { return nil }, done, nil)
	defer func() { close(done); remove() }()
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, relay: hub, opt: Options{DataDir: dataDir}, policyApplyTimeout: 20 * time.Millisecond}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	_, err = rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{
		Name: "demo", Workspace: "default", Policy: &sandboxv1.SandboxPolicy{Version: 1},
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "timed out waiting") {
		t.Fatalf("unacknowledged update error=%v; want bounded FailedPrecondition timeout", err)
	}
}

func TestUpdateConfigRejectsUnsupportedAndUnauthorizedMutations(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-update-config")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team", Members: []store.WorkspaceMember{{Subject: "reader", Role: "reader"}}}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	base := &openshellv1.UpdateConfigRequest{Name: "demo", Workspace: "team", SettingKey: "ocsf_json_enabled", SettingValue: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_BoolValue{BoolValue: true}}}
	reader := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "reader", Scopes: []string{"config:write"}})
	if _, err := rpc.UpdateConfig(reader, base); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("workspace reader write error=%v; want PermissionDenied", err)
	}
	local := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	deleteSandbox := &openshellv1.UpdateConfigRequest{Name: base.GetName(), Workspace: base.GetWorkspace(), SettingKey: base.GetSettingKey(), DeleteSetting: true}
	if response, err := rpc.UpdateConfig(local, deleteSandbox); err != nil || response.GetDeleted() {
		t.Fatalf("missing sandbox setting delete response=%v err=%v; want a successful no-op", response, err)
	}
	if err := st.SetSetting(base.GetSettingKey(), "true"); err != nil {
		t.Fatal(err)
	}
	if _, err := rpc.UpdateConfig(local, deleteSandbox); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("globally managed sandbox setting delete error=%v; want FailedPrecondition", err)
	}
	badEnum := &openshellv1.UpdateConfigRequest{Global: true, SettingKey: "proposal_approval_mode", SettingValue: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_StringValue{StringValue: "autom"}}}
	if _, err := rpc.UpdateConfig(local, badEnum); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid registered value error=%v; want InvalidArgument", err)
	}
	policyUpdate := &openshellv1.UpdateConfigRequest{Global: true, Policy: &sandboxv1.SandboxPolicy{Version: 1}}
	policyResp, err := rpc.UpdateConfig(local, policyUpdate)
	if err != nil || policyResp.GetVersion() != 1 || policyResp.GetPolicyHash() == "" {
		t.Fatalf("global policy update resp=%v err=%v", policyResp, err)
	}
	mergeUpdate := &openshellv1.UpdateConfigRequest{Global: true, MergeOperations: []*openshellv1.PolicyMergeOperation{{}}}
	if _, err := rpc.UpdateConfig(local, mergeUpdate); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("policy merge error=%v; want InvalidArgument", err)
	}
}

func TestUpdateConfigAnnotationsAndResourceVersionCAS(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-config-cas-rpc")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	first, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{Name: "demo", SettingKey: "proposal_approval_mode", SettingValue: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_StringValue{StringValue: "manual"}}, Annotations: map[string]string{"audit.example/source": "console"}})
	if err != nil || first.GetAnnotations()["audit.example/source"] != "console" {
		t.Fatalf("first update=%v err=%v", first, err)
	}
	sandbox, _ := st.GetSandbox("demo")
	if sandbox.ResourceVersion != 2 {
		t.Fatalf("resource version=%d; want 2", sandbox.ResourceVersion)
	}
	second, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{Name: "demo", SettingKey: "proposal_approval_mode", SettingValue: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_StringValue{StringValue: "auto"}}, ExpectedResourceVersion: sandbox.ResourceVersion})
	if err != nil || second.GetSettingsRevision() != 2 {
		t.Fatalf("second update=%v err=%v", second, err)
	}
	_, err = rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{Name: "demo", SettingKey: "proposal_approval_mode", SettingValue: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_StringValue{StringValue: "manual"}}, ExpectedResourceVersion: sandbox.ResourceVersion})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("stale update error=%v; want Aborted", err)
	}
	_, err = rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{Name: "demo", SettingKey: "proposal_approval_mode", SettingValue: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_StringValue{StringValue: "manual"}}, Annotations: map[string]string{"bad key": "value"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid annotation error=%v; want InvalidArgument", err)
	}
}

func TestGetSandboxConfigEnforcesPrincipalScope(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-sandbox-config")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-123", Workspace: "team"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	if _, err := rpc.GetSandboxConfig(context.Background(), &sandboxv1.GetSandboxConfigRequest{SandboxId: "demo"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous error=%v; want Unauthenticated", err)
	}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "other"})
	if _, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{SandboxId: "demo"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-sandbox error=%v; want PermissionDenied", err)
	}
	ctx = withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "reader", Scopes: []string{"config:read"}})
	if _, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{SandboxId: "demo"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unregistered workspace error=%v; want NotFound", err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team", Members: []store.WorkspaceMember{{Subject: "reader", Role: "reader"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{SandboxId: "demo"}); err != nil {
		t.Fatalf("workspace reader denied: %v", err)
	}
}

func TestGetSandboxConfigAppliesGlobalPolicyOverrideAndFailureMode(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-global-sandbox-config")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default", PolicyRev: 2, BasePolicyYAML: "version: 1\n"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetGlobalPolicy("version: 3\n"); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{options: Options{PolicyValidationFailureMode: "retain_last_valid"}, runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	resp, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{SandboxId: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetPolicySource() != sandboxv1.PolicySource_POLICY_SOURCE_GLOBAL || resp.GetVersion() != 2 || resp.GetGlobalPolicyVersion() != 1 {
		t.Fatalf("global policy source/version/revision=%v/%d/%d", resp.GetPolicySource(), resp.GetVersion(), resp.GetGlobalPolicyVersion())
	}
	if resp.GetPolicyValidationFailureMode() != "retain_last_valid" {
		t.Fatalf("failure mode=%q", resp.GetPolicyValidationFailureMode())
	}
}

func TestGetSandboxConfigDualAuthAllowsSandboxBearerOnlyForItsSandbox(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-sandbox-config-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-123"}); err != nil {
		t.Fatal(err)
	}
	token, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{grpcRuntime: &grpcRuntime{st: st}}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	authed, err := authenticateGRPC(ctx, "/openshell.v1.OpenShell/GetSandboxConfig", opt)
	if err != nil || PrincipalFrom(authed).Sandbox != "demo" {
		t.Fatalf("sandbox dual auth principal=%+v err=%v", PrincipalFrom(authed), err)
	}
	if _, err := authenticateGRPC(ctx, "/openshell.v1.OpenShell/GetGatewayConfig", opt); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("sandbox token accessed gateway config: %v", err)
	}
	if _, err := authenticateGRPC(ctx, "/openshell.v1.OpenShell/UpdateConfig", opt); err != nil {
		t.Fatalf("sandbox token rejected by dual-auth UpdateConfig: %v", err)
	}
}

func TestRefreshSandboxTokenAcceptsImmediatelyPreviousActiveSupervisorToken(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-active-token-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-123"}); err != nil {
		t.Fatal(err)
	}
	first, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	current, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{grpcRuntime: &grpcRuntime{st: st}}
	oldContext := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+first))
	refreshedContext, err := authenticateGRPC(oldContext, "/openshell.v1.OpenShell/RefreshSandboxToken", opt)
	if err != nil {
		t.Fatalf("previous active token was not accepted for refresh: %v", err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	response, err := rpc.RefreshSandboxToken(refreshedContext, &openshellv1.RefreshSandboxTokenRequest{})
	if err != nil || response.GetToken() != current {
		t.Fatalf("refresh response=%v err=%v; want current token", response, err)
	}
	if _, err := authenticateGRPC(oldContext, "/openshell.v1.OpenShell/GetSandboxConfig", opt); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("previous token accessed ordinary RPC after rotation: %v", err)
	}
}

func TestUpdateConfigAllowsSandboxPolicySyncOnlyForOwnSandbox(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-sandbox-policy-sync")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-id", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBasePolicy("demo", "version: 1\n"); err != nil {
		t.Fatal(err)
	}
	token, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{grpcRuntime: &grpcRuntime{st: st}}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	authed, err := authenticateGRPC(ctx, "/openshell.v1.OpenShell/UpdateConfig", opt)
	if err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	resp, err := rpc.UpdateConfig(authed, &openshellv1.UpdateConfigRequest{Name: "demo", Policy: &sandboxv1.SandboxPolicy{Version: 1}})
	if err != nil || resp.GetVersion() != 1 {
		t.Fatalf("policy sync resp=%v err=%v", resp, err)
	}
	settingMutation := &openshellv1.UpdateConfigRequest{Name: "demo", SettingKey: "ocsf_json_enabled", SettingValue: &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_BoolValue{BoolValue: true}}}
	if _, err := rpc.UpdateConfig(authed, settingMutation); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("sandbox token setting mutation error=%v; want Unauthenticated", err)
	}
}

func TestUpdateConfigDeliversEffectivePolicyToRuntimeFile(t *testing.T) {
	dataDir := t.TempDir()
	st, err := store.Open(t.TempDir(), "gw-policy-runtime")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default", BasePolicyYAML: "version: 1\n"}); err != nil {
		t.Fatal(err)
	}
	policyDir := filepath.Join(dataDir, "sandboxes", "demo")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(policyDir, "policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, opt: Options{DataDir: dataDir}}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	if _, err := rpc.UpdateConfig(ctx, &openshellv1.UpdateConfigRequest{
		Name: "demo", Workspace: "default",
		Policy: &sandboxv1.SandboxPolicy{Version: 1, NetworkPolicies: map[string]*sandboxv1.NetworkPolicyRule{
			"api": {Name: "api", Endpoints: []*sandboxv1.NetworkEndpoint{{Host: "api.example.com", Port: 443}}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "api.example.com") {
		t.Fatalf("runtime policy was not delivered: %s", raw)
	}
}

func TestGetGatewayConfigRejectsUnavailableAndMalformedState(t *testing.T) {
	if _, err := (&openShellRPC{}).GetGatewayConfig(context.Background(), &sandboxv1.GetGatewayConfigRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("nil runtime error=%v; want Unavailable", err)
	}
	st, err := store.Open(t.TempDir(), "gw-config")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("ocsf_json_enabled", "sometimes"); err != nil {
		t.Fatal(err)
	}
	if _, err := (&openShellRPC{runtime: &grpcRuntime{st: st}}).GetGatewayConfig(context.Background(), &sandboxv1.GetGatewayConfigRequest{}); status.Code(err) != codes.Internal {
		t.Fatalf("malformed setting error=%v; want Internal", err)
	}
}
