package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	core "github.com/cautem/cautem-core"
	corepolicy "github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

// UpdateConfig implements registered setting mutations, full policy snapshots,
// sandbox annotation projections and optimistic resource-version checks.
func (s *openShellRPC) UpdateConfig(ctx context.Context, req *openshellv1.UpdateConfigRequest) (*openshellv1.UpdateConfigResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "config runtime is not initialized")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := validateConfigAnnotations(req.GetAnnotations()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if len(req.GetMergeOperations()) != 0 {
		if req.GetPolicy() != nil || strings.TrimSpace(req.GetSettingKey()) != "" || req.GetDeleteSetting() {
			return nil, status.Error(codes.InvalidArgument, "policy, setting_key, and merge_operations are mutually exclusive")
		}
		return s.updateConfigPolicyMerge(ctx, req)
	}
	if req.GetPolicy() != nil {
		if strings.TrimSpace(req.GetSettingKey()) != "" || req.GetSettingValue() != nil || req.GetDeleteSetting() {
			return nil, status.Error(codes.InvalidArgument, "policy and setting mutations are mutually exclusive")
		}
		return s.updateConfigPolicy(ctx, req)
	}
	key := strings.TrimSpace(req.GetSettingKey())
	if key == "" {
		return nil, status.Error(codes.InvalidArgument, "setting_key is required")
	}
	kind, ok := registeredOpenShellSettings[key]
	if !ok || key == "policy" {
		return nil, status.Errorf(codes.InvalidArgument, "setting %q is not registered", key)
	}
	if req.GetDeleteSetting() {
		if req.GetSettingValue() != nil {
			return nil, status.Error(codes.InvalidArgument, "delete_setting cannot include setting_value")
		}
	} else if req.GetSettingValue() == nil {
		return nil, status.Error(codes.InvalidArgument, "setting_value is required")
	}
	value := ""
	if !req.GetDeleteSetting() {
		var err error
		value, err = settingValueString(key, kind, req.GetSettingValue())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "setting %q has an invalid value type or value", key)
		}
	}

	p := PrincipalFrom(ctx)
	if req.GetGlobal() {
		if len(req.GetAnnotations()) != 0 {
			return nil, status.Error(codes.InvalidArgument, "annotations are only supported for sandbox-scoped updates")
		}
		if !isConfigAdmin(p, s.options.OIDC.AdminRole) {
			return nil, status.Error(codes.PermissionDenied, "platform admin role required for global settings")
		}
		deleted := false
		if req.GetDeleteSetting() {
			_, deleted = s.runtime.st.GetSetting(key)
			if err := s.runtime.st.DeleteSetting(key); err != nil {
				return nil, status.Error(codes.Internal, "could not delete global setting")
			}
		} else if err := s.runtime.st.SetSetting(key, value); err != nil {
			return nil, status.Error(codes.Internal, "could not store global setting")
		}
		_, revision := s.runtime.st.SettingsSnapshot()
		return &openshellv1.UpdateConfigResponse{SettingsRevision: revision, Deleted: deleted}, nil
	}

	if p.Kind != PrincipalUser {
		return nil, status.Error(codes.Unauthenticated, "authenticated user required")
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required for sandbox-scoped settings")
	}
	sandbox, ok := s.runtime.st.GetSandbox(name)
	if !ok {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	if workspace := strings.TrimSpace(req.GetWorkspace()); workspace != "" && workspace != sandbox.Workspace {
		return nil, status.Error(codes.PermissionDenied, "sandbox does not belong to requested workspace")
	}
	if err := s.requireSandboxConfigWrite(p, sandbox.Workspace); err != nil {
		return nil, err
	}
	if _, managedGlobally := s.runtime.st.GetSetting(key); managedGlobally {
		return nil, status.Errorf(codes.FailedPrecondition, "setting %q is managed globally; delete the global setting before sandbox update", key)
	}
	updated, deleted, err := s.runtime.st.ApplySandboxConfig(name, req.GetExpectedResourceVersion(), req.GetAnnotations(), key, value, req.GetDeleteSetting(), nil)
	if err != nil {
		if errors.Is(err, store.ErrResourceVersionConflict) {
			return nil, status.Error(codes.Aborted, "sandbox resource version changed")
		}
		return nil, status.Error(codes.Internal, "could not store sandbox setting")
	}
	return &openshellv1.UpdateConfigResponse{SettingsRevision: updated.SettingsRevision, Annotations: updated.Annotations, Deleted: deleted}, nil
}

func (s *openShellRPC) updateConfigPolicy(ctx context.Context, req *openshellv1.UpdateConfigRequest) (*openshellv1.UpdateConfigResponse, error) {
	doc, err := parseOpenShellSandboxPolicy(req.GetPolicy())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "policy is invalid: %v", err)
	}
	policyYAML, err := yaml.Marshal(doc)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not serialize validated policy")
	}
	canonicalProto, err := policyDocumentToProto(doc)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not encode validated policy")
	}
	policyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(canonicalProto)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not serialize validated policy")
	}
	digest := sha256.Sum256(policyBytes)
	policyHash := hex.EncodeToString(digest[:])
	p := PrincipalFrom(ctx)
	if req.GetGlobal() {
		if len(req.GetAnnotations()) != 0 {
			return nil, status.Error(codes.InvalidArgument, "annotations are only supported for sandbox-scoped updates")
		}
		if !isConfigAdmin(p, s.options.OIDC.AdminRole) {
			return nil, status.Error(codes.PermissionDenied, "platform admin role required for global policy")
		}
		_, expectedPolicyRevision := s.runtime.st.GlobalPolicySnapshot()
		policyRevision, err := applyGlobalPolicy(ctx, s.runtime.st, s.runtime, string(policyYAML), expectedPolicyRevision, s.runtime.opt.ProviderProfileSources)
		if err != nil {
			if errors.Is(err, store.ErrResourceVersionConflict) {
				return nil, status.Error(codes.Aborted, "global policy or sandbox state changed")
			}
			return nil, status.Error(codes.FailedPrecondition, "global policy could not be applied to every sandbox")
		}
		_, settingsRevision := s.runtime.st.SettingsSnapshot()
		version := uint32(0)
		if policyRevision <= uint64(^uint32(0)) {
			version = uint32(policyRevision)
		}
		return &openshellv1.UpdateConfigResponse{Version: version, PolicyHash: policyHash, SettingsRevision: settingsRevision}, nil
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required for sandbox policy updates")
	}
	sandbox, ok := s.runtime.st.GetSandbox(name)
	if !ok {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	if p.Kind == PrincipalSandbox {
		if p.Sandbox != sandbox.Name && p.Sandbox != sandbox.ID {
			return nil, status.Error(codes.PermissionDenied, "sandbox principal cannot update another sandbox policy")
		}
		if !sameStaticSandboxPolicy(sandbox.BasePolicyYAML, doc) {
			return nil, status.Error(codes.PermissionDenied, "sandbox callers may only update network policy fields")
		}
	} else {
		if p.Kind != PrincipalUser {
			return nil, status.Error(codes.Unauthenticated, "authenticated user required")
		}
		if workspace := strings.TrimSpace(req.GetWorkspace()); workspace != "" && workspace != sandbox.Workspace {
			return nil, status.Error(codes.PermissionDenied, "sandbox does not belong to requested workspace")
		}
		if err := s.requireSandboxConfigWrite(p, sandbox.Workspace); err != nil {
			return nil, err
		}
		if !sameStaticSandboxPolicy(sandbox.BasePolicyYAML, doc) {
			return nil, status.Error(codes.PermissionDenied, "sandbox updates may only change network policy fields")
		}
	}
	if globalPolicy, _ := s.runtime.st.GlobalPolicySnapshot(); strings.TrimSpace(globalPolicy) != "" {
		return nil, status.Error(codes.FailedPrecondition, "sandbox policy is managed by the global policy")
	}
	if strings.TrimSpace(sandbox.BasePolicyYAML) == "" {
		return nil, status.Error(codes.FailedPrecondition, "sandbox has no stored base policy")
	}
	updated, _, err := s.runtime.st.ApplySandboxConfig(name, req.GetExpectedResourceVersion(), req.GetAnnotations(), "", "", false, policyYAMLString(policyYAML))
	if err != nil {
		if errors.Is(err, store.ErrResourceVersionConflict) {
			return nil, status.Error(codes.Aborted, "sandbox resource version changed")
		}
		if errors.Is(err, store.ErrSandboxPolicyManagedGlobally) {
			return nil, status.Error(codes.FailedPrecondition, "sandbox policy is managed by the global policy")
		}
		return nil, status.Error(codes.Internal, "could not store sandbox policy revision")
	}
	if err := s.syncSandboxRuntimePolicy(ctx, name, updated.PolicyRev); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "sandbox policy was stored but could not be delivered to the running runtime")
	}
	if err := s.waitSandboxPolicyApplied(ctx, name, updated.PolicyRev); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &openshellv1.UpdateConfigResponse{Version: uint32(updated.PolicyRev), PolicyHash: policyHash, Annotations: updated.Annotations}, nil
}

// syncSandboxRuntimePolicy updates the shared policy file used by local
// container backends and asks remote compute backends to deliver the same
// effective revision through their own runtime contract.
func (s *openShellRPC) syncSandboxRuntimePolicy(ctx context.Context, name string, revision int) error {
	if s == nil || s.runtime == nil || s.runtime.st == nil {
		return nil
	}
	sandbox, ok := s.runtime.st.GetSandbox(name)
	if !ok {
		return fmt.Errorf("sandbox %q not found", name)
	}
	effective, err := effectivePolicyWithSources(s.runtime.st, BuiltinProvidersDir(), name, s.runtime.opt.ProviderProfileSources)
	if err != nil {
		return fmt.Errorf("compose effective policy: %w", err)
	}
	serialized, err := yaml.Marshal(effective)
	if err != nil {
		return fmt.Errorf("serialize effective policy: %w", err)
	}
	content := append([]byte(fmt.Sprintf("# cautem-policy-revision: %d\n", revision)), serialized...)
	if strings.TrimSpace(s.runtime.opt.DataDir) != "" {
		path := filepath.Join(s.runtime.opt.DataDir, "sandboxes", sandbox.Name, "policy.yaml")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("create runtime policy directory: %w", err)
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("open runtime policy: %w", err)
		}
		if _, err := file.Write(content); err != nil {
			_ = file.Close()
			return fmt.Errorf("write runtime policy: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return fmt.Errorf("sync runtime policy: %w", err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close runtime policy: %w", err)
		}
	}
	if sandbox.RuntimeID == "" || strings.TrimSpace(sandbox.ComputeDriver) == "" {
		return nil
	}
	if s.runtime.compute == nil {
		if isKubernetesComputeDriver(sandbox.ComputeDriver) {
			return fmt.Errorf("kubernetes compute driver is unavailable for policy update")
		}
		return nil
	}
	engine, err := s.runtime.compute.engine(sandbox.ComputeDriver)
	if err != nil {
		return fmt.Errorf("open sandbox compute driver for policy update: %w", err)
	}
	updater, supportsPolicyUpdate := engine.(driver.SandboxPolicyUpdater)
	if !supportsPolicyUpdate {
		if isKubernetesComputeDriver(sandbox.ComputeDriver) {
			return fmt.Errorf("kubernetes compute driver cannot deliver policy updates")
		}
		return nil
	}
	if err := updater.UpdateSandboxPolicy(ctx, core.ID(sandbox.RuntimeID), content); err != nil {
		return fmt.Errorf("update sandbox policy in compute runtime: %w", err)
	}
	return nil
}

func (s *openShellRPC) waitSandboxPolicyApplied(ctx context.Context, name string, revision int) error {
	if s == nil || s.runtime == nil || s.runtime.st == nil || s.runtime.relay == nil {
		return nil
	}
	connected := s.runtime.relay.Connected(name)
	sandbox, exists := s.runtime.st.GetSandbox(name)
	restartingKubernetes := false
	if exists && sandbox.Status == "running" {
		var err error
		restartingKubernetes, err = sandboxUsesRestartedPolicyDelivery(s.runtime, sandbox)
		if err != nil {
			return fmt.Errorf("inspect compute policy delivery while waiting for acknowledgement: %w", err)
		}
	}
	if !connected && !restartingKubernetes {
		return nil
	}
	timeout := s.runtime.policyApplyTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
		if restartingKubernetes {
			timeout = 2 * time.Minute
		}
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		item, err := s.runtime.st.GetPolicyRevision(name, revision)
		if err != nil {
			return fmt.Errorf("policy revision %d was not retained: %w", revision, err)
		}
		switch item.Status {
		case store.PolicyStatusLoaded:
			return nil
		case store.PolicyStatusFailed:
			if item.LoadError == "" {
				return fmt.Errorf("runtime rejected policy revision %d", revision)
			}
			return fmt.Errorf("runtime rejected policy revision %d: %s", revision, item.LoadError)
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("timed out waiting for runtime to apply policy revision %d", revision)
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func sandboxUsesRestartedPolicyDelivery(runtime *grpcRuntime, sandbox store.Sandbox) (bool, error) {
	if runtime == nil || runtime.compute == nil || !isKubernetesComputeDriver(sandbox.ComputeDriver) {
		return false, nil
	}
	engine, err := runtime.compute.engine(sandbox.ComputeDriver)
	if err != nil {
		return false, err
	}
	_, ok := engine.(driver.SandboxPolicyUpdater)
	return ok, nil
}

func isKubernetesComputeDriver(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "kubernetes", "k8s":
		return true
	default:
		return false
	}
}

func policyYAMLString(value []byte) *string {
	serialized := string(value)
	return &serialized
}

var (
	configAnnotationName   = regexp.MustCompile(`^[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?$`)
	configAnnotationPrefix = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$`)
)

func validateConfigAnnotations(annotations map[string]string) error {
	if len(annotations) > 128 {
		return fmt.Errorf("annotations exceeds 128 entries")
	}
	for key, value := range annotations {
		parts := strings.Split(key, "/")
		if len(key) == 0 || len(parts) > 2 || len(parts[len(parts)-1]) > 63 || !configAnnotationName.MatchString(parts[len(parts)-1]) {
			return fmt.Errorf("annotation key %q is invalid", key)
		}
		if len(parts) == 2 && (len(parts[0]) > 253 || !configAnnotationPrefix.MatchString(parts[0])) {
			return fmt.Errorf("annotation key %q is invalid", key)
		}
		if len(value) > 8192 {
			return fmt.Errorf("annotation %q exceeds 8192 bytes", key)
		}
	}
	return nil
}

func sameStaticSandboxPolicy(currentYAML string, next corepolicy.Document) bool {
	var current corepolicy.Document
	if strings.TrimSpace(currentYAML) == "" || yaml.Unmarshal([]byte(currentYAML), &current) != nil || current.Validate() != nil {
		return false
	}
	current.NetworkPolicies = nil
	next.NetworkPolicies = nil
	return reflect.DeepEqual(current, next)
}

func settingValueString(key, kind string, setting *sandboxv1.SettingValue) (string, error) {
	if setting == nil {
		return "", status.Error(codes.InvalidArgument, "setting value is missing")
	}
	switch kind {
	case "string":
		value, ok := setting.GetValue().(*sandboxv1.SettingValue_StringValue)
		if !ok {
			return "", status.Error(codes.InvalidArgument, "expected string setting")
		}
		allowed := map[string][]string{"ocsf_schema_version": {"", "1.1", "1.3"}, "proposal_approval_mode": {"manual", "auto"}}
		if choices, constrained := allowed[key]; constrained {
			valid := false
			for _, choice := range choices {
				valid = valid || value.StringValue == choice
			}
			if !valid {
				return "", status.Errorf(codes.InvalidArgument, "setting %q has an unsupported value", key)
			}
		}
		return value.StringValue, nil
	case "bool":
		value, ok := setting.GetValue().(*sandboxv1.SettingValue_BoolValue)
		if !ok {
			return "", status.Error(codes.InvalidArgument, "expected bool setting")
		}
		return strconv.FormatBool(value.BoolValue), nil
	case "int":
		value, ok := setting.GetValue().(*sandboxv1.SettingValue_IntValue)
		if !ok {
			return "", status.Error(codes.InvalidArgument, "expected int setting")
		}
		return strconv.FormatInt(value.IntValue, 10), nil
	default:
		return "", status.Errorf(codes.InvalidArgument, "unknown setting type %q", kind)
	}
}

func isConfigAdmin(p Principal, configuredAdminRole string) bool {
	if p.Kind != PrincipalUser {
		return false
	}
	if p.IDP == "local" || p.IDP == "local_dev" {
		return true
	}
	roles := append([]string(nil), p.Roles...)
	if configuredAdminRole != "" {
		for _, role := range roles {
			if role == configuredAdminRole {
				return true
			}
		}
	}
	return containsString(roles, "platform_admin") || containsString(roles, "platform-admin") || containsString(roles, "openshell-admin")
}

func (s *openShellRPC) requireSandboxConfigWrite(p Principal, workspace string) error {
	if p.IDP == "local" || p.IDP == "local_dev" {
		return nil
	}
	if !containsString(p.Scopes, "config:write") && !containsString(p.Scopes, "openshell:all") {
		return status.Error(codes.PermissionDenied, "config:write scope required")
	}
	if workspace == "" {
		workspace = "default"
	}
	ws, ok := s.runtime.st.GetWorkspace(workspace)
	if !ok {
		return status.Error(codes.NotFound, "workspace not found")
	}
	for _, member := range ws.Members {
		if member.Subject == p.Subject && (strings.EqualFold(member.Role, "owner") || strings.EqualFold(member.Role, "admin")) {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "workspace admin access required")
}
