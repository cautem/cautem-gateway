package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-providers/provider"
	"github.com/cautem/cautem-runtime/secrets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

// GetSandboxConfig returns the effective policy/settings snapshot and selected
// statically configured supervisor middleware services.
func (s *openShellRPC) GetSandboxConfig(ctx context.Context, req *sandboxv1.GetSandboxConfigRequest) (*sandboxv1.GetSandboxConfigResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "sandbox config runtime is not initialized")
	}
	id := strings.TrimSpace(req.GetSandboxId())
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id is required")
	}
	sandbox, ok := s.runtime.st.GetSandbox(id)
	if !ok {
		sandbox, ok = s.runtime.st.GetSandboxByID(id)
	}
	if !ok {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	principal := PrincipalFrom(ctx)
	if principal.Kind == PrincipalSandbox {
		if principal.Sandbox != sandbox.Name && principal.Sandbox != sandbox.ID {
			return nil, status.Error(codes.PermissionDenied, "sandbox principal cannot read another sandbox config")
		}
	} else if err := s.requireSandboxConfigRead(principal, sandbox.Workspace); err != nil {
		return nil, err
	}

	policyYAML, globalPolicyRevision := s.runtime.st.GlobalPolicySnapshot()
	source := sandboxv1.PolicySource_POLICY_SOURCE_GLOBAL
	version := uint32(0)
	if strings.TrimSpace(policyYAML) != "" {
		version = uint32(sandbox.PolicyRev)
		if version == 0 {
			version = 1
		}
	}
	globalPolicyVersion := uint32(0)
	if source == sandboxv1.PolicySource_POLICY_SOURCE_GLOBAL && strings.TrimSpace(policyYAML) != "" && globalPolicyRevision <= uint64(^uint32(0)) {
		globalPolicyVersion = uint32(globalPolicyRevision)
	}
	if strings.TrimSpace(policyYAML) == "" {
		policyYAML = sandbox.BasePolicyYAML
		source = sandboxv1.PolicySource_POLICY_SOURCE_SANDBOX
		if strings.TrimSpace(policyYAML) == "" && len(sandbox.PolicyRevisions) > 0 {
			latest := sandbox.PolicyRevisions[len(sandbox.PolicyRevisions)-1]
			policyYAML = latest.YAML
			if latest.Rev > 0 {
				version = uint32(latest.Rev)
			}
		}
		if sandbox.PolicyRev > 0 {
			version = uint32(sandbox.PolicyRev)
		}
	}
	var policyMessage *sandboxv1.SandboxPolicy
	var policyBytes []byte
	policyHash := ""
	if strings.TrimSpace(policyYAML) != "" {
		var doc policy.Document
		var err error
		if err := yaml.Unmarshal([]byte(policyYAML), &doc); err != nil {
			return nil, status.Error(codes.FailedPrecondition, "stored sandbox policy is invalid")
		}
		if err := doc.Validate(); err != nil {
			return nil, status.Error(codes.FailedPrecondition, "stored sandbox policy is invalid")
		}
		if doc.Version == 0 {
			return nil, status.Error(codes.FailedPrecondition, "stored sandbox policy has no version")
		}
		if source == sandboxv1.PolicySource_POLICY_SOURCE_SANDBOX && len(sandbox.AttachedProviders) > 0 {
			doc, err = composeStoredSandboxProviderPolicy(s.runtime.st, sandbox, doc, s.runtime.opt.ProviderProfileSources)
			if err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "provider policy composition failed: %v", err)
			}
		}
		if version == 0 {
			version = doc.Version
		}
		policyMessage, err = policyDocumentToProto(doc)
		if err != nil {
			return nil, status.Error(codes.FailedPrecondition, "stored sandbox policy is incompatible with the OpenShell policy schema")
		}
		policyBytes, err = proto.MarshalOptions{Deterministic: true}.Marshal(policyMessage)
		if err != nil {
			return nil, status.Error(codes.Internal, "could not serialize sandbox policy")
		}
		policyDigest := sha256.Sum256(policyBytes)
		policyHash = hex.EncodeToString(policyDigest[:])
	}
	middlewareServices, err := requiredSupervisorMiddlewareServices(policyMessage, s.options.SupervisorMiddlewareServices)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "effective policy middleware registration is invalid: %v", err)
	}
	if s.runtime.drivers != nil {
		if err := s.runtime.drivers.validateMiddlewareConfigs(ctx, policyMessage); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "effective policy middleware configuration is invalid: %v", err)
		}
	}

	globalSettings, _ := s.runtime.st.SettingsSnapshot()
	effective := make(map[string]*sandboxv1.EffectiveSetting, len(registeredOpenShellSettings))
	for key, kind := range registeredOpenShellSettings {
		item := &sandboxv1.EffectiveSetting{Scope: sandboxv1.SettingScope_SETTING_SCOPE_UNSPECIFIED, Value: &sandboxv1.SettingValue{}}
		if raw, exists := sandbox.Settings[key]; exists {
			value, err := settingValue(kind, raw)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "stored setting %q is invalid", key)
			}
			item.Value = value
			item.Scope = sandboxv1.SettingScope_SETTING_SCOPE_SANDBOX
		}
		if raw, exists := globalSettings[key]; exists {
			value, err := settingValue(kind, raw)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "stored setting %q is invalid", key)
			}
			item.Value = value
			item.Scope = sandboxv1.SettingScope_SETTING_SCOPE_GLOBAL
		}
		effective[key] = item
	}
	failureMode := strings.TrimSpace(s.options.PolicyValidationFailureMode)
	if failureMode == "" {
		failureMode = "fail_closed"
	}
	configInput, err := json.Marshal(struct {
		Policy        []byte                                   `json:"policy"`
		Source        sandboxv1.PolicySource                   `json:"source"`
		Settings      map[string]*sandboxv1.EffectiveSetting   `json:"settings"`
		FailureMode   string                                   `json:"failure_mode"`
		ExtensionAuth bool                                     `json:"extension_authentication_enabled"`
		Middleware    []*sandboxv1.SupervisorMiddlewareService `json:"middleware_services"`
	}{policyBytes, source, effective, failureMode, false, middlewareServices})
	if err != nil {
		return nil, status.Error(codes.Internal, "could not fingerprint effective sandbox config")
	}
	configDigest := sha256.Sum256(configInput)
	configRevision := uint64(0)
	for i := 0; i < 8; i++ {
		configRevision = configRevision<<8 | uint64(configDigest[i])
	}
	if configRevision == 0 {
		configRevision = 1
	}
	providerEnvRevision, err := providerEnvironmentRevision(ctx, s.runtime.st, s.runtime.sec, sandbox, s.runtime.opt.ProviderProfileSources)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "provider environment revision is unavailable")
	}

	return &sandboxv1.GetSandboxConfigResponse{
		Policy: policyMessage, Version: version, PolicyHash: policyHash,
		Settings: effective, ConfigRevision: configRevision, PolicySource: source,
		ProviderEnvRevision:          providerEnvRevision,
		GlobalPolicyVersion:          globalPolicyVersion,
		SupervisorMiddlewareServices: middlewareServices,
		Workspace:                    sandbox.Workspace, PolicyValidationFailureMode: failureMode,
	}, nil
}

func composeStoredSandboxProviderPolicy(st *store.Store, sandbox store.Sandbox, base policy.Document, profileSources []string) (policy.Document, error) {
	layers := make([]provider.Layer, 0, len(sandbox.AttachedProviders))
	for _, name := range sandbox.AttachedProviders {
		instance, ok := st.GetProvider(name)
		if !ok {
			return policy.Document{}, fmt.Errorf("attached provider %q is missing", name)
		}
		profile, _, err := resolveProfileForWorkspaceWithSources(st, BuiltinProvidersDir(), instance.Type, sandbox.Workspace, profileSources)
		if err != nil {
			return policy.Document{}, err
		}
		keys := append([]string(nil), instance.EnvVars...)
		if len(keys) == 0 {
			keys = profile.EnvKeys()
		}
		layers = append(layers, provider.Layer{InstanceName: name, Profile: profile, EnvVars: keys})
	}
	effective, err := provider.EffectivePolicy(base, layers, false)
	if err != nil {
		return policy.Document{}, err
	}
	if err := effective.Validate(); err != nil {
		return policy.Document{}, err
	}
	return effective, nil
}

func policyDocumentToProto(doc policy.Document) (*sandboxv1.SandboxPolicy, error) {
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}
	if filesystem, exists := fields["filesystem_policy"]; exists {
		fields["filesystem"] = filesystem
		delete(fields, "filesystem_policy")
	}
	if len(doc.NetworkMiddlewares) > 0 {
		middlewares := make(map[string]any, len(doc.NetworkMiddlewares))
		for name, node := range doc.NetworkMiddlewares {
			var config any
			if err := node.Decode(&config); err != nil {
				return nil, err
			}
			middlewares[name] = config
		}
		fields["network_middlewares"] = middlewares
	}
	encoded, err = json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	message := &sandboxv1.SandboxPolicy{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(encoded, message); err != nil {
		return nil, err
	}
	return message, nil
}

func providerEnvironmentRevision(ctx context.Context, st *store.Store, sec *secrets.LocalEncrypted, sandbox store.Sandbox, profileSources []string) (uint64, error) {
	type providerState struct {
		Name             string           `json:"name"`
		Type             string           `json:"type"`
		Workspace        string           `json:"workspace"`
		EnvVars          []string         `json:"env_vars"`
		CredentialExpiry map[string]int64 `json:"credential_expiry"`
		Runtime          bool             `json:"runtime_credentials"`
		Profile          json.RawMessage  `json:"profile"`
		CredentialHash   string           `json:"credential_hash"`
	}
	states := make([]providerState, 0, len(sandbox.AttachedProviders))
	for _, name := range sandbox.AttachedProviders {
		record, ok := st.GetProvider(name)
		if !ok {
			return 0, fmt.Errorf("attached provider %q is missing", name)
		}
		profile, _, err := resolveProfileForWorkspaceWithSources(st, BuiltinProvidersDir(), record.Type, sandbox.Workspace, profileSources)
		if err != nil {
			return 0, fmt.Errorf("provider profile is unavailable")
		}
		profileJSON, err := json.Marshal(profile)
		if err != nil {
			return 0, fmt.Errorf("provider profile cannot be fingerprinted")
		}
		keys := append([]string(nil), record.EnvVars...)
		if len(keys) == 0 {
			keys = profile.EnvKeys()
		}
		sort.Strings(keys)
		credentials := map[string]string{}
		if sec != nil {
			credentials, err = sec.GetProviderCredentials(ctx, name, keys)
			if err != nil {
				return 0, fmt.Errorf("provider credentials cannot be fingerprinted")
			}
		}
		credentialJSON, err := json.Marshal(credentials)
		if err != nil {
			return 0, fmt.Errorf("provider credentials cannot be fingerprinted")
		}
		credentialDigest := sha256.Sum256(credentialJSON)
		state := providerState{
			Name: name, Type: record.Type, Workspace: record.Workspace,
			EnvVars: keys, CredentialExpiry: record.CredentialExpiresAtMS,
			Runtime: record.RuntimeCredentials, Profile: profileJSON,
			CredentialHash: hex.EncodeToString(credentialDigest[:]),
		}
		states = append(states, state)
	}
	encoded, err := json.Marshal(states)
	if err != nil {
		return 0, fmt.Errorf("provider state cannot be fingerprinted")
	}
	digest := sha256.Sum256(encoded)
	var revision uint64
	for i := 0; i < 8; i++ {
		revision = revision<<8 | uint64(digest[i])
	}
	if revision == 0 {
		return 1, nil
	}
	return revision, nil
}

func (s *openShellRPC) requireSandboxConfigRead(p Principal, workspace string) error {
	if p.Kind != PrincipalUser {
		return status.Error(codes.Unauthenticated, "authenticated user required")
	}
	if p.IDP == "local" || p.IDP == "local_dev" {
		return nil
	}
	if !containsString(p.Scopes, "config:read") && !containsString(p.Scopes, "openshell:all") {
		return status.Error(codes.PermissionDenied, "config:read scope required")
	}
	if workspace == "" {
		workspace = "default"
	}
	ws, ok := s.runtime.st.GetWorkspace(workspace)
	if !ok {
		return status.Error(codes.NotFound, "workspace not found")
	}
	for _, member := range ws.Members {
		if member.Subject == p.Subject {
			switch strings.ToLower(strings.TrimSpace(member.Role)) {
			case "owner", "admin", "user", "member", "reader", "viewer":
				return nil
			}
		}
	}
	return status.Error(codes.PermissionDenied, "workspace sandbox config access required")
}

var registeredOpenShellSettings = map[string]string{
	"ocsf_json_enabled":              "bool",
	"ocsf_schema_version":            "string",
	"agent_policy_proposals_enabled": "bool",
	"proposal_approval_mode":         "string",
}

func settingValue(kind, raw string) (*sandboxv1.SettingValue, error) {
	switch kind {
	case "string":
		return &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_StringValue{StringValue: raw}}, nil
	case "bool":
		value, err := parseRegisteredBool(raw)
		if err != nil {
			return nil, err
		}
		return &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_BoolValue{BoolValue: value}}, nil
	case "int":
		value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return nil, err
		}
		return &sandboxv1.SettingValue{Value: &sandboxv1.SettingValue_IntValue{IntValue: value}}, nil
	default:
		return nil, fmt.Errorf("unknown setting type %q", kind)
	}
}

func parseRegisteredBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true, nil
	case "0", "false", "no", "n", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid bool %q", raw)
	}
}
