package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/quarshell-core/defaults"
	coreenv "github.com/cautem/quarshell-core/env"
	"github.com/cautem/quarshell-core/policy"
	"github.com/cautem/quarshell-providers/provider"
	"gopkg.in/yaml.v3"
)

type sandboxRuntimeInputs struct {
	gatewayID       string
	basePolicy      policy.Document
	effectivePolicy policy.Document
	baseYAML        []byte
	effectiveYAML   []byte
	attached        []string
	env             []string
	proxyEnv        []string
	policyPath      string
	gatewayURL      string
	proxyBin        string
	initBin         string
	sshBin          string
	supervisorBin   string
}

func (s *compatRPCAdapter) prepareSandboxRuntime(req *compatv1.CreateSandboxRequest, driverName, name, workspace string) (sandboxRuntimeInputs, error) {
	out := sandboxRuntimeInputs{gatewayID: strings.TrimSpace(s.runtime.st.Snapshot().GatewayID)}
	if out.gatewayID == "" {
		return out, fmt.Errorf("gateway installation identity is unavailable")
	}
	var err error
	var sandboxPolicy policy.Document
	hasSandboxPolicy := req.GetSpec().GetPolicy() != nil
	if hasSandboxPolicy {
		sandboxPolicy, err = parseSandboxPolicy(req.GetSpec().GetPolicy())
		if err != nil {
			return out, err
		}
		out.baseYAML, err = yaml.Marshal(sandboxPolicy)
		if err != nil {
			return out, err
		}
	}
	globalYAML, _ := s.runtime.st.GlobalPolicySnapshot()
	hasGlobalPolicy := strings.TrimSpace(globalYAML) != ""
	var effective policy.Document
	switch {
	case hasGlobalPolicy:
		effective, err = parseGlobalPolicyYAML(globalYAML)
		if err != nil {
			return out, err
		}
		// A global policy is complete and takes precedence over both sandbox
		// policy and provider layers. Keep any explicit sandbox policy as its
		// own stored source policy, but do not compose it into the runtime one.
	case hasSandboxPolicy:
		effective = sandboxPolicy
	default:
		effective = restrictiveDefaultPolicy()
	}
	if err = enrichProxyBaselineFilesystem(&effective); err != nil {
		return out, err
	}
	out.basePolicy = sandboxPolicy
	out.effectivePolicy = effective
	var layers []provider.Layer
	for _, providerName := range req.GetSpec().GetProviders() {
		if hasGlobalPolicy {
			break
		}
		providerName = strings.TrimSpace(providerName)
		if providerName == "" {
			return out, fmt.Errorf("provider name must not be empty")
		}
		inst, ok := s.runtime.st.GetProvider(providerName)
		if !ok || !providerInWorkspace(inst, workspace) {
			return out, fmt.Errorf("provider %q is not available in workspace", providerName)
		}
		profile, _, err := resolveProfileForWorkspaceWithSources(s.runtime.st, BuiltinProvidersDir(), inst.Type, workspace, s.runtime.opt.ProviderProfileSources)
		if err != nil {
			return out, fmt.Errorf("provider %q profile is unavailable", providerName)
		}
		keys := append([]string(nil), inst.EnvVars...)
		if len(keys) == 0 {
			keys, err = profile.DiscoverEnvVars()
			if err != nil {
				return out, fmt.Errorf("provider %q credentials are invalid", providerName)
			}
		}
		out.attached = append(out.attached, providerName)
		layers = append(layers, provider.Layer{InstanceName: providerName, Profile: profile, EnvVars: keys})
	}
	if len(layers) > 0 {
		out.effectivePolicy, err = provider.EffectivePolicy(effective, layers, false)
		if err != nil {
			return out, fmt.Errorf("provider policy composition failed: %w", err)
		}
	}
	if err = out.effectivePolicy.Validate(); err != nil {
		return out, fmt.Errorf("sandbox policy is invalid: %w", err)
	}
	policyMessage, err := policyDocumentToProto(out.effectivePolicy)
	if err != nil {
		return out, fmt.Errorf("sandbox policy middleware config is invalid: %w", err)
	}
	middlewareEnv, err := s.supervisorMiddlewareProxyEnv(policyMessage)
	if err != nil {
		return out, err
	}
	out.effectiveYAML, err = yaml.Marshal(out.effectivePolicy)
	if err != nil {
		return out, err
	}
	policyDir := filepath.Join(s.runtime.opt.DataDir, "sandboxes", name)
	if err = os.MkdirAll(policyDir, 0o700); err != nil {
		return out, fmt.Errorf("sandbox policy storage unavailable")
	}
	out.policyPath = filepath.Join(policyDir, "policy.yaml")
	if err = os.WriteFile(out.policyPath, out.effectiveYAML, 0o600); err != nil {
		return out, fmt.Errorf("sandbox policy storage unavailable")
	}
	for _, helper := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		path, err := sandboxHelperPath(helper)
		if err != nil {
			return out, err
		}
		switch helper {
		case "cautem":
			out.proxyBin = path
		case "cautem-init":
			out.initBin = path
		case "cautem-sshd":
			out.sshBin = path
		case "cautem-supervisor":
			out.supervisorBin = path
		}
	}
	out.gatewayURL, err = sandboxGatewayURLForExecutionMode(s.runtime.opt, s.runtime.compute.configured[driverName], driverName == "vm")
	if err != nil {
		return out, err
	}
	out.env = coreenv.FromHostForGuest(out.effectivePolicy.CredentialEnvKeys()...)
	guestEnv := map[string]string{}
	for _, entry := range out.env {
		k, v, ok := strings.Cut(entry, "=")
		if ok {
			guestEnv[k] = v
		}
	}
	for k, v := range req.GetSpec().GetTemplate().GetEnvironment() {
		guestEnv[k] = v
	}
	for k, v := range req.GetSpec().GetEnvironment() {
		guestEnv[k] = v
	}
	for _, key := range out.effectivePolicy.CredentialEnvKeys() {
		guestEnv[key] = coreenv.PlaceholderPrefix + key
	}
	out.env = out.env[:0]
	for k, v := range guestEnv {
		if !validEnvKey(k) || strings.ContainsRune(v, '\x00') {
			return out, fmt.Errorf("invalid environment entry %q", k)
		}
		out.env = append(out.env, k+"="+v)
	}
	// Keep secrets and token grant metadata in the proxy sidecar only.
	out.proxyEnv = coreenv.SecretsFromHost(out.effectivePolicy.CredentialEnvKeys()...)
	for _, key := range defaults.ProxyEnvKeys {
		if value, ok := os.LookupEnv(key); ok && value != "" {
			out.proxyEnv = append(out.proxyEnv, key+"="+value)
		}
	}
	grants := map[string]sandboxTokenGrant{}
	for _, layer := range layers {
		for _, credential := range layer.Profile.Credentials {
			if credential.TokenGrant == nil {
				continue
			}
			g := credential.TokenGrant
			for _, key := range credential.EnvVars {
				if key == "" {
					continue
				}
				entry := sandboxTokenGrant{Provider: layer.InstanceName, CredentialKey: credential.Name, TokenEndpoint: g.TokenEndpoint, GrantType: g.GrantType, Audience: g.Audience, JWTSVIDAudience: g.JWTSVIDAudience, ClientAssertionType: g.ClientAssertionType, RequestedTokenType: g.RequestedTokenType, Scopes: append([]string(nil), g.Scopes...)}
				if ttl, e := time.ParseDuration(g.CacheTTL); e == nil && ttl > 0 {
					entry.CacheTTLSeconds = int64(ttl / time.Second)
				}
				if g.SubjectToken != nil {
					entry.SubjectTokenType = g.SubjectToken.SubjectTokenType
					entry.SubjectTokenCredential = g.SubjectToken.Credential
				}
				for _, override := range g.AudienceOverrides {
					entry.AudienceOverrides = append(entry.AudienceOverrides, sandboxTokenGrantOverride{Host: override.Host, Path: override.Path, Port: override.Port, Audience: override.Audience, Scopes: append([]string(nil), override.Scopes...)})
				}
				grants[key] = entry
			}
		}
	}
	if len(grants) > 0 {
		b, e := json.Marshal(grants)
		if e != nil {
			return out, fmt.Errorf("token grant configuration is invalid")
		}
		out.proxyEnv = append(out.proxyEnv, "CAUTEM_TOKEN_GRANTS="+string(b))
	}
	out.proxyEnv = append(out.proxyEnv, middlewareEnv...)
	sort.Strings(out.env)
	sort.Strings(out.proxyEnv)
	return out, nil
}

func (s *compatRPCAdapter) supervisorMiddlewareProxyEnv(policy *sandboxv1.SandboxPolicy) ([]string, error) {
	if policy == nil || len(policy.GetNetworkMiddlewares()) == 0 {
		return nil, nil
	}
	services := make(map[string]*sandboxv1.SupervisorMiddlewareService, len(s.options.SupervisorMiddlewareServices))
	for _, service := range s.options.SupervisorMiddlewareServices {
		if service != nil {
			services[service.GetName()] = service
		}
	}
	type item struct {
		Name            string         `json:"name"`
		Endpoint        string         `json:"endpoint"`
		Timeout         string         `json:"timeout,omitempty"`
		FailClosed      bool           `json:"fail_closed"`
		MaxPayloadBytes uint64         `json:"max_payload_bytes,omitempty"`
		Config          map[string]any `json:"config,omitempty"`
		TLSCAPEM        string         `json:"tls_ca_cert_pem,omitempty"`
		Order           int32          `json:"order"`
		Include         []string       `json:"include,omitempty"`
		Exclude         []string       `json:"exclude,omitempty"`
	}
	items := make([]item, 0, len(policy.GetNetworkMiddlewares()))
	for _, config := range policy.GetNetworkMiddlewares() {
		if config == nil {
			continue
		}
		service, ok := services[config.GetMiddleware()]
		if !ok {
			return nil, fmt.Errorf("middleware %q is not registered", config.GetMiddleware())
		}
		var fields map[string]any
		if config.GetConfig() != nil {
			fields = config.GetConfig().AsMap()
		}
		selector := config.GetEndpoints()
		var include, exclude []string
		if selector != nil {
			include = append([]string(nil), selector.GetInclude()...)
			exclude = append([]string(nil), selector.GetExclude()...)
		}
		items = append(items, item{Name: config.GetMiddleware(), Endpoint: service.GetGrpcEndpoint(), Timeout: service.GetRequestTimeout().AsDuration().String(), FailClosed: strings.ToLower(config.GetOnError()) != "fail_open", MaxPayloadBytes: service.GetMaxPayloadBytes(), Config: fields, TLSCAPEM: base64.StdEncoding.EncodeToString(service.GetTlsCaCertPem()), Order: config.GetOrder(), Include: include, Exclude: exclude})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Order != items[j].Order {
			return items[i].Order < items[j].Order
		}
		return items[i].Name < items[j].Name
	})
	encoded, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("serialize supervisor middleware configuration: %w", err)
	}
	return []string{"CAUTEM_SUPERVISOR_MIDDLEWARES=" + string(encoded)}, nil
}
