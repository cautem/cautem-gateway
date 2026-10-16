package httpapi

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-providers/provider"
	"github.com/cautem/cautem-runtime/secrets"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"gopkg.in/yaml.v3"
)

// setSandboxBasePolicy validates and stores base YAML, then returns effective YAML.
func setSandboxBasePolicy(st *store.Store, builtinDir, name string, body []byte) (effective []byte, stripped int, err error) {
	return setSandboxBasePolicyWithSources(st, builtinDir, name, body, nil)
}

func setSandboxBasePolicyWithSources(st *store.Store, builtinDir, name string, body []byte, profileSources []string) (effective []byte, stripped int, err error) {
	if _, ok := st.GetSandbox(name); !ok {
		return nil, 0, fmt.Errorf("sandbox %q not found", name)
	}
	doc, err := policy.Parse(body)
	if err != nil {
		return nil, 0, fmt.Errorf("base policy: %w", err)
	}
	doc, stripped = provider.OmitProviderComposed(doc)
	if err := doc.Validate(); err != nil {
		return nil, 0, fmt.Errorf("base policy: %w", err)
	}
	storeYAML := body
	if stripped > 0 {
		storeYAML, err = yaml.Marshal(doc)
		if err != nil {
			return nil, 0, err
		}
	}
	prev, _ := st.GetSandbox(name)
	prevBase := prev.BasePolicyYAML
	if err := st.SetBasePolicy(name, string(storeYAML)); err != nil {
		return nil, 0, err
	}
	effDoc, err := effectivePolicyWithSources(st, builtinDir, name, profileSources)
	if err != nil {
		_ = st.SetBasePolicy(name, prevBase) // roll back
		return nil, 0, fmt.Errorf("effective policy: %w", err)
	}
	b, err := yaml.Marshal(effDoc)
	if err != nil {
		_ = st.SetBasePolicy(name, prevBase)
		return nil, 0, err
	}
	return b, stripped, nil
}

func setSandboxBasePolicyWithSourcesExpected(st *store.Store, builtinDir, name string, body []byte, profileSources []string, expected int) (effective []byte, stripped int, revision int, err error) {
	if _, ok := st.GetSandbox(name); !ok {
		return nil, 0, 0, fmt.Errorf("sandbox %q not found", name)
	}
	doc, err := policy.Parse(body)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("base policy: %w", err)
	}
	doc, stripped = provider.OmitProviderComposed(doc)
	if err := doc.Validate(); err != nil {
		return nil, 0, 0, fmt.Errorf("base policy: %w", err)
	}
	storeYAML := body
	if stripped > 0 {
		storeYAML, err = yaml.Marshal(doc)
		if err != nil {
			return nil, 0, 0, err
		}
	}
	previous, _ := st.GetSandbox(name)
	newRevision, updated, err := st.SetBasePolicyIfRevision(name, string(storeYAML), expected)
	if err != nil {
		return nil, 0, 0, err
	}
	if !updated {
		return nil, 0, newRevision, fmt.Errorf("sandbox policy revision changed")
	}
	effectiveDoc, err := effectivePolicyWithSources(st, builtinDir, name, profileSources)
	if err != nil {
		_ = st.SetBasePolicy(name, previous.BasePolicyYAML)
		return nil, 0, 0, fmt.Errorf("effective policy: %w", err)
	}
	effective, err = yaml.Marshal(effectiveDoc)
	if err != nil {
		_ = st.SetBasePolicy(name, previous.BasePolicyYAML)
		return nil, 0, 0, err
	}
	return effective, stripped, newRevision, nil
}

func resolveSandboxSecrets(ctx context.Context, st *store.Store, sec *secrets.LocalEncrypted, builtinDir, sandbox string) (map[string]string, error) {
	return resolveSandboxSecretsWithSources(ctx, st, sec, builtinDir, sandbox, nil)
}

func resolveSandboxSecretsWithSources(ctx context.Context, st *store.Store, sec *secrets.LocalEncrypted, builtinDir, sandbox string, profileSources []string) (map[string]string, error) {
	return resolveSandboxSecretsWithSourcesAndDrivers(ctx, st, sec, nil, Options{}, builtinDir, sandbox, profileSources)
}

func resolveProviderCredentialsForRecord(ctx context.Context, sec *secrets.LocalEncrypted, drivers *driverRegistry, record store.ProviderRecord, keys []string) (map[string]string, error) {
	if drivers != nil && record.CredentialDriver != "" {
		values, _, err := drivers.resolveProviderCredentialsWithExpiry(ctx, record, keys, sec)
		return values, err
	}
	if sec == nil {
		return nil, fmt.Errorf("local credential storage is not initialized")
	}
	return sec.GetProviderCredentials(ctx, record.Name, keys)
}

func resolveSandboxSecretsWithSourcesAndDrivers(ctx context.Context, st *store.Store, sec *secrets.LocalEncrypted, drivers *driverRegistry, opt Options, builtinDir, sandbox string, profileSources []string) (map[string]string, error) {
	sb, ok := st.GetSandbox(sandbox)
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", sandbox)
	}
	out := map[string]string{}
	if sec == nil && drivers == nil {
		return out, nil
	}
	for _, pname := range sb.AttachedProviders {
		inst, ok := st.GetProvider(pname)
		if !ok {
			continue
		}
		for key, cfg := range inst.Refresh {
			expiresAt := cfg.ExpiresAtMS
			if expiresAt == 0 {
				expiresAt = inst.CredentialExpiresAtMS[key]
			}
			if expiresAt == 0 {
				continue // no known expiry; first rotation remains an explicit operation
			}
			refreshAt := time.Now().Add(time.Duration(cfg.RefreshBeforeSeconds) * time.Second).UnixMilli()
			if refreshAt >= expiresAt {
				if err := refreshStoredProviderCredentialWithDrivers(ctx, st, sec, drivers, opt, pname, key); err != nil {
					return nil, fmt.Errorf("provider %s credential %s refresh: %w", pname, key, err)
				}
				// Refresh updates the durable expiry and may rotate the set of
				// output keys; use the fresh record for the fail-closed check below.
				inst, _ = st.GetProvider(pname)
			}
		}
		now := time.Now().UnixMilli()
		for key, expiresAt := range inst.CredentialExpiresAtMS {
			if expiresAt > 0 && expiresAt <= now {
				return nil, fmt.Errorf("provider %s credential %s is expired", pname, key)
			}
		}
		keys := inst.EnvVars
		if len(keys) == 0 {
			if prof, _, err := resolveProfileForWorkspaceWithSources(st, builtinDir, inst.Type, sb.Workspace, profileSources); err == nil {
				keys = prof.EnvKeys()
			}
		}
		var creds map[string]string
		var resolvedExpiry map[string]int64
		var err error
		if drivers != nil {
			creds, resolvedExpiry, err = drivers.resolveProviderCredentialsWithExpiry(ctx, inst, keys, sec)
		} else {
			creds, err = sec.GetProviderCredentials(ctx, pname, keys)
		}
		if err != nil {
			return nil, err
		}
		if len(resolvedExpiry) > 0 {
			if inst.CredentialExpiresAtMS == nil {
				inst.CredentialExpiresAtMS = map[string]int64{}
			}
			changed := false
			for key, expiresAt := range resolvedExpiry {
				if inst.CredentialExpiresAtMS[key] != expiresAt {
					inst.CredentialExpiresAtMS[key] = expiresAt
					changed = true
				}
			}
			if changed {
				if err := st.UpsertProvider(inst); err != nil {
					return nil, fmt.Errorf("persist credential expiry: %w", err)
				}
			}
		}
		maps.Copy(out, creds)
	}
	aliasGitHubTokenKeys(out)
	return out, nil
}

// aliasGitHubTokenKeys mirrors GITHUB_TOKEN ↔ GH_TOKEN so guest/policy can use either
// name while the provider instance only stores one key.
func aliasGitHubTokenKeys(out map[string]string) {
	if out == nil {
		return
	}
	gh, hasGH := out["GITHUB_TOKEN"]
	tok, hasTok := out["GH_TOKEN"]
	if hasGH && strings.TrimSpace(gh) != "" && !hasTok {
		out["GH_TOKEN"] = gh
	}
	if hasTok && strings.TrimSpace(tok) != "" && !hasGH {
		out["GITHUB_TOKEN"] = tok
	}
}

func listProfilesWithSources(st *store.Store, builtinDir, workspace string, profileSources []string) []map[string]string {
	profileSources = effectiveProviderProfileSources(profileSources)
	catalog := map[string]map[string]string{}
	workspaceOverrides := map[string]bool{}
	if providerProfileSourceEnabled(profileSources, "builtin") && builtinDir != "" {
		if m, err := provider.LoadDir(builtinDir); err == nil {
			for id, prof := range m {
				catalog[id] = map[string]string{"id": id, "category": prof.Category, "source": "builtin", "scope": "builtin"}
			}
		}
	}
	if providerProfileSourceEnabled(profileSources, "user") {
		for key, rec := range st.Snapshot().Profiles {
			isWorkspace := rec.Scope == "workspace" || strings.HasPrefix(key, "workspace/")
			if isWorkspace && (workspace == "" || rec.Workspace != workspace) {
				continue
			}
			if !isWorkspace && workspace == "" && rec.Workspace != "" {
				continue
			}
			id := rec.ID
			if !isWorkspace && workspaceOverrides[id] {
				continue
			}
			category := ""
			if prof, err := provider.ParseYAML([]byte(rec.YAML)); err == nil {
				category = prof.Category
			}
			scope := "global"
			if isWorkspace {
				scope = "workspace"
			}
			catalog[id] = map[string]string{"id": id, "category": category, "source": "custom", "scope": scope}
			if isWorkspace {
				workspaceOverrides[id] = true
			}
		}
	}
	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, catalog[id])
	}
	return out
}

func resolveProfileForWorkspaceWithSources(st *store.Store, builtinDir, id, workspace string, profileSources []string) (provider.Profile, string, error) {
	profileSources = effectiveProviderProfileSources(profileSources)
	if providerProfileSourceEnabled(profileSources, "user") {
		if rec, ok := st.GetProfileScoped(id, workspace); ok {
			p, err := provider.ParseYAML([]byte(rec.YAML))
			p.Source = "user"
			p.Scope = "platform"
			if rec.Scope == "workspace" || rec.Workspace != "" {
				p.Scope = "workspace"
			}
			return p, "custom", err
		}
	}
	if providerProfileSourceEnabled(profileSources, "builtin") && builtinDir != "" {
		path := filepath.Join(builtinDir, id+".yaml")
		if _, err := os.Stat(path); err == nil {
			p, err := provider.LoadFile(path)
			p.Source, p.Scope = "builtin", ""
			return p, "builtin", err
		}
		path = filepath.Join(builtinDir, id+".yml")
		if _, err := os.Stat(path); err == nil {
			p, err := provider.LoadFile(path)
			p.Source, p.Scope = "builtin", ""
			return p, "builtin", err
		}
	}
	return provider.Profile{}, "", fmt.Errorf("profile %q not found", id)
}

func effectiveProviderProfileSources(configured []string) []string {
	if configured == nil {
		return []string{"builtin", "user"}
	}
	return append([]string(nil), configured...)
}

func providerProfileSourceEnabled(sources []string, source string) bool {
	for _, configured := range sources {
		if configured == source {
			return true
		}
	}
	return false
}

func effectivePolicyWithSources(st *store.Store, builtinDir, sandbox string, profileSources []string) (policy.Document, error) {
	globalYAML, _ := st.GlobalPolicySnapshot()
	return effectivePolicyWithGlobalPolicy(st, builtinDir, sandbox, profileSources, globalYAML)
}

func effectivePolicyWithGlobalPolicy(st *store.Store, builtinDir, sandbox string, profileSources []string, globalYAML string) (policy.Document, error) {
	sb, ok := st.GetSandbox(sandbox)
	if !ok {
		return policy.Document{}, fmt.Errorf("sandbox %q not found", sandbox)
	}
	if strings.TrimSpace(globalYAML) != "" {
		effective, err := parseGlobalPolicyYAML(globalYAML)
		if err != nil {
			return policy.Document{}, err
		}
		if err := enrichProxyBaselineFilesystem(&effective); err != nil {
			return policy.Document{}, err
		}
		return effective, nil
	}
	var base policy.Document
	hasSandboxPolicy := strings.TrimSpace(sb.BasePolicyYAML) != ""
	if hasSandboxPolicy {
		doc, err := policy.Parse([]byte(sb.BasePolicyYAML))
		if err != nil {
			return policy.Document{}, err
		}
		base = doc
	} else {
		base = restrictiveDefaultPolicy()
	}
	var layers []provider.Layer
	for _, name := range sb.AttachedProviders {
		inst, ok := st.GetProvider(name)
		if !ok {
			continue
		}
		prof, _, err := resolveProfileForWorkspaceWithSources(st, builtinDir, inst.Type, sb.Workspace, profileSources)
		if err != nil {
			return policy.Document{}, err
		}
		envVars := append([]string(nil), inst.EnvVars...)
		if len(envVars) == 0 {
			envVars, err = prof.DiscoverEnvVars()
			if err != nil {
				return policy.Document{}, err
			}
		}
		layers = append(layers, provider.Layer{
			InstanceName: name,
			Profile:      prof,
			EnvVars:      envVars,
		})
	}
	effective, err := provider.EffectivePolicy(base, layers, false)
	if err != nil {
		return policy.Document{}, err
	}
	if err := enrichProxyBaselineFilesystem(&effective); err != nil {
		return policy.Document{}, err
	}
	return effective, nil
}

// BuiltinProvidersDir resolves the provider-module profile catalog or packaged catalog.
func BuiltinProvidersDir() string {
	return provider.FindBuiltinDir()
}
