package httpapi

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-providers/provider"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// staticCredentialEndpointBindings derives the only destinations where a
// static provider key may be resolved. Audit-only rules cannot authorize
// secret delivery because they do not enforce the endpoint boundary.
func staticCredentialEndpointBindings(doc policy.Document) map[string]*compatv1.StaticCredentialBinding {
	out := map[string]*compatv1.StaticCredentialBinding{}
	seen := map[string]map[string]struct{}{}
	for _, rule := range doc.NetworkAllows() {
		if strings.EqualFold(strings.TrimSpace(rule.Enforcement), "audit") {
			continue
		}
		host := strings.TrimSpace(rule.Host)
		if host == "" {
			continue
		}
		ports := make([]int, 0, 1+len(rule.Ports))
		if rule.Port > 0 {
			ports = append(ports, rule.Port)
		}
		ports = append(ports, rule.Ports...)
		for _, key := range rule.CredentialKeys {
			key = strings.TrimSpace(key)
			if !validEnvKey(key) {
				continue
			}
			for _, port := range ports {
				if port < 1 || port > 65535 {
					continue
				}
				endpoint := &compatv1.StaticCredentialEndpointBinding{
					Host: host,
					Port: uint32(port),
					Path: strings.TrimSpace(rule.Path),
				}
				fingerprint := endpoint.Host + "\x00" + strconv.Itoa(int(endpoint.Port)) + "\x00" + endpoint.Path
				if seen[key] == nil {
					seen[key] = map[string]struct{}{}
				}
				if _, ok := seen[key][fingerprint]; ok {
					continue
				}
				seen[key][fingerprint] = struct{}{}
				if out[key] == nil {
					out[key] = &compatv1.StaticCredentialBinding{}
				}
				out[key].Endpoints = append(out[key].Endpoints, endpoint)
			}
		}
	}
	for _, binding := range out {
		sort.Slice(binding.Endpoints, func(i, j int) bool {
			a, b := binding.Endpoints[i], binding.Endpoints[j]
			if a.Host != b.Host {
				return a.Host < b.Host
			}
			if a.Port != b.Port {
				return a.Port < b.Port
			}
			return a.Path < b.Path
		})
	}
	return out
}

func (s *compatRPCAdapter) resolveSandboxStaticCredentials(
	ctx context.Context,
	sandbox store.Sandbox,
	policyBindings map[string]*compatv1.StaticCredentialBinding,
) (map[string]string, map[string]*timestamppb.Timestamp, map[string]*compatv1.StaticCredentialBinding, compatv1.ProviderReadinessReason, error) {
	type providerSelection struct {
		record store.ProviderRecord
		keys   []string
	}

	environment := map[string]string{}
	expirations := map[string]*timestamppb.Timestamp{}
	selected := map[string][]providerSelection{}
	readiness := compatv1.ProviderReadinessReason_PROVIDER_READINESS_REASON_UNSPECIFIED
	withheld, unsupported, waiting := false, false, false
	dynamicSubjects := map[string]struct{}{}
	unknownKeyOwners := map[string]int{}
	profiles := make(map[string]provider.Profile, len(sandbox.AttachedProviders))
	records := make(map[string]store.ProviderRecord, len(sandbox.AttachedProviders))

	for _, name := range sandbox.AttachedProviders {
		record, ok := s.runtime.st.GetProvider(name)
		if !ok {
			withheld = true
			continue
		}
		if !providerInWorkspace(record, sandbox.Workspace) {
			withheld = true
			addUnknownCredentialKeyOwners(unknownKeyOwners, record.EnvVars)
			continue
		}
		profile, _, err := resolveProfileForWorkspaceWithSources(
			s.runtime.st, BuiltinProvidersDir(), record.Type, sandbox.Workspace, s.runtime.opt.ProviderProfileSources,
		)
		if err != nil {
			withheld = true
			addUnknownCredentialKeyOwners(unknownKeyOwners, record.EnvVars)
			continue
		}
		records[name] = record
		profiles[name] = profile
		for _, credential := range profile.Credentials {
			if credential.TokenGrant == nil || credential.TokenGrant.SubjectToken == nil || credential.TokenGrant.SubjectToken.Source != "provider_credential" {
				continue
			}
			for _, subject := range profile.Credentials {
				if subject.Name == credential.TokenGrant.SubjectToken.Credential {
					for _, key := range subject.EnvVars {
						dynamicSubjects[strings.TrimSpace(key)] = struct{}{}
					}
				}
			}
		}
	}

	keyOwners := map[string]int{}
	for key, owners := range unknownKeyOwners {
		keyOwners[key] = owners
	}
	for name, record := range records {
		profile := profiles[name]
		keys := append([]string(nil), record.EnvVars...)
		if len(keys) == 0 {
			keys = profile.EnvKeys()
		}
		seen := map[string]struct{}{}
		for _, rawKey := range keys {
			key := strings.TrimSpace(rawKey)
			if !validEnvKey(key) {
				withheld = true
				continue
			}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			// Count every selected provider source before filtering unsupported
			// or unbound credentials. Two providers claiming the same env key
			// must never make the remaining source appear unambiguous.
			keyOwners[key]++
			credential, ok := profileCredentialForEnvKey(profile, key)
			if !ok {
				withheld = true
				continue
			}
			if _, hasBinding := policyBindings[key]; !hasBinding {
				withheld = true
				continue
			}
			if credential.TokenGrant != nil || credential.StablePlaceholder {
				unsupported = true
				continue
			}
			if _, subject := dynamicSubjects[key]; subject {
				unsupported = true
				continue
			}
			selected[key] = append(selected[key], providerSelection{record: record, keys: []string{key}})
		}
	}

	filteredBindings := map[string]*compatv1.StaticCredentialBinding{}
	for key, owners := range selected {
		if keyOwners[key] != 1 || len(owners) != 1 {
			withheld = true
			continue
		}
		filteredBindings[key] = policyBindings[key]
	}

	for key, owners := range selected {
		if keyOwners[key] != 1 || len(owners) != 1 {
			continue
		}
		selection := owners[0]
		record := selection.record
		if err := s.refreshBoundProviderCredentials(ctx, record, selection.keys); err != nil {
			return nil, nil, nil, readiness, err
		}
		if refreshed, ok := s.runtime.st.GetProvider(record.Name); ok {
			record = refreshed
		}
		var values map[string]string
		resolvedExpirations := map[string]int64{}
		var err error
		if s.runtime.drivers != nil {
			values, resolvedExpirations, err = s.runtime.drivers.resolveProviderCredentialsWithExpiry(ctx, record, selection.keys, s.runtime.sec)
		} else {
			values, err = resolveProviderCredentialsForRecord(ctx, s.runtime.sec, nil, record, selection.keys)
		}
		if err != nil {
			return nil, nil, nil, readiness, err
		}
		if len(resolvedExpirations) > 0 {
			if record.CredentialExpiresAtMS == nil {
				record.CredentialExpiresAtMS = map[string]int64{}
			}
			changed := false
			for credentialKey, expiresAt := range resolvedExpirations {
				if record.CredentialExpiresAtMS[credentialKey] != expiresAt {
					record.CredentialExpiresAtMS[credentialKey] = expiresAt
					changed = true
				}
			}
			if changed {
				if err := s.runtime.st.UpsertProvider(record); err != nil {
					return nil, nil, nil, readiness, err
				}
			}
		}
		value := strings.TrimSpace(values[key])
		if value == "" {
			profile := profiles[record.Name]
			if profileCredentialRequiredForEnvKey(profile, key) {
				waiting = true
			}
			continue
		}
		environment[key] = values[key]
		expiresAt := resolvedExpirations[key]
		if expiresAt == 0 {
			expiresAt = record.CredentialExpiresAtMS[key]
		}
		if expiresAt > 0 {
			if expiresAt <= time.Now().UnixMilli() {
				return nil, nil, nil, readiness, errExpiredProviderCredential
			}
			expirations[key] = timestamppb.New(time.UnixMilli(expiresAt))
		}
	}

	switch {
	case unsupported:
		readiness = compatv1.ProviderReadinessReason_PROVIDER_READINESS_REASON_UNSUPPORTED_SUPERVISOR
	case withheld:
		readiness = compatv1.ProviderReadinessReason_PROVIDER_READINESS_REASON_CREDENTIALS_WITHHELD
	case waiting:
		readiness = compatv1.ProviderReadinessReason_PROVIDER_READINESS_REASON_WAITING_FOR_CREDENTIALS
	}
	return environment, expirations, filteredBindings, readiness, nil
}

func addUnknownCredentialKeyOwners(owners map[string]int, keys []string) {
	seen := map[string]struct{}{}
	for _, rawKey := range keys {
		key := strings.TrimSpace(rawKey)
		if !validEnvKey(key) {
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		owners[key]++
	}
}

func profileCredentialForEnvKey(profile provider.Profile, key string) (provider.Credential, bool) {
	var found provider.Credential
	count := 0
	for _, credential := range profile.Credentials {
		for _, envKey := range credential.EnvVars {
			if strings.TrimSpace(envKey) == key {
				found = credential
				count++
			}
		}
	}
	return found, count == 1
}

func profileCredentialRequiredForEnvKey(profile provider.Profile, key string) bool {
	credential, ok := profileCredentialForEnvKey(profile, key)
	return ok && credential.Required
}

func (s *compatRPCAdapter) refreshBoundProviderCredentials(ctx context.Context, record store.ProviderRecord, keys []string) error {
	owners := map[string]struct{}{}
	now := time.Now().UnixMilli()
	for _, key := range keys {
		owner := providerRefreshOwner(record, key)
		if owner == "" {
			continue
		}
		config, ok := record.Refresh[owner]
		if !ok {
			continue
		}
		expiresAt := config.ExpiresAtMS
		if expiresAt == 0 {
			expiresAt = record.CredentialExpiresAtMS[key]
		}
		if expiresAt > 0 && now+config.RefreshBeforeSeconds*1000 >= expiresAt {
			owners[owner] = struct{}{}
		}
	}
	for owner := range owners {
		if err := refreshStoredProviderCredentialWithDrivers(ctx, s.runtime.st, s.runtime.sec, s.runtime.drivers, s.runtime.opt, record.Name, owner); err != nil {
			return err
		}
	}
	return nil
}

var errExpiredProviderCredential = status.Error(codes.FailedPrecondition, "bound provider credential is expired")
