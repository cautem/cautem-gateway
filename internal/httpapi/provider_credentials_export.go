package httpapi

import (
	"context"
	"strings"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-providers/provider"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maxProviderCredentialKeys     = 32
	maxProviderCredentialKeyBytes = 256
	maxProviderCredentialResponse = 1 << 20
	defaultCredentialLifetime     = 5 * time.Minute
	maxCredentialLifetime         = 24 * time.Hour
)

// GetProviderCredentials exports selected usable runtime values to a directly
// authenticated operator. Refresh materials and token-grant inputs are never
// returned by this endpoint.
func (s *compatRPCAdapter) GetProviderCredentials(ctx context.Context, req *compatv1.GetProviderCredentialsRequest) (*compatv1.GetProviderCredentialsResponse, error) {
	if s.runtime == nil || s.runtime.st == nil || s.runtime.sec == nil {
		return nil, status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	principal := PrincipalFrom(ctx)
	if principal.Kind != PrincipalUser || principal.IDP != "mtls" || !containsString(principal.Roles, "operator") {
		return nil, status.Error(codes.PermissionDenied, "verified mTLS operator identity required")
	}
	workspace, name, keys, lifetime, err := validateProviderCredentialRequest(req)
	if err != nil {
		return nil, err
	}
	if _, ok := s.runtime.st.GetWorkspace(workspace); !ok {
		return nil, status.Error(codes.NotFound, "workspace not found")
	}
	record, ok := s.runtime.st.GetProvider(name)
	if !ok || !providerInWorkspace(record, workspace) {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	profile, _, err := resolveProfileForWorkspaceWithSources(s.runtime.st, BuiltinProvidersDir(), record.Type, record.Workspace, s.runtime.opt.ProviderProfileSources)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "provider has no supported runtime credential profile")
	}
	if err := validateExportableProviderKeys(profile, record, keys); err != nil {
		return nil, err
	}

	// Refresh only selected credentials that are within the requested safety
	// margin. A refresh may persist even when a later selected key fails, while
	// the RPC response itself is always all-or-nothing.
	if err := refreshSelectedProviderCredentials(ctx, s, record, keys, lifetime); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "runtime credential refresh failed")
	}
	record, ok = s.runtime.st.GetProvider(name)
	if !ok || !providerInWorkspace(record, workspace) {
		return nil, status.Error(codes.Aborted, "provider changed during credential retrieval")
	}

	var values map[string]string
	expirations := make(map[string]int64)
	if s.runtime.drivers != nil {
		values, expirations, err = s.runtime.drivers.resolveProviderCredentialsWithExpiry(ctx, record, keys, s.runtime.sec)
	} else {
		values, err = s.runtime.sec.GetProviderCredentials(ctx, record.Name, keys)
	}
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "runtime credential retrieval failed")
	}
	response := &compatv1.GetProviderCredentialsResponse{Credentials: make(map[string]*compatv1.ProviderCredentialValue, len(keys))}
	responseBytes := 0
	deadline := time.Now().Add(lifetime).UnixMilli()
	for _, key := range keys {
		value, exists := values[key]
		if !exists {
			return nil, status.Error(codes.NotFound, "selected runtime credential is missing")
		}
		expiresAt := expirations[key]
		if expiresAt == 0 {
			expiresAt = record.CredentialExpiresAtMS[key]
		}
		if expiresAt > 0 && expiresAt <= deadline {
			return nil, status.Error(codes.FailedPrecondition, "credential cannot meet the requested remaining lifetime")
		}
		item := &compatv1.ProviderCredentialValue{Value: value}
		if expiresAt > 0 {
			item.ExpirationTime = timestamppb.New(time.UnixMilli(expiresAt))
		}
		response.Credentials[key] = item
		responseBytes += len(key) + len(value) + 64
		if responseBytes > maxProviderCredentialResponse {
			return nil, status.Error(codes.ResourceExhausted, "credential response exceeds 1 MiB")
		}
	}
	return response, nil
}

func validateProviderCredentialRequest(req *compatv1.GetProviderCredentialsRequest) (workspace, name string, keys []string, lifetime time.Duration, err error) {
	if req == nil {
		return "", "", nil, 0, status.Error(codes.InvalidArgument, "request is required")
	}
	workspace = strings.TrimSpace(requestWorkspace(req.GetWorkspaceScope()))
	if workspace == "" || scopeAllWorkspaces(req.GetWorkspaceScope()) {
		return "", "", nil, 0, status.Error(codes.InvalidArgument, "a named workspace is required")
	}
	name = req.GetName()
	if name == "" || strings.TrimSpace(name) != name || len(name) > 253 {
		return "", "", nil, 0, status.Error(codes.InvalidArgument, "canonical provider name is required")
	}
	keys = req.GetCredentialKeys()
	if len(keys) == 0 || len(keys) > maxProviderCredentialKeys {
		return "", "", nil, 0, status.Error(codes.InvalidArgument, "select between 1 and 32 runtime credential keys")
	}
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if len(key) > maxProviderCredentialKeyBytes || !validEnvKey(key) {
			return "", "", nil, 0, status.Error(codes.InvalidArgument, "credential keys must be runtime environment keys")
		}
		if _, duplicate := seen[key]; duplicate {
			return "", "", nil, 0, status.Error(codes.InvalidArgument, "credential keys must be unique")
		}
		seen[key] = struct{}{}
	}
	lifetime = defaultCredentialLifetime
	if requested := req.GetMinimumRemainingLifetime(); requested != nil {
		if err := requested.CheckValid(); err != nil || requested.AsDuration() < 0 {
			return "", "", nil, 0, status.Error(codes.InvalidArgument, "invalid minimum_remaining_lifetime")
		}
		if requested.AsDuration() != 0 {
			lifetime = requested.AsDuration()
		}
	}
	if lifetime > maxCredentialLifetime {
		return "", "", nil, 0, status.Error(codes.InvalidArgument, "minimum_remaining_lifetime exceeds 24 hours")
	}
	return workspace, name, append([]string(nil), keys...), lifetime, nil
}

func validateExportableProviderKeys(profile provider.Profile, record store.ProviderRecord, keys []string) error {
	declared := make(map[string]provider.Credential)
	for _, credential := range profile.Credentials {
		for _, key := range credential.EnvVars {
			declared[key] = credential
		}
	}
	for _, key := range keys {
		credential, ok := declared[key]
		if !ok || credential.TokenGrant != nil {
			return status.Error(codes.FailedPrecondition, "selected key is not an exportable runtime credential")
		}
		if !containsString(record.EnvVars, key) && record.CredentialHandles[key].Handle == "" && !providerRefreshOwnsKey(record, key) {
			return status.Error(codes.NotFound, "selected runtime credential is missing")
		}
	}
	return nil
}

func refreshSelectedProviderCredentials(ctx context.Context, s *compatRPCAdapter, record store.ProviderRecord, keys []string, lifetime time.Duration) error {
	deadline := time.Now().Add(lifetime).UnixMilli()
	refresh := make(map[string]struct{})
	for _, key := range keys {
		expiresAt := record.CredentialExpiresAtMS[key]
		if cfg, ok := record.Refresh[key]; ok && cfg.ExpiresAtMS > 0 {
			expiresAt = cfg.ExpiresAtMS
		}
		if expiresAt == 0 || expiresAt > deadline {
			continue
		}
		owner := providerRefreshOwner(record, key)
		if owner == "" {
			return status.Error(codes.FailedPrecondition, "credential cannot meet the requested remaining lifetime")
		}
		refresh[owner] = struct{}{}
	}
	for owner := range refresh {
		if err := refreshStoredProviderCredentialWithDrivers(ctx, s.runtime.st, s.runtime.sec, s.runtime.drivers, s.runtime.opt, record.Name, owner); err != nil {
			return err
		}
	}
	return nil
}

func providerRefreshOwnsKey(record store.ProviderRecord, key string) bool {
	return providerRefreshOwner(record, key) != ""
}

func providerRefreshOwner(record store.ProviderRecord, key string) string {
	for owner, config := range record.Refresh {
		if owner == key || config.CredentialKey == key {
			return owner
		}
		for _, output := range config.Outputs {
			if output == key {
				return owner
			}
		}
	}
	return ""
}
