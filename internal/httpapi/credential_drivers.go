package httpapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	"github.com/cautem/cautem-runtime/secrets"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	credentialsv1 "github.com/cautem/quarshell-gateway/internal/upstreamproto/credentialsv1"
)

// driverRegistry is the typed boundary for configured built-in and external
// OpenShell drivers. Built-ins keep their existing lazy Engine path; remote
// entries are represented by generated clients and are probed explicitly.
// Keeping this registry separate from the public gateway server is important:
// ComputeDriver and CredentialDriver are plugin-side contracts, not public
// OpenShell RPCs.

// listCredentialDriverCredentials exercises the optional ListCredentials
// contract without ever exposing credential values. The protocol deliberately
// returns handles, keys, and metadata only; validating handles here catches a
// misbehaving external driver during startup or an explicit probe.
func (r *driverRegistry) listCredentialDriverCredentials(ctx context.Context, name string) ([]*credentialsv1.ListedCredential, error) {
	if r == nil {
		return nil, fmt.Errorf("credential driver registry is nil")
	}
	name = normalizeDriverName(name)
	r.mu.Lock()
	registration, ok := r.credential[name]
	r.mu.Unlock()
	if !ok || registration.client == nil {
		return nil, fmt.Errorf("credential driver %q is not an external driver", name)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	response, err := registration.client.ListCredentials(probeCtx, &credentialsv1.ListCredentialsRequest{})
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("driver returned an empty ListCredentials response")
	}
	for index, credential := range response.GetCredentials() {
		if credential == nil || strings.TrimSpace(credential.GetHandle()) == "" {
			return nil, fmt.Errorf("driver returned credential %d without a handle", index)
		}
	}
	return response.GetCredentials(), nil
}

// evaluateGatewayInterceptors runs the configured validate phase after the
// gateway has prepared an operation but before it performs durable or backend
// side effects. Only bindings selected by the service manifest are called.
// Failure policy is resolved per binding, then manifest, then registration.

func (r *driverRegistry) credentialDriver(name string) (credentialDriverRegistration, bool) {
	key := normalizeDriverName(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	registration, ok := r.credential[key]
	return registration, ok
}

func (r *driverRegistry) selectedCredentialDriver(opt Options) (credentialDriverRegistration, string, error) {
	name := normalizeDriverName(opt.DefaultCredentialDriver)
	if name == "" && len(opt.CredentialDriverNames) == 1 {
		name = normalizeDriverName(opt.CredentialDriverNames[0])
	}
	if name == "" {
		if len(opt.CredentialDriverNames) > 1 {
			return credentialDriverRegistration{}, "", fmt.Errorf("multiple credential drivers are configured; default_credential_driver is required")
		}
		return credentialDriverRegistration{}, "", nil
	}
	registration, ok := r.credentialDriver(name)
	if !ok {
		return credentialDriverRegistration{}, "", fmt.Errorf("credential driver %q is not configured", name)
	}
	return registration, name, nil
}

func (r *driverRegistry) storeProviderCredentials(ctx context.Context, opt Options, sec *secrets.LocalEncrypted, provider, workspace string, values map[string]string, existing map[string]store.CredentialHandle) (string, map[string]store.CredentialHandle, error) {
	registration, driverName, err := r.selectedCredentialDriver(opt)
	if err != nil {
		return "", nil, err
	}
	if registration.client == nil {
		if sec == nil {
			return "", nil, fmt.Errorf("local credential storage is not initialized")
		}
		if err := sec.PutProviderCredentials(ctx, provider, values); err != nil {
			return "", nil, err
		}
		return "", nil, nil
	}
	handles := make(map[string]store.CredentialHandle, len(values))
	for key, value := range values {
		request := &credentialsv1.StoreCredentialRequest{Provider: provider, CredentialKey: key, Value: value, Workspace: workspace, ProviderId: provider}
		if old := existing[key]; old.Handle != "" {
			request.ExistingHandle = &datamodelv1.CredentialHandle{Driver: old.Driver, Handle: old.Handle, Metadata: old.Metadata}
		}
		response, callErr := registration.client.StoreCredential(ctx, request)
		if callErr != nil {
			return "", nil, fmt.Errorf("credential driver %q store %s: %w", driverName, key, callErr)
		}
		if response == nil || response.GetHandle() == nil || strings.TrimSpace(response.GetHandle().GetHandle()) == "" {
			return "", nil, fmt.Errorf("credential driver %q store %s returned an empty handle", driverName, key)
		}
		handle := response.GetHandle()
		handleDriver := strings.TrimSpace(handle.GetDriver())
		if handleDriver == "" {
			handleDriver = driverName
		}
		handles[key] = store.CredentialHandle{Driver: handleDriver, Handle: handle.GetHandle(), Metadata: handle.GetMetadata()}
	}
	return driverName, handles, nil
}

func (r *driverRegistry) deleteProviderCredential(ctx context.Context, provider, workspace string, handle store.CredentialHandle) error {
	if handle.Driver == "" || handle.Handle == "" {
		return nil
	}
	registration, ok := r.credentialDriver(handle.Driver)
	if !ok || registration.client == nil {
		return fmt.Errorf("credential driver %q is not configured", handle.Driver)
	}
	_, err := registration.client.DeleteCredential(ctx, &credentialsv1.DeleteCredentialRequest{Provider: provider, CredentialKey: "", Workspace: workspace, ProviderId: provider, Handle: &datamodelv1.CredentialHandle{Driver: handle.Driver, Handle: handle.Handle, Metadata: handle.Metadata}})
	return err
}

func (r *driverRegistry) resolveProviderCredentials(ctx context.Context, record store.ProviderRecord, keys []string, sec *secrets.LocalEncrypted) (map[string]string, error) {
	values, _, err := r.resolveProviderCredentialsWithExpiry(ctx, record, keys, sec)
	return values, err
}

// resolveProviderCredentialsWithExpiry preserves the optional expiry returned
// by CredentialDriver. An external driver is authoritative for the lifetime of
// a handle: an expired value must never cross the sandbox environment boundary,
// even when the gateway has not persisted the expiry yet.

// resolveProviderCredentialsWithExpiry preserves the optional expiry returned
// by CredentialDriver. An external driver is authoritative for the lifetime of
// a handle: an expired value must never cross the sandbox environment boundary,
// even when the gateway has not persisted the expiry yet.
func (r *driverRegistry) resolveProviderCredentialsWithExpiry(ctx context.Context, record store.ProviderRecord, keys []string, sec *secrets.LocalEncrypted) (map[string]string, map[string]int64, error) {
	if record.CredentialDriver == "" {
		if sec == nil {
			return nil, nil, fmt.Errorf("local credential storage is not initialized")
		}
		values, err := sec.GetProviderCredentials(ctx, record.Name, keys)
		return values, nil, err
	}
	registration, ok := r.credentialDriver(record.CredentialDriver)
	if !ok || registration.client == nil {
		return nil, nil, fmt.Errorf("credential driver %q is not configured", record.CredentialDriver)
	}
	requests := make([]*credentialsv1.ResolveCredentialRequest, 0, len(keys))
	for _, key := range keys {
		handle, ok := record.CredentialHandles[key]
		if !ok || handle.Handle == "" {
			return nil, nil, fmt.Errorf("provider %s credential %s has no driver handle", record.Name, key)
		}
		requests = append(requests, &credentialsv1.ResolveCredentialRequest{RequestId: key, Provider: record.Name, CredentialKey: key, Workspace: record.Workspace, ProviderId: record.Name, Handle: &datamodelv1.CredentialHandle{Driver: handle.Driver, Handle: handle.Handle, Metadata: handle.Metadata}})
	}
	response, err := registration.client.ResolveCredentials(ctx, &credentialsv1.ResolveCredentialsRequest{Credentials: requests})
	if err != nil {
		return nil, nil, err
	}
	if response == nil {
		return nil, nil, fmt.Errorf("credential driver %q returned an empty resolve response", record.CredentialDriver)
	}
	values := make(map[string]string, len(response.GetCredentials()))
	expires := make(map[string]int64)
	for _, credential := range response.GetCredentials() {
		if credential == nil || credential.GetRequestId() == "" {
			return nil, nil, fmt.Errorf("credential driver %q returned an invalid resolve response", record.CredentialDriver)
		}
		values[credential.GetRequestId()] = credential.GetValue()
		if expiration := credential.GetExpirationTime(); expiration != nil {
			if err := expiration.CheckValid(); err != nil {
				return nil, nil, fmt.Errorf("credential driver %q returned an invalid expiry for %s", record.CredentialDriver, credential.GetRequestId())
			}
			expiresAt := expiration.AsTime().UnixMilli()
			if expiresAt <= 0 {
				return nil, nil, fmt.Errorf("credential driver %q returned an invalid expiry for %s", record.CredentialDriver, credential.GetRequestId())
			}
			expires[credential.GetRequestId()] = expiresAt
		}
	}
	for _, key := range keys {
		if _, ok := values[key]; !ok {
			return nil, nil, fmt.Errorf("credential driver %q omitted credential %s", record.CredentialDriver, key)
		}
		if expiresAt := expires[key]; expiresAt > 0 && expiresAt <= time.Now().UnixMilli() {
			return nil, nil, fmt.Errorf("credential %s is expired", key)
		}
	}
	return values, expires, nil
}
