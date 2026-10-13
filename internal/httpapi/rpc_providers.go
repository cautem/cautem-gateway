package httpapi

import (
	"context"
	"sort"
	"strconv"
	"strings"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-runtime/secrets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *openShellRPC) CreateProvider(ctx context.Context, req *openshellv1.CreateProviderRequest) (*openshellv1.ProviderResponse, error) {
	if req == nil || req.GetProvider() == nil || req.GetProvider().GetMetadata() == nil {
		return nil, status.Error(codes.InvalidArgument, "provider metadata is required")
	}
	p := req.GetProvider()
	name := strings.TrimSpace(p.GetMetadata().GetName())
	if name == "" || strings.TrimSpace(p.GetType()) == "" {
		return nil, status.Error(codes.InvalidArgument, "provider name and type are required")
	}
	workspace := defaultWorkspace(req.GetWorkspace())
	if p.GetMetadata().GetWorkspace() != "" && defaultWorkspace(p.GetMetadata().GetWorkspace()) != workspace {
		return nil, status.Error(codes.InvalidArgument, "provider workspace does not match request workspace")
	}
	if err := s.requireProviderAccess(ctx, workspace, true); err != nil {
		return nil, err
	}
	if _, exists := s.runtime.st.GetProvider(name); exists {
		return nil, status.Error(codes.AlreadyExists, "provider already exists")
	}
	if err := s.persistProvider(ctx, name, workspace, p); err != nil {
		return nil, err
	}
	record, _ := s.runtime.st.GetProvider(name)
	return &openshellv1.ProviderResponse{Provider: providerAttachmentToProto(record)}, nil
}

func (s *openShellRPC) GetProvider(ctx context.Context, req *openshellv1.GetProviderRequest) (*openshellv1.ProviderResponse, error) {
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	workspace := defaultWorkspace(req.GetWorkspace())
	if err := s.requireProviderAccess(ctx, workspace, false); err != nil {
		return nil, err
	}
	record, ok := s.runtime.st.GetProvider(req.GetName())
	if !ok || !providerInWorkspace(record, workspace) {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	return &openshellv1.ProviderResponse{Provider: providerAttachmentToProto(record)}, nil
}

func (s *openShellRPC) ListProviders(ctx context.Context, req *openshellv1.ListProvidersRequest) (*openshellv1.ListProvidersResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	workspace := defaultWorkspace(req.GetWorkspace())
	if req.GetAllWorkspaces() {
		if req.GetWorkspace() != "" {
			return nil, status.Error(codes.InvalidArgument, "all_workspaces and workspace are mutually exclusive")
		}
		if !isConfigAdmin(PrincipalFrom(ctx), s.options.OIDC.AdminRole) {
			return nil, status.Error(codes.PermissionDenied, "platform admin role required for all-workspace listing")
		}
	} else if err := s.requireProviderAccess(ctx, workspace, false); err != nil {
		return nil, err
	}
	items := s.runtime.st.Snapshot().Providers
	names := make([]string, 0, len(items))
	for name, record := range items {
		if req.GetAllWorkspaces() || providerInWorkspace(record, workspace) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	limit := req.GetLimit()
	if limit == 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	start := int(req.GetOffset())
	if start >= len(names) {
		return &openshellv1.ListProvidersResponse{}, nil
	}
	end := start + int(limit)
	if end > len(names) {
		end = len(names)
	}
	response := &openshellv1.ListProvidersResponse{Providers: make([]*datamodelv1.Provider, 0, end-start)}
	for _, name := range names[start:end] {
		response.Providers = append(response.Providers, providerAttachmentToProto(items[name]))
	}
	return response, nil
}

func (s *openShellRPC) UpdateProvider(ctx context.Context, req *openshellv1.UpdateProviderRequest) (*openshellv1.ProviderResponse, error) {
	if req == nil || req.GetProvider() == nil || req.GetProvider().GetMetadata() == nil {
		return nil, status.Error(codes.InvalidArgument, "provider metadata is required")
	}
	p := req.GetProvider()
	name := strings.TrimSpace(p.GetMetadata().GetName())
	old, ok := s.runtime.st.GetProvider(name)
	if !ok {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	workspace := defaultWorkspace(req.GetWorkspace())
	if err := s.requireProviderAccess(ctx, workspace, true); err != nil {
		return nil, err
	}
	if !providerInWorkspace(old, workspace) {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	if p.GetType() == "" {
		p.Type = old.Type
	}
	if p.Credentials != nil {
		oldKeys := make(map[string]struct{}, len(old.EnvVars))
		for _, key := range old.EnvVars {
			oldKeys[key] = struct{}{}
		}
		for _, key := range p.GetCredentials() {
			delete(oldKeys, key)
		}
		for key := range oldKeys {
			if err := s.revokeProviderCredential(ctx, old, key); err != nil {
				return nil, status.Error(codes.Internal, "could not revoke removed provider credential")
			}
		}
	}
	if err := s.persistProvider(ctx, name, workspace, p); err != nil {
		return nil, err
	}
	record, _ := s.runtime.st.GetProvider(name)
	return &openshellv1.ProviderResponse{Provider: providerAttachmentToProto(record)}, nil
}

func (s *openShellRPC) DeleteProvider(ctx context.Context, req *openshellv1.DeleteProviderRequest) (*openshellv1.DeleteProviderResponse, error) {
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	workspace := defaultWorkspace(req.GetWorkspace())
	if err := s.requireProviderAccess(ctx, workspace, true); err != nil {
		return nil, err
	}
	record, ok := s.runtime.st.GetProvider(req.GetName())
	if !ok || !providerInWorkspace(record, workspace) {
		return &openshellv1.DeleteProviderResponse{Deleted: false}, nil
	}
	if len(record.CredentialHandles) > 0 || s.runtime.sec != nil {
		if err := s.revokeAllProviderCredentials(ctx, record); err != nil {
			return nil, status.Error(codes.Internal, "could not revoke provider credentials")
		}
	}
	if err := s.runtime.st.DeleteProvider(req.GetName()); err != nil {
		return nil, status.Error(codes.Internal, "could not delete provider")
	}
	return &openshellv1.DeleteProviderResponse{Deleted: true}, nil
}

func (s *openShellRPC) persistProvider(ctx context.Context, name, workspace string, p *datamodelv1.Provider) error {
	if s.runtime == nil || s.runtime.st == nil {
		return status.Error(codes.Unavailable, "provider store is not initialized")
	}
	credentials := p.GetCredentials()
	old, hasOld := s.runtime.st.GetProvider(name)
	envVars := make([]string, 0, len(credentials))
	if credentials == nil && hasOld {
		envVars = append(envVars, old.EnvVars...)
	} else {
		for key := range credentials {
			envVars = append(envVars, key)
		}
	}
	sort.Strings(envVars)
	expires := cloneInt64Map(p.GetCredentialExpiresAtMs())
	if credentials == nil && hasOld {
		expires = cloneInt64Map(old.CredentialExpiresAtMS)
	}
	record := store.ProviderRecord{Name: name, Type: p.GetType(), Workspace: workspace, EnvVars: envVars, CredentialExpiresAtMS: expires, Config: cloneStringMap(p.GetConfig())}
	if hasOld {
		record.RuntimeCredentials = old.RuntimeCredentials
	}
	if raw := p.GetMetadata().GetAnnotations()["cautem.io/runtime-credentials"]; raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return status.Error(codes.InvalidArgument, "runtime credential annotation must be boolean")
		}
		record.RuntimeCredentials = value
	}
	if credentials == nil && hasOld {
		record.CredentialDriver = old.CredentialDriver
		record.CredentialHandles = cloneCredentialHandles(old.CredentialHandles)
	}
	if len(credentials) > 0 {
		if s.runtime.drivers != nil {
			driverName, handles, err := s.runtime.drivers.storeProviderCredentials(ctx, s.runtime.opt, s.runtime.sec, name, workspace, credentials, old.CredentialHandles)
			if err != nil {
				return status.Error(codes.Unavailable, "could not store provider credentials")
			}
			record.CredentialDriver, record.CredentialHandles = driverName, handles
		} else if s.runtime.sec != nil {
			if err := s.runtime.sec.PutProviderCredentials(ctx, name, credentials); err != nil {
				return status.Error(codes.Internal, "could not store provider credentials")
			}
		}
	}
	if err := s.runtime.st.UpsertProvider(record); err != nil {
		return status.Error(codes.Internal, "could not persist provider")
	}
	return nil
}

func (s *openShellRPC) revokeProviderCredential(ctx context.Context, record store.ProviderRecord, key string) error {
	if handle, ok := record.CredentialHandles[key]; ok && s.runtime.drivers != nil {
		return s.runtime.drivers.deleteProviderCredential(ctx, record.Name, record.Workspace, handle)
	}
	if s.runtime.sec == nil {
		return nil
	}
	return s.runtime.sec.Delete(ctx, secrets.ProviderKey(record.Name, key))
}

func (s *openShellRPC) revokeAllProviderCredentials(ctx context.Context, record store.ProviderRecord) error {
	for key := range record.CredentialHandles {
		if err := s.revokeProviderCredential(ctx, record, key); err != nil {
			return err
		}
	}
	if s.runtime.sec != nil {
		return s.runtime.sec.DeletePrefix(ctx, "provider/"+record.Name+"/")
	}
	return nil
}

func cloneInt64Map(in map[string]int64) map[string]int64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int64, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneCredentialHandles(in map[string]store.CredentialHandle) map[string]store.CredentialHandle {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]store.CredentialHandle, len(in))
	for key, handle := range in {
		handle.Metadata = cloneStringMap(handle.Metadata)
		out[key] = handle
	}
	return out
}
