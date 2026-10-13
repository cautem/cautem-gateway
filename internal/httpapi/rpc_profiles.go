package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-providers/provider"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

func (s *openShellRPC) ListProviderProfiles(ctx context.Context, req *openshellv1.ListProviderProfilesRequest) (*openshellv1.ListProviderProfilesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	authWorkspace := workspace
	if authWorkspace == "" {
		authWorkspace = "default"
	}
	if err := s.requireProviderAccess(ctx, authWorkspace, false); err != nil {
		return nil, err
	}
	items := listProfilesWithSources(s.runtime.st, BuiltinProvidersDir(), workspace, s.runtime.opt.ProviderProfileSources)
	sort.Slice(items, func(i, j int) bool { return items[i]["id"] < items[j]["id"] })
	limit := req.GetLimit()
	if limit == 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	start := int(req.GetOffset())
	if start >= len(items) {
		return &openshellv1.ListProviderProfilesResponse{}, nil
	}
	end := start + int(limit)
	if end > len(items) {
		end = len(items)
	}
	response := &openshellv1.ListProviderProfilesResponse{Profiles: make([]*openshellv1.ProviderProfile, 0, end-start)}
	for _, item := range items[start:end] {
		profile, source, err := resolveProfileForWorkspaceWithSources(s.runtime.st, BuiltinProvidersDir(), item["id"], workspace, s.runtime.opt.ProviderProfileSources)
		if err != nil {
			continue
		}
		response.Profiles = append(response.Profiles, profileToProto(profile, source, profileScope(profile, source), profileResourceVersion(s.runtime.st, profile, workspace, source)))
	}
	return response, nil
}

func (s *openShellRPC) GetProviderProfile(ctx context.Context, req *openshellv1.GetProviderProfileRequest) (*openshellv1.ProviderProfileResponse, error) {
	if req == nil || strings.TrimSpace(req.GetId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	authWorkspace := workspace
	if authWorkspace == "" {
		authWorkspace = "default"
	}
	if err := s.requireProviderAccess(ctx, authWorkspace, false); err != nil {
		return nil, err
	}
	profile, source, err := resolveProfileForWorkspaceWithSources(s.runtime.st, BuiltinProvidersDir(), req.GetId(), workspace, s.runtime.opt.ProviderProfileSources)
	if err != nil {
		return nil, status.Error(codes.NotFound, "provider profile not found")
	}
	return &openshellv1.ProviderProfileResponse{Profile: profileToProto(profile, source, profileScope(profile, source), profileResourceVersion(s.runtime.st, profile, workspace, source))}, nil
}

func (s *openShellRPC) ImportProviderProfiles(ctx context.Context, req *openshellv1.ImportProviderProfilesRequest) (*openshellv1.ImportProviderProfilesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	if err := s.requireProviderAccess(ctx, workspace, true); err != nil {
		return nil, err
	}
	diagnostics := make([]*openshellv1.ProviderProfileDiagnostic, 0)
	profiles := make([]*openshellv1.ProviderProfile, 0, len(req.GetProfiles()))
	for _, item := range req.GetProfiles() {
		if item == nil || item.GetProfile() == nil || strings.TrimSpace(item.GetProfile().GetId()) == "" {
			diagnostics = append(diagnostics, &openshellv1.ProviderProfileDiagnostic{Message: "profile id is required", Severity: "error"})
			continue
		}
		id := item.GetProfile().GetId()
		yaml, err := profileToYAML(item.GetProfile())
		if err != nil {
			diagnostics = append(diagnostics, profileDiagnostic(id, err))
			continue
		}
		if _, err := provider.ParseYAML([]byte(yaml)); err != nil {
			diagnostics = append(diagnostics, profileDiagnostic(id, err))
			continue
		}
		scope, scopeWorkspace := "workspace", workspace
		if req.GetWorkspace() == "" {
			scope, scopeWorkspace = "global", ""
		}
		if err := s.runtime.st.CreateProfileScoped(scope, scopeWorkspace, id, yaml); err != nil {
			diagnostics = append(diagnostics, profileDiagnostic(id, err))
			continue
		}
		stored, _ := s.runtime.st.GetProfileInScope(scope, scopeWorkspace, id)
		parsed, _ := provider.ParseYAML([]byte(yaml))
		profiles = append(profiles, profileToProto(parsed, "user", scope, stored.Version))
	}
	return &openshellv1.ImportProviderProfilesResponse{Diagnostics: diagnostics, Profiles: profiles, Imported: len(diagnostics) == 0}, nil
}

func (s *openShellRPC) UpdateProviderProfiles(ctx context.Context, req *openshellv1.UpdateProviderProfilesRequest) (*openshellv1.UpdateProviderProfilesResponse, error) {
	if req == nil || req.GetProfile() == nil || req.GetProfile().GetProfile() == nil {
		return nil, status.Error(codes.InvalidArgument, "profile is required")
	}
	id := strings.TrimSpace(req.GetId())
	if id == "" {
		id = strings.TrimSpace(req.GetProfile().GetProfile().GetId())
	}
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "profile id is required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	if err := s.requireProviderAccess(ctx, workspace, true); err != nil {
		return nil, err
	}
	yaml, err := profileToYAML(req.GetProfile().GetProfile())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "profile is invalid: %v", err)
	}
	if _, err := provider.ParseYAML([]byte(yaml)); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "profile is invalid: %v", err)
	}
	scope, scopeWorkspace := "workspace", workspace
	if req.GetWorkspace() == "" {
		scope, scopeWorkspace = "global", ""
	}
	expected := ""
	if req.GetExpectedResourceVersion() != 0 {
		expected = fmt.Sprintf("%d", req.GetExpectedResourceVersion())
	}
	if err := s.runtime.st.ReplaceProfileIfVersionScoped(scope, scopeWorkspace, id, yaml, expected); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Aborted, err.Error())
	}
	stored, _ := s.runtime.st.GetProfileInScope(scope, scopeWorkspace, id)
	parsed, _ := provider.ParseYAML([]byte(yaml))
	return &openshellv1.UpdateProviderProfilesResponse{Profile: profileToProto(parsed, "user", scope, stored.Version), Updated: true}, nil
}

func (s *openShellRPC) LintProviderProfiles(ctx context.Context, req *openshellv1.LintProviderProfilesRequest) (*openshellv1.LintProviderProfilesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	if err := s.requireProviderAccess(ctx, workspace, true); err != nil {
		return nil, err
	}
	diagnostics := make([]*openshellv1.ProviderProfileDiagnostic, 0)
	for _, item := range req.GetProfiles() {
		if item == nil || item.GetProfile() == nil {
			diagnostics = append(diagnostics, &openshellv1.ProviderProfileDiagnostic{Message: "profile is required", Severity: "error"})
			continue
		}
		yaml, err := profileToYAML(item.GetProfile())
		if err == nil {
			_, err = provider.ParseYAML([]byte(yaml))
		}
		if err != nil {
			diagnostics = append(diagnostics, profileDiagnostic(item.GetProfile().GetId(), err))
		}
	}
	return &openshellv1.LintProviderProfilesResponse{Diagnostics: diagnostics, Valid: len(diagnostics) == 0}, nil
}

func (s *openShellRPC) DeleteProviderProfile(ctx context.Context, req *openshellv1.DeleteProviderProfileRequest) (*openshellv1.DeleteProviderProfileResponse, error) {
	if req == nil || strings.TrimSpace(req.GetId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	if err := s.requireProviderAccess(ctx, workspace, true); err != nil {
		return nil, err
	}
	scope, scopeWorkspace := "workspace", workspace
	if req.GetWorkspace() == "" {
		scope, scopeWorkspace = "global", ""
	}
	if _, ok := s.runtime.st.GetProfileInScope(scope, scopeWorkspace, req.GetId()); !ok {
		return &openshellv1.DeleteProviderProfileResponse{Deleted: false}, nil
	}
	if err := s.runtime.st.DeleteProfileScoped(scope, scopeWorkspace, req.GetId()); err != nil {
		return nil, status.Error(codes.Internal, "could not delete provider profile")
	}
	return &openshellv1.DeleteProviderProfileResponse{Deleted: true}, nil
}

func profileDiagnostic(id string, err error) *openshellv1.ProviderProfileDiagnostic {
	return &openshellv1.ProviderProfileDiagnostic{ProfileId: id, Message: err.Error(), Severity: "error"}
}

func profileToYAML(profile *openshellv1.ProviderProfile) (string, error) {
	if profile == nil {
		return "", fmt.Errorf("profile is required")
	}
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(profile)
	if err != nil {
		return "", err
	}
	var values map[string]any
	if err := json.Unmarshal(b, &values); err != nil {
		return "", err
	}
	if category, ok := values["category"].(string); ok {
		category = strings.TrimPrefix(category, "PROVIDER_PROFILE_CATEGORY_")
		values["category"] = strings.ToLower(category)
	}
	b, err = json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func profileToProto(profile provider.Profile, source, scope string, resourceVersion uint64) *openshellv1.ProviderProfile {
	b, _ := json.Marshal(profile)
	var values map[string]any
	_ = json.Unmarshal(b, &values)
	if category, ok := values["category"].(string); ok {
		values["category"] = "PROVIDER_PROFILE_CATEGORY_" + strings.ToUpper(strings.ReplaceAll(category, "-", "_"))
	}
	b, _ = json.Marshal(values)
	out := &openshellv1.ProviderProfile{}
	_ = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(b, out)
	out.Id = profile.ID
	out.Source = source
	out.Scope = scope
	out.ResourceVersion = resourceVersion
	return out
}

func profileScope(profile provider.Profile, source string) string {
	if source == "builtin" {
		return ""
	}
	if profile.Scope == "workspace" {
		return "workspace"
	}
	return "platform"
}

func profileResourceVersion(st *store.Store, profile provider.Profile, workspace, source string) uint64 {
	if source != "custom" && source != "user" {
		return 0
	}
	if rec, ok := st.GetProfileScoped(profile.ID, workspace); ok {
		return rec.Version
	}
	return 0
}
