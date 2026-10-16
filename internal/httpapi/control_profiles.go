package httpapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"github.com/cautem/cautem-providers/provider"
	"gopkg.in/yaml.v3"
)

func (a *controlAPI) ListProviderProfiles(ctx context.Context, req *connect.Request[controlv1.ListProviderProfilesRequest]) (*connect.Response[controlv1.ListProviderProfilesResponse], error) {
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	if err := a.requireProviderProfileAccess(ctx, workspace, false); err != nil {
		return nil, err
	}
	items := listProfilesWithSources(a.store, BuiltinProvidersDir(), workspace, a.opt.ProviderProfileSources)
	result := &controlv1.ListProviderProfilesResponse{Profiles: make([]*controlv1.ProviderProfileSummary, 0, len(items))}
	for _, item := range items {
		summary := &controlv1.ProviderProfileSummary{Id: item["id"], Category: item["category"], Source: item["source"], Scope: item["scope"]}
		if item["source"] == "custom" {
			scope, scopeWorkspace := profileStorageScope(item["scope"], workspace)
			if profile, ok := a.store.GetProfileInScope(scope, scopeWorkspace, item["id"]); ok {
				summary.ResourceVersion = profile.Version
			}
		}
		result.Profiles = append(result.Profiles, summary)
	}
	return connect.NewResponse(result), nil
}

func (a *controlAPI) GetProviderProfile(ctx context.Context, req *connect.Request[controlv1.GetProviderProfileRequest]) (*connect.Response[controlv1.GetProviderProfileResponse], error) {
	id := strings.TrimSpace(req.Msg.GetId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("profile id is required"))
	}
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	if err := a.requireProviderProfileAccess(ctx, workspace, false); err != nil {
		return nil, err
	}
	profile, source, err := resolveProfileForWorkspaceWithSources(a.store, BuiltinProvidersDir(), id, workspace, a.opt.ProviderProfileSources)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("provider profile not found"))
	}
	version := uint64(0)
	profileYAML := ""
	if source == "custom" {
		record, ok := a.store.GetProfileScoped(id, workspace)
		if !ok {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("provider profile not found"))
		}
		scope := "platform"
		if record.Scope == "workspace" || record.Workspace != "" {
			scope = "workspace"
		}
		profileYAMLBytes, marshalErr := profileDocumentWithMetadata([]byte(record.YAML), map[string]string{
			"source": "user", "scope": scope,
		}, record.Version)
		if marshalErr != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("could not encode provider profile"))
		}
		profileYAML, version = string(profileYAMLBytes), record.Version
	} else {
		profileYAMLBytes, readErr := loadBuiltinProfileDocument(id)
		if readErr != nil {
			profileYAMLBytes, readErr = yaml.Marshal(profile)
		}
		if readErr != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("could not encode provider profile"))
		}
		profileYAML = string(profileYAMLBytes)
	}
	return connect.NewResponse(&controlv1.GetProviderProfileResponse{
		ProfileYaml: profileYAML, Source: source, ResourceVersion: version,
	}), nil
}

func (a *controlAPI) ImportProviderProfile(ctx context.Context, req *connect.Request[controlv1.ImportProviderProfileRequest]) (*connect.Response[controlv1.ImportProviderProfileResponse], error) {
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	if err := a.requireProviderProfileAccess(ctx, workspace, true); err != nil {
		return nil, err
	}
	document := req.Msg.GetProfileYaml()
	if len(document) == 0 || len(document) > 1<<20 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("profile document must be between 1 byte and 1 MiB"))
	}
	profile, err := provider.ParseYAML([]byte(document))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("profile is invalid: %w", err))
	}
	id := strings.TrimSpace(req.Msg.GetId())
	if id == "" || profile.ID != id {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("profile id does not match request"))
	}
	scope, scopeWorkspace := "global", ""
	if workspace != "" {
		scope, scopeWorkspace = "workspace", workspace
	}
	if err := a.store.CreateProfileScoped(scope, scopeWorkspace, id, document); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("profile %q already exists; use update", id))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not store provider profile"))
	}
	return connect.NewResponse(&controlv1.ImportProviderProfileResponse{ImportedId: id}), nil
}

func (a *controlAPI) UpdateProviderProfile(ctx context.Context, req *connect.Request[controlv1.UpdateProviderProfileRequest]) (*connect.Response[controlv1.UpdateProviderProfileResponse], error) {
	id := strings.TrimSpace(req.Msg.GetId())
	if id == "" || req.Msg.GetExpectedResourceVersion() == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("profile id and expected resource version are required"))
	}
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	if err := a.requireProviderProfileAccess(ctx, workspace, true); err != nil {
		return nil, err
	}
	if len(req.Msg.GetProfileYaml()) == 0 || len(req.Msg.GetProfileYaml()) > 1<<20 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("profile document must be at most 1 MiB"))
	}
	profile, err := provider.ParseYAML([]byte(req.Msg.GetProfileYaml()))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("profile is invalid: %w", err))
	}
	if profile.ID != id {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("profile id does not match request"))
	}
	if profile.ResourceVersion != req.Msg.GetExpectedResourceVersion() {
		return nil, connect.NewError(connect.CodeAborted, errors.New("profile resource version does not match request"))
	}
	scope, scopeWorkspace := "global", ""
	if workspace != "" {
		scope, scopeWorkspace = "workspace", workspace
	}
	if _, ok := a.store.GetProfileInScope(scope, scopeWorkspace, id); !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("custom provider profile not found"))
	}
	if err := a.store.ReplaceProfileIfVersionScoped(scope, scopeWorkspace, id, req.Msg.GetProfileYaml(), fmt.Sprint(req.Msg.GetExpectedResourceVersion())); err != nil {
		if strings.Contains(err.Error(), "changed since it was read") {
			return nil, connect.NewError(connect.CodeAborted, errors.New("provider profile changed since it was read"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not store provider profile"))
	}
	updated, _ := a.store.GetProfileInScope(scope, scopeWorkspace, id)
	return connect.NewResponse(&controlv1.UpdateProviderProfileResponse{ResourceVersion: updated.Version}), nil
}

func (a *controlAPI) DeleteProviderProfile(ctx context.Context, req *connect.Request[controlv1.DeleteProviderProfileRequest]) (*connect.Response[controlv1.DeleteProviderProfileResponse], error) {
	id := strings.TrimSpace(req.Msg.GetId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("profile id is required"))
	}
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	if err := a.requireProviderProfileAccess(ctx, workspace, true); err != nil {
		return nil, err
	}
	scope, scopeWorkspace := "global", ""
	if workspace != "" {
		scope, scopeWorkspace = "workspace", workspace
	}
	if _, ok := a.store.GetProfileInScope(scope, scopeWorkspace, id); !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("custom provider profile not found"))
	}
	if err := a.store.DeleteProfileScoped(scope, scopeWorkspace, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not delete provider profile"))
	}
	return connect.NewResponse(&controlv1.DeleteProviderProfileResponse{Deleted: true}), nil
}

func (a *controlAPI) requireProviderProfileAccess(ctx context.Context, workspace string, write bool) error {
	if err := a.requireUser(ctx, false); err != nil {
		return err
	}
	p := PrincipalFrom(ctx)
	if workspace == "" {
		if p.IDP != "local" && p.IDP != "local_dev" && !isConfigAdmin(p, a.opt.OIDC.AdminRole) {
			return connect.NewError(connect.CodePermissionDenied, errors.New("platform admin required for global provider profiles"))
		}
		return nil
	}
	if a.opt.grpcRuntime == nil {
		return connect.NewError(connect.CodeUnavailable, errors.New("provider access service is unavailable"))
	}
	access := (&compatRPCAdapter{runtime: a.opt.grpcRuntime}).requireProviderAccess(ctx, workspace, write)
	if access == nil {
		return nil
	}
	return providerAccessError(access)
}

func profileStorageScope(scope, workspace string) (string, string) {
	if scope == "workspace" {
		return "workspace", workspace
	}
	return "global", ""
}

func loadBuiltinProfileDocument(id string) ([]byte, error) {
	for _, suffix := range []string{".yaml", ".yml"} {
		data, err := os.ReadFile(filepath.Join(BuiltinProvidersDir(), id+suffix))
		if err == nil {
			return data, nil
		}
	}
	return nil, os.ErrNotExist
}

// profileDocumentWithMetadata overlays gateway-owned fields on the stored YAML
// syntax tree. Keeping the rest of the document intact allows newer clients to
// round-trip profile fields unknown to this gateway version.
func profileDocumentWithMetadata(document []byte, metadata map[string]string, version uint64) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(document, &root); err != nil {
		return nil, err
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("provider profile must be a YAML mapping")
	}
	mapping := root.Content[0]
	set := func(key, value string) {
		for i := 0; i+1 < len(mapping.Content); i += 2 {
			if mapping.Content[i].Value == key {
				mapping.Content[i+1].Kind = yaml.ScalarNode
				mapping.Content[i+1].Tag = "!!str"
				mapping.Content[i+1].Value = value
				return
			}
		}
		mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
	}
	for key, value := range metadata {
		set(key, value)
	}
	set("resource_version", fmt.Sprint(version))
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "resource_version" {
			mapping.Content[i+1].Tag = "!!int"
			break
		}
	}
	return yaml.Marshal(&root)
}
