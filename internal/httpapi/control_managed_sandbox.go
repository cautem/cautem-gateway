package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
)

const maxManagedSandboxPolicyBytes = 1 << 20

func (a *controlAPI) SyncManagedSandbox(ctx context.Context, req *connect.Request[controlv1.SyncManagedSandboxRequest]) (response *connect.Response[controlv1.SyncManagedSandboxResponse], resultErr error) {
	msg := req.Msg
	workspace, name, err := a.managedSandboxTarget(ctx, msg.GetWorkspace(), msg.GetName(), http.MethodPut, "")
	if err != nil {
		return nil, err
	}
	auditErr := a.auditManagedSandbox(ctx, "sandbox.registry.sync", workspace, name, "attempt", "")
	if auditErr != nil {
		return nil, auditErr
	}
	defer func() {
		outcome, code := "succeeded", "ok"
		if resultErr != nil {
			outcome, code = "failed", connect.CodeOf(resultErr).String()
		}
		if auditErr := a.auditManagedSandbox(ctx, "sandbox.registry.sync", workspace, name, outcome, code); auditErr != nil {
			response, resultErr = nil, auditErr
		}
	}()
	if !validSandboxName(workspace) || len(name) > 19 || !validDNSLabel(name) || len(msg.GetRuntimeId()) > 1024 || len(msg.GetImage()) > 1024 || len(msg.GetNetwork()) > 256 || len(msg.GetStatus()) > 32 || len(msg.GetBasePolicyYaml()) > maxManagedSandboxPolicyBytes || len(msg.GetLabels()) > 64 || len(msg.GetAttachedProviders()) > 64 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid managed sandbox metadata"))
	}
	if !validManagedStatus(msg.GetStatus()) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid managed sandbox status"))
	}
	labelBytes := 0
	labels := make(map[string]string, len(msg.GetLabels()))
	for key, value := range msg.GetLabels() {
		labelBytes += len(key) + len(value)
		if len(key) == 0 || len(key) > 128 || len(value) > 1024 || labelBytes > 16<<10 {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid sandbox labels"))
		}
		labels[key] = value
	}
	providers := make([]string, 0, len(msg.GetAttachedProviders()))
	seen := map[string]struct{}{}
	for _, providerName := range msg.GetAttachedProviders() {
		providerName = strings.TrimSpace(providerName)
		if providerName == "" || len(providerName) > 128 {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid attached provider name"))
		}
		if _, duplicate := seen[providerName]; duplicate {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("duplicate attached provider"))
		}
		record, ok := a.store.GetProvider(providerName)
		if !ok || !providerInWorkspace(record, workspace) {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("attached provider is not available in the workspace"))
		}
		seen[providerName] = struct{}{}
		providers = append(providers, providerName)
	}
	unlockLifecycle := a.lockLogLifecycle()
	defer unlockLifecycle()
	previous, previousExists := a.store.GetSandbox(name)
	if previousExists {
		if previous.Workspace != "" && previous.Workspace != workspace {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("sandbox belongs to another workspace"))
		}
		if !cliManagedSandbox(previous) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox is owned by another runtime manager"))
		}
	}
	if !previousExists || previous.ID != strings.TrimSpace(msg.GetRuntimeId()) {
		if err := a.logs.ClearArchive(name); err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("old sandbox logs could not be cleared"))
		}
	}
	record := store.Sandbox{
		Name: name, ID: strings.TrimSpace(msg.GetRuntimeId()), RuntimeID: strings.TrimSpace(msg.GetRuntimeId()),
		ComputeDriver: "cli-managed", Image: strings.TrimSpace(msg.GetImage()), Workspace: workspace,
		Network: strings.TrimSpace(msg.GetNetwork()), Status: strings.TrimSpace(msg.GetStatus()),
		Labels: labels, BasePolicyYAML: msg.GetBasePolicyYaml(), AttachedProviders: providers, UpdatedAt: time.Now().UTC(),
	}
	if err := a.store.UpsertSandbox(record); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("managed sandbox registry update failed"))
	}
	stored, ok := a.store.GetSandbox(name)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("managed sandbox registry update failed"))
	}
	return connect.NewResponse(&controlv1.SyncManagedSandboxResponse{ResourceVersion: stored.ResourceVersion}), nil
}

func (a *controlAPI) GetManagedSandbox(ctx context.Context, req *connect.Request[controlv1.GetManagedSandboxRequest]) (*connect.Response[controlv1.GetManagedSandboxResponse], error) {
	workspace, err := a.requireWorkspace(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Msg.GetName())
	if name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("sandbox name required"))
	}
	record, ok := a.store.GetSandbox(name)
	if !ok || record.Workspace != "" && record.Workspace != workspace {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	return connect.NewResponse(&controlv1.GetManagedSandboxResponse{
		Name: record.Name, RuntimeId: record.ID, Image: record.Image, Workspace: defaultWorkspace(record.Workspace),
		Network: record.Network, Status: record.Status, Labels: cloneStringMap(record.Labels),
		BasePolicyYaml: record.BasePolicyYAML, AttachedProviders: append([]string(nil), record.AttachedProviders...), ResourceVersion: record.ResourceVersion,
	}), nil
}

func (a *controlAPI) DeleteManagedSandbox(ctx context.Context, req *connect.Request[controlv1.DeleteManagedSandboxRequest]) (response *connect.Response[controlv1.DeleteManagedSandboxResponse], resultErr error) {
	workspace, name, err := a.managedSandboxTarget(ctx, req.Msg.GetWorkspace(), req.Msg.GetName(), http.MethodDelete, "")
	if err != nil {
		return nil, err
	}
	if err := a.auditManagedSandbox(ctx, "sandbox.registry.delete", workspace, name, "attempt", ""); err != nil {
		return nil, err
	}
	defer func() {
		outcome, code := "succeeded", "ok"
		if resultErr != nil {
			outcome, code = "failed", connect.CodeOf(resultErr).String()
		}
		if err := a.auditManagedSandbox(ctx, "sandbox.registry.delete", workspace, name, outcome, code); err != nil {
			response, resultErr = nil, err
		}
	}()
	unlockLifecycle := a.lockLogLifecycle()
	defer unlockLifecycle()
	current, ok := a.store.GetSandbox(name)
	if !ok {
		return connect.NewResponse(&controlv1.DeleteManagedSandboxResponse{Deleted: false}), nil
	}
	if current.Workspace != "" && current.Workspace != workspace {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	if !cliManagedSandbox(current) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox is not CLI-managed"))
	}
	if err := a.logs.Retain(name, workspace); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("sandbox logs could not be retained"))
	}
	if err := a.store.DeleteSandbox(name); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("managed sandbox registry delete failed"))
	}
	if a.opt.grpcRuntime != nil && a.opt.grpcRuntime.relay != nil {
		a.opt.grpcRuntime.relay.Disconnect(name)
	}
	return connect.NewResponse(&controlv1.DeleteManagedSandboxResponse{Deleted: true}), nil
}

func (a *controlAPI) IssueManagedSandboxToken(ctx context.Context, req *connect.Request[controlv1.IssueManagedSandboxTokenRequest]) (*connect.Response[controlv1.IssueManagedSandboxTokenResponse], error) {
	workspace, name, err := a.managedSandboxTarget(ctx, req.Msg.GetWorkspace(), req.Msg.GetName(), http.MethodPost, "/supervisor-token")
	if err != nil {
		return nil, err
	}
	if err := a.auditManagedSandbox(ctx, "sandbox.token.issue", workspace, name, "attempt", ""); err != nil {
		return nil, err
	}
	current, ok := a.store.GetSandbox(name)
	if !ok || current.Workspace != "" && current.Workspace != workspace || !cliManagedSandbox(current) {
		_ = a.auditManagedSandbox(ctx, "sandbox.token.issue", workspace, name, "failed", "not_found")
		return nil, connect.NewError(connect.CodeNotFound, errors.New("managed sandbox not found"))
	}
	token, err := a.store.IssueSandboxToken(name)
	if err != nil {
		_ = a.auditManagedSandbox(ctx, "sandbox.token.issue", workspace, name, "failed", "internal")
		return nil, connect.NewError(connect.CodeInternal, errors.New("supervisor token could not be issued"))
	}
	if a.opt.grpcRuntime != nil && a.opt.grpcRuntime.relay != nil {
		a.opt.grpcRuntime.relay.Disconnect(name)
	}
	if err := a.auditManagedSandbox(ctx, "sandbox.token.issue", workspace, name, "succeeded", "ok"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&controlv1.IssueManagedSandboxTokenResponse{Token: token}), nil
}

func cliManagedSandbox(record store.Sandbox) bool {
	if record.ComputeDriver == "cli-managed" {
		return true
	}
	// Before the Control RPC migration, CLI registrations left these fields
	// empty. Treat only those records as legacy CLI-managed entries.
	return record.ComputeDriver == "" && record.RuntimeID == "" && record.SpecJSON == ""
}

func (a *controlAPI) managedSandboxTarget(ctx context.Context, rawWorkspace, rawName string, method, suffix string) (string, string, error) {
	principal := PrincipalFrom(ctx)
	if principal.Kind == PrincipalNone {
		return "", "", connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	if principal.Kind != PrincipalUser {
		return "", "", connect.NewError(connect.CodePermissionDenied, errors.New("user principal required"))
	}
	workspace := strings.TrimSpace(rawWorkspace)
	if workspace == "" {
		workspace = "default"
	}
	name := strings.TrimSpace(rawName)
	if name == "" || len(name) > 19 || !validDNSLabel(name) || !validSandboxName(workspace) {
		return "", "", connect.NewError(connect.CodeInvalidArgument, errors.New("invalid workspace or sandbox name"))
	}
	path := "/v1/sandboxes/" + url.PathEscape(name) + suffix
	if (principal.IDP == "oidc" || principal.IDP == "mtls") && !oidcRouteAuthorized(principal, method, &url.URL{Path: path}, a.opt.OIDC) {
		return "", "", connect.NewError(connect.CodePermissionDenied, errors.New("insufficient role or scope"))
	}
	if principal.IDP != "local" && principal.IDP != "local_dev" && !isConfigAdmin(principal, a.opt.OIDC.AdminRole) {
		if !containsString(principal.Scopes, "sandbox:write") && !containsString(principal.Scopes, "openshell:all") {
			return "", "", connect.NewError(connect.CodePermissionDenied, errors.New("sandbox:write scope required"))
		}
		ws, ok := a.store.GetWorkspace(workspace)
		if !ok {
			return "", "", connect.NewError(connect.CodeNotFound, errors.New("workspace not found"))
		}
		member := false
		for _, item := range ws.Members {
			if item.Subject == principal.Subject {
				switch strings.ToLower(strings.TrimSpace(item.Role)) {
				case "owner", "admin", "user", "member":
					member = true
				}
			}
		}
		if !member {
			return "", "", connect.NewError(connect.CodePermissionDenied, errors.New("workspace sandbox access required"))
		}
	}
	return workspace, name, nil
}

func (a *controlAPI) auditManagedSandbox(ctx context.Context, action, workspace, name, outcome, code string) error {
	actor := PrincipalFrom(ctx).Subject
	if actor == "" {
		actor = "unknown"
	}
	if _, err := a.store.AppendAuditEvent(store.AuditEvent{Actor: actor, Action: action, Workspace: workspace, Sandbox: name, Outcome: outcome, Code: code}); err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("managed sandbox audit write failed"))
	}
	return nil
}

func validManagedStatus(value string) bool {
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '_' && r != '-' {
			return false
		}
	}
	return len(value) <= 32
}
