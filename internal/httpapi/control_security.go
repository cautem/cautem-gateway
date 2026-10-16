package httpapi

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"
)

// controlSecurityPolicy is the reviewable security contract for every public
// Control RPC. The descriptor inventory test fails when a method is added
// without an auth route and disclosure decision.
type controlSecurityPolicy struct {
	Method     string
	Route      string
	Disclosure string
}

var controlSecurityPolicies = map[string]controlSecurityPolicy{
	"/cautem.control.v1.ConsoleService/GetViewer":                            {http.MethodGet, "/v1/whoami", "caller identity only"},
	"/cautem.control.v1.ConsoleService/GetConsoleCapabilities":               {http.MethodGet, "/v1/whoami", "feature and driver names; no configuration"},
	"/cautem.control.v1.ConsoleService/GetOverview":                          {http.MethodGet, "/v1/sandboxes", "workspace-scoped aggregate counts"},
	"/cautem.control.v1.GatewayAdminService/GetGatewayInfo":                  {http.MethodGet, "/v1/settings", "redacted gateway and driver health"},
	"/cautem.control.v1.SandboxService/ListSandboxes":                        {http.MethodGet, "/v1/sandboxes", "redacted workspace sandbox summaries"},
	"/cautem.control.v1.SandboxService/GetSandbox":                           {http.MethodGet, "/v1/sandboxes", "redacted workspace sandbox summary"},
	"/cautem.control.v1.SandboxService/WatchSandboxes":                       {http.MethodGet, "/v1/sandboxes", "redacted workspace sandbox stream"},
	"/cautem.control.v1.SandboxService/GetSandboxLogs":                       {http.MethodGet, "/v1/logs", "bounded workspace sandbox logs"},
	"/cautem.control.v1.SandboxService/AppendSandboxLogs":                    {http.MethodPost, "/v1/logs", "write-only bounded log records"},
	"/cautem.control.v1.SandboxService/WatchSandboxLogs":                     {http.MethodGet, "/v1/logs", "bounded workspace sandbox log stream"},
	"/cautem.control.v1.SandboxService/CreateSandbox":                        {http.MethodPost, "/v1/sandboxes", "redacted result and durable operation id"},
	"/cautem.control.v1.SandboxService/AttachMainProcess":                    {http.MethodGet, "/v1/sandboxes", "workspace-scoped canonical process stream"},
	"/cautem.control.v1.SandboxService/StartSandbox":                         {http.MethodPost, "/v1/sandboxes", "redacted result and durable operation id"},
	"/cautem.control.v1.SandboxService/StopSandbox":                          {http.MethodPost, "/v1/sandboxes", "redacted result and durable operation id"},
	"/cautem.control.v1.SandboxService/DeleteSandbox":                        {http.MethodDelete, "/v1/sandboxes", "deletion result and durable operation id"},
	"/cautem.control.v1.ManagedSandboxService/SyncManagedSandbox":            {http.MethodPost, "/v1/sandboxes", "redacted managed sandbox summary"},
	"/cautem.control.v1.ManagedSandboxService/GetManagedSandbox":             {http.MethodGet, "/v1/sandboxes", "redacted managed sandbox summary"},
	"/cautem.control.v1.ManagedSandboxService/DeleteManagedSandbox":          {http.MethodDelete, "/v1/sandboxes", "deletion status only"},
	"/cautem.control.v1.ManagedSandboxService/IssueManagedSandboxToken":      {http.MethodPost, "/v1/sandboxes", "new supervisor token; never listed"},
	"/cautem.control.v1.OperationsService/GetOperation":                      {http.MethodGet, "/v1/sandboxes", "caller-owned operation only"},
	"/cautem.control.v1.OperationsService/ListOperations":                    {http.MethodGet, "/v1/sandboxes", "caller-owned workspace operations"},
	"/cautem.control.v1.OperationsService/ListAuditEvents":                   {http.MethodGet, "/v1/settings", "admin-only audit metadata; secrets redacted"},
	"/cautem.control.v1.CatalogService/ListServices":                         {http.MethodGet, "/v1/services", "workspace-scoped service summaries"},
	"/cautem.control.v1.CatalogService/ListTemplates":                        {http.MethodGet, "/v1/templates", "workspace-scoped template summaries"},
	"/cautem.control.v1.CatalogService/ListWorkspaces":                       {http.MethodGet, "/v1/workspaces/read", "caller-visible workspace summaries"},
	"/cautem.control.v1.CatalogService/GetWorkspace":                         {http.MethodGet, "/v1/workspaces/read", "caller-visible workspace summary"},
	"/cautem.control.v1.WorkspaceAdminService/UpdateWorkspaceQuota":          {http.MethodPost, "/v1/workspaces/write", "workspace quota and aggregate allocation usage"},
	"/cautem.control.v1.InferenceService/GetInferenceRoute":                  {http.MethodGet, "/v1/sandboxes", "route metadata without credentials"},
	"/cautem.control.v1.InferenceService/UpdateInferenceRoute":               {http.MethodPost, "/v1/sandboxes", "route metadata without credentials"},
	"/cautem.control.v1.InferenceService/ClearInferenceRoute":                {http.MethodDelete, "/v1/sandboxes", "clear status only"},
	"/cautem.control.v1.PolicyService/GetGlobalPolicy":                       {http.MethodGet, "/v1/settings", "policy document and revision"},
	"/cautem.control.v1.PolicyService/UpdateGlobalPolicy":                    {http.MethodPost, "/v1/settings", "policy document, validation, and revision"},
	"/cautem.control.v1.PolicyService/GetSandboxPolicy":                      {http.MethodGet, "/v1/sandboxes", "workspace sandbox policy and revision"},
	"/cautem.control.v1.PolicyService/UpdateSandboxPolicy":                   {http.MethodPost, "/v1/sandboxes", "workspace sandbox policy and revision"},
	"/cautem.control.v1.PolicyService/ListSandboxPolicyRevisions":            {http.MethodGet, "/v1/sandboxes", "workspace sandbox policy revision metadata"},
	"/cautem.control.v1.PolicyService/GetSandboxPolicyRevision":              {http.MethodGet, "/v1/sandboxes", "workspace sandbox historical policy"},
	"/cautem.control.v1.PolicyService/ListPolicyProposals":                   {http.MethodGet, "/v1/sandboxes", "workspace policy proposals"},
	"/cautem.control.v1.PolicyService/GetPolicyProposal":                     {http.MethodGet, "/v1/sandboxes", "workspace policy proposal"},
	"/cautem.control.v1.PolicyService/ApprovePolicyProposal":                 {http.MethodPost, "/v1/settings", "proposal decision and validation result"},
	"/cautem.control.v1.PolicyService/RejectPolicyProposal":                  {http.MethodPost, "/v1/settings", "proposal decision and reason"},
	"/cautem.control.v1.ProviderProfileService/ListProviderProfiles":         {http.MethodGet, "/v1/providers", "profile metadata without credentials"},
	"/cautem.control.v1.ProviderProfileService/GetProviderProfile":           {http.MethodGet, "/v1/providers", "profile document without credentials"},
	"/cautem.control.v1.ProviderProfileService/ImportProviderProfile":        {http.MethodPost, "/v1/providers", "validated profile without credentials"},
	"/cautem.control.v1.ProviderProfileService/UpdateProviderProfile":        {http.MethodPost, "/v1/providers", "validated profile without credentials"},
	"/cautem.control.v1.ProviderProfileService/DeleteProviderProfile":        {http.MethodDelete, "/v1/providers", "deletion status only"},
	"/cautem.control.v1.ProviderCredentialService/UpdateProviderCredentials": {http.MethodPost, "/v1/providers", "write-only credentials; handles are not returned"},
}

var controlSandboxProcedures = map[string]bool{
	"/cautem.control.v1.SandboxService/AppendSandboxLogs": true,
}

func (a *controlAPI) authorizeControlProcedure(ctx context.Context, procedure string) error {
	policy, ok := controlSecurityPolicies[procedure]
	if !ok {
		return connect.NewError(connect.CodeUnimplemented, errors.New("control procedure has no security policy"))
	}
	p := PrincipalFrom(ctx)
	if p.Kind == PrincipalNone {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	if p.Kind == PrincipalSandbox && controlSandboxProcedures[procedure] {
		return nil
	}
	if p.Kind != PrincipalUser {
		return connect.NewError(connect.CodePermissionDenied, errors.New("user principal required"))
	}
	if (p.IDP == "oidc" || p.IDP == "mtls") && a.opt.OIDC.ScopesClaim != "" {
		required := oidcRouteScope(policy.Method, policy.Route)
		if required == "" || (required != "scope:none" && !containsString(p.Scopes, required) && !containsString(p.Scopes, "openshell:all")) {
			return connect.NewError(connect.CodePermissionDenied, errors.New("insufficient scope"))
		}
	}
	return nil
}

type controlSecurityInterceptor struct{ api *controlAPI }

func (i controlSecurityInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
		if err := i.api.authorizeControlProcedure(ctx, request.Spec().Procedure); err != nil {
			return nil, err
		}
		return next(ctx, request)
	}
}

func (controlSecurityInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i controlSecurityInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, connection connect.StreamingHandlerConn) error {
		if err := i.api.authorizeControlProcedure(ctx, connection.Spec().Procedure); err != nil {
			return err
		}
		return next(ctx, connection)
	}
}
