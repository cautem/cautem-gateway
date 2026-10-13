package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func grpcAuthServerOptions(opt Options) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.UnaryInterceptor(grpcUnaryAuthInterceptor(opt)),
		grpc.StreamInterceptor(grpcStreamAuthInterceptor(opt)),
	}
}

func grpcUnaryAuthInterceptor(opt Options) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		authCtx, err := authenticateGRPC(ctx, info.FullMethod, opt)
		if err != nil {
			return nil, err
		}
		return handler(authCtx, req)
	}
}

func grpcStreamAuthInterceptor(opt Options) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := authenticateGRPC(stream.Context(), info.FullMethod, opt)
		if err != nil {
			return err
		}
		return handler(srv, &principalServerStream{ServerStream: stream, ctx: ctx})
	}
}

type principalServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *principalServerStream) Context() context.Context { return s.ctx }

func authenticateGRPC(ctx context.Context, fullMethod string, opt Options) (context.Context, error) {
	if isPublicRoute(fullMethod) {
		return ctx, nil
	}
	runtime := opt.grpcRuntime
	if runtime == nil || runtime.st == nil {
		return nil, status.Error(codes.Unauthenticated, "gateway authentication runtime is unavailable")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("authorization")
	if len(values) > 1 {
		return nil, status.Error(codes.Unauthenticated, "invalid authorization metadata")
	}
	var header http.Header
	if len(values) == 1 {
		header = make(http.Header)
		header.Set("Authorization", values[0])
	}
	r := &http.Request{Header: header}
	tok := bearerToken(r)
	p, valid := resolvePrincipal(r, runtime.st, runtime.oidc, runtime.opt.OIDC)
	if !valid {
		if fullMethod == "/openshell.v1.OpenShell/RefreshSandboxToken" {
			if sandbox, ok := runtime.st.SandboxForRefreshToken(tok); ok {
				p = Principal{Kind: PrincipalSandbox, Subject: "sandbox:" + sandbox, IDP: "sandbox", Sandbox: sandbox}
				valid = true
			}
		}
		if !valid && fullMethod == "/openshell.v1.OpenShell/FinalizeMainProcessExit" {
			if sandbox, ok := runtime.st.SandboxForFinalizeToken(tok); ok {
				p = Principal{Kind: PrincipalSandbox, Subject: "sandbox:" + sandbox, IDP: "sandbox", Sandbox: sandbox}
				valid = true
			}
		}
		if !valid {
			return nil, status.Error(codes.Unauthenticated, "invalid bearer token")
		}
	}
	if p.Kind == PrincipalNone && opt.EnableMTLSAuth {
		if remote, ok := peer.FromContext(ctx); ok {
			if tlsInfo, ok := remote.AuthInfo.(credentials.TLSInfo); ok {
				r.TLS = &tlsInfo.State
				p = mtlsPrincipal(r)
			}
		}
	}
	if p.Kind == PrincipalNone {
		if !opt.AllowUnauthenticated {
			return nil, status.Error(codes.Unauthenticated, "authentication required")
		}
		p = Principal{Kind: PrincipalUser, Subject: "local-dev", IDP: "local_dev", Roles: []string{"platform_admin", "platform-admin", "user"}}
	}
	if fullMethod == "/openshell.v1.OpenShell/GetSandboxConfig" || fullMethod == "/openshell.v1.OpenShell/UpdateConfig" {
		if p.Kind != PrincipalSandbox && p.Kind != PrincipalUser {
			return nil, status.Error(codes.PermissionDenied, "sandbox or user principal is required for this RPC")
		}
	} else if grpcSandboxMethod(fullMethod) {
		if p.Kind != PrincipalSandbox || !grpcSandboxMethodAllowed(fullMethod) {
			return nil, status.Error(codes.PermissionDenied, "sandbox principal is required for this RPC")
		}
	} else if p.Kind == PrincipalSandbox {
		return nil, status.Error(codes.PermissionDenied, "sandbox principal is not allowed for this RPC")
	}
	if p.IDP == "oidc" || p.IDP == "mtls" {
		method, path := grpcAuthRoute(fullMethod)
		if method == "" || !oidcRouteAuthorized(p, method, &url.URL{Path: path}, runtime.opt.OIDC) {
			return nil, status.Error(codes.PermissionDenied, "identity denied by gateway role or scope policy")
		}
	}
	if p.Kind == PrincipalSandbox {
		p.BearerToken = tok
	}
	return withPrincipal(ctx, p), nil
}

func grpcAuthRoute(fullMethod string) (string, string) {
	parts := strings.Split(strings.Trim(fullMethod, "/"), "/")
	if len(parts) != 2 || parts[0] != "openshell.v1.OpenShell" {
		return "", ""
	}
	name := parts[1]
	switch name {
	case "GetCurrentUser":
		return http.MethodGet, "/v1/whoami"
	case "GetGatewayInfo", "GetGatewayConfig", "GetSandboxConfig":
		return http.MethodGet, "/v1/settings"
	case "GetProvider", "ListProviders", "ListProviderProfiles", "GetProviderProfile", "GetProviderRefreshStatus":
		return http.MethodGet, "/v1/providers"
	case "CreateProvider", "UpdateProvider", "ImportProviderProfiles", "UpdateProviderProfiles", "LintProviderProfiles", "ConfigureProviderRefresh", "RotateProviderCredential":
		return http.MethodPost, "/v1/providers"
	case "DeleteProvider", "DeleteProviderProfile", "DeleteProviderRefresh":
		return http.MethodDelete, "/v1/providers"
	case "ListSandboxProviders":
		return http.MethodGet, "/v1/providers"
	case "CreateSandbox", "StartSandbox", "StopSandbox", "DeleteSandbox", "AttachSandboxProvider", "DetachSandboxProvider", "BeginRootfsTarStaging", "IssueSandboxToken", "RefreshSandboxToken":
		return http.MethodPost, "/v1/sandboxes"
	case "GetSandbox", "ListSandboxes", "WatchSandbox", "GetSandboxPolicyStatus", "ListSandboxPolicies", "GetDraftPolicy", "GetDraftHistory", "GetSandboxLogs":
		return http.MethodGet, "/v1/sandboxes"
	case "CreateSshSession":
		return http.MethodPost, "/v1/ssh-sessions"
	case "RevokeSshSession":
		return http.MethodDelete, "/v1/ssh-sessions"
	case "GetService", "ListServices":
		return http.MethodGet, "/v1/services"
	case "ExposeService":
		return http.MethodPost, "/v1/services"
	case "DeleteService":
		return http.MethodDelete, "/v1/services"
	case "ExecSandbox", "ExecSandboxInteractive", "ForwardTcp":
		return http.MethodPost, "/v1/sandboxes"
	case "CreateWorkspace", "DeleteWorkspace":
		return http.MethodPost, "/v1/workspaces/admin"
	case "AddWorkspaceMember", "RemoveWorkspaceMember":
		return http.MethodPost, "/v1/workspaces/write"
	case "GetWorkspace", "ListWorkspaces", "ListWorkspaceMembers":
		return http.MethodGet, "/v1/workspaces/read"
	case "CreateSandboxTemplate":
		return http.MethodPost, "/v1/templates"
	case "DeleteSandboxTemplate":
		return http.MethodDelete, "/v1/templates"
	case "GetSandboxTemplate", "ListSandboxTemplates":
		return http.MethodGet, "/v1/templates"
	case "UpdateConfig", "ApproveDraftChunk", "RejectDraftChunk", "ApproveAllDraftChunks", "EditDraftChunk", "UndoDraftChunk", "ClearDraftChunks":
		return http.MethodPost, "/v1/settings"
	case "SubmitPolicyAnalysis":
		return http.MethodPost, "/v1/sandboxes"
	default:
		return "", ""
	}
}

func grpcSandboxMethodAllowed(method string) bool {
	switch strings.TrimSpace(method) {
	case "/openshell.v1.OpenShell/ReportPolicyStatus",
		"/openshell.v1.OpenShell/GetSandboxProviderEnvironment",
		"/openshell.v1.OpenShell/ExchangeProviderSubjectToken",
		"/openshell.v1.OpenShell/PushSandboxLogs",
		"/openshell.v1.OpenShell/ConnectSupervisor",
		"/openshell.v1.OpenShell/ReportMainProcessExit",
		"/openshell.v1.OpenShell/FinalizeMainProcessExit",
		"/openshell.v1.OpenShell/RelayStream",
		"/openshell.v1.OpenShell/SubmitPolicyAnalysis",
		"/openshell.v1.OpenShell/IssueSandboxToken",
		"/openshell.v1.OpenShell/RefreshSandboxToken":
		return true
	default:
		return false
	}
}

func grpcSandboxMethod(method string) bool {
	return grpcSandboxMethodAllowed(method)
}
