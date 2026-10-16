package httpapi

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/cautem/cautem-core/relayproto"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-runtime/idp"
)

// PrincipalKind distinguishes operators from sandbox supervisors.
type PrincipalKind int

const (
	PrincipalNone PrincipalKind = iota
	// PrincipalUser is an operator (OIDC JWT or local-dev token): full API.
	PrincipalUser
	// PrincipalSandbox is one sandbox supervisor (proxy sidecar): only its own
	// secrets/logs/proposals/relay routes.
	PrincipalSandbox
)

// Principal is the authenticated caller of one request.
type Principal struct {
	Kind    PrincipalKind
	Subject string
	IDP     string
	Sandbox string // PrincipalSandbox only
	Roles   []string
	Scopes  []string
	// BearerToken is request-local and never serialized or logged. It is used
	// only by RefreshSandboxToken after an operator rotation.
	BearerToken string
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

type principalKey struct{}

// PrincipalFrom returns the request principal set by the auth middleware.
func PrincipalFrom(ctx context.Context) Principal {
	p, _ := ctx.Value(principalKey{}).(Principal)
	return p
}

func withPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// AuthOptions configure the gateway auth middleware.
type AuthOptions struct {
	OIDC         *idp.OIDC
	OIDCSettings OIDCOptions
	// AllowUnauthenticated is the OpenShell allow_unauthenticated_users escape
	// hatch: requests without a bearer act as a local operator. Unsafe.
	AllowUnauthenticated bool
	EnableMTLSAuth       bool
	Log                  *slog.Logger
}

// publicRoutes never require a bearer. /v1/ssh/connect authenticates with the
// SSH session token inside its handler; /v1/auth/login is loopback-only.
func isPublicRoute(path string) bool {
	if isBrowserTerminalPath(path) {
		// The terminal authenticates the WebSocket's first frame before exec.
		return true
	}
	if isBrowserServiceProxyPath(path) {
		// The service proxy authenticates an opaque, path-scoped cookie session.
		return true
	}
	switch path {
	case "/healthz", "/v1/healthz", "/v1/auth/oidc", "/v1/auth/login", relayproto.PathSSHConnect,
		"/openshell.v1.OpenShell/Health", "/grpc.health.v1.Health/Check":
		return true
	}
	return false
}

// resolvePrincipal maps a bearer token to a principal. ok=false means a token
// was presented but is not valid.
func resolvePrincipal(r *http.Request, st *store.Store, validator *idp.OIDC, settings OIDCOptions) (Principal, bool) {
	tok := bearerToken(r)
	if tok == "" {
		return Principal{}, true
	}
	if validator != nil {
		if claims, err := validator.Validate(r.Context(), tok); err == nil {
			sub := claims.Subject
			if sub == "" {
				sub = claims.Email
			}
			if sub == "" {
				sub = "oidc-user"
			}
			roles := oidcRoles(claims.Raw, settings)
			return Principal{Kind: PrincipalUser, Subject: sub, IDP: "oidc", Roles: roles, Scopes: claimScopes(claims.Raw, settings.ScopesClaim)}, true
		}
	}
	if local := st.AuthToken(); local != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(local)) == 1 {
		return Principal{Kind: PrincipalUser, Subject: "local-dev", IDP: "local"}, true
	}
	if name, ok := st.SandboxForToken(tok); ok {
		return Principal{Kind: PrincipalSandbox, Subject: "sandbox:" + name, IDP: "sandbox", Sandbox: name}, true
	}
	return Principal{}, false
}

func oidcRoles(raw map[string]any, settings OIDCOptions) []string {
	roles := claimRoles(raw, settings.RolesClaim)
	if settings.RolesClaimSet && settings.RolesClaim == "" {
		roles = nil
	}
	if settings.AdminRole != "" && containsString(roles, settings.AdminRole) {
		roles = append(roles, "platform_admin", "platform-admin")
	}
	if settings.UserRole != "" && containsString(roles, settings.UserRole) {
		roles = append(roles, "user")
	}
	return roles
}

func claimRoles(raw map[string]any, path string) []string {
	if path == "" {
		path = "realm_access.roles"
	}
	value, ok := claimPath(raw, path)
	if !ok {
		return nil
	}
	var out []string
	switch values := value.(type) {
	case []string:
		out = append(out, values...)
	case []any:
		for _, value := range values {
			if role, ok := value.(string); ok {
				out = append(out, role)
			}
		}
	case string:
		out = append(out, values)
	}
	return out
}

func claimScopes(raw map[string]any, path string) []string {
	if path == "" {
		return nil
	}
	value, ok := claimPath(raw, path)
	if !ok {
		return nil
	}
	switch scopes := value.(type) {
	case string:
		return strings.Fields(scopes)
	case []string:
		return append([]string(nil), scopes...)
	case []any:
		out := make([]string, 0, len(scopes))
		for _, item := range scopes {
			if scope, ok := item.(string); ok {
				out = append(out, scope)
			}
		}
		return out
	default:
		return nil
	}
}

func claimPath(raw map[string]any, path string) (any, bool) {
	var current any = raw
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// withAuth enforces authentication on every route except isPublicRoute and
// scopes sandbox principals to sandboxRouteAllowed.
func withAuth(next http.Handler, st *store.Store, opt AuthOptions) http.Handler {
	log := opt.Log
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, controlAPIPathPrefix) {
			// Control RPC mounts its own principal resolver and method checks.
			next.ServeHTTP(w, r)
			return
		}
		if isPublicRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		p, valid := resolvePrincipal(r, st, opt.OIDC, opt.OIDCSettings)
		if !valid {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}
		if p.Kind == PrincipalNone {
			if opt.EnableMTLSAuth {
				p = mtlsPrincipal(r)
			}
		}
		if p.Kind == PrincipalNone {
			if !opt.AllowUnauthenticated {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "authentication required (cautem gateway login)", http.StatusUnauthorized)
				return
			}
			p = Principal{Kind: PrincipalUser, Subject: "local-dev", IDP: "local_dev", Roles: []string{"platform_admin", "platform-admin", "user"}}
		}
		if p.Kind == PrincipalSandbox && !sandboxRouteAllowed(r.Method, r.URL, p.Sandbox) {
			log.Warn("sandbox principal denied",
				slog.String("op", "gateway.auth"),
				slog.String("sandbox", p.Sandbox),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path))
			http.Error(w, "forbidden for sandbox principal", http.StatusForbidden)
			return
		}
		if (p.IDP == "oidc" || p.IDP == "mtls") && !oidcRouteAuthorized(p, r.Method, r.URL, opt.OIDCSettings) {
			log.Warn("identity denied by gateway role/scope policy", slog.String("op", "gateway.auth"), slog.String("method", r.Method), slog.String("path", r.URL.Path))
			http.Error(w, "forbidden by gateway role policy", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

func mtlsPrincipal(r *http.Request) Principal {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return Principal{}
	}
	cert := r.TLS.PeerCertificates[0]
	subject := cert.Subject.CommonName
	if subject == "" {
		subject = "unknown"
	}
	return Principal{Kind: PrincipalUser, Subject: subject, IDP: "mtls", Roles: append([]string(nil), cert.Subject.OrganizationalUnit...)}
}

func oidcRouteAuthorized(principal Principal, method string, target *url.URL, settings OIDCOptions) bool {
	if settings.ScopesClaim != "" {
		required := oidcRouteScope(method, target.Path)
		if required == "" || (required != "scope:none" && !containsString(principal.Scopes, required)) {
			return false
		}
	}
	adminConfigured, userConfigured := settings.AdminRole != "", settings.UserRole != ""
	if !adminConfigured && !userConfigured {
		return true
	}
	if adminConfigured != userConfigured {
		return false
	}
	admin := containsString(principal.Roles, settings.AdminRole)
	user := containsString(principal.Roles, settings.UserRole) || admin
	adminOnly := method != http.MethodGet && method != http.MethodHead
	if isBrowserServiceSessionPath(target.Path) {
		adminOnly = false
	}
	// Workspace member writes are authorized by workspace membership in the
	// RPC handler; requiring the gateway-wide admin role here would over-restrict
	// OpenShell's workspace-admin grant.
	if target.Path == "/v1/workspaces/write" {
		adminOnly = false
	}
	if strings.HasPrefix(target.Path, "/v1/rootfs-tar/") {
		adminOnly = false // workspace membership is checked by the upload handler.
	}
	if !adminOnly {
		// These reads expose gateway-wide credentials, sessions, or mutable policy state.
		switch target.Path {
		case "/v1/ssh-sessions", "/v1/providers":
			adminOnly = true
		}
		if strings.HasPrefix(target.Path, "/v1/providers/") {
			adminOnly = true
		}
	}
	if adminOnly {
		return admin
	}
	return user
}

// oidcRouteScope maps the gateway's REST surface to the scopes declared by
// the corresponding OpenShell RPC authorization rules. Unknown routes fail
// closed whenever scope enforcement is enabled.
func oidcRouteScope(method, path string) string {
	read := method == http.MethodGet || method == http.MethodHead
	switch {
	case isBrowserServiceSessionPath(path):
		return "sandbox:read"
	case path == "/v1/workspaces/read":
		return "workspace:read"
	case path == "/v1/workspaces/write":
		return "workspace:write"
	case path == "/v1/workspaces/admin":
		return "workspace:write"
	case strings.HasPrefix(path, "/v1/rootfs-tar/"):
		return "sandbox:write"
	case path == "/v1/workspaces" || strings.HasPrefix(path, "/v1/workspaces/"):
		if read {
			return "workspace:read"
		}
		return "workspace:write"
	case path == "/v1/whoami":
		return "scope:none"
	case path == "/v1/providers" || strings.HasPrefix(path, "/v1/providers/"):
		if read {
			return "provider:read"
		}
		return "provider:write"
	case path == "/v1/settings" || strings.HasPrefix(path, "/v1/settings/") || path == "/debug/loglevel" || strings.HasPrefix(path, "/debug/loglevel/"):
		if read {
			return "config:read"
		}
		return "config:write"
	case path == "/v1/sandboxes" || strings.HasPrefix(path, "/v1/sandboxes/") || path == "/v1/ssh-sessions" || strings.HasPrefix(path, "/v1/ssh-sessions/") || path == "/v1/logs" || path == "/v1/templates" || strings.HasPrefix(path, "/v1/templates/") || path == "/v1/inference" || path == "/v1/services" || strings.HasPrefix(path, "/v1/services/") || path == "/v1/workspaces" || strings.HasPrefix(path, "/v1/workspaces/"):
		if read {
			return "sandbox:read"
		}
		return "sandbox:write"
	default:
		return ""
	}
}

// sandboxRouteAllowed is the complete allowlist for a sandbox supervisor
// token. Handlers for supervisor streams re-check channel ownership.
func sandboxRouteAllowed(method string, u *url.URL, sandbox string) bool {
	path := u.Path
	switch {
	case path == relayproto.PathSupervisorConnect:
		return method == http.MethodGet && u.Query().Get("sandbox") == sandbox
	case strings.HasPrefix(path, relayproto.PathSupervisorRelay):
		return method == http.MethodGet
	case path == "/v1/whoami":
		return method == http.MethodGet
	}
	prefix := "/v1/sandboxes/" + sandbox + "/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, prefix), "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "secrets":
		return method == http.MethodGet
	case len(parts) == 1 && parts[0] == "logs":
		return method == http.MethodPost
	case len(parts) == 1 && parts[0] == "proposals":
		return method == http.MethodPost
	case len(parts) == 2 && parts[0] == "proposals":
		return method == http.MethodGet
	}
	return false
}

// isLoopbackRequest is true only for direct loopback peers (no proxy hops)
// addressed by a loopback Host, which defeats DNS-rebinding pages.
func isLoopbackRequest(r *http.Request) bool {
	return isDirectLoopbackPeer(r) && isLoopbackHostHeader(r.Host)
}

func isDirectLoopbackPeer(r *http.Request) bool {
	if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	return true
}

func isLoopbackHostHeader(h string) bool {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// isLoopbackRedirect accepts only http://127.0.0.1:PORT/… or localhost
// callbacks, so a web page cannot bounce the local token to another origin.
func isLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() == "" {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}
