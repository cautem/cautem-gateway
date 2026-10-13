package httpapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	edgeSuffixOpenShell = ".openshell.localhost"
	edgeSuffixOSG       = ".cautem.localhost"
)

// withEdgeRouter proxies Host *.openshell.localhost / *.cautem.localhost to registered services.
// Service requests are authenticated and workspace-scoped before the request is relayed.
// Other requests fall through to the control-plane mux (.localhost resolves to 127.0.0.1).
func withEdgeRouter(next http.Handler, st *store.Store, auth AuthOptions, relays ...*sshrelay.Hub) http.Handler {
	var relay *sshrelay.Hub
	if len(relays) > 0 {
		relay = relays[0]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		name, ok := edgeServiceName(host)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		principal, err := edgeServicePrincipal(r, st, auth)
		if err != nil {
			if status.Code(err) == codes.Unauthenticated {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			http.Error(w, "service access denied", http.StatusForbidden)
			return
		}
		svc, found := st.GetService(name)
		if !found {
			http.Error(w, fmt.Sprintf("service %q not exposed", name), http.StatusNotFound)
			return
		}
		sandbox, found := st.GetSandbox(svc.Sandbox)
		if !found {
			http.Error(w, "service sandbox not found", http.StatusNotFound)
			return
		}
		workspace := defaultWorkspace(sandbox.Workspace)
		if err := requireSandboxReadWorkspace(withPrincipal(r.Context(), principal), st, workspace); err != nil {
			if status.Code(err) == codes.NotFound {
				http.Error(w, "service not found", http.StatusNotFound)
				return
			}
			http.Error(w, "service access denied", http.StatusForbidden)
			return
		}
		if !strings.EqualFold(strings.TrimSpace(sandbox.Status), "running") {
			http.Error(w, "service sandbox is not running", http.StatusServiceUnavailable)
			return
		}
		r = r.WithContext(withPrincipal(r.Context(), principal))
		backendHost := strings.TrimSpace(svc.BackendHost)
		backendPort := svc.BackendPort
		if backendHost == "" && relay == nil {
			backendHost = "127.0.0.1"
		}
		if backendPort <= 0 {
			backendPort = svc.Port
		}
		if backendPort <= 0 {
			http.Error(w, "service has no backend port", http.StatusBadGateway)
			return
		}
		targetHost := backendHost
		if targetHost == "" {
			targetHost = "127.0.0.1"
		}
		target, err := url.Parse(fmt.Sprintf("http://%s", net.JoinHostPort(targetHost, fmt.Sprintf("%d", backendPort))))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = target.Host
				pr.Out.Header.Del("Authorization")
				pr.Out.Header.Del("Proxy-Authorization")
				pr.Out.Header.Del("Cookie")
			},
			ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, err error) {
				http.Error(rw, "edge proxy: "+err.Error(), http.StatusBadGateway)
			},
		}
		if backendHost == "" && relay != nil {
			proxy.Transport = &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return relay.OpenChannel(ctx, svc.Sandbox, fmt.Sprintf("tcp://127.0.0.1:%d", backendPort))
				},
				ForceAttemptHTTP2: false,
			}
		}
		proxy.ServeHTTP(w, r)
	})
}

func edgeServicePrincipal(r *http.Request, st *store.Store, auth AuthOptions) (Principal, error) {
	principal, valid := resolvePrincipal(r, st, auth.OIDC, auth.OIDCSettings)
	if !valid {
		return Principal{}, status.Error(codes.Unauthenticated, "invalid bearer token")
	}
	if principal.Kind == PrincipalNone && auth.EnableMTLSAuth {
		principal = mtlsPrincipal(r)
	}
	if principal.Kind == PrincipalNone && auth.AllowUnauthenticated {
		principal = Principal{Kind: PrincipalUser, Subject: "local-dev", IDP: "local_dev", Roles: []string{"platform_admin", "platform-admin", "user"}}
	}
	if principal.Kind == PrincipalNone && auth.OIDC == nil && strings.TrimSpace(auth.OIDCSettings.Issuer) == "" && !auth.EnableMTLSAuth && isDirectLoopbackPeer(r) {
		// Local-only gateways expose loopback service URLs for desktop workflows.
		// Shared deployments must configure OIDC or mTLS, which disables this path.
		principal = Principal{Kind: PrincipalUser, Subject: "local-dev", IDP: "local_dev", Roles: []string{"platform_admin", "platform-admin", "user"}}
	}
	if principal.Kind == PrincipalNone {
		return Principal{}, status.Error(codes.Unauthenticated, "authentication required")
	}
	if principal.Kind != PrincipalUser {
		return Principal{}, status.Error(codes.PermissionDenied, "user principal required")
	}
	if (principal.IDP == "oidc" || principal.IDP == "mtls") && !oidcRouteAuthorized(principal, http.MethodGet, &url.URL{Path: "/v1/services"}, auth.OIDCSettings) {
		return Principal{}, status.Error(codes.PermissionDenied, "sandbox read role or scope required")
	}
	return principal, nil
}

func edgeServiceName(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, suf := range []string{edgeSuffixOpenShell, edgeSuffixOSG} {
		if before, ok := strings.CutSuffix(host, suf); ok {
			name := before
			if name == "" || strings.Contains(name, ".") {
				return "", false
			}
			return name, true
		}
	}
	return "", false
}
