package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/coder/websocket"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	browserServiceSessionCookie  = "cautem_service_session"
	browserServiceSessionTTL     = 5 * time.Minute
	browserServiceSessionLimit   = 4096
	browserServiceRecheck        = time.Second
	browserServiceMessageLimit   = 16 << 20
	browserServiceWebSocketLimit = 256
)

type browserServiceSession struct {
	principal Principal
	sandbox   string
	service   string
	expiresAt time.Time
}

type browserServiceSessions struct {
	mu                   sync.Mutex
	byToken              map[string]browserServiceSession
	activeGUIByWorkspace map[string]uint32
	newToken             func() (string, error)
}

func (s *browserServiceSessions) activeGUICountTotal() uint32 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var count uint32
	for _, active := range s.activeGUIByWorkspace {
		count = saturatingAdd32(count, active)
	}
	return count
}

type browserServiceInfo struct {
	Name      string `json:"name"`
	Port      int    `json:"port"`
	Running   bool   `json:"running"`
	ProxyPath string `json:"proxyPath"`
}

func newBrowserServiceSessions() *browserServiceSessions {
	return &browserServiceSessions{
		byToken:              make(map[string]browserServiceSession),
		activeGUIByWorkspace: make(map[string]uint32),
		newToken: func() (string, error) {
			var raw [32]byte
			if _, err := rand.Read(raw[:]); err != nil {
				return "", err
			}
			return base64.RawURLEncoding.EncodeToString(raw[:]), nil
		},
	}
}

func (s *browserServiceSessions) acquireGUI(workspace string, st *store.Store) (func(), bool) {
	s.mu.Lock()
	if st != nil {
		if record, ok := st.GetWorkspace(workspace); ok && record.Quota.ConcurrentGUISessions > 0 && s.activeGUIByWorkspace[workspace] >= record.Quota.ConcurrentGUISessions {
			recordWorkspaceQuotaRejection("workspace concurrent GUI session quota exceeded")
			s.mu.Unlock()
			return nil, false
		}
	}
	s.activeGUIByWorkspace[workspace]++
	s.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			if count := s.activeGUIByWorkspace[workspace]; count <= 1 {
				delete(s.activeGUIByWorkspace, workspace)
			} else {
				s.activeGUIByWorkspace[workspace] = count - 1
			}
			s.mu.Unlock()
		})
	}, true
}

func (s *browserServiceSessions) activeGUICount(workspace string) uint32 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeGUIByWorkspace[workspace]
}

func (s *browserServiceSessions) withWorkspaceGUICount(workspace string, fn func(uint32) error) error {
	if s == nil {
		return fn(0)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(s.activeGUIByWorkspace[workspace])
}

func (s *browserServiceSessions) issue(session browserServiceSession, now time.Time) (string, error) {
	if !session.expiresAt.After(now) {
		return "", errors.New("service session already expired")
	}
	token, err := s.newToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, current := range s.byToken {
		if !current.expiresAt.After(now) {
			delete(s.byToken, key)
		}
	}
	if len(s.byToken) >= browserServiceSessionLimit {
		return "", errors.New("service session capacity reached")
	}
	s.byToken[token] = session
	return token, nil
}

func (s *browserServiceSessions) get(token string, now time.Time) (browserServiceSession, bool) {
	if token == "" {
		return browserServiceSession{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.byToken[token]
	if !ok {
		return browserServiceSession{}, false
	}
	if !session.expiresAt.After(now) {
		delete(s.byToken, token)
		return browserServiceSession{}, false
	}
	return session, true
}

func mountBrowserServices(mux *http.ServeMux, st *store.Store, relay *sshrelay.Hub, auth AuthOptions) *browserServiceSessions {
	sessions := newBrowserServiceSessions()
	websocketSlots := make(chan struct{}, browserServiceWebSocketLimit)
	mux.HandleFunc("GET /v1/sandboxes/{sandbox}/services", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("sandbox")
		principal := PrincipalFrom(r.Context())
		_, sandbox, err := serviceSandboxAccess(r.Context(), principal, name, "", st)
		if err != nil {
			writeServiceAccessError(w, err)
			return
		}
		items := make([]browserServiceInfo, 0)
		for _, item := range st.ListServices() {
			if item.Sandbox != name {
				continue
			}
			items = append(items, browserServiceInfo{
				Name: item.Name, Port: item.Port,
				Running:   strings.EqualFold(strings.TrimSpace(sandbox.Status), "running"),
				ProxyPath: browserServiceProxyPath(name, item.Name),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"services": items})
	})
	mux.HandleFunc("POST /v1/sandboxes/{sandbox}/services/{service}/session", func(w http.ResponseWriter, r *http.Request) {
		principal := PrincipalFrom(r.Context())
		name, serviceName := r.PathValue("sandbox"), r.PathValue("service")
		if !validDNSLabel(name) || !validDNSLabel(serviceName) {
			http.NotFound(w, r)
			return
		}
		_, sandbox, err := serviceSandboxAccess(r.Context(), principal, name, serviceName, st)
		if err != nil {
			writeServiceAccessError(w, err)
			return
		}
		if !strings.EqualFold(strings.TrimSpace(sandbox.Status), "running") {
			http.Error(w, "service sandbox is not running", http.StatusServiceUnavailable)
			return
		}
		expiresAt := browserServiceSessionExpiry(r, principal, auth)
		if !expiresAt.After(time.Now()) {
			http.Error(w, "authenticated session has expired", http.StatusUnauthorized)
			return
		}
		token, err := sessions.issue(browserServiceSession{principal: principal, sandbox: name, service: serviceName, expiresAt: expiresAt}, time.Now())
		if err != nil {
			http.Error(w, "service sessions are unavailable", http.StatusServiceUnavailable)
			return
		}
		proxyPath := browserServiceProxyPath(name, serviceName)
		http.SetCookie(w, &http.Cookie{
			Name: browserServiceSessionCookie, Value: token, Path: proxyPath,
			Expires: expiresAt, MaxAge: max(1, int(time.Until(expiresAt).Seconds())),
			HttpOnly: true, Secure: r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
			SameSite: http.SameSiteStrictMode,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"url": proxyPath, "expiresAt": expiresAt.UTC()})
	})
	mux.HandleFunc("/v1/sandboxes/{sandbox}/services/{service}/proxy/{path...}", func(w http.ResponseWriter, r *http.Request) {
		session, ok := sessions.get(serviceSessionCookie(r), time.Now())
		if !ok || session.sandbox != r.PathValue("sandbox") || session.service != r.PathValue("service") {
			http.Error(w, "service session is missing or expired", http.StatusUnauthorized)
			return
		}
		if !sameOriginUnsafeRequest(r) {
			http.Error(w, "cross-origin service request denied", http.StatusForbidden)
			return
		}
		record, sandbox, err := serviceSandboxAccess(r.Context(), session.principal, session.sandbox, session.service, st)
		if err != nil {
			writeServiceAccessError(w, err)
			return
		}
		if !strings.EqualFold(strings.TrimSpace(sandbox.Status), "running") {
			http.Error(w, "service sandbox is not running", http.StatusServiceUnavailable)
			return
		}
		if isWebSocketRequest(r) {
			if isBrowserGUIService(record) {
				release, acquired := sessions.acquireGUI(defaultWorkspace(sandbox.Workspace), st)
				if !acquired {
					http.Error(w, "workspace concurrent GUI session quota reached", http.StatusTooManyRequests)
					return
				}
				defer release()
			}
			select {
			case websocketSlots <- struct{}{}:
				defer func() { <-websocketSlots }()
			default:
				http.Error(w, "service WebSocket capacity reached", http.StatusServiceUnavailable)
				return
			}
			proxyBrowserServiceWebSocket(w, r, record, relay, sessions, serviceSessionCookie(r), session, st)
			return
		}
		proxyBrowserServiceHTTP(w, r, record, relay)
	})
	return sessions
}

func isBrowserGUIService(record store.ServiceRecord) bool {
	if record.Port == 6080 {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.Name)) {
	case "display", "novnc", "gui":
		return true
	default:
		return false
	}
}

func mountBrowserServiceManagement(mux *http.ServeMux, st *store.Store, runtime *grpcRuntime, opt Options) {
	mux.HandleFunc("POST /v1/sandboxes/{sandbox}/services", func(w http.ResponseWriter, r *http.Request) {
		if runtime == nil || runtime.st == nil {
			http.Error(w, "service registry is unavailable", http.StatusServiceUnavailable)
			return
		}
		name := r.PathValue("sandbox")
		if !validDNSLabel(name) {
			http.NotFound(w, r)
			return
		}
		sandbox, ok := st.GetSandbox(name)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if !strings.EqualFold(strings.TrimSpace(sandbox.Status), "running") {
			http.Error(w, "service sandbox is not running", http.StatusServiceUnavailable)
			return
		}
		var body struct {
			Name string `json:"name"`
			Port uint32 `json:"port"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			http.Error(w, "invalid service request", http.StatusBadRequest)
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			http.Error(w, "invalid service request", http.StatusBadRequest)
			return
		}
		response, err := (&openShellRPC{runtime: runtime, options: opt}).ExposeService(withPrincipal(r.Context(), PrincipalFrom(r.Context())), &openshellv1.ExposeServiceRequest{
			Sandbox: name, Workspace: defaultWorkspace(sandbox.Workspace), Service: body.Name, TargetPort: body.Port,
		})
		if err != nil {
			writeServiceAccessError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"name": response.GetEndpoint().GetServiceName(), "port": response.GetEndpoint().GetTargetPort()})
	})
	mux.HandleFunc("DELETE /v1/sandboxes/{sandbox}/services/{service}", func(w http.ResponseWriter, r *http.Request) {
		if runtime == nil || runtime.st == nil {
			http.Error(w, "service registry is unavailable", http.StatusServiceUnavailable)
			return
		}
		sandbox, ok := st.GetSandbox(r.PathValue("sandbox"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		response, err := (&openShellRPC{runtime: runtime, options: opt}).DeleteService(withPrincipal(r.Context(), PrincipalFrom(r.Context())), &openshellv1.DeleteServiceRequest{
			Sandbox: r.PathValue("sandbox"), Service: r.PathValue("service"), Workspace: defaultWorkspace(sandbox.Workspace),
		})
		if err != nil {
			writeServiceAccessError(w, err)
			return
		}
		if !response.GetDeleted() {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func browserServiceProxyPath(sandbox, service string) string {
	return "/v1/sandboxes/" + url.PathEscape(sandbox) + "/services/" + url.PathEscape(service) + "/proxy/"
}

func isBrowserServiceProxyPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) >= 6 && parts[0] == "v1" && parts[1] == "sandboxes" && validDNSLabel(parts[2]) && parts[3] == "services" && validDNSLabel(parts[4]) && parts[5] == "proxy"
}

func isBrowserServiceSessionPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 6 && parts[0] == "v1" && parts[1] == "sandboxes" && validDNSLabel(parts[2]) && parts[3] == "services" && validDNSLabel(parts[4]) && parts[5] == "session"
}

func browserServiceSessionExpiry(r *http.Request, principal Principal, auth AuthOptions) time.Time {
	expiresAt := time.Now().Add(browserServiceSessionTTL)
	switch principal.IDP {
	case "oidc":
		if auth.OIDC == nil {
			return time.Time{}
		}
		claims, err := auth.OIDC.Validate(r.Context(), bearerToken(r))
		if err != nil {
			return time.Time{}
		}
		exp, ok := claims.Raw["exp"].(float64)
		if !ok {
			return time.Time{}
		}
		tokenExpiry := time.Unix(int64(exp), 0)
		if tokenExpiry.Before(expiresAt) {
			expiresAt = tokenExpiry
		}
	case "mtls":
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return time.Time{}
		}
		certExpiry := r.TLS.PeerCertificates[0].NotAfter
		if certExpiry.Before(expiresAt) {
			expiresAt = certExpiry
		}
	}
	return expiresAt
}

func serviceSessionCookie(r *http.Request) string {
	cookie, err := r.Cookie(browserServiceSessionCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func serviceSandboxAccess(ctx context.Context, principal Principal, sandboxName, serviceName string, st *store.Store) (store.ServiceRecord, store.Sandbox, error) {
	if st == nil || principal.Kind != PrincipalUser {
		return store.ServiceRecord{}, store.Sandbox{}, status.Error(codes.Unauthenticated, "user session required")
	}
	sandbox, ok := st.GetSandbox(sandboxName)
	if !ok {
		return store.ServiceRecord{}, store.Sandbox{}, status.Error(codes.NotFound, "sandbox not found")
	}
	if err := requireSandboxReadWorkspace(withPrincipal(ctx, principal), st, defaultWorkspace(sandbox.Workspace)); err != nil {
		return store.ServiceRecord{}, store.Sandbox{}, err
	}
	if serviceName == "" {
		return store.ServiceRecord{}, sandbox, nil
	}
	service, ok := st.GetService(serviceName)
	if !ok || service.Sandbox != sandboxName {
		return store.ServiceRecord{}, store.Sandbox{}, status.Error(codes.NotFound, "service not found")
	}
	return service, sandbox, nil
}

func writeServiceAccessError(w http.ResponseWriter, err error) {
	switch status.Code(err) {
	case codes.Unauthenticated:
		http.Error(w, "authentication required", http.StatusUnauthorized)
	case codes.PermissionDenied:
		http.Error(w, "service access denied", http.StatusForbidden)
	case codes.NotFound:
		http.Error(w, "service not found", http.StatusNotFound)
	case codes.InvalidArgument:
		http.Error(w, "invalid service request", http.StatusBadRequest)
	case codes.AlreadyExists:
		http.Error(w, "service name is already in use", http.StatusConflict)
	default:
		http.Error(w, "service access unavailable", http.StatusServiceUnavailable)
	}
}

func sameOriginUnsafeRequest(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "", "same-origin", "none":
		// Empty is supported for non-browser clients and older browsers. Modern
		// browsers identify cross-origin sibling sites as "same-site".
	default:
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host) && ((r.TLS != nil && parsed.Scheme == "https") || (r.TLS == nil && parsed.Scheme == "http") || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), parsed.Scheme))
}

func isWebSocketRequest(r *http.Request) bool {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	for _, token := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}

func browserServiceTarget(rec store.ServiceRecord, request *http.Request) (*url.URL, error) {
	port := rec.BackendPort
	if port <= 0 {
		port = rec.Port
	}
	if port <= 0 || port > 65535 {
		return nil, errors.New("service backend port is invalid")
	}
	host := strings.TrimSpace(rec.BackendHost)
	if host == "" {
		host = "127.0.0.1"
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(request.PathValue("path"), "/"), "/"), "/")
	for _, part := range parts {
		if part == "." || part == ".." {
			return nil, errors.New("service path traversal is denied")
		}
	}
	suffix := strings.TrimPrefix(request.PathValue("path"), "/")
	if suffix == "" {
		suffix = "/"
	} else {
		suffix = "/" + suffix
	}
	return &url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: suffix, RawQuery: request.URL.RawQuery}, nil
}

func browserServiceTransport(rec store.ServiceRecord, relay *sshrelay.Hub) *http.Transport {
	port := rec.BackendPort
	if port <= 0 {
		port = rec.Port
	}
	host := strings.TrimSpace(rec.BackendHost)
	transport := &http.Transport{ForceAttemptHTTP2: false}
	if host == "" && relay != nil {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return relay.OpenChannel(ctx, rec.Sandbox, fmt.Sprintf("tcp://127.0.0.1:%d", port))
		}
	}
	return transport
}

func stripBrowserServiceCredentials(header http.Header) {
	header.Del("Authorization")
	header.Del("Proxy-Authorization")
	cookies := header.Values("Cookie")
	header.Del("Cookie")
	for _, cookieHeader := range cookies {
		for _, item := range strings.Split(cookieHeader, ";") {
			name, _, ok := strings.Cut(strings.TrimSpace(item), "=")
			if ok && name != "" && !strings.EqualFold(name, browserServiceSessionCookie) {
				header.Add("Cookie", strings.TrimSpace(item))
			}
		}
	}
}

func proxyBrowserServiceHTTP(w http.ResponseWriter, r *http.Request, rec store.ServiceRecord, relay *sshrelay.Hub) {
	target, err := browserServiceTarget(rec, r)
	if err != nil {
		http.Error(w, "invalid service path", http.StatusBadRequest)
		return
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = target.Path
			pr.Out.URL.RawPath = target.RawPath
			pr.Out.URL.RawQuery = target.RawQuery
			pr.Out.Host = target.Host
			stripBrowserServiceCredentials(pr.Out.Header)
			pr.Out.Header.Set("X-Forwarded-Host", r.Host)
			if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
				pr.Out.Header.Set("X-Forwarded-Proto", "https")
			} else {
				pr.Out.Header.Set("X-Forwarded-Proto", "http")
			}
		},
		Transport: browserServiceTransport(rec, relay),
		ModifyResponse: func(response *http.Response) error {
			rewriteBrowserServiceResponse(response, target, rec)
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(rw, "service is unavailable", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

func rewriteBrowserServiceResponse(response *http.Response, target *url.URL, rec store.ServiceRecord) {
	if raw := response.Header.Get("Location"); raw != "" {
		location, err := url.Parse(raw)
		if err == nil && ((!location.IsAbs() && !strings.HasPrefix(raw, "//")) || strings.EqualFold(location.Host, target.Host)) {
			location.Path = browserServiceProxyPath(rec.Sandbox, rec.Name) + strings.TrimPrefix(location.Path, "/")
			location.RawPath = ""
			location.Scheme = ""
			location.Host = ""
			response.Header.Set("Location", location.String())
		}
	}
	cookies := response.Cookies()
	if len(cookies) == 0 {
		return
	}
	response.Header.Del("Set-Cookie")
	for _, cookie := range cookies {
		if strings.EqualFold(cookie.Name, browserServiceSessionCookie) {
			continue
		}
		cookie.Path = browserServiceProxyPath(rec.Sandbox, rec.Name)
		cookie.Domain = ""
		response.Header.Add("Set-Cookie", cookie.String())
	}
}

func proxyBrowserServiceWebSocket(w http.ResponseWriter, r *http.Request, rec store.ServiceRecord, relay *sshrelay.Hub, sessions *browserServiceSessions, sessionToken string, session browserServiceSession, st *store.Store) {
	target, err := browserServiceTarget(rec, r)
	if err != nil {
		http.Error(w, "invalid service path", http.StatusBadRequest)
		return
	}
	target.Scheme = "ws"
	transport := browserServiceTransport(rec, relay)
	defer transport.CloseIdleConnections()
	upstreamHeaders := r.Header.Clone()
	stripBrowserServiceCredentials(upstreamHeaders)
	upstreamHeaders.Del("Connection")
	upstreamHeaders.Del("Upgrade")
	upstreamHeaders.Del("Sec-WebSocket-Key")
	upstreamHeaders.Del("Sec-WebSocket-Version")
	upstreamHeaders.Del("Sec-WebSocket-Extensions")
	upstreamHeaders.Del("Sec-WebSocket-Protocol")
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-IP"} {
		upstreamHeaders.Del(name)
	}
	upstreamHeaders.Set("Origin", "http://"+target.Host)
	protocols := parseWebSocketProtocols(r.Header.Values("Sec-WebSocket-Protocol"))
	upstream, _, err := websocket.Dial(r.Context(), target.String(), &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport}, HTTPHeader: upstreamHeaders, Subprotocols: protocols,
	})
	if err != nil {
		http.Error(w, "service WebSocket is unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.CloseNow()
	acceptOptions := &websocket.AcceptOptions{}
	if protocol := upstream.Subprotocol(); protocol != "" {
		acceptOptions.Subprotocols = []string{protocol}
	}
	client, err := websocket.Accept(w, r, acceptOptions)
	if err != nil {
		return
	}
	client.SetReadLimit(browserServiceMessageLimit)
	upstream.SetReadLimit(browserServiceMessageLimit)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go monitorBrowserService(ctx, cancel, client, upstream, sessions, sessionToken, session, st)
	bridgeBrowserWebSockets(ctx, client, upstream)
}

func parseWebSocketProtocols(values []string) []string {
	var out []string
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if protocol := strings.TrimSpace(item); protocol != "" {
				out = append(out, protocol)
			}
		}
	}
	return out
}

func monitorBrowserService(ctx context.Context, cancel context.CancelFunc, client, upstream *websocket.Conn, sessions *browserServiceSessions, sessionToken string, session browserServiceSession, st *store.Store) {
	ticker := time.NewTicker(browserServiceRecheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if !session.expiresAt.After(now) {
				cancel()
				_ = client.CloseNow()
				_ = upstream.CloseNow()
				return
			}
			current, ok := sessions.get(sessionToken, now)
			if !ok || current.principal.Subject != session.principal.Subject || current.principal.IDP != session.principal.IDP {
				cancel()
				_ = client.CloseNow()
				_ = upstream.CloseNow()
				return
			}
			_, sandbox, err := serviceSandboxAccess(ctx, current.principal, current.sandbox, current.service, st)
			if err != nil || !strings.EqualFold(strings.TrimSpace(sandbox.Status), "running") {
				cancel()
				_ = client.CloseNow()
				_ = upstream.CloseNow()
				return
			}
		}
	}
}

func bridgeBrowserWebSockets(ctx context.Context, client, upstream *websocket.Conn) {
	type result struct{ err error }
	results := make(chan result, 2)
	pump := func(dst, src *websocket.Conn) {
		for {
			kind, data, err := src.Read(ctx)
			if err != nil {
				results <- result{err: err}
				return
			}
			if err := dst.Write(ctx, kind, data); err != nil {
				results <- result{err: err}
				return
			}
		}
	}
	go pump(upstream, client)
	go pump(client, upstream)
	select {
	case <-ctx.Done():
	case <-results:
	}
	_ = client.CloseNow()
	_ = upstream.CloseNow()
}
