package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/coder/websocket"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestBrowserServiceSessionProxiesSameOriginHTTPWithoutGatewayCredentials(t *testing.T) {
	var forwardedAuthorization, forwardedSession bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedAuthorization = r.Header.Get("Authorization") != ""
		forwardedSession = strings.Contains(r.Header.Get("Cookie"), browserServiceSessionCookie)
		if r.URL.Path != "/health" || r.Header.Get("Cookie") != "app=kept" {
			http.Error(w, "unexpected upstream request", http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "app-session", Value: "kept", Path: "/", Domain: "internal.example", HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: browserServiceSessionCookie, Value: "service-controlled", Path: "/"})
		_, _ = w.Write([]byte("service-ok"))
	}))
	t.Cleanup(backend.Close)
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	st, localToken := browserServiceTestStore(t, "running", host, port)
	mux := http.NewServeMux()
	mountBrowserServices(mux, st, sshrelay.NewHub(), AuthOptions{})
	front := httptest.NewServer(withAuth(mux, st, AuthOptions{}))
	t.Cleanup(front.Close)

	listReq, _ := http.NewRequest(http.MethodGet, front.URL+"/v1/sandboxes/demo/services", nil)
	listReq.Header.Set("Authorization", "Bearer "+localToken)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Services []browserServiceInfo `json:"services"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	_ = listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK || len(list.Services) != 1 || list.Services[0].Name != "web" || !list.Services[0].Running {
		t.Fatalf("service discovery status=%d result=%+v", listResp.StatusCode, list.Services)
	}

	sessionReq, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/sandboxes/demo/services/web/session", nil)
	sessionReq.Header.Set("Authorization", "Bearer "+localToken)
	sessionResp, err := http.DefaultClient.Do(sessionReq)
	if err != nil {
		t.Fatal(err)
	}
	var session struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(sessionResp.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	_ = sessionResp.Body.Close()
	if sessionResp.StatusCode != http.StatusOK {
		t.Fatalf("service session status=%d body=%s", sessionResp.StatusCode, session.URL)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range sessionResp.Cookies() {
		if cookie.Name == browserServiceSessionCookie {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.Path != browserServiceProxyPath("demo", "web") {
		t.Fatalf("service session cookie=%+v", sessionCookie)
	}
	proxyReq, _ := http.NewRequest(http.MethodGet, front.URL+session.URL+"health", nil)
	proxyReq.Header.Set("Cookie", browserServiceSessionCookie+"="+sessionCookie.Value+"; app=kept")
	proxyReq.Header.Set("Authorization", "Bearer must-not-reach-service")
	proxyResp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(proxyResp.Body)
	_ = proxyResp.Body.Close()
	if proxyResp.StatusCode != http.StatusOK || string(body) != "service-ok" {
		t.Fatalf("proxy status=%d body=%q", proxyResp.StatusCode, body)
	}
	if forwardedAuthorization || forwardedSession {
		t.Fatalf("gateway credentials reached service: authorization=%t session=%t", forwardedAuthorization, forwardedSession)
	}
	var appCookie *http.Cookie
	for _, cookie := range proxyResp.Cookies() {
		if cookie.Name == "app-session" {
			appCookie = cookie
		}
	}
	if appCookie == nil || appCookie.Path != browserServiceProxyPath("demo", "web") || appCookie.Domain != "" {
		t.Fatalf("upstream app cookie was not scoped to the service path: %+v", appCookie)
	}
	for _, cookie := range proxyResp.Cookies() {
		if cookie.Name == browserServiceSessionCookie {
			t.Fatal("upstream service overwrote the gateway session cookie")
		}
	}

	siblingSiteReq, _ := http.NewRequest(http.MethodGet, front.URL+session.URL+"health", nil)
	siblingSiteReq.Header.Set("Cookie", browserServiceSessionCookie+"="+sessionCookie.Value)
	siblingSiteReq.Header.Set("Sec-Fetch-Site", "same-site")
	siblingSiteResp, err := http.DefaultClient.Do(siblingSiteReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = siblingSiteResp.Body.Close()
	if siblingSiteResp.StatusCode != http.StatusForbidden {
		t.Fatalf("same-site cross-origin read status=%d, want forbidden", siblingSiteResp.StatusCode)
	}

	unsafeReq, _ := http.NewRequest(http.MethodPost, front.URL+session.URL+"health", strings.NewReader("mutate"))
	unsafeReq.Header.Set("Cookie", browserServiceSessionCookie+"="+sessionCookie.Value)
	unsafeReq.Header.Set("Origin", "https://attacker.example")
	unsafeResp, err := http.DefaultClient.Do(unsafeReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = unsafeResp.Body.Close()
	if unsafeResp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin mutation status=%d, want forbidden", unsafeResp.StatusCode)
	}
}

func TestBrowserServiceSessionDeniedForStoppedSandboxAndExpiredTicket(t *testing.T) {
	backend := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(backend.Close)
	host, portText, _ := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	st, _ := browserServiceTestStore(t, "stopped", host, port)
	mux := http.NewServeMux()
	sessions := mountBrowserServices(mux, st, sshrelay.NewHub(), AuthOptions{})
	front := httptest.NewServer(withAuth(mux, st, AuthOptions{}))
	t.Cleanup(front.Close)
	localToken, err := st.EnsureAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	createReq, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/sandboxes/demo/services/web/session", nil)
	createReq.Header.Set("Authorization", "Bearer "+localToken)
	createResp, err := http.DefaultClient.Do(createReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = createResp.Body.Close()
	if createResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("stopped sandbox service session status=%d", createResp.StatusCode)
	}

	principal := Principal{Kind: PrincipalUser, IDP: "local", Subject: "local-dev"}
	ticket, err := sessions.issue(browserServiceSession{principal: principal, sandbox: "demo", service: "web", expiresAt: time.Now().Add(-time.Second)}, time.Now().Add(-2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	proxyReq, _ := http.NewRequest(http.MethodGet, front.URL+browserServiceProxyPath("demo", "web"), nil)
	proxyReq.Header.Set("Cookie", browserServiceSessionCookie+"="+ticket)
	proxyResp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = proxyResp.Body.Close()
	if proxyResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired service session status=%d", proxyResp.StatusCode)
	}
}

func TestBrowserServiceAccessRequiresWorkspaceMembership(t *testing.T) {
	st, _ := browserServiceTestStore(t, "running", "127.0.0.1", 8080)
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team-a", Members: []store.WorkspaceMember{{Subject: "alice", Role: "reader"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team-a", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	principal := Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "alice", Scopes: []string{"sandbox:read"}}
	if _, _, err := serviceSandboxAccess(t.Context(), principal, "demo", "web", st); err != nil {
		t.Fatalf("workspace member could not access service: %v", err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team-a"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := serviceSandboxAccess(t.Context(), principal, "demo", "web", st); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unaffiliated user access code=%s err=%v; want PermissionDenied", status.Code(err), err)
	}
}

func TestBrowserServiceManagementExposesAndDeletesWorkspaceService(t *testing.T) {
	st, localToken := browserServiceTestStore(t, "running", "", 0)
	runtime := &grpcRuntime{st: st}
	mux := http.NewServeMux()
	mountBrowserServiceManagement(mux, st, runtime, Options{})
	server := httptest.NewServer(withAuth(mux, st, AuthOptions{}))
	t.Cleanup(server.Close)

	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/sandboxes/demo/services", strings.NewReader(`{"name":"novnc","port":6080}`))
	request.Header.Set("Authorization", "Bearer "+localToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("expose service status=%d", response.StatusCode)
	}
	service, ok := st.GetService("novnc")
	if !ok || service.Sandbox != "demo" || service.Port != 6080 {
		t.Fatalf("exposed service=%+v, found=%t", service, ok)
	}

	request, _ = http.NewRequest(http.MethodDelete, server.URL+"/v1/sandboxes/demo/services/novnc", nil)
	request.Header.Set("Authorization", "Bearer "+localToken)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete service status=%d", response.StatusCode)
	}
	if _, ok := st.GetService("novnc"); ok {
		t.Fatal("deleted service remains in the registry")
	}
}

func TestBrowserServiceWebSocketClosesWhenWorkspaceMembershipIsRemoved(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	t.Cleanup(backend.Close)
	host, portText, _ := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	st, _ := browserServiceTestStore(t, "running", host, port)
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team-a", Members: []store.WorkspaceMember{{Subject: "alice", Role: "user"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team-a", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	sessions := mountBrowserServices(mux, st, sshrelay.NewHub(), AuthOptions{})
	front := httptest.NewServer(withAuth(mux, st, AuthOptions{}))
	t.Cleanup(front.Close)
	principal := Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "alice", Scopes: []string{"sandbox:read"}}
	conn := openBrowserServiceTestSocket(t, front.URL, sessions, principal, time.Now().Add(time.Minute))
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team-a"}); err != nil {
		t.Fatal(err)
	}
	assertBrowserServiceSocketCloses(t, conn, "workspace membership removal")

	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team-a", Members: []store.WorkspaceMember{{Subject: "alice", Role: "user"}}}); err != nil {
		t.Fatal(err)
	}
	expiringConn := openBrowserServiceTestSocket(t, front.URL, sessions, principal, time.Now().Add(500*time.Millisecond))
	assertBrowserServiceSocketCloses(t, expiringConn, "service session expiry")

	activeConn := openBrowserServiceTestSocket(t, front.URL, sessions, principal, time.Now().Add(time.Minute))
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team-a", Status: "stopped"}); err != nil {
		t.Fatal(err)
	}
	assertBrowserServiceSocketCloses(t, activeConn, "sandbox stop")
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team-a", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	deletedConn := openBrowserServiceTestSocket(t, front.URL, sessions, principal, time.Now().Add(time.Minute))
	if err := st.DeleteSandbox("demo"); err != nil {
		t.Fatal(err)
	}
	assertBrowserServiceSocketCloses(t, deletedConn, "sandbox deletion")
}

func openBrowserServiceTestSocket(t *testing.T, gatewayURL string, sessions *browserServiceSessions, principal Principal, expiresAt time.Time) *websocket.Conn {
	t.Helper()
	token, err := sessions.issue(browserServiceSession{principal: principal, sandbox: "demo", service: "web", expiresAt: expiresAt}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wsURL := "ws" + strings.TrimPrefix(gatewayURL, "http") + browserServiceProxyPath("demo", "web") + "socket"
	conn, _, err := websocket.Dial(t.Context(), wsURL, &websocket.DialOptions{HTTPHeader: http.Header{"Cookie": []string{browserServiceSessionCookie + "=" + token}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

func assertBrowserServiceSocketCloses(t *testing.T, conn *websocket.Conn, reason string) {
	t.Helper()
	readCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if _, _, err := conn.Read(readCtx); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WebSocket did not close after %s: %v", reason, err)
	}
}

func browserServiceTestStore(t *testing.T, state, backendHost string, backendPort int) (*store.Store, string) {
	t.Helper()
	st, err := store.Open(t.TempDir(), "browser-service-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default", Status: state}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertService(store.ServiceRecord{Name: "web", Sandbox: "demo", Port: backendPort, BackendHost: backendHost, BackendPort: backendPort}); err != nil {
		t.Fatal(err)
	}
	token, err := st.EnsureAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	return st, token
}
