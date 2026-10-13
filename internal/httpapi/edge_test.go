package httpapi

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
)

func TestEdgeServiceName(t *testing.T) {
	name, ok := edgeServiceName("web.openshell.localhost")
	if !ok || name != "web" {
		t.Fatalf("got %q %v", name, ok)
	}
	name, ok = edgeServiceName("api.cautem.localhost")
	if !ok || name != "api" {
		t.Fatalf("got %q %v", name, ok)
	}
	if _, ok := edgeServiceName("127.0.0.1"); ok {
		t.Fatal("expected no match")
	}
	if _, ok := edgeServiceName("a.b.openshell.localhost"); ok {
		t.Fatal("expected nested subdomain reject")
	}
}

func TestEdgeRouterProxies(t *testing.T) {
	forwardedCredentials := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedCredentials = r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != ""
		_, _ = io.WriteString(w, "ok:"+r.URL.Path)
	}))
	t.Cleanup(backend.Close)

	host, portStr, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	if host == "::1" || host == "" {
		host = "127.0.0.1"
	}

	dir := t.TempDir()
	st, err := store.Open(dir, "test-gw")
	if err != nil {
		t.Fatal(err)
	}
	token := prepareEdgeSandbox(t, st, "running")
	if err := st.UpsertService(store.ServiceRecord{
		Name: "web", Sandbox: "sb", Port: port, BackendHost: host, BackendPort: port,
	}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := withEdgeRouter(mux, st, AuthOptions{OIDCSettings: OIDCOptions{Issuer: "https://identity.example.test"}})

	req := httptest.NewRequest(http.MethodGet, "http://web.openshell.localhost/hi", nil)
	req.Host = "web.openshell.localhost"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated edge status %d body %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "http://web.openshell.localhost/hi", nil)
	req.Host = "web.openshell.localhost"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Cookie", "user-session=private")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "ok:/hi" {
		t.Fatalf("body %q", got)
	}
	if forwardedCredentials {
		t.Fatal("user credentials were forwarded to the sandbox service")
	}
	local := withEdgeRouter(mux, st, AuthOptions{})
	proxiedLocalRequest := httptest.NewRequest(http.MethodGet, "http://web.openshell.localhost/hi", nil)
	proxiedLocalRequest.Host = "web.openshell.localhost"
	proxiedLocalRequest.RemoteAddr = "127.0.0.1:12345"
	proxiedLocalRequest.Header.Set("X-Forwarded-For", "203.0.113.10")
	proxiedLocalRecorder := httptest.NewRecorder()
	local.ServeHTTP(proxiedLocalRecorder, proxiedLocalRequest)
	if proxiedLocalRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("forwarded local service URL status %d body %s", proxiedLocalRecorder.Code, proxiedLocalRecorder.Body.String())
	}
	localRequest := httptest.NewRequest(http.MethodGet, "http://web.openshell.localhost/hi", nil)
	localRequest.Host = "web.openshell.localhost"
	localRequest.RemoteAddr = "127.0.0.1:12345"
	localRecorder := httptest.NewRecorder()
	local.ServeHTTP(localRecorder, localRequest)
	if localRecorder.Code != http.StatusOK {
		t.Fatalf("local service URL status %d body %s", localRecorder.Code, localRecorder.Body.String())
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "sb", ID: "sb-id", Workspace: "default", Status: "stopped"}); err != nil {
		t.Fatal(err)
	}
	stopped := httptest.NewRequest(http.MethodGet, "http://web.openshell.localhost/hi", nil)
	stopped.Host = "web.openshell.localhost"
	stopped.Header.Set("Authorization", "Bearer "+token)
	stoppedRec := httptest.NewRecorder()
	h.ServeHTTP(stoppedRec, stopped)
	if stoppedRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("stopped sandbox status %d body %s", stoppedRec.Code, stoppedRec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/v1/healthz", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("control plane status %d", rec2.Code)
	}
}

func TestEdgeRouterRelaysExposedService(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	relay := sshrelay.NewHub()
	relay.OpenTimeout = time.Second
	remove := relay.RegisterOpenShellSupervisor("sb", "instance", func(channel, target string) error {
		if target != "tcp://127.0.0.1:8080" {
			t.Fatalf("relay target %q", target)
		}
		conn, err := relay.AcceptOpenShellRelay("sb", channel)
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				return
			}
			body := "relay:" + req.URL.Path
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		}()
		return nil
	}, done, nil)
	t.Cleanup(remove)

	st, err := store.Open(t.TempDir(), "test-gw")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertService(store.ServiceRecord{Name: "web", Sandbox: "sb", Port: 8080}); err != nil {
		t.Fatal(err)
	}

	token := prepareEdgeSandbox(t, st, "running")
	h := withEdgeRouter(http.NotFoundHandler(), st, AuthOptions{}, relay)
	req := httptest.NewRequest(http.MethodGet, "http://web.openshell.localhost/relay", nil)
	req.Host = "web.openshell.localhost"
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "relay:/relay" {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func prepareEdgeSandbox(t *testing.T, st *store.Store, sandboxStatus string) string {
	t.Helper()
	if err := st.UpsertSandbox(store.Sandbox{Name: "sb", ID: "sb-id", Workspace: "default", Status: sandboxStatus}); err != nil {
		t.Fatal(err)
	}
	token, err := st.EnsureAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestOAuth2TokenParseGrant(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			http.Error(w, "bad grant", 400)
			return
		}
		if r.Form.Get("refresh_token") != "rt" {
			http.Error(w, "bad rt", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"at","expires_in":3600}`)
	}))
	t.Cleanup(ts.Close)

	tok, exp, err := oauth2Token(map[string]string{
		"token_url":     ts.URL,
		"refresh_token": "rt",
		"client_id":     "cid",
		"client_secret": "sec",
	}, "refresh_token")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "at" || exp <= 0 {
		t.Fatalf("tok=%q exp=%d", tok, exp)
	}
}
