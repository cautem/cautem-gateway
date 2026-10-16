package integration

import (
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/cautem/quarshell-gateway/internal/httpapi"
	controlv1 "github.com/cautem/quarshell-proto/gen/go/cautem/control/v1"
	"github.com/cautem/quarshell-proto/gen/go/cautem/control/v1/controlv1connect"
)

func TestAuthRequiredOnAPI(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	for _, path := range []string{"/v1/sandboxes", "/v1/whoami", "/v1/ssh-sessions", "/debug/loglevel", "/v1/sandboxes/demo/secrets", "/v1/providers"} {
		for _, token := range []string{"", "wrong-token"} {
			if code, _ := g.do(http.MethodGet, path, token, nil); code != http.StatusUnauthorized {
				t.Errorf("GET %s with token %q = %d, want 401", path, token, code)
			}
		}
	}
	for _, path := range []string{"/v1/sandboxes/demo/ssh-session", "/v1/sandboxes/demo/exec", "/v1/sandboxes/demo/supervisor-token"} {
		if code, _ := g.do(http.MethodPost, path, "", nil); code != http.StatusUnauthorized {
			t.Errorf("POST %s without token = %d, want 401", path, code)
		}
	}
	if code, _ := g.do(http.MethodGet, "/healthz", "", nil); code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", code)
	}
	if code, _ := g.do(http.MethodGet, "/v1/sandboxes", g.token, nil); code != http.StatusNotFound {
		t.Errorf("removed /v1/sandboxes route with token = %d, want 404", code)
	}
}

func TestSandboxPrincipalScope(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("demo")
	g.createSandbox("other")
	token := g.sandboxToken("demo")
	viewer := controlv1connect.NewConsoleServiceClient(http.DefaultClient, g.srv.URL)
	request := connect.NewRequest(&controlv1.GetViewerRequest{})
	request.Header().Set("Authorization", "Bearer "+token)
	if _, err := viewer.GetViewer(t.Context(), request); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("sandbox principal GetViewer error = %v, want permission denied", err)
	}
	logs := controlv1connect.NewSandboxServiceClient(http.DefaultClient, g.srv.URL)
	read := connect.NewRequest(&controlv1.GetSandboxLogsRequest{Name: "demo"})
	read.Header().Set("Authorization", "Bearer "+token)
	if _, err := logs.GetSandboxLogs(t.Context(), read); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("sandbox principal log read error = %v, want permission denied", err)
	}
}

func TestAllowUnauthenticated(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{AllowUnauthenticated: true})
	viewer := controlv1connect.NewConsoleServiceClient(http.DefaultClient, g.srv.URL)
	if _, err := viewer.GetViewer(t.Context(), connect.NewRequest(&controlv1.GetViewerRequest{})); err != nil {
		t.Fatalf("unsafe mode GetViewer error = %v", err)
	}
	if code, _ := g.do(http.MethodGet, "/v1/sandboxes", "wrong", nil); code != http.StatusUnauthorized {
		t.Fatalf("unsafe mode with bad token = %d, want 401", code)
	}
}

func TestLocalLoginLoopbackOnly(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	get := func(path string, headers map[string]string) *http.Response {
		req, err := http.NewRequest(http.MethodGet, g.srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range headers {
			if key == "Host" {
				req.Host = value
				continue
			}
			req.Header.Set(key, value)
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}
	for _, tc := range []struct {
		path    string
		headers map[string]string
		want    int
	}{
		{"/v1/auth/login", nil, http.StatusOK},
		{"/v1/auth/login", map[string]string{"X-Forwarded-For": "203.0.113.9"}, http.StatusForbidden},
		{"/v1/auth/login", map[string]string{"Host": "evil.example:7443"}, http.StatusForbidden},
		{"/v1/auth/login?redirect_uri=https://evil.example/cb", nil, http.StatusBadRequest},
	} {
		if res := get(tc.path, tc.headers); res.StatusCode != tc.want {
			t.Errorf("%s headers=%v: status=%d, want %d", tc.path, tc.headers, res.StatusCode, tc.want)
		}
	}
	res := get("/v1/auth/login?redirect_uri=http://127.0.0.1:5555/cb", nil)
	if res.StatusCode != http.StatusFound || !strings.HasPrefix(res.Header.Get("Location"), "http://127.0.0.1:5555/cb?token=") {
		t.Fatalf("loopback redirect = %d %s", res.StatusCode, res.Header.Get("Location"))
	}
}
