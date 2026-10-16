package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"github.com/cautem/cautem-proto/gen/go/cautem/control/v1/controlv1connect"
	"github.com/cautem/quarshell-gateway/internal/httpapi"
)

func TestProviderCredentialLifecycleThroughCompatRPC(t *testing.T) {
	var rotations atomic.Int32
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse refresh request: %v", err)
		}
		if got := r.Form.Get("refresh_token"); got != "initial-refresh" {
			t.Errorf("refresh_token=%q", got)
		}
		rotations.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":300}`)
	}))
	defer tokenEndpoint.Close()

	g := newTestGateway(t, httpapi.Options{})
	profileClient := controlv1connect.NewProviderProfileServiceClient(http.DefaultClient, g.srv.URL)
	profileRequest := connect.NewRequest(&controlv1.ImportProviderProfileRequest{
		Id: "openai", ProfileYaml: "id: openai\ndisplay_name: OpenAI\nsource: builtin\nscope: platform\n",
	})
	profileRequest.Header().Set("Authorization", "Bearer "+g.token)
	if _, err := profileClient.ImportProviderProfile(t.Context(), profileRequest); err != nil {
		t.Fatalf("create OpenAI profile through RPC: %v", err)
	}

	client, _ := g.openShellClient()
	ctx := g.rpcContext(t.Context(), g.token)
	_, err := client.CreateProvider(ctx, &compatv1.CreateProviderRequest{Provider: &datamodelv1.Provider{
		Metadata: &datamodelv1.ObjectMeta{Name: "acme", Workspace: "default"},
		Type:     "openai", Credentials: map[string]string{"API_KEY": "initial-access", "REFRESH_TOKEN": "initial-refresh"},
	}})
	if err != nil {
		t.Fatalf("create provider over RPC: %v", err)
	}
	configured, err := client.ConfigureProviderRefresh(ctx, &compatv1.ConfigureProviderRefreshRequest{
		Provider: "acme", CredentialKey: "API_KEY",
		Strategy: compatv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN,
		Material: map[string]string{"token_url": tokenEndpoint.URL, "refresh_token": "initial-refresh"},
	})
	if err != nil || configured.GetStatus().GetStatus() != "configured" {
		t.Fatalf("configure provider refresh over RPC: response=%v err=%v", configured, err)
	}
	rotated, err := client.RotateProviderCredential(ctx, &compatv1.RotateProviderCredentialRequest{Provider: "acme", CredentialKey: "API_KEY"})
	if err != nil || rotated.GetStatus().GetStatus() != "configured" {
		t.Fatalf("rotate provider credential over RPC: response=%v err=%v", rotated, err)
	}
	if rotations.Load() != 1 {
		t.Fatalf("token endpoint rotations=%d, want 1", rotations.Load())
	}
	got, err := client.GetProvider(ctx, &compatv1.GetProviderRequest{Name: "acme"})
	if err != nil {
		t.Fatalf("read provider over RPC: %v", err)
	}
	text := got.GetProvider().String()
	for _, secret := range []string{"initial-access", "initial-refresh", "rotated-access", "rotated-refresh", tokenEndpoint.URL} {
		if strings.Contains(text, secret) {
			t.Fatalf("provider response leaked %q: %s", secret, text)
		}
	}
	if got.GetProvider().GetCredentials()["API_KEY"] != "REDACTED" {
		t.Fatalf("provider response did not redact API_KEY: %s", text)
	}

	if _, err := client.DeleteProvider(ctx, &compatv1.DeleteProviderRequest{Name: "acme"}); err != nil {
		t.Fatalf("delete provider over RPC: %v", err)
	}
	if _, err := client.GetProvider(ctx, &compatv1.GetProviderRequest{Name: "acme"}); err == nil {
		t.Fatal("deleted provider remained available through OpenShell RPC")
	}
}
