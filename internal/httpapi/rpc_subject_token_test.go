//go:build linux || darwin

package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-runtime/secrets"
	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type subjectTokenWorkloadAPIServer struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	response *workload.JWTSVIDResponse
	bundles  *workload.JWTBundlesResponse
}

func (s *subjectTokenWorkloadAPIServer) FetchJWTSVID(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	return s.response, nil
}

func (s *subjectTokenWorkloadAPIServer) FetchJWTBundles(_ *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	if err := stream.Send(s.bundles); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestExchangeProviderSubjectTokenUsesWorkloadSVIDAndProviderCredential(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "subject-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{
		"sub": "spiffe://example.test/supervisor",
		"aud": []string{"https://issuer.example/token"},
		"iss": "https://issuer.example",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	supervisorSVID, err := compact.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	trustDomain, err := spiffeid.TrustDomainFromString("example.test")
	if err != nil {
		t.Fatal(err)
	}
	bundle := jwtbundle.New(trustDomain)
	if err := bundle.AddJWTAuthority("subject-test-key", &key.PublicKey); err != nil {
		t.Fatal(err)
	}
	bundleBytes, err := bundle.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	socketDir, err := os.MkdirTemp("", "gw-wapi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	workloadServer := &subjectTokenWorkloadAPIServer{
		response: &workload.JWTSVIDResponse{Svids: []*workload.JWTSVID{{SpiffeId: "spiffe://example.test/gateway", Svid: supervisorSVID}}},
		bundles:  &workload.JWTBundlesResponse{Bundles: map[string][]byte{"example.test": bundleBytes}},
	}
	grpcServer := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(grpcServer, workloadServer)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})
	// Confirm the fake Workload API is usable before exercising the gateway.
	source, err := workloadapi.NewJWTSource(context.Background(), workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+socket)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.FetchJWTSVID(context.Background(), jwtsvid.Params{Audience: "https://issuer.example/token"}); err != nil {
		t.Fatal(err)
	}
	_ = source.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		for _, field := range []string{"client_assertion", "subject_token", "audience", "requested_token_type"} {
			if strings.TrimSpace(r.Form.Get(field)) == "" {
				t.Errorf("token exchange field %q is empty: %v", field, r.Form)
			}
		}
		if r.Form.Get("subject_token") != "provider-subject-token" {
			t.Errorf("subject_token=%q", r.Form.Get("subject_token"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"exchanged-access","expires_in":300,"token_type":"Bearer"}`)
	}))
	defer tokenServer.Close()

	st, err := store.Open(t.TempDir(), "subject-token")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	profile := `id: subject-profile
display_name: Subject profile
credentials:
  - name: subject
    env_vars: [SUBJECT_TOKEN]
  - name: access
    token_grant:
      grant_type: token_exchange
      token_endpoint: ` + tokenServer.URL + `
      jwt_svid_audience: https://issuer.example/token
      subject_token:
        source: provider_credential
        credential: subject
`
	if err := st.UpsertProfile("subject-profile", profile); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "provider", Type: "subject-profile", Workspace: "default", EnvVars: []string{"SUBJECT_TOKEN"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "sandbox-id", ID: "sandbox-id", Workspace: "default", AttachedProviders: []string{"provider"}}); err != nil {
		t.Fatal(err)
	}
	if err := sec.PutProviderCredentials(context.Background(), "provider", map[string]string{"SUBJECT_TOKEN": "provider-subject-token"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET", "")
	t.Setenv("CAUTEM_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET", socket)
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, sec: sec, opt: Options{ProviderProfileSources: []string{"user"}}}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "sandbox-id"})
	response, err := rpc.ExchangeProviderSubjectToken(ctx, &openshellv1.ExchangeProviderSubjectTokenRequest{SandboxId: "sandbox-id", Provider: "provider", CredentialKey: "access", SupervisorJwtSvid: supervisorSVID})
	if err != nil {
		t.Fatalf("subject token exchange: %v", err)
	}
	if response.GetAccessToken() != "exchanged-access" || response.GetExpiresIn() != 300 || response.GetTokenType() != "Bearer" {
		t.Fatalf("response=%+v", response)
	}
	_, err = rpc.ExchangeProviderSubjectToken(ctx, &openshellv1.ExchangeProviderSubjectTokenRequest{
		SandboxId: "sandbox-id", Provider: "provider", CredentialKey: "access", SupervisorJwtSvid: "provider-secret-invalid-svid",
	})
	if status.Code(err) != codes.Unauthenticated || strings.Contains(err.Error(), "provider-secret-invalid-svid") {
		t.Fatalf("invalid supervisor SVID error=%v; want redacted Unauthenticated", err)
	}
}
