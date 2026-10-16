package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-runtime/secrets"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestGetProviderCredentialsRequiresVerifiedMTLSOperator(t *testing.T) {
	ctx := operatorTLSContext("operator")
	authenticated, err := authenticateProviderCredentialOperator(ctx, Options{EnableMTLSAuth: true})
	if err != nil || PrincipalFrom(authenticated).IDP != "mtls" {
		t.Fatalf("authenticated principal=%+v err=%v", PrincipalFrom(authenticated), err)
	}
	if _, err := authenticateProviderCredentialOperator(operatorTLSContext("user"), Options{EnableMTLSAuth: true}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-operator mTLS cert error=%v", err)
	}
	withBearer := metadata.NewIncomingContext(operatorTLSContext("operator"), metadata.Pairs("authorization", "Bearer token"))
	if _, err := authenticateProviderCredentialOperator(withBearer, Options{EnableMTLSAuth: true}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bearer plus mTLS error=%v", err)
	}
	if _, err := authenticateProviderCredentialOperator(operatorTLSContext("operator"), Options{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("disabled mTLS error=%v", err)
	}
}

func TestGetProviderCredentialsValidatesSelectionAndExportsAllOrNothing(t *testing.T) {
	st, err := store.Open(t.TempDir(), "provider-credential-export")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team-a"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProfile("provider-profile", `id: provider-profile
display_name: Export test
credentials:
  - name: api_token
    env_vars: [API_TOKEN]
  - name: exchange_token
    env_vars: [EXCHANGE_TOKEN]
    token_grant:
      grant_type: token_exchange
      token_endpoint: https://issuer.example/token
`); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "provider-a", Type: "provider-profile", Workspace: "team-a", EnvVars: []string{"API_TOKEN", "EXCHANGE_TOKEN"}}); err != nil {
		t.Fatal(err)
	}
	if err := sec.PutProviderCredentials(context.Background(), "provider-a", map[string]string{"API_TOKEN": "runtime-secret", "EXCHANGE_TOKEN": "subject-secret"}); err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, sec: sec, opt: Options{ProviderProfileSources: []string{"user"}}}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, Subject: "operator", IDP: "mtls", Roles: []string{"operator"}})
	request := &compatv1.GetProviderCredentialsRequest{
		WorkspaceScope: workspaceScope("team-a"), Name: "provider-a", CredentialKeys: []string{"API_TOKEN"},
	}
	response, err := rpc.GetProviderCredentials(ctx, request)
	if err != nil || response.GetCredentials()["API_TOKEN"].GetValue() != "runtime-secret" || response.GetCredentials()["API_TOKEN"].GetExpirationTime() != nil {
		t.Fatalf("response=%v err=%v", response, err)
	}
	for _, invalid := range []*compatv1.GetProviderCredentialsRequest{
		{WorkspaceScope: workspaceScope("team-a"), Name: "provider-a", CredentialKeys: []string{"API_TOKEN", "API_TOKEN"}},
		{WorkspaceScope: workspaceScope("team-a"), Name: "provider-a", CredentialKeys: []string{"EXCHANGE_TOKEN"}},
		{WorkspaceScope: allWorkspacesScope(), Name: "provider-a", CredentialKeys: []string{"API_TOKEN"}},
		{WorkspaceScope: workspaceScope("team-a"), Name: "provider-a", CredentialKeys: []string{"API_TOKEN"}, MinimumRemainingLifetime: durationpb.New(25 * time.Hour)},
	} {
		if got, err := rpc.GetProviderCredentials(ctx, invalid); err == nil || len(got.GetCredentials()) != 0 {
			t.Fatalf("invalid request returned credentials: response=%v err=%v", got, err)
		}
	}
	missing, err := rpc.GetProviderCredentials(ctx, &compatv1.GetProviderCredentialsRequest{
		WorkspaceScope: workspaceScope("team-a"), Name: "provider-a", CredentialKeys: []string{"API_TOKEN", "MISSING_TOKEN"},
	})
	if status.Code(err) != codes.FailedPrecondition || len(missing.GetCredentials()) != 0 {
		t.Fatalf("mixed selection returned partial data: response=%v err=%v", missing, err)
	}
	if _, err := rpc.GetProviderCredentials(context.Background(), request); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unauthenticated handler call error=%v", err)
	}
}

func operatorTLSContext(role string) context.Context {
	certificate := &x509.Certificate{Subject: pkix.Name{CommonName: "operator-test", OrganizationalUnit: []string{role}}}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: state}})
}
