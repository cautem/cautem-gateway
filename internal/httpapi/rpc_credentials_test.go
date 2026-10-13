package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-runtime/secrets"
)

func TestGetSandboxProviderEnvironmentRequiresMatchingSupervisorAndReturnsEncryptedCredential(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "sandbox-a", ID: "sandbox-a", AttachedProviders: []string{"provider-a"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "provider-a", Type: "unused", EnvVars: []string{"API_TOKEN"}}); err != nil {
		t.Fatal(err)
	}
	if err := sec.PutProviderCredentials(context.Background(), "provider-a", map[string]string{"API_TOKEN": "secret-value"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, sec: sec}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "sandbox-a"})
	response, err := rpc.GetSandboxProviderEnvironment(ctx, &openshellv1.GetSandboxProviderEnvironmentRequest{SandboxId: "sandbox-a"})
	if err != nil || response.GetEnvironment()["API_TOKEN"] != "secret-value" {
		t.Fatalf("response=%v err=%v", response, err)
	}
	if _, err := rpc.GetSandboxProviderEnvironment(ctx, &openshellv1.GetSandboxProviderEnvironmentRequest{SandboxId: "sandbox-b"}); err == nil {
		t.Fatal("sandbox supervisor read another sandbox's credentials")
	}
}

func TestOpenShellCredentialRefreshRPCConfiguresRotatesAndDeletesVaultMaterial(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "initial-refresh" {
			t.Errorf("token form=%v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"rotated-secret","expires_in":300,"refresh_token":"next-refresh"}`))
	}))
	defer tokenServer.Close()
	st, err := store.Open(t.TempDir(), "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := store.ProviderRecord{Name: "p", Type: "unused", EnvVars: []string{"API_TOKEN"}}
	if err := st.UpsertProvider(rec); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, sec: sec}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	configured, err := rpc.ConfigureProviderRefresh(ctx, &openshellv1.ConfigureProviderRefreshRequest{Provider: "p", CredentialKey: "API_TOKEN", Strategy: openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN, Material: map[string]string{"token_url": tokenServer.URL, "refresh_token": "initial-refresh"}})
	if err != nil || configured.GetStatus().GetStatus() != "configured" {
		t.Fatalf("configured=%v err=%v", configured, err)
	}
	refreshStatus, err := rpc.GetProviderRefreshStatus(ctx, &openshellv1.GetProviderRefreshStatusRequest{Provider: "p", CredentialKey: "API_TOKEN"})
	if err != nil || len(refreshStatus.GetCredentials()) != 1 || refreshStatus.GetCredentials()[0].GetCredentialKey() != "API_TOKEN" {
		t.Fatalf("refresh status=%v err=%v", refreshStatus, err)
	}
	current, err := rpc.RotateProviderCredential(ctx, &openshellv1.RotateProviderCredentialRequest{Provider: "p", CredentialKey: "API_TOKEN"})
	if err != nil || current.GetStatus().GetStatus() != "configured" {
		t.Fatalf("rotated=%v err=%v", current, err)
	}
	values, err := sec.GetProviderCredentials(ctx, "p", []string{"API_TOKEN"})
	if err != nil || values["API_TOKEN"] != "rotated-secret" {
		t.Fatalf("vault values=%v err=%v", values, err)
	}
	deleted, err := rpc.DeleteProviderRefresh(ctx, &openshellv1.DeleteProviderRefreshRequest{Provider: "p", CredentialKey: "API_TOKEN"})
	if err != nil || !deleted.GetDeleted() {
		t.Fatalf("deleted=%v err=%v", deleted, err)
	}
}

func TestOpenShellCredentialRefreshRPCSupportsGoogleServiceAccountJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || r.Form.Get("assertion") == "" {
			t.Errorf("unexpected JWT grant form: %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "google-rotated", "expires_in": 300})
	}))
	defer tokenServer.Close()

	st, err := store.Open(t.TempDir(), "gw-google-refresh")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "google", Type: "unused", EnvVars: []string{"GOOGLE_TOKEN"}}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, sec: sec}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.ConfigureProviderRefresh(ctx, &openshellv1.ConfigureProviderRefreshRequest{
		Provider: "google", CredentialKey: "GOOGLE_TOKEN",
		Strategy: openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT,
		Material: map[string]string{"client_email": "svc@example.test", "private_key": privateKey, "token_url": tokenServer.URL, "scope": "scope:test"},
	})
	if err != nil {
		t.Fatalf("configure google refresh: %v", err)
	}
	if _, err := rpc.RotateProviderCredential(ctx, &openshellv1.RotateProviderCredentialRequest{Provider: "google", CredentialKey: "GOOGLE_TOKEN"}); err != nil {
		t.Fatalf("rotate google refresh: %v", err)
	}
	values, err := sec.GetProviderCredentials(ctx, "google", []string{"GOOGLE_TOKEN"})
	if err != nil || values["GOOGLE_TOKEN"] != "google-rotated" {
		t.Fatalf("google credentials=%v err=%v", values, err)
	}
}

func TestOpenShellCredentialRefreshRPCSupportsAWSSTSAssumeRole(t *testing.T) {
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		if r.Form.Get("Action") != "AssumeRole" || r.Form.Get("RoleArn") != "arn:aws:iam::123456789012:role/test" {
			t.Errorf("STS form=%v", r.Form)
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASIA-ROTATED</AccessKeyId><SecretAccessKey>secret-rotated</SecretAccessKey><SessionToken>session-rotated</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	defer stsServer.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", stsServer.URL)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	st, err := store.Open(t.TempDir(), "gw-aws-refresh")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProfile("aws-profile", `id: aws-profile
display_name: AWS
credentials:
  - name: AWS_ACCESS_KEY_ID
    env_vars: [AWS_ACCESS_KEY_ID]
    refresh:
      strategy: aws_sts_assume_role
      additional_outputs:
        - output: secret_access_key
          credential: AWS_SECRET_ACCESS_KEY
        - output: session_token
          credential: AWS_SESSION_TOKEN
`); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "aws", Type: "aws-profile", Workspace: "default", EnvVars: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, sec: sec, opt: Options{ProviderProfileSources: []string{"user"}}}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	if _, err := rpc.ConfigureProviderRefresh(ctx, &openshellv1.ConfigureProviderRefreshRequest{
		Provider: "aws", CredentialKey: "AWS_ACCESS_KEY_ID",
		Strategy: openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE,
		Material: map[string]string{"role_arn": "arn:aws:iam::123456789012:role/test", "aws_region": "us-east-1", "aws_access_key_id": "source-access", "aws_secret_access_key": "source-secret"},
	}); err != nil {
		t.Fatalf("configure AWS refresh: %v", err)
	}
	if _, err := rpc.RotateProviderCredential(ctx, &openshellv1.RotateProviderCredentialRequest{Provider: "aws", CredentialKey: "AWS_ACCESS_KEY_ID"}); err != nil {
		t.Fatalf("rotate AWS refresh: %v", err)
	}
	values, err := sec.GetProviderCredentials(ctx, "aws", []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"})
	if err != nil || values["AWS_ACCESS_KEY_ID"] != "ASIA-ROTATED" || values["AWS_SECRET_ACCESS_KEY"] != "secret-rotated" || values["AWS_SESSION_TOKEN"] != "session-rotated" {
		t.Fatalf("AWS credentials=%v err=%v", values, err)
	}
}

func TestResolveSandboxSecretsRejectsExpiredCredentialWithoutRefresh(t *testing.T) {
	st, err := store.Open(t.TempDir(), "expired-credential")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{
		Name: "expired", Type: "test", EnvVars: []string{"API_TOKEN"},
		CredentialExpiresAtMS: map[string]int64{"API_TOKEN": time.Now().Add(-time.Minute).UnixMilli()},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "sandbox", AttachedProviders: []string{"expired"}}); err != nil {
		t.Fatal(err)
	}
	if err := sec.PutProviderCredentials(context.Background(), "expired", map[string]string{"API_TOKEN": "stale"}); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSandboxSecrets(context.Background(), st, sec, "", "sandbox"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired credential was accepted: %v", err)
	}
}
