package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-gateway/internal/gatewayconfig"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSupervisorMiddlewareConfigAndSelection(t *testing.T) {
	name, endpoint := "acme/guard", "https://middleware.example:9443"
	maxPayload := uint64(4096)
	configs := []gatewayconfig.Middleware{{Name: &name, GRPCEndpoint: &endpoint, MaxPayloadBytes: &maxPayload}}
	services, err := supervisorMiddlewareServices(configs)
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0].GetAudience() != "urn:openshell:extension:middleware:acme/guard" || services[0].GetMaxPayloadBytes() != maxPayload {
		t.Fatalf("registered services=%v", services)
	}
	policy := &sandboxv1.SandboxPolicy{NetworkMiddlewares: map[string]*sandboxv1.NetworkMiddlewareConfig{
		"guard-config": {Middleware: name},
	}}
	selected, err := requiredSupervisorMiddlewareServices(policy, services)
	if err != nil || len(selected) != 1 || selected[0].GetName() != name {
		t.Fatalf("selected services=%v err=%v", selected, err)
	}
	if _, err := requiredSupervisorMiddlewareServices(policy, nil); err == nil {
		t.Fatal("unregistered policy middleware was accepted")
	}
	if selected, err := requiredSupervisorMiddlewareServices(&sandboxv1.SandboxPolicy{}, services); err != nil || len(selected) != 0 {
		t.Fatalf("unused registration selected: %v err=%v", selected, err)
	}
}

func TestGetSandboxConfigReturnsOnlySelectedMiddlewareServices(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-middleware-config")
	if err != nil {
		t.Fatal(err)
	}
	policy := "version: 1\nnetwork_middlewares:\n  guard-config:\n    middleware: acme/guard\n    endpoints:\n      include: [api.example.com]\n"
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default", BasePolicyYAML: policy, PolicyRev: 1}); err != nil {
		t.Fatal(err)
	}
	name, endpoint := "acme/guard", "https://middleware.example:9443"
	maxPayload := uint64(4096)
	services, err := supervisorMiddlewareServices([]gatewayconfig.Middleware{{Name: &name, GRPCEndpoint: &endpoint, MaxPayloadBytes: &maxPayload}})
	if err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{options: Options{SupervisorMiddlewareServices: services}, runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	response, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.GetSupervisorMiddlewareServices()) != 1 || response.GetSupervisorMiddlewareServices()[0].GetName() != name {
		t.Fatalf("middleware services=%v", response.GetSupervisorMiddlewareServices())
	}
	rpc.options.SupervisorMiddlewareServices = nil
	if _, err := rpc.GetSandboxConfig(ctx, &sandboxv1.GetSandboxConfigRequest{Name: "demo"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unregistered policy middleware error=%v", err)
	}
}

func TestSupervisorMiddlewareConfigRejectsUnsafeAndInvalidValues(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		insecure bool
		timeout  string
		wantErr  bool
	}{
		{name: "safe", endpoint: "https://middleware.example:9443", timeout: "10ms"},
		{name: "plaintext", endpoint: "http://middleware.example:9443", timeout: "500ms", wantErr: true},
		{name: "short_timeout", endpoint: "https://middleware.example:9443", timeout: "9ms", wantErr: true},
		{name: "unsupported_timeout_unit", endpoint: "https://middleware.example:9443", timeout: "1m", wantErr: true},
		{name: "fractional_timeout", endpoint: "https://middleware.example:9443", timeout: "1.5s", wantErr: true},
		{name: "explicit_insecure", endpoint: "http://middleware.example:9443", insecure: true, timeout: "30s"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, endpoint, timeout := "guard", test.endpoint, test.timeout
			maxPayload := uint64(1024)
			_, err := supervisorMiddlewareServices([]gatewayconfig.Middleware{{Name: &name, GRPCEndpoint: &endpoint, MaxPayloadBytes: &maxPayload, Timeout: &timeout, AllowInsecureTransport: test.insecure}})
			if (err != nil) != test.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
	name, endpoint := "guard", "https://middleware.example:9443"
	maxPayload := uint64(1024)
	if _, err := supervisorMiddlewareServices([]gatewayconfig.Middleware{{Name: &name, GRPCEndpoint: &endpoint, MaxPayloadBytes: &maxPayload}, {Name: &name, GRPCEndpoint: &endpoint, MaxPayloadBytes: &maxPayload}}); err == nil {
		t.Fatal("duplicate registration name was accepted")
	}
}

func TestReadMiddlewareCAPEMPreservesCertificateBundles(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeCertificate := func(serial int64, key *ecdsa.PrivateKey) []byte {
		t.Helper()
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "middleware-test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	path := t.TempDir() + "/ca.pem"
	data := append(makeCertificate(1, key1), makeCertificate(2, key2)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sanitized, err := readMiddlewareCAPEM(path)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for rest := sanitized; len(rest) > 0; {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("invalid sanitized CA bundle at %q", rest)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Fatalf("invalid certificate in sanitized bundle: %v", err)
		}
		count++
		rest = remaining
	}
	if count != 2 {
		t.Fatalf("sanitized certificate count=%d; want 2", count)
	}
}
