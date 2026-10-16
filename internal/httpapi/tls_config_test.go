package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

func writeTestCertificate(t *testing.T, dir, prefix string, dnsNames []string, isCA bool) (string, string, *x509.Certificate) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: prefix, OrganizationalUnit: []string{"ops-admin"}},
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    dnsNames, IsCA: isCA, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, prefix+".crt")
	keyPath := filepath.Join(dir, prefix+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, cert
}

func TestBuildGatewayTLSConfigLoadsClientCAAndSNIKeypair(t *testing.T) {
	dir := t.TempDir()
	internalCert, internalKey, _ := writeTestCertificate(t, dir, "internal", []string{"gateway.internal"}, false)
	externalCert, externalKey, _ := writeTestCertificate(t, dir, "external", []string{"gateway.example.com", "*.example.com"}, false)
	caCert, _, _ := writeTestCertificate(t, dir, "client-ca", nil, true)
	opt := Options{TLSCert: internalCert, TLSKey: internalKey, TLSClientCA: caCert, EnableMTLSAuth: true,
		TLSExternalCert: externalCert, TLSExternalKey: externalKey, TLSExternalServerNames: []string{"*.example.com"}}
	config, err := buildGatewayTLSConfig(opt)
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientAuth != tls.RequireAndVerifyClientCert || config.ClientCAs == nil {
		t.Fatalf("client auth=%v pool=%v", config.ClientAuth, config.ClientCAs)
	}
	got, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err != nil || got.Leaf == nil || got.Leaf.Subject.CommonName != "external" {
		t.Fatalf("SNI external cert=%v err=%v", got, err)
	}
	got, err = config.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.internal"})
	if err != nil || got.Leaf == nil || got.Leaf.Subject.CommonName != "internal" {
		t.Fatalf("SNI default cert=%v err=%v", got, err)
	}
}

func TestBuildGatewayTLSConfigRejectsIncompleteExternalAndBadCA(t *testing.T) {
	dir := t.TempDir()
	cert, key, _ := writeTestCertificate(t, dir, "internal", []string{"gateway.internal"}, false)
	for _, opt := range []Options{
		{TLSCert: cert, TLSKey: key, TLSExternalCert: cert},
		{TLSCert: cert, TLSKey: key, TLSExternalCert: cert, TLSExternalKey: key, TLSExternalServerNames: []string{"api.example.test"}},
		{TLSCert: cert, TLSKey: key, TLSClientCA: filepath.Join(dir, "missing.pem")},
	} {
		if _, err := buildGatewayTLSConfig(opt); err == nil {
			t.Errorf("invalid TLS config accepted: %+v", opt)
		}
	}
}

func TestTLSPreflightFailureDoesNotCreateGatewayState(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state-must-not-exist")
	err := Serve(context.Background(), Options{
		Listen: "127.0.0.1:0", RequireTLS: true,
		TLSCert: filepath.Join(t.TempDir(), "missing.crt"), TLSKey: filepath.Join(t.TempDir(), "missing.key"),
		DataDir: dataDir,
	})
	if err == nil {
		t.Fatal("missing TLS material was accepted")
	}
	if _, statErr := os.Stat(dataDir); !os.IsNotExist(statErr) {
		t.Fatalf("TLS preflight created state dir: %v", statErr)
	}
}

func TestTLSOptionalClientCertificateWithOIDCAndRequiredMTLSWithoutOIDC(t *testing.T) {
	dir := t.TempDir()
	cert, key, _ := writeTestCertificate(t, dir, "internal", []string{"gateway.internal"}, false)
	ca, _, _ := writeTestCertificate(t, dir, "client-ca", nil, true)
	optional, err := buildGatewayTLSConfig(Options{TLSCert: cert, TLSKey: key, TLSClientCA: ca, OIDC: OIDCOptions{Issuer: "https://issuer.example"}, EnableMTLSAuth: true})
	if err != nil || optional.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("OIDC client auth=%v err=%v", optional, err)
	}
	required, err := buildGatewayTLSConfig(Options{TLSCert: cert, TLSKey: key, TLSClientCA: ca, EnableMTLSAuth: true})
	if err != nil || required.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("mTLS client auth=%v err=%v", required, err)
	}
}

func TestMTLSPrincipalUsesVerifiedCertificateIdentity(t *testing.T) {
	_, _, cert := writeTestCertificate(t, t.TempDir(), "alice", nil, false)
	r := &http.Request{TLS: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}
	principal := mtlsPrincipal(r)
	if principal.Kind != PrincipalUser || principal.Subject != "alice" || principal.IDP != "mtls" || len(principal.Roles) != 1 || principal.Roles[0] != "ops-admin" {
		t.Fatalf("mTLS principal=%+v", principal)
	}
	if got := mtlsPrincipal(&http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}); got.Kind != PrincipalNone {
		t.Fatalf("unverified certificate authenticated: %+v", got)
	}
}

func TestMTLSAuthMiddlewareUsesOnlyVerifiedPeerCertificates(t *testing.T) {
	_, _, cert := writeTestCertificate(t, t.TempDir(), "alice", nil, false)
	st, err := store.Open(t.TempDir(), "gateway")
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := PrincipalFrom(r.Context())
		w.Header().Set("X-Principal", principal.Subject)
		w.Header().Set("X-IDP", principal.IDP)
		w.WriteHeader(http.StatusNoContent)
	})
	handler := withAuth(next, st, AuthOptions{EnableMTLSAuth: true})
	request := httptest.NewRequest(http.MethodGet, "/v1/settings", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || recorder.Header().Get("X-Principal") != "alice" || recorder.Header().Get("X-IDP") != "mtls" {
		t.Fatalf("verified mTLS request status=%d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/settings", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unverified mTLS request status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}
