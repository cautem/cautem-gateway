package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenShellGatewayStartupPrecedence(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, key := range []string{"OPENSHELL_GATEWAY_CONFIG", "OPENSHELL_GATEWAY_NAME", "OPENSHELL_BIND_ADDRESS", "OPENSHELL_SERVER_PORT", "OPENSHELL_HEALTH_PORT", "OPENSHELL_METRICS_PORT", "OPENSHELL_DISABLE_TLS", EnvSSHSessionTTL, EnvAllowUnauthenticated} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "gateway.toml")
	input := `[openshell]
version=1
[openshell.gateway]
name="file-name"
bind_address="127.0.0.1:18080"
ssh_session_ttl_secs=60
disable_tls=true
[openshell.gateway.auth]
allow_unauthenticated_users=false
`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	opt, err := resolveGatewayOptions([]string{"--config", path})
	if err != nil || opt.Name != "file-name" || opt.Listen != "127.0.0.1:18080" || opt.SSHSessionTTL != time.Minute || opt.AllowUnauthenticated {
		t.Fatalf("file options=%+v err=%v", opt, err)
	}
	t.Setenv("OPENSHELL_GATEWAY_NAME", "env-name")
	t.Setenv("OPENSHELL_BIND_ADDRESS", "::1")
	t.Setenv("OPENSHELL_SERVER_PORT", "18081")
	t.Setenv(EnvSSHSessionTTL, "120")
	t.Setenv(EnvAllowUnauthenticated, "true")
	opt, err = resolveGatewayOptions([]string{"--config=" + path})
	if err != nil || opt.Name != "env-name" || opt.Listen != "[::1]:18081" || opt.SSHSessionTTL != 2*time.Minute || !opt.AllowUnauthenticated {
		t.Fatalf("env options=%+v err=%v", opt, err)
	}
	opt, err = resolveGatewayOptions([]string{"--config", path, "--name=flag-name", "--port=18082", "--ssh-session-ttl-secs", "30", "--allow-unauthenticated-users=false"})
	if err != nil || opt.Name != "flag-name" || opt.Listen != "[::1]:18082" || opt.SSHSessionTTL != 30*time.Second || opt.AllowUnauthenticated {
		t.Fatalf("flag options=%+v err=%v", opt, err)
	}
}

func TestGatewayPostgreSQLURLSupportsEnvironmentAndFlagPrecedence(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENSHELL_DB_URL", "")
	opt, err := resolveGatewayOptions(nil)
	if err != nil || opt.DatabaseURL != "" {
		t.Fatalf("empty optional environment database URL=%q err=%v", opt.DatabaseURL, err)
	}
	t.Setenv("OPENSHELL_DB_URL", "postgres://env:secret@db.example:5432/gateway?sslmode=require")
	opt, err = resolveGatewayOptions(nil)
	if err != nil || opt.DatabaseURL != "postgres://env:secret@db.example:5432/gateway?sslmode=require" {
		t.Fatalf("environment database URL=%q err=%v", opt.DatabaseURL, err)
	}
	opt, err = resolveGatewayOptions([]string{"--db-url=postgresql://flag:secret@db.example:5432/gateway?sslmode=require"})
	if err != nil || opt.DatabaseURL != "postgresql://flag:secret@db.example:5432/gateway?sslmode=require" {
		t.Fatalf("flag database URL=%q err=%v", opt.DatabaseURL, err)
	}
	t.Setenv("OPENSHELL_DB_URL", "not-a-postgres-url")
	opt, err = resolveGatewayOptions([]string{"--db-url", "postgres://flag@db.example/gateway"})
	if err != nil || opt.DatabaseURL != "postgres://flag@db.example/gateway" {
		t.Fatalf("flag did not override invalid environment: database URL=%q err=%v", opt.DatabaseURL, err)
	}
	if _, err := resolveGatewayOptions([]string{"--db-url", "sqlite:///gateway.db"}); err == nil || !strings.Contains(err.Error(), "PostgreSQL URL") {
		t.Fatalf("non-PostgreSQL database URL error=%v", err)
	}
}

func TestOpenShellBackendSelectionsAreResolvedToRegistryPlaceholders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	config := `[openshell.gateway]
disable_tls=true
compute_drivers=["docker", "podman", "vm", "kubernetes"]
credential_drivers=["local"]
default_credential_driver="local"
[openshell.gateway.credential_storage]
type="local_encrypted"
[openshell.drivers.docker]
default_image="sandbox:test"
[openshell.drivers.podman]
default_image="sandbox:test"
[openshell.drivers.vm]
state_dir="/tmp/vm-state"
[openshell.drivers.kubernetes]
namespace="sandbox"
[openshell.credential_drivers.local]
type="local_encrypted"
`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	opt, err := resolveGatewayOptions([]string{"--config", path})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(opt.ComputeDriverNames, ",") != "docker,podman,vm,kubernetes" || opt.ComputeDriverConfigs["docker"]["default_image"] != "sandbox:test" || opt.ComputeDriverConfigs["kubernetes"]["namespace"] != "sandbox" {
		t.Fatalf("compute registry config=%+v configs=%+v", opt.ComputeDriverNames, opt.ComputeDriverConfigs)
	}
	if strings.Join(opt.CredentialDriverNames, ",") != "local" || opt.CredentialDriverConfigs["local"]["type"] != "local_encrypted" || opt.CredentialStorage["type"] != "local_encrypted" {
		t.Fatalf("credential registry config=%+v", opt)
	}
}

func TestGatewayUnsupportedConfigFailsBeforeCreatingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	if err := os.WriteFile(path, []byte("[openshell.gateway]\ndisable_tls=true\ngrpc_rate_limit_requests=12\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state-must-not-exist")
	err := Run([]string{"--config", path, "--data-dir", state})
	if err == nil || !strings.Contains(err.Error(), "grpc_rate_limit_requests") {
		t.Fatalf("unsupported config diagnostic=%v", err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("invalid config created state: %v", err)
	}
}

func TestGatewayTTLRejectsTrailingInputAndOverflow(t *testing.T) {
	for _, value := range []string{"30suffix", "9223372036854775807", "18446744073709551615", "-1"} {
		if _, err := parseTTLSecs(value); err == nil {
			t.Fatalf("invalid TTL accepted: %s", value)
		}
	}
	if value, err := parseTTLSecs("0"); err != nil || value >= 0 {
		t.Fatalf("TTL zero semantics=%v err=%v", value, err)
	}
}

func TestDisabledTLSIgnoresConfiguredFiles(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "gateway.toml")
	if err := os.WriteFile(path, []byte(`[openshell.gateway]
disable_tls=true
[openshell.gateway.tls]
cert_path="missing.pem"
key_path="missing.key"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	opt, err := resolveGatewayOptions([]string{"--config", path})
	if err != nil || opt.RequireTLS || !opt.DisableTLS || opt.TLSCert != "" || opt.TLSKey != "" {
		t.Fatalf("disabled TLS options=%+v err=%v", opt, err)
	}
	opt, err = resolveGatewayOptions([]string{"--config", path, "--disable-tls=false"})
	if err != nil || !opt.RequireTLS || opt.TLSCert != "missing.pem" {
		t.Fatalf("enabled TLS options=%+v err=%v", opt, err)
	}
	if err := os.WriteFile(path, []byte("[openshell.gateway]\ndisable_tls=true\n[openshell.gateway.tls]\ncert_path=\"server.pem\"\nkey_path=\"server.key\"\nclient_ca_path=\"client-ca.pem\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveGatewayOptions([]string{"--config", path}); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("TLS disable with client CA should be rejected: %v", err)
	}
}

func TestGatewayTLSConfigFileEnvAndFlagPrecedence(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "gateway.toml")
	config := `[openshell.gateway]
disable_tls=false
[openshell.gateway.tls]
cert_path="gateway.pem"
key_path="gateway.key"
client_ca_path="client-ca.pem"
external_cert_path="external.pem"
external_key_path="external.key"
external_server_names=["*.example.test"]
[openshell.gateway.mtls_auth]
enabled=true
`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err := resolveGatewayOptions([]string{"--config", path})
	if err != nil || !opts.RequireTLS || !opts.EnableMTLSAuth || opts.TLSClientCA != "client-ca.pem" || opts.TLSExternalCert != "external.pem" || opts.TLSExternalKey != "external.key" || len(opts.TLSExternalServerNames) != 1 {
		t.Fatalf("TLS TOML options=%+v err=%v", opts, err)
	}
	t.Setenv("OPENSHELL_TLS_CLIENT_CA", "env-ca.pem")
	t.Setenv("OPENSHELL_ENABLE_MTLS_AUTH", "false")
	opts, err = resolveGatewayOptions([]string{"--config", path})
	if err != nil || opts.TLSClientCA != "env-ca.pem" || opts.EnableMTLSAuth {
		t.Fatalf("TLS env override=%+v err=%v", opts, err)
	}
	opts, err = resolveGatewayOptions([]string{"--config", path, "--tls-client-ca", "flag-ca.pem", "--enable-mtls-auth=false"})
	if err != nil || opts.TLSClientCA != "flag-ca.pem" || opts.EnableMTLSAuth {
		t.Fatalf("TLS flag override=%+v err=%v", opts, err)
	}
}

func TestGatewayProfileSourceConfigIsAppliedAndInterceptorSourceFailsClosed(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "gateway.toml")
	builtin := "[openshell.gateway]\ndisable_tls=true\nprovider_profile_sources=[{type=\"builtin\"}]\n"
	if err := os.WriteFile(path, []byte(builtin), 0o600); err != nil {
		t.Fatal(err)
	}
	opt, err := resolveGatewayOptions([]string{"--config", path})
	if err != nil || len(opt.ProviderProfileSources) != 1 || opt.ProviderProfileSources[0] != "builtin" {
		t.Fatalf("profile source options=%v err=%v", opt.ProviderProfileSources, err)
	}
	interceptor := "[openshell.gateway]\ndisable_tls=true\nprovider_profile_sources=[{type=\"interceptor\",name=\"catalog\"}]\n"
	if err := os.WriteFile(path, []byte(interceptor), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveGatewayOptions([]string{"--config", path}); err == nil || !strings.Contains(err.Error(), "interceptor requires gateway interceptor runtime") {
		t.Fatalf("unsupported interceptor profile source was not rejected: %v", err)
	}
}

func TestGatewayFlagsShadowInvalidSupportedEnvironment(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OPENSHELL_BIND_ADDRESS", "not-an-ip")
	t.Setenv("OPENSHELL_SERVER_PORT", "not-a-port")
	t.Setenv("OPENSHELL_DISABLE_TLS", "not-a-bool")
	t.Setenv(EnvSSHSessionTTL, "invalid-seconds")
	t.Setenv(EnvAllowUnauthenticated, "not-a-bool")
	opt, err := resolveGatewayOptions([]string{"--bind-address=::1", "--port=18080", "--disable-tls", "--ssh-session-ttl-secs=30", "--allow-unauthenticated-users=false"})
	if err != nil || opt.Listen != "[::1]:18080" || opt.SSHSessionTTL != 30*time.Second || opt.AllowUnauthenticated || !opt.DisableTLS {
		t.Fatalf("overridden environment options=%+v err=%v", opt, err)
	}
	flags := gatewayExplicitFlags([]string{"--name", "--port", "--log-level", "info"})
	if flags["--port"] || !flags["--name"] || !flags["--log-level"] {
		t.Fatalf("value interpreted as a flag: %v", flags)
	}
}

func TestOpenShellAuxiliaryListenersUseFileEnvAndFlagPrecedence(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, key := range []string{"OPENSHELL_GATEWAY_CONFIG", "OPENSHELL_HEALTH_PORT", "OPENSHELL_METRICS_PORT"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "gateway.toml")
	input := "[openshell.gateway]\nbind_address=\"127.0.0.1:17670\"\nhealth_bind_address=\"127.0.0.2:18081\"\nmetrics_bind_address=\"127.0.0.3:19090\"\ndisable_tls=true\n"
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	opt, err := resolveGatewayOptions([]string{"--config", path})
	if err != nil || opt.HealthListen != "127.0.0.2:18081" || opt.MetricsListen != "127.0.0.3:19090" {
		t.Fatalf("TOML listener settings=%+v err=%v", opt, err)
	}
	t.Setenv("OPENSHELL_HEALTH_PORT", "18082")
	t.Setenv("OPENSHELL_METRICS_PORT", "0")
	opt, err = resolveGatewayOptions([]string{"--config", path})
	if err != nil || opt.HealthListen != "127.0.0.1:18082" || opt.MetricsListen != "" {
		t.Fatalf("environment listener settings=%+v err=%v", opt, err)
	}
	opt, err = resolveGatewayOptions([]string{"--config", path, "--health-port=18083", "--metrics-port=19091"})
	if err != nil || opt.HealthListen != "127.0.0.1:18083" || opt.MetricsListen != "127.0.0.1:19091" {
		t.Fatalf("CLI listener settings=%+v err=%v", opt, err)
	}
	opt, err = resolveGatewayOptions([]string{"--config", path, "--health-port=18084", "--bind-address=::1"})
	if err != nil || opt.HealthListen != "[::1]:18084" {
		t.Fatalf("flag order changed listener address: %+v err=%v", opt, err)
	}
	opt, err = resolveGatewayOptions([]string{"--config", path, "--bind-address=::1"})
	if err != nil || opt.HealthListen != "[::1]:18082" {
		t.Fatalf("env port did not follow CLI bind address: %+v err=%v", opt, err)
	}
}

func TestAuxiliaryHealthAndMetricsContracts(t *testing.T) {
	for _, route := range []string{"/healthz", "/readyz", "/health"} {
		rec := httptest.NewRecorder()
		healthHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, route, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d", route, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	gatewayMetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "cautem_gateway_up 1") {
		t.Fatalf("metrics response=%d %q", rec.Code, rec.Body.String())
	}
}

func TestOpenShellOIDCConfigAndClaims(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, key := range []string{"OPENSHELL_GATEWAY_CONFIG", "OPENSHELL_OIDC_ISSUER", "OPENSHELL_OIDC_AUDIENCE", "OPENSHELL_OIDC_JWKS_TTL", "OPENSHELL_OIDC_ROLES_CLAIM", "OPENSHELL_OIDC_ADMIN_ROLE", "OPENSHELL_OIDC_USER_ROLE", "OPENSHELL_OIDC_SCOPES_CLAIM"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "gateway.toml")
	input := "[openshell.gateway]\ndisable_tls=true\n[openshell.gateway.oidc]\nissuer=\"https://id.example\"\naudience=\"cli-app\"\nroles_claim=\"realm_access.roles\"\nadmin_role=\"ops-admin\"\nuser_role=\"ops-user\"\n"
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	opt, err := resolveGatewayOptions([]string{"--config", path})
	if err != nil || opt.OIDC.Issuer != "https://id.example" || opt.OIDC.Audience != "cli-app" || opt.OIDC.JWKSTTLSecs != 3600 || opt.OIDC.AdminRole != "ops-admin" || opt.OIDC.UserRole != "ops-user" || opt.OIDC.ScopesClaim != "" {
		t.Fatalf("TOML OIDC config=%+v err=%v", opt.OIDC, err)
	}
	settings := OIDCOptions{RolesClaim: "realm_access.roles", AdminRole: "ops-admin", UserRole: "ops-user", ScopesClaim: "scope"}
	claims := map[string]any{"realm_access": map[string]any{"roles": []any{"ops-admin", "ops-user"}}, "scope": "openshell:all sandbox:read"}
	roles := oidcRoles(claims, settings)
	for _, role := range []string{"ops-admin", "ops-user", "platform_admin", "platform-admin", "user"} {
		if !containsString(roles, role) {
			t.Fatalf("configured role %q missing in %v", role, roles)
		}
	}
	if scopes := claimScopes(claims, settings.ScopesClaim); len(scopes) != 2 || scopes[0] != "openshell:all" {
		t.Fatalf("scopes=%v", scopes)
	}
	if _, err := newOIDCValidator(OIDCOptions{Issuer: "https://id.example", JWKSTTLSecs: 0}); err == nil {
		t.Fatal("zero JWKS cache TTL must fail closed")
	}
	scopedPath := filepath.Join(t.TempDir(), "scoped-gateway.toml")
	scoped := strings.Replace(input, "user_role=\"ops-user\"\n", "user_role=\"ops-user\"\nscopes_claim=\"scope\"\n", 1)
	if err := os.WriteFile(scopedPath, []byte(scoped), 0o600); err != nil {
		t.Fatal(err)
	}
	if scopedOptions, err := resolveGatewayOptions([]string{"--config", scopedPath}); err != nil || scopedOptions.OIDC.ScopesClaim != "scope" {
		t.Fatalf("OIDC scopes claim config=%+v err=%v", scopedOptions.OIDC, err)
	}
	if err := os.Setenv("OPENSHELL_OIDC_AUDIENCE", "env-aud"); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("OPENSHELL_OIDC_JWKS_TTL", "120"); err != nil {
		t.Fatal(err)
	}
	opt, err = resolveGatewayOptions([]string{"--config", path})
	if err != nil || opt.OIDC.Audience != "env-aud" || opt.OIDC.JWKSTTLSecs != 120 {
		t.Fatalf("OIDC env config=%+v err=%v", opt.OIDC, err)
	}
	if err := os.Setenv("OPENSHELL_OIDC_JWKS_TTL", "invalid"); err != nil {
		t.Fatal(err)
	}
	opt, err = resolveGatewayOptions([]string{"--config", path, "--oidc-jwks-ttl=90", "--oidc-admin-role=custom-admin"})
	if err != nil || opt.OIDC.JWKSTTLSecs != 90 || opt.OIDC.AdminRole != "custom-admin" {
		t.Fatalf("OIDC CLI override=%+v err=%v", opt.OIDC, err)
	}
}

func TestOpenShellOIDCScopesAuthorizeRESTRoutes(t *testing.T) {
	settings := OIDCOptions{ScopesClaim: "scope"}
	user := Principal{IDP: "oidc", Scopes: []string{"sandbox:read", "provider:read"}}
	for _, route := range []struct {
		method, path string
		allowed      bool
	}{
		{http.MethodGet, "/v1/sandboxes", true},
		{http.MethodPost, "/v1/sandboxes", false},
		{http.MethodGet, "/v1/providers", true},
		{http.MethodPost, "/v1/providers", false},
		{http.MethodGet, "/v1/whoami", true},
		{http.MethodGet, "/unmapped", false},
	} {
		if got := oidcRouteAuthorized(user, route.method, &url.URL{Path: route.path}, settings); got != route.allowed {
			t.Errorf("%s %s authorized=%v, want %v", route.method, route.path, got, route.allowed)
		}
	}
}

func TestOpenShellOIDCRolesAuthorizeReadsAndWrites(t *testing.T) {
	settings := OIDCOptions{AdminRole: "ops-admin", UserRole: "ops-user"}
	user := Principal{Kind: PrincipalUser, IDP: "oidc", Roles: []string{"ops-user"}}
	admin := Principal{Kind: PrincipalUser, IDP: "oidc", Roles: []string{"ops-admin"}}
	for _, route := range []struct {
		method, path              string
		userAllowed, adminAllowed bool
	}{
		{http.MethodPost, "/v1/sandboxes", false, true},
		{http.MethodGet, "/v1/sandboxes", true, true},
	} {
		u := &url.URL{Path: route.path}
		if got := oidcRouteAuthorized(user, route.method, u, settings); got != route.userAllowed {
			t.Errorf("user %s %s = %v", route.method, route.path, got)
		}
		if got := oidcRouteAuthorized(admin, route.method, u, settings); got != route.adminAllowed {
			t.Errorf("admin %s %s = %v", route.method, route.path, got)
		}
	}
	if !oidcRouteAuthorized(user, http.MethodPost, &url.URL{Path: "/anything"}, OIDCOptions{}) {
		t.Fatal("both roles empty must preserve OpenShell authentication-only mode")
	}
}
