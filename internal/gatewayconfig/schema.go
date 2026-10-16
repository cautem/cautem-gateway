// Package gatewayconfig implements the pinned compatibility gateway TOML schema.
package gatewayconfig

type File struct {
	Compatibility Root `toml:"openshell"`
}

type Root struct {
	Version           *uint32        `toml:"version"`
	Gateway           Gateway        `toml:"gateway"`
	Supervisor        Supervisor     `toml:"supervisor"`
	Drivers           map[string]any `toml:"drivers"`
	CredentialDrivers map[string]any `toml:"credential_drivers"`
}

type Gateway struct {
	Name               *string `toml:"name"`
	BindAddress        *string `toml:"bind_address"`
	HealthBindAddress  *string `toml:"health_bind_address"`
	MetricsBindAddress *string `toml:"metrics_bind_address"`
	LogLevel           *string `toml:"log_level"`
	// ComputeDriver is the pinned OpenShell v0.1.4 single-backend selector.
	// ComputeDrivers remains available for existing Cautem multi-backend files.
	ComputeDriver               *string          `toml:"compute_driver"`
	ComputeDrivers              *[]string        `toml:"compute_drivers"`
	CredentialDrivers           *[]string        `toml:"credential_drivers"`
	DefaultCredentialDriver     *string          `toml:"default_credential_driver"`
	CredentialStorage           *map[string]any  `toml:"credential_storage"`
	SandboxNamespace            *string          `toml:"sandbox_namespace"`
	SSHSessionTTLSecs           *uint64          `toml:"ssh_session_ttl_secs"`
	GRPCRateLimitRequests       *uint64          `toml:"grpc_rate_limit_requests"`
	GRPCRateLimitWindowSeconds  *uint64          `toml:"grpc_rate_limit_window_seconds"`
	PolicyValidationFailureMode *string          `toml:"policy_validation_failure_mode"`
	ServerSANs                  *[]string        `toml:"server_sans"`
	EnableLoopbackServiceHTTP   *bool            `toml:"enable_loopback_service_http"`
	DefaultImage                *string          `toml:"default_image"`
	SupervisorImage             *string          `toml:"supervisor_image"`
	ClientTLSSecretName         *string          `toml:"client_tls_secret_name"`
	ServiceAccountName          *string          `toml:"service_account_name"`
	HostGatewayIP               *string          `toml:"host_gateway_ip"`
	EnableUserNamespaces        *bool            `toml:"enable_user_namespaces"`
	SATokenTTLSecs              *int64           `toml:"sa_token_ttl_secs"`
	GuestTLSCA                  *string          `toml:"guest_tls_ca"`
	GuestTLSCert                *string          `toml:"guest_tls_cert"`
	GuestTLSKey                 *string          `toml:"guest_tls_key"`
	DisableTLS                  *bool            `toml:"disable_tls"`
	TLS                         *TLS             `toml:"tls"`
	OIDC                        *OIDC            `toml:"oidc"`
	Auth                        *Auth            `toml:"auth"`
	Interceptors                []Interceptor    `toml:"interceptors"`
	ProviderProfileSources      *[]ProfileSource `toml:"provider_profile_sources"`
	MTLSAuth                    *MTLSAuth        `toml:"mtls_auth"`
	GatewayJWT                  *JWT             `toml:"gateway_jwt"`
	OTLP                        *OTLP            `toml:"otlp"`
	DatabaseURL                 *string          `toml:"database_url"`
}

type OTLP struct {
	Endpoint    *string `toml:"endpoint"`
	ServiceName *string `toml:"service_name"`
}

type Supervisor struct {
	Middleware []Middleware `toml:"middleware"`
}

type Middleware struct {
	Name                   *string `toml:"name"`
	GRPCEndpoint           *string `toml:"grpc_endpoint"`
	TLSCACertPath          *string `toml:"tls_ca_cert_path"`
	Audience               *string `toml:"audience"`
	AllowInsecureTransport bool    `toml:"allow_insecure_transport"`
	MaxPayloadBytes        *uint64 `toml:"max_payload_bytes"`
	MaxBodyBytes           *uint64 `toml:"max_body_bytes"`
	Timeout                *string `toml:"timeout"`
}

type TLS struct {
	CertPath            *string  `toml:"cert_path"`
	KeyPath             *string  `toml:"key_path"`
	ClientCAPath        *string  `toml:"client_ca_path"`
	RequireClientAuth   bool     `toml:"require_client_auth"`
	ExternalCertPath    *string  `toml:"external_cert_path"`
	ExternalKeyPath     *string  `toml:"external_key_path"`
	ExternalServerNames []string `toml:"external_server_names"`
}

type OIDC struct {
	Issuer      *string `toml:"issuer"`
	Audience    *string `toml:"audience"`
	JWKSTTLSecs *uint64 `toml:"jwks_ttl_secs"`
	RolesClaim  *string `toml:"roles_claim"`
	AdminRole   *string `toml:"admin_role"`
	UserRole    *string `toml:"user_role"`
	ScopesClaim string  `toml:"scopes_claim"`
}

type Auth struct {
	AllowUnauthenticatedUsers bool `toml:"allow_unauthenticated_users"`
}

type MTLSAuth struct {
	Enabled bool `toml:"enabled"`
}

type JWT struct {
	SigningKeyPath *string `toml:"signing_key_path"`
	PublicKeyPath  *string `toml:"public_key_path"`
	KIDPath        *string `toml:"kid_path"`
	GatewayID      *string `toml:"gateway_id"`
	TTLSecs        uint64  `toml:"ttl_secs"`
}

type Interceptor struct {
	Name                   *string   `toml:"name"`
	GRPCEndpoint           *string   `toml:"grpc_endpoint"`
	TLSCACertPath          *string   `toml:"tls_ca_cert_path"`
	Audience               *string   `toml:"audience"`
	AllowInsecureTransport bool      `toml:"allow_insecure_transport"`
	Order                  int32     `toml:"order"`
	FailurePolicy          *string   `toml:"failure_policy"`
	Timeout                *string   `toml:"timeout"`
	MaxResponseBytes       *uint64   `toml:"max_response_bytes"`
	MaxPatches             *uint64   `toml:"max_patches"`
	BindingPolicy          *string   `toml:"binding_policy"`
	Bindings               []Binding `toml:"bindings"`
}

type Binding struct {
	ID            *string   `toml:"id"`
	RPC           *string   `toml:"rpc"`
	Service       *string   `toml:"service"`
	Method        *string   `toml:"method"`
	Phases        *[]string `toml:"phases"`
	Disabled      bool      `toml:"disabled"`
	FailurePolicy *string   `toml:"failure_policy"`
}

type ProfileSource struct {
	Type string  `toml:"type"`
	Name *string `toml:"name"`
}
