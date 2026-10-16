package httpapi

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cautem/cautem-core/defaults"
	"github.com/cautem/cautem-gateway/internal/gatewayconfig"
)

// configStartup resolves file values and environment before command flags.
// Unsupported consumers are reported before Serve can create state/listeners.
func configStartup(args []string) (Options, *gatewayconfig.File, error) {
	opt := Options{Listen: defaults.GatewayListen, DataDir: defaultDataDir(), PolicyValidationFailureMode: "fail_closed"}
	explicit := gatewayExplicitFlags(args)
	if explicit["--help"] || explicit["-h"] {
		return opt, nil, nil
	}
	pathFlag := ""
	for i := 0; i < len(args); i++ {
		arg, _, _ := strings.Cut(args[i], "=")
		if arg == "--config" {
			if i+1 == len(args) {
				return opt, nil, fmt.Errorf("--config needs a value")
			}
			if args[i+1] == "" {
				return opt, nil, fmt.Errorf("--config needs a non-empty path")
			}
			pathFlag = args[i+1]
		}
		if gatewayFlagTakesValue(arg) {
			i++
		}
	}
	path, found, err := gatewayconfig.SelectPath(pathFlag)
	if err != nil {
		return opt, nil, err
	}
	var file *gatewayconfig.File
	if found {
		parsed, err := gatewayconfig.Load(path)
		if err != nil {
			return opt, nil, err
		}
		file = &parsed
		g := file.Compatibility.Gateway
		opt.SupervisorMiddlewareServices, err = supervisorMiddlewareServices(file.Compatibility.Supervisor.Middleware)
		if err != nil {
			return opt, file, err
		}
		opt.GatewayInterceptors = append([]gatewayconfig.Interceptor(nil), g.Interceptors...)
		if g.PolicyValidationFailureMode != nil {
			opt.PolicyValidationFailureMode = *g.PolicyValidationFailureMode
		}
		opt.Name, opt.Listen, opt.RequireTLS = "openshell", "127.0.0.1:17670", true
		opt.OIDC = OIDCOptions{Audience: "openshell-cli", JWKSTTLSecs: 3600, RolesClaim: "realm_access.roles", AdminRole: "openshell-admin", UserRole: "openshell-user"}
		if g.Name != nil {
			opt.Name = *g.Name
		}
		opt.ComputeDriverNames = []string{"docker"}
		if g.ComputeDriver != nil {
			opt.ComputeDriverNames = []string{*g.ComputeDriver}
		} else if g.ComputeDrivers != nil {
			opt.ComputeDriverNames = append([]string(nil), (*g.ComputeDrivers)...)
		}
		if len(opt.ComputeDriverNames) == 0 {
			return opt, file, fmt.Errorf("openshell.gateway.compute_drivers must select at least one driver")
		}
		opt.ComputeDriverConfigs = make(DriverConfigs)
		inheritable := []string{"sandbox_namespace", "default_image", "supervisor_image", "client_tls_secret_name", "service_account_name", "host_gateway_ip", "enable_user_namespaces", "sa_token_ttl_secs", "guest_tls_ca", "guest_tls_cert", "guest_tls_key"}
		for name, raw := range file.Compatibility.Drivers {
			if _, ok := raw.(map[string]any); !ok {
				return opt, file, fmt.Errorf("openshell.drivers.%s must be a table", name)
			}
			opt.ComputeDriverConfigs[name] = file.DriverTable(name, inheritable)
		}
		seenCompute := map[string]bool{}
		for _, name := range opt.ComputeDriverNames {
			if !isLocalComputeDriver(name) {
				config := opt.ComputeDriverConfigs[name]
				if config == nil || strings.TrimSpace(stringConfig(config, "grpc_endpoint")) == "" {
					return opt, file, fmt.Errorf("openshell.gateway.compute_drivers: unknown driver %q (registered backend or grpc_endpoint-backed driver required)", name)
				}
			}
			if seenCompute[name] {
				return opt, file, fmt.Errorf("openshell.gateway.compute_drivers: duplicate driver %q", name)
			}
			seenCompute[name] = true
		}
		if g.CredentialDrivers != nil {
			opt.CredentialDriverNames = append([]string(nil), (*g.CredentialDrivers)...)
		}
		if g.CredentialStorage != nil {
			opt.CredentialStorage = *g.CredentialStorage
		}
		if g.DefaultCredentialDriver != nil {
			opt.DefaultCredentialDriver = *g.DefaultCredentialDriver
		}
		opt.CredentialDriverConfigs = make(DriverConfigs)
		for name, raw := range file.Compatibility.CredentialDrivers {
			table, ok := raw.(map[string]any)
			if !ok {
				return opt, file, fmt.Errorf("openshell.credential_drivers.%s must be a table", name)
			}
			opt.CredentialDriverConfigs[name] = table
		}
		for _, name := range opt.CredentialDriverNames {
			if _, ok := opt.CredentialDriverConfigs[name]; !ok {
				return opt, file, fmt.Errorf("openshell.gateway.credential_drivers selects unconfigured driver %q", name)
			}
		}
		if opt.DefaultCredentialDriver != "" {
			selected := false
			for _, name := range opt.CredentialDriverNames {
				if name == opt.DefaultCredentialDriver {
					selected = true
					break
				}
			}
			if !selected {
				return opt, file, fmt.Errorf("openshell.gateway.default_credential_driver must be in credential_drivers")
			}
		}

		if g.BindAddress != nil {
			opt.Listen = *g.BindAddress
		}
		if g.HealthBindAddress != nil {
			opt.HealthListen = *g.HealthBindAddress
		}
		if g.MetricsBindAddress != nil {
			opt.MetricsListen = *g.MetricsBindAddress
		}
		if g.LogLevel != nil {
			opt.LogLevel = *g.LogLevel
		}
		if g.SSHSessionTTLSecs != nil {
			opt.SSHSessionTTL, err = parseTTLSecs(strconv.FormatUint(*g.SSHSessionTTLSecs, 10))
			if err != nil {
				return opt, file, fmt.Errorf("openshell.gateway.ssh_session_ttl_secs: %w", err)
			}
		}
		if g.Auth != nil {
			opt.AllowUnauthenticated = g.Auth.AllowUnauthenticatedUsers
		}
		if g.OIDC != nil {
			opt.OIDC.Issuer, opt.OIDC.Audience = *g.OIDC.Issuer, *g.OIDC.Audience
			opt.OIDC.JWKSTTLSecs, opt.OIDC.JWKSTTLSecsSet = *g.OIDC.JWKSTTLSecs, true
			opt.OIDC.RolesClaim, opt.OIDC.AdminRole, opt.OIDC.UserRole = *g.OIDC.RolesClaim, *g.OIDC.AdminRole, *g.OIDC.UserRole
			opt.OIDC.ScopesClaim = g.OIDC.ScopesClaim
			opt.OIDC.RolesClaimSet, opt.OIDC.AdminRoleSet, opt.OIDC.UserRoleSet = true, true, true
		}
		if g.DisableTLS != nil {
			opt.RequireTLS = !*g.DisableTLS
			opt.DisableTLS = *g.DisableTLS
		}
		if g.TLS != nil {
			opt.TLSCert, opt.TLSKey = *g.TLS.CertPath, *g.TLS.KeyPath
			if g.TLS.ClientCAPath != nil {
				opt.TLSClientCA = *g.TLS.ClientCAPath
			}
			opt.TLSRequireClientAuth = g.TLS.RequireClientAuth
			if g.TLS.ExternalCertPath != nil {
				opt.TLSExternalCert = *g.TLS.ExternalCertPath
			}
			if g.TLS.ExternalKeyPath != nil {
				opt.TLSExternalKey = *g.TLS.ExternalKeyPath
			}
			opt.TLSExternalServerNames = append([]string(nil), g.TLS.ExternalServerNames...)
		}
		if g.MTLSAuth != nil {
			opt.EnableMTLSAuth = g.MTLSAuth.Enabled
		}
		if g.ProviderProfileSources != nil {
			for _, source := range *g.ProviderProfileSources {
				if source.Type != "interceptor" {
					opt.ProviderProfileSources = append(opt.ProviderProfileSources, source.Type)
				}
			}
		}
	}
	if file == nil {
		for _, env := range []string{"OPENSHELL_OIDC_ISSUER", "OPENSHELL_OIDC_AUDIENCE", "OPENSHELL_OIDC_JWKS_TTL", "OPENSHELL_OIDC_ROLES_CLAIM", "OPENSHELL_OIDC_ADMIN_ROLE", "OPENSHELL_OIDC_USER_ROLE", "OPENSHELL_OIDC_SCOPES_CLAIM"} {
			if _, present := os.LookupEnv(env); present {
				file = nil
				opt.OIDC = OIDCOptions{Audience: "openshell-cli", JWKSTTLSecs: 3600, RolesClaim: "realm_access.roles", AdminRole: "openshell-admin", UserRole: "openshell-user"}
				break
			}
		}
		for _, flag := range []string{"--oidc-issuer", "--oidc-audience", "--oidc-jwks-ttl", "--oidc-roles-claim", "--oidc-admin-role", "--oidc-user-role", "--oidc-scopes-claim"} {
			if explicit[flag] {
				opt.OIDC = OIDCOptions{Audience: "openshell-cli", JWKSTTLSecs: 3600, RolesClaim: "realm_access.roles", AdminRole: "openshell-admin", UserRole: "openshell-user"}
				break
			}
		}
	}
	// Existing aliases remain below flags; pinned env names override local aliases.
	if value, present := os.LookupEnv("CAUTEM_LOG_LEVEL"); present && !explicit["--log-level"] {
		opt.LogLevel = value
	}
	oidcFromEnvAndFlags(&opt)
	if value, present := os.LookupEnv(EnvSSHSessionTTL); present && !explicit["--ssh-session-ttl-secs"] {
		opt.SSHSessionTTL, err = parseTTLSecs(value)
		if err != nil {
			return opt, file, fmt.Errorf("%s: invalid seconds", EnvSSHSessionTTL)
		}
	}
	if value, present := os.LookupEnv(EnvAllowUnauthenticated); present && !explicit["--allow-unauthenticated-users"] {
		if strings.EqualFold(value, "yes") {
			value = "true"
		}
		opt.AllowUnauthenticated, err = strconv.ParseBool(value)
		if err != nil {
			return opt, file, fmt.Errorf("%s must be a boolean", EnvAllowUnauthenticated)
		}
	}
	if value, present := os.LookupEnv("OPENSHELL_DB_URL"); present && !explicit["--db-url"] {
		if strings.TrimSpace(value) != "" {
			opt.DatabaseURL = value
		}
	}
	if value, present := gatewayFlagValue(args, "--db-url"); present {
		if strings.TrimSpace(value) == "" {
			return opt, file, fmt.Errorf("--db-url needs a non-empty PostgreSQL URL")
		}
		opt.DatabaseURL = value
	}
	if opt.DatabaseURL != "" {
		parsed, parseErr := url.Parse(opt.DatabaseURL)
		if parseErr != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
			return opt, file, fmt.Errorf("gateway database URL must be a PostgreSQL URL with a host")
		}
	}
	for _, key := range []string{"OPENSHELL_DRIVERS", "OPENSHELL_COMPUTE_DRIVER_SOCKET", "OPENSHELL_GRPC_RATE_LIMIT_REQUESTS", "OPENSHELL_GRPC_RATE_LIMIT_WINDOW_SECONDS", "OPENSHELL_SERVER_SAN", "OPENSHELL_ENABLE_LOOPBACK_SERVICE_HTTP"} {
		if _, present := os.LookupEnv(key); present {
			return opt, file, fmt.Errorf("gateway runtime consumer not implemented for %s", key)
		}
	}
	if value, present := os.LookupEnv("OPENSHELL_TLS_CLIENT_CA"); present && !explicit["--tls-client-ca"] {
		if value == "" {
			return opt, file, fmt.Errorf("OPENSHELL_TLS_CLIENT_CA must not be empty")
		}
		opt.TLSClientCA = value
	}
	if value, present := os.LookupEnv("OPENSHELL_ENABLE_MTLS_AUTH"); present && !explicit["--enable-mtls-auth"] {
		enabled, parseErr := strconv.ParseBool(value)
		if parseErr != nil {
			return opt, file, fmt.Errorf("OPENSHELL_ENABLE_MTLS_AUTH must be a boolean")
		}
		opt.EnableMTLSAuth = enabled
	}
	for env, target := range map[string]*string{"OPENSHELL_GATEWAY_NAME": &opt.Name, "OPENSHELL_LOG_LEVEL": &opt.LogLevel, "OPENSHELL_TLS_CERT": &opt.TLSCert, "OPENSHELL_TLS_KEY": &opt.TLSKey} {
		flag := map[string]string{"OPENSHELL_GATEWAY_NAME": "--name", "OPENSHELL_LOG_LEVEL": "--log-level", "OPENSHELL_TLS_CERT": "--tls-cert", "OPENSHELL_TLS_KEY": "--tls-key"}[env]
		if value, present := os.LookupEnv(env); present && !explicit[flag] {
			*target = value
			if env == "OPENSHELL_OIDC_ROLES_CLAIM" {
				opt.OIDC.RolesClaimSet = true
			}
			if env == "OPENSHELL_OIDC_ADMIN_ROLE" {
				opt.OIDC.AdminRoleSet = true
			}
			if env == "OPENSHELL_OIDC_USER_ROLE" {
				opt.OIDC.UserRoleSet = true
			}
		}
	}
	for env, target := range map[string]*string{"OPENSHELL_OIDC_ISSUER": &opt.OIDC.Issuer, "OPENSHELL_OIDC_AUDIENCE": &opt.OIDC.Audience, "OPENSHELL_OIDC_ROLES_CLAIM": &opt.OIDC.RolesClaim, "OPENSHELL_OIDC_ADMIN_ROLE": &opt.OIDC.AdminRole, "OPENSHELL_OIDC_USER_ROLE": &opt.OIDC.UserRole, "OPENSHELL_OIDC_SCOPES_CLAIM": &opt.OIDC.ScopesClaim} {
		flag := map[string]string{"OPENSHELL_OIDC_ISSUER": "--oidc-issuer", "OPENSHELL_OIDC_AUDIENCE": "--oidc-audience", "OPENSHELL_OIDC_ROLES_CLAIM": "--oidc-roles-claim", "OPENSHELL_OIDC_ADMIN_ROLE": "--oidc-admin-role", "OPENSHELL_OIDC_USER_ROLE": "--oidc-user-role", "OPENSHELL_OIDC_SCOPES_CLAIM": "--oidc-scopes-claim"}[env]
		if value, present := os.LookupEnv(env); present && !explicit[flag] {
			*target = value
		}
	}
	if value, present := os.LookupEnv("OPENSHELL_OIDC_JWKS_TTL"); present && !explicit["--oidc-jwks-ttl"] {
		seconds, parseErr := strconv.ParseUint(value, 10, 64)
		if parseErr != nil {
			return opt, file, fmt.Errorf("OPENSHELL_OIDC_JWKS_TTL must be positive seconds")
		}
		opt.OIDC.JWKSTTLSecs, opt.OIDC.JWKSTTLSecsSet = seconds, true
	}
	if value, present := os.LookupEnv("OPENSHELL_DISABLE_TLS"); present && !explicit["--disable-tls"] {
		disabled, err := strconv.ParseBool(value)
		if err != nil {
			return opt, file, fmt.Errorf("OPENSHELL_DISABLE_TLS must be a boolean")
		}
		opt.RequireTLS = !disabled
		opt.DisableTLS = disabled
	}
	if value, present := gatewayFlagValue(args, "--tls-cert"); present {
		opt.TLSCert = value
	}
	if value, present := gatewayFlagValue(args, "--tls-key"); present {
		opt.TLSKey = value
	}
	if value, present := gatewayFlagValue(args, "--tls-client-ca"); present {
		if value == "" {
			return opt, file, fmt.Errorf("--tls-client-ca needs a non-empty path")
		}
		opt.TLSClientCA = value
	}
	if value, present := gatewayFlagValue(args, "--enable-mtls-auth"); present {
		enabled, parseErr := strconv.ParseBool(value)
		if parseErr != nil {
			return opt, file, fmt.Errorf("--enable-mtls-auth must be a boolean")
		}
		opt.EnableMTLSAuth = enabled
	} else if gatewayFlagPresent(args, "--enable-mtls-auth") {
		opt.EnableMTLSAuth = true
	}
	if value, present := gatewayFlagValue(args, "--disable-tls"); present {
		disabled, parseErr := strconv.ParseBool(value)
		if parseErr != nil {
			return opt, file, fmt.Errorf("--disable-tls must be a boolean")
		}
		opt.DisableTLS, opt.RequireTLS = disabled, !disabled
	} else if gatewayFlagPresent(args, "--disable-tls") {
		opt.DisableTLS, opt.RequireTLS = true, false
	}
	host, port, err := net.SplitHostPort(opt.Listen)
	if err != nil {
		return opt, file, fmt.Errorf("gateway bind address must be a socket address")
	}
	if value, present := os.LookupEnv("OPENSHELL_BIND_ADDRESS"); present && !explicit["--bind-address"] && !explicit["--listen"] {
		if _, err := netip.ParseAddr(value); err != nil {
			return opt, file, fmt.Errorf("OPENSHELL_BIND_ADDRESS must be an IP address")
		}
		host = value
	}
	if value, present := os.LookupEnv("OPENSHELL_SERVER_PORT"); present && !explicit["--port"] && !explicit["--listen"] {
		if _, err := strconv.ParseUint(value, 10, 16); err != nil {
			return opt, file, fmt.Errorf("OPENSHELL_SERVER_PORT must be a uint16")
		}
		port = value
	}
	opt.Listen = net.JoinHostPort(host, port)
	for _, listener := range []struct {
		env, flag string
		target    *string
	}{{"OPENSHELL_HEALTH_PORT", "--health-port", &opt.HealthListen}, {"OPENSHELL_METRICS_PORT", "--metrics-port", &opt.MetricsListen}} {
		if value, present := os.LookupEnv(listener.env); present && !explicit[listener.flag] {
			if _, err := strconv.ParseUint(value, 10, 16); err != nil {
				return opt, file, fmt.Errorf("%s must be a uint16", listener.env)
			}
			if value == "0" {
				*listener.target = ""
			} else {
				*listener.target = net.JoinHostPort(host, value)
			}
		}
	}
	return opt, file, nil
}

// args have already been normalized. Skip value tokens so a value resembling
// a flag cannot accidentally suppress an environment value.
func gatewayExplicitFlags(args []string) map[string]bool {
	flags := map[string]bool{}
	for i := 0; i < len(args); i++ {
		key, _, _ := strings.Cut(args[i], "=")
		flags[key] = true
		if gatewayFlagTakesValue(key) {
			i++
		}
	}
	return flags
}

func gatewayFlagPresent(args []string, target string) bool {
	return gatewayExplicitFlags(args)[target]
}

func gatewayFlagValue(args []string, target string) (string, bool) {
	for i := 0; i < len(args); i++ {
		key, value, hasValue := strings.Cut(args[i], "=")
		if key != target {
			if gatewayFlagTakesValue(key) {
				i++
			}
			continue
		}
		if hasValue {
			return value, true
		}
		if target == "--enable-mtls-auth" || target == "--disable-tls" {
			return "true", true
		}
		if i+1 < len(args) {
			return args[i+1], true
		}
		return "", true
	}
	return "", false
}

func gatewayFlagTakesValue(key string) bool {
	return key != "--disable-tls" && key != "--allow-unauthenticated-users" && key != "--enable-mtls-auth" && key != "--oidc-allow-insecure-http" && key != "--help" && key != "-h"
}

func optionalListenerAddress(mainAddress, configured, port string) (string, error) {
	if port == "" {
		return configured, nil
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", fmt.Errorf("listener port must be a uint16")
	}
	if value == 0 {
		return "", nil
	}
	host, _, err := net.SplitHostPort(mainAddress)
	if err != nil {
		return "", fmt.Errorf("gateway bind address must be a socket address")
	}
	return net.JoinHostPort(host, port), nil
}

func configRuntimeGaps(file *gatewayconfig.File, opt Options) error {
	var gaps []string
	if file != nil {
		g := file.Compatibility.Gateway
		supported := map[string]bool{"name": true, "bind_address": true, "health_bind_address": true, "metrics_bind_address": true, "log_level": true, "ssh_session_ttl_secs": true, "disable_tls": true, "auth": true, "tls": true, "oidc": true, "mtls_auth": true, "provider_profile_sources": true, "credential_storage": true, "compute_driver": true, "compute_drivers": true, "credential_drivers": true, "default_credential_driver": true, "interceptors": true}
		value := reflect.ValueOf(g)
		for i := 0; i < value.NumField(); i++ {
			field, key := value.Field(i), value.Type().Field(i).Tag.Get("toml")
			if !supported[key] && !field.IsZero() {
				gaps = append(gaps, "openshell.gateway."+key)
			}
		}
		if g.ProviderProfileSources != nil {
			for _, source := range *g.ProviderProfileSources {
				if source.Type == "interceptor" {
					gaps = append(gaps, "openshell.gateway.provider_profile_sources interceptor requires gateway interceptor runtime")
				}
			}
		}
		if g.TLS != nil && g.TLS.RequireClientAuth && opt.TLSClientCA == "" {
			gaps = append(gaps, "openshell.gateway.tls.require_client_auth requires client_ca_path")
		}
	}
	if opt.EnableMTLSAuth && opt.TLSClientCA == "" {
		gaps = append(gaps, "openshell.gateway.mtls_auth.enabled requires tls.client_ca_path")
	}
	if opt.OIDC.Issuer != "" && (opt.OIDC.AdminRole == "") != (opt.OIDC.UserRole == "") {
		gaps = append(gaps, "openshell.gateway.oidc admin_role/user_role must both be set or both be empty")
	}
	if opt.RequireTLS && (opt.TLSCert == "" || opt.TLSKey == "") {
		gaps = append(gaps, "automatic gateway TLS certificate generation")
	}
	if len(gaps) > 0 {
		sort.Strings(gaps)
		return fmt.Errorf("gateway config runtime consumers not implemented: %s", strings.Join(gaps, ", "))
	}
	return nil
}

func normalizedGatewayArgs(args []string) []string {
	var result []string
	for _, arg := range args {
		if key, value, ok := strings.Cut(arg, "="); ok && strings.HasPrefix(key, "--") {
			if key == "--disable-tls" || key == "--allow-unauthenticated-users" || key == "--enable-mtls-auth" || key == "--oidc-allow-insecure-http" {
				result = append(result, arg)
			} else {
				result = append(result, key, value)
			}
		} else {
			result = append(result, arg)
		}
	}
	return result
}

func checkedSeconds(value uint64) (time.Duration, error) {
	if value > uint64(math.MaxInt64/int64(time.Second)) {
		return 0, fmt.Errorf("seconds exceed supported duration")
	}
	if value == 0 {
		return -1, nil
	}
	return time.Duration(value) * time.Second, nil
}
