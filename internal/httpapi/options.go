// Package gateway is the control-plane daemon (P8).
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-gateway/internal/gatewayconfig"
	"google.golang.org/grpc"

	"github.com/cautem/cautem-gateway/internal/logger"
	"github.com/cautem/slogx"
)

// DriverConfigs maps a driver name to its decoded configuration table.
// Keep this an alias so existing Options literals remain source-compatible.

type DriverConfigs = map[string]map[string]any

// Options configure the HTTP(S) control plane.

// Options configure the HTTP(S) control plane.
type Options struct {
	Name                         string // operator-facing gateway installation identity
	LogLevel                     string // explicit startup filter
	RequireTLS                   bool   // selected OpenShell TLS posture
	DisableTLS                   bool   // explicit disable_tls ignores TLS files
	Listen                       string // default defaults.GatewayListen
	HealthListen                 string // optional unauthenticated liveness/readiness listener
	MetricsListen                string // optional Prometheus exposition listener
	DataDir                      string // durable state
	DatabaseURL                  string // optional PostgreSQL-backed durable registry; env/CLI only
	TLSCert                      string // optional
	TLSKey                       string // optional
	TLSClientCA                  string
	TLSRequireClientAuth         bool
	TLSExternalCert              string
	TLSExternalKey               string
	TLSExternalServerNames       []string
	EnableMTLSAuth               bool
	ProviderProfileSources       []string
	RegisterGRPC                 func(*grpc.Server)
	grpcRuntime                  *grpcRuntime
	ComputeDriverNames           []string
	ComputeDriverConfigs         DriverConfigs
	CredentialDriverNames        []string
	DefaultCredentialDriver      string
	PolicyValidationFailureMode  string
	SupervisorMiddlewareServices []*sandboxv1.SupervisorMiddlewareService
	CredentialDriverConfigs      DriverConfigs
	CredentialStorage            map[string]any
	GatewayInterceptors          []gatewayconfig.Interceptor
	tlsConfig                    *tls.Config
	OIDC                         OIDCOptions
	// SSHSessionTTL bounds SSH session tokens (OpenShell ssh_session_ttl_secs).
	// Zero selects DefaultSSHSessionTTL; negative disables expiry.
	SSHSessionTTL time.Duration
	// AllowUnauthenticated is the unsafe OpenShell allow_unauthenticated_users switch.
	AllowUnauthenticated bool
}

// EnvAllowUnauthenticated enables Options.AllowUnauthenticated (unsafe, dev only).

// EnvAllowUnauthenticated enables Options.AllowUnauthenticated (unsafe, dev only).
const EnvAllowUnauthenticated = "CAUTEM_GATEWAY_ALLOW_UNAUTHENTICATED"

// EnvSSHSessionTTL overrides the SSH session TTL in seconds (0 = no expiry).

// EnvSSHSessionTTL overrides the SSH session TTL in seconds (0 = no expiry).
const EnvSSHSessionTTL = "CAUTEM_SSH_SESSION_TTL_SECS"

// Run starts the gateway until context cancel / signal via ListenAndServe.

// Run starts the gateway until context cancel / signal via ListenAndServe.
func Run(args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opt, err := resolveGatewayOptions(args)
	if errors.Is(err, errGatewayHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	var level slog.Level
	if opt.LogLevel != "" {
		var err error
		level, err = slogx.ParseLevel(opt.LogLevel)
		if err != nil {
			return fmt.Errorf("gateway log_level filter is not supported")
		}
	}
	log := logger.Setup(ctx, logger.Options{Service: "cautem-gateway", Level: level, LevelSet: opt.LogLevel != ""})
	if opt.Name != "" {
		log = log.With("openshell.gateway.name", opt.Name)
	}
	ctx = logger.ToContext(ctx, log)
	return Serve(ctx, opt)
}

var errGatewayHelp = errors.New("gateway help requested")

func resolveGatewayOptions(args []string) (Options, error) {
	args = normalizedGatewayArgs(args)
	opt, configFile, err := configStartup(args)
	if err != nil {
		return Options{}, err
	}
	var healthPortFlag, metricsPortFlag string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--config needs a value")
			}
		case "--name", "--log-level", "--bind-address", "--port", "--health-port", "--metrics-port", "--oidc-jwks-ttl", "--oidc-roles-claim", "--oidc-admin-role", "--oidc-user-role", "--oidc-scopes-claim", "--tls-client-ca", "--db-url":
			flag := args[i]
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("%s needs a value", flag)
			}
			switch flag {
			case "--name":
				opt.Name = args[i]
			case "--log-level":
				opt.LogLevel = args[i]
			case "--bind-address":
				if net.ParseIP(args[i]) == nil {
					return Options{}, fmt.Errorf("--bind-address must be an IP address")
				}
				_, port, _ := net.SplitHostPort(opt.Listen)
				opt.Listen = net.JoinHostPort(args[i], port)
			case "--port":
				if _, err := strconv.ParseUint(args[i], 10, 16); err != nil {
					return Options{}, fmt.Errorf("--port must be a uint16")
				}
				host, _, _ := net.SplitHostPort(opt.Listen)
				opt.Listen = net.JoinHostPort(host, args[i])
			case "--health-port", "--metrics-port":
				if flag == "--health-port" {
					healthPortFlag = args[i]
				} else {
					metricsPortFlag = args[i]
				}
			case "--tls-client-ca":
				opt.TLSClientCA = args[i]
			case "--db-url":
				if strings.TrimSpace(args[i]) == "" {
					return Options{}, fmt.Errorf("--db-url needs a non-empty PostgreSQL URL")
				}
				opt.DatabaseURL = args[i]
			case "--oidc-jwks-ttl":
				seconds, err := strconv.ParseUint(args[i], 10, 64)
				if err != nil {
					return Options{}, fmt.Errorf("--oidc-jwks-ttl must be positive seconds")
				}
				opt.OIDC.JWKSTTLSecs, opt.OIDC.JWKSTTLSecsSet = seconds, true
			case "--oidc-roles-claim":
				opt.OIDC.RolesClaim = args[i]
				opt.OIDC.RolesClaimSet = true
			case "--oidc-admin-role":
				opt.OIDC.AdminRole = args[i]
				opt.OIDC.AdminRoleSet = true
			case "--oidc-user-role":
				opt.OIDC.UserRole = args[i]
				opt.OIDC.UserRoleSet = true
			case "--oidc-scopes-claim":
				opt.OIDC.ScopesClaim = args[i]
			}
		case "--disable-tls", "--disable-tls=true":
			opt.RequireTLS = false
			opt.DisableTLS = true
		case "--disable-tls=false":
			opt.RequireTLS = true
			opt.DisableTLS = false
		case "--listen":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--listen needs a value")
			}
			opt.Listen = args[i]
		case "--data-dir":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--data-dir needs a value")
			}
			opt.DataDir = args[i]
		case "--tls-cert":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--tls-cert needs a value")
			}
			opt.TLSCert = args[i]
		case "--tls-key":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--tls-key needs a value")
			}
			opt.TLSKey = args[i]
		case "--enable-mtls-auth", "--enable-mtls-auth=true":
			opt.EnableMTLSAuth = true
		case "--enable-mtls-auth=false":
			opt.EnableMTLSAuth = false
		case "--oidc-issuer":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--oidc-issuer needs a value")
			}
			opt.OIDC.Issuer = args[i]
		case "--oidc-audience":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--oidc-audience needs a value")
			}
			opt.OIDC.Audience = args[i]
		case "--oidc-client-id":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--oidc-client-id needs a value")
			}
			opt.OIDC.ClientID = args[i]
		case "--oidc-allow-insecure-http", "--oidc-allow-insecure-http=true":
			opt.OIDC.AllowInsecureHTTP = true
		case "--oidc-allow-insecure-http=false":
			opt.OIDC.AllowInsecureHTTP = false
		case "--ssh-session-ttl-secs":
			i++
			if i >= len(args) {
				return Options{}, fmt.Errorf("--ssh-session-ttl-secs needs a value")
			}
			ttl, err := parseTTLSecs(args[i])
			if err != nil {
				return Options{}, fmt.Errorf("--ssh-session-ttl-secs: %w", err)
			}
			opt.SSHSessionTTL = ttl
		case "--allow-unauthenticated-users", "--allow-unauthenticated-users=true":
			opt.AllowUnauthenticated = true
		case "--allow-unauthenticated-users=false":
			opt.AllowUnauthenticated = false
		case "-h", "--help":
			fmt.Fprintf(os.Stderr, "usage: cautem-gateway [--config TOML] [--name NAME] [--listen ADDR] [--data-dir DIR] [--db-url URL]\n")
			fmt.Fprintf(os.Stderr, "                 [--bind-address IP] [--port N] [--log-level LEVEL] [--disable-tls]\n")
			fmt.Fprintf(os.Stderr, "                 [--health-port N] [--metrics-port N]\n")
			fmt.Fprintf(os.Stderr, "                 [--tls-cert FILE] [--tls-key FILE] [--tls-client-ca FILE]\n")
			fmt.Fprintf(os.Stderr, "                 [--enable-mtls-auth]\n")
			fmt.Fprintf(os.Stderr, "                 [--oidc-issuer URL] [--oidc-client-id ID] [--oidc-audience AUD]\n")
			fmt.Fprintf(os.Stderr, "                 [--oidc-jwks-ttl N] [--oidc-roles-claim PATH] [--oidc-admin-role NAME] [--oidc-user-role NAME] [--oidc-scopes-claim PATH]\n")
			fmt.Fprintf(os.Stderr, "                 [--oidc-allow-insecure-http] [--ssh-session-ttl-secs N]\n")
			fmt.Fprintf(os.Stderr, "                 [--allow-unauthenticated-users]  (unsafe: local development only)\n")
			return Options{}, errGatewayHelp
		default:
			return Options{}, fmt.Errorf("unknown flag %q", args[i])
		}
	}
	for _, listener := range []struct {
		flagPort, env, name string
		target              *string
	}{{healthPortFlag, "OPENSHELL_HEALTH_PORT", "--health-port", &opt.HealthListen}, {metricsPortFlag, "OPENSHELL_METRICS_PORT", "--metrics-port", &opt.MetricsListen}} {
		port := listener.flagPort
		if port == "" && !gatewayExplicitFlags(args)[listener.name] {
			if value, present := os.LookupEnv(listener.env); present {
				port = value
			}
		}
		if port != "" {
			address, err := optionalListenerAddress(opt.Listen, *listener.target, port)
			if err != nil {
				return Options{}, fmt.Errorf("%s: %w", listener.name, err)
			}
			*listener.target = address
		}
	}
	if err := configRuntimeGaps(configFile, opt); err != nil {
		return Options{}, err
	}
	if _, err := newOIDCValidator(opt.OIDC); err != nil {
		return Options{}, fmt.Errorf("gateway OIDC config: %w", err)
	}
	if opt.DisableTLS {
		if opt.TLSClientCA != "" || opt.EnableMTLSAuth {
			return Options{}, fmt.Errorf("--disable-tls cannot be combined with client certificate verification or mTLS authentication")
		}
		opt.TLSCert, opt.TLSKey = "", ""
	}
	return opt, nil
}

func parseTTLSecs(s string) (time.Duration, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("want seconds >= 0, got %q", s)
	}
	return checkedSeconds(n)
}

func defaultDataDir() string {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "cautem", "gateway")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "cautem-gateway")
	}
	return filepath.Join(home, ".local", "state", "cautem", "gateway")
}

func configuredDriverStatus(names []string, configs DriverConfigs) []map[string]string {
	if len(names) == 0 {
		names = []string{"docker"}
	}
	out := make([]map[string]string, 0, len(names))
	for _, name := range names {
		state := "compatibility_stub"
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "docker", "podman":
			state = "engine_registered_lazy"
		case "vm", "kubernetes":
			state = "compatibility_stub"
		default:
			if isNativeComputeDriver(name) {
				state = "backend_registered_lazy"
			} else if stringConfig(driverConfig(configs, name), "grpc_endpoint") != "" {
				state = "remote_registered"
			}
		}
		out = append(out, map[string]string{"name": name, "state": state})
	}
	return out
}

func newGatewayID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "gw-" + hex.EncodeToString(b[:])
}

// Serve runs the HTTP API.
