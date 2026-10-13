package httpapi

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	computev1 "github.com/cautem/cautem-gateway/internal/upstreamproto/computev1"
	credentialsv1 "github.com/cautem/cautem-gateway/internal/upstreamproto/credentialsv1"
	interceptorv1 "github.com/cautem/cautem-gateway/internal/upstreamproto/interceptorv1"
	middlewarev1 "github.com/cautem/cautem-gateway/internal/upstreamproto/middlewarev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

// driverRegistry is the typed boundary for configured built-in and external
// OpenShell drivers. Built-ins keep their existing lazy Engine path; remote
// entries are represented by generated clients and are probed explicitly.
// Keeping this registry separate from the public gateway server is important:
// ComputeDriver and CredentialDriver are plugin-side contracts, not public
// OpenShell RPCs.

type driverRegistry struct {
	mu          sync.Mutex
	compute     map[string]computeDriverRegistration
	credential  map[string]credentialDriverRegistration
	middleware  map[string]middlewareRegistration
	interceptor map[string]interceptorRegistration
}

type computeDriverRegistration struct {
	name   string
	config map[string]any
	client computev1.ComputeDriverClient
	conn   *grpc.ClientConn
}

type credentialDriverRegistration struct {
	name   string
	config map[string]any
	client credentialsv1.CredentialDriverClient
	conn   *grpc.ClientConn
}

type middlewareRegistration struct {
	service *sandboxv1.SupervisorMiddlewareService
	client  middlewarev1.SupervisorMiddlewareClient
	conn    *grpc.ClientConn
}

type interceptorRegistration struct {
	config   gatewayInterceptorConfig
	client   interceptorv1.GatewayInterceptorClient
	conn     *grpc.ClientConn
	manifest *interceptorv1.InterceptorManifest
}

type gatewayInterceptorConfig struct {
	name            string
	endpoint        string
	tlsCACertPath   string
	audience        string
	allowInsecure   bool
	order           int32
	failurePolicy   string
	timeout         string
	maxResponseSize uint64
	maxPatches      uint64
	bindingPolicy   string
	bindings        []gatewayInterceptorBinding
}

type gatewayInterceptorBinding struct {
	id            string
	rpc           string
	service       string
	method        string
	phases        []string
	disabled      bool
	failurePolicy string
}

func newDriverRegistry(opt Options) (*driverRegistry, error) {
	computeNames := opt.ComputeDriverNames
	if len(computeNames) == 0 {
		computeNames = []string{"docker"}
	}
	r := &driverRegistry{
		compute:     map[string]computeDriverRegistration{},
		credential:  map[string]credentialDriverRegistration{},
		middleware:  map[string]middlewareRegistration{},
		interceptor: map[string]interceptorRegistration{},
	}
	for _, name := range computeNames {
		key := normalizeDriverName(name)
		if key == "" {
			return nil, fmt.Errorf("compute driver name must not be empty")
		}
		if _, exists := r.compute[key]; exists {
			return nil, fmt.Errorf("duplicate compute driver %q", name)
		}
		config := driverConfig(opt.ComputeDriverConfigs, name)
		registration := computeDriverRegistration{name: key, config: config}
		if !isBuiltinComputeDriver(key) {
			endpoint := stringConfig(config, "grpc_endpoint")
			if endpoint == "" {
				return nil, fmt.Errorf("compute driver %q: grpc_endpoint is required for an external driver", name)
			}
			client, conn, err := openComputeDriverClient(endpoint, config)
			if err != nil {
				return nil, fmt.Errorf("compute driver %q: %w", name, err)
			}
			registration.client, registration.conn = client, conn
		}
		r.compute[key] = registration
	}
	for _, name := range opt.CredentialDriverNames {
		key := normalizeDriverName(name)
		if key == "" {
			return nil, fmt.Errorf("credential driver name must not be empty")
		}
		if _, exists := r.credential[key]; exists {
			return nil, fmt.Errorf("duplicate credential driver %q", name)
		}
		config := driverConfig(opt.CredentialDriverConfigs, name)
		registration := credentialDriverRegistration{name: key, config: config}
		if endpoint := stringConfig(config, "grpc_endpoint"); endpoint != "" {
			client, conn, err := openCredentialDriverClient(endpoint, config)
			if err != nil {
				return nil, fmt.Errorf("credential driver %q: %w", name, err)
			}
			registration.client, registration.conn = client, conn
		} else if !isBuiltinCredentialDriver(key, config) {
			return nil, fmt.Errorf("credential driver %q: grpc_endpoint is required for an external driver", name)
		}
		r.credential[key] = registration
	}
	for _, service := range opt.SupervisorMiddlewareServices {
		if service == nil {
			return nil, fmt.Errorf("middleware registration must not be nil")
		}
		key := strings.TrimSpace(service.GetName())
		if key == "" {
			return nil, fmt.Errorf("middleware registration name must not be empty")
		}
		if _, exists := r.middleware[key]; exists {
			return nil, fmt.Errorf("duplicate middleware registration %q", key)
		}
		client, conn, err := openMiddlewareClient(service)
		if err != nil {
			return nil, fmt.Errorf("middleware %q: %w", key, err)
		}
		r.middleware[key] = middlewareRegistration{service: service, client: client, conn: conn}
	}
	for _, configured := range opt.GatewayInterceptors {
		config, err := normalizeGatewayInterceptorConfig(configured)
		if err != nil {
			return nil, err
		}
		if _, exists := r.interceptor[config.name]; exists {
			return nil, fmt.Errorf("duplicate gateway interceptor %q", config.name)
		}
		client, conn, err := openGatewayInterceptorClient(config)
		if err != nil {
			return nil, fmt.Errorf("interceptor %q: %w", config.name, err)
		}
		r.interceptor[config.name] = interceptorRegistration{config: config, client: client, conn: conn}
	}
	return r, nil
}

func (r *driverRegistry) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var first error
	for name, registration := range r.compute {
		if registration.conn != nil {
			if err := registration.conn.Close(); err != nil && first == nil {
				first = fmt.Errorf("close compute driver %q: %w", name, err)
			}
		}
	}
	for name, registration := range r.credential {
		if registration.conn != nil {
			if err := registration.conn.Close(); err != nil && first == nil {
				first = fmt.Errorf("close credential driver %q: %w", name, err)
			}
		}
	}
	for name, registration := range r.middleware {
		if registration.conn != nil {
			if err := registration.conn.Close(); err != nil && first == nil {
				first = fmt.Errorf("close middleware %q: %w", name, err)
			}
		}
	}
	for name, registration := range r.interceptor {
		if registration.conn != nil {
			if err := registration.conn.Close(); err != nil && first == nil {
				first = fmt.Errorf("close interceptor %q: %w", name, err)
			}
		}
	}
	return first
}

// Probe calls the related protocol capability methods. It is intentionally
// explicit and bounded: gateway startup must not hang on an unavailable
// optional plugin, while an operator-requested probe gets a useful error.

// Probe calls the related protocol capability methods. It is intentionally
// explicit and bounded: gateway startup must not hang on an unavailable
// optional plugin, while an operator-requested probe gets a useful error.
func (r *driverRegistry) probe(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for name, registration := range r.compute {
		if registration.client == nil {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := registration.client.GetCapabilities(probeCtx, &computev1.GetCapabilitiesRequest{})
		cancel()
		if err != nil {
			return fmt.Errorf("compute driver %q capability probe: %w", name, err)
		}
	}
	for name, registration := range r.credential {
		if registration.client == nil {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		capabilities, err := registration.client.GetCapabilities(probeCtx, &credentialsv1.GetCredentialDriverCapabilitiesRequest{})
		cancel()
		if err != nil {
			return fmt.Errorf("credential driver %q capability probe: %w", name, err)
		}
		if capabilities != nil && capabilities.GetSupportsList() {
			if _, err := r.listCredentialDriverCredentials(ctx, name); err != nil {
				return fmt.Errorf("credential driver %q list probe: %w", name, err)
			}
		}
	}
	for name, registration := range r.middleware {
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		manifest, err := registration.client.Describe(probeCtx, &emptypb.Empty{})
		cancel()
		if err != nil {
			return fmt.Errorf("middleware %q Describe: %w", name, err)
		}
		if err := validateMiddlewareManifest(name, registration.service, manifest); err != nil {
			return err
		}
	}
	for name, registration := range r.interceptor {
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		manifest, err := registration.client.Describe(probeCtx, &interceptorv1.DescribeRequest{})
		cancel()
		if err != nil {
			return fmt.Errorf("interceptor %q Describe: %w", name, err)
		}
		if err := validateGatewayInterceptorManifest(registration.config, manifest); err != nil {
			return err
		}
		r.mu.Lock()
		current := r.interceptor[name]
		current.manifest = manifest
		r.interceptor[name] = current
		r.mu.Unlock()
	}
	return nil
}

// listCredentialDriverCredentials exercises the optional ListCredentials
// contract without ever exposing credential values. The protocol deliberately
// returns handles, keys, and metadata only; validating handles here catches a
// misbehaving external driver during startup or an explicit probe.

func driverConfig(configs DriverConfigs, name string) map[string]any {
	if config := configs[name]; config != nil {
		return config
	}
	return configs[normalizeDriverName(name)]
}

func normalizeDriverName(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

func isBuiltinComputeDriver(name string) bool {
	switch normalizeDriverName(name) {
	case "docker", "podman", "kubernetes", "vm":
		return true
	default:
		return false
	}
}

func isBuiltinCredentialDriver(name string, config map[string]any) bool {
	if normalizeDriverName(name) == "local" {
		return true
	}
	return strings.EqualFold(stringConfig(config, "type"), "local_encrypted")
}

func stringConfig(config map[string]any, key string) string {
	value, _ := config[key].(string)
	return strings.TrimSpace(value)
}

func openComputeDriverClient(endpoint string, config map[string]any) (computev1.ComputeDriverClient, *grpc.ClientConn, error) {
	conn, err := dialDriverEndpoint(endpoint, config)
	if err != nil {
		return nil, nil, err
	}
	return computev1.NewComputeDriverClient(conn), conn, nil
}

func openCredentialDriverClient(endpoint string, config map[string]any) (credentialsv1.CredentialDriverClient, *grpc.ClientConn, error) {
	conn, err := dialDriverEndpoint(endpoint, config)
	if err != nil {
		return nil, nil, err
	}
	return credentialsv1.NewCredentialDriverClient(conn), conn, nil
}

func dialDriverEndpoint(raw string, config map[string]any) (*grpc.ClientConn, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("grpc_endpoint must be an http(s) URL without credentials")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("grpc_endpoint scheme must be http or https")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("grpc_endpoint must not contain a path")
	}
	var opts []grpc.DialOption
	if u.Scheme == "https" {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()})))
	} else if boolConfig(config, "allow_insecure_transport") {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		return nil, fmt.Errorf("plain-text grpc_endpoint requires allow_insecure_transport=true")
	}
	return grpc.NewClient(u.Host, opts...)
}

func boolConfig(config map[string]any, key string) bool {
	value, _ := config[key].(bool)
	return value
}
