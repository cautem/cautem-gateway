package httpapi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-gateway/internal/gatewayconfig"
	"google.golang.org/protobuf/types/known/durationpb"
)

const maxSupervisorMiddlewarePayload = 4 << 20

var stableMiddlewareName = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)

func supervisorMiddlewareServices(configs []gatewayconfig.Middleware) ([]*sandboxv1.SupervisorMiddlewareService, error) {
	services := make([]*sandboxv1.SupervisorMiddlewareService, 0, len(configs))
	seen := map[string]struct{}{}
	for i, config := range configs {
		name := strings.TrimSpace(valueOrEmpty(config.Name))
		if !stableMiddlewareName.MatchString(name) || strings.HasPrefix(name, "openshell/") {
			return nil, fmt.Errorf("openshell.supervisor.middleware[%d].name is invalid", i)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("openshell.supervisor.middleware contains duplicate name %q", name)
		}
		seen[name] = struct{}{}
		endpoint := strings.TrimSpace(valueOrEmpty(config.GRPCEndpoint))
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("openshell.supervisor.middleware[%d].grpc_endpoint must be an http(s) URL", i)
		}
		if u.Scheme == "http" && !config.AllowInsecureTransport {
			return nil, fmt.Errorf("openshell.supervisor.middleware[%d] plaintext endpoint requires allow_insecure_transport=true", i)
		}
		maxPayload := uint64(0)
		if config.MaxPayloadBytes != nil {
			maxPayload = *config.MaxPayloadBytes
		}
		if maxPayload == 0 || maxPayload > maxSupervisorMiddlewarePayload {
			return nil, fmt.Errorf("openshell.supervisor.middleware[%d].max_payload_bytes must be between 1 and %d", i, maxSupervisorMiddlewarePayload)
		}
		timeout := ""
		if config.Timeout != nil {
			timeout = strings.TrimSpace(*config.Timeout)
			if err := validateMiddlewareTimeout(timeout); err != nil {
				return nil, fmt.Errorf("openshell.supervisor.middleware[%d].timeout: %w", i, err)
			}
		}
		audience := strings.TrimSpace(valueOrEmpty(config.Audience))
		if audience == "" {
			audience = "urn:openshell:extension:middleware:" + name
		}
		var caPEM []byte
		if config.TLSCACertPath != nil {
			if u.Scheme != "https" {
				return nil, fmt.Errorf("openshell.supervisor.middleware[%d].tls_ca_cert_path requires an https endpoint", i)
			}
			caPEM, err = readMiddlewareCAPEM(*config.TLSCACertPath)
			if err != nil {
				return nil, fmt.Errorf("openshell.supervisor.middleware[%d].tls_ca_cert_path: %w", i, err)
			}
		}
		requestTimeout, _ := time.ParseDuration(timeout)
		services = append(services, &sandboxv1.SupervisorMiddlewareService{
			Name: name, GrpcEndpoint: endpoint, MaxPayloadBytes: maxPayload,
			RequestTimeout: durationpb.New(requestTimeout), TlsCaCertPem: caPEM, Audience: audience,
			AllowInsecureTransport: config.AllowInsecureTransport,
		})
	}
	return services, nil
}

func validateMiddlewareTimeout(raw string) error {
	unit := uint64(0)
	value := ""
	switch {
	case strings.HasSuffix(raw, "ms"):
		unit, value = 1, strings.TrimSuffix(raw, "ms")
	case strings.HasSuffix(raw, "s"):
		unit, value = 1000, strings.TrimSuffix(raw, "s")
	default:
		return fmt.Errorf("must be an integer duration with ms or s suffix")
	}
	amount, err := strconv.ParseUint(value, 10, 64)
	if err != nil || amount > 30_000/unit || amount*unit < 10 || amount*unit > 30_000 {
		return fmt.Errorf("must be a duration from 10ms through 30s")
	}
	return nil
}

func readMiddlewareCAPEM(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sanitized []byte
	count := 0
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			if strings.TrimSpace(string(data)) != "" {
				return nil, fmt.Errorf("PEM bundle contains invalid data")
			}
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("PEM bundle may contain certificate blocks only")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("invalid certificate: %w", err)
		}
		sanitized = append(sanitized, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("PEM bundle contains no certificates")
	}
	return sanitized, nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func requiredSupervisorMiddlewareServices(policy *sandboxv1.SandboxPolicy, configured []*sandboxv1.SupervisorMiddlewareService) ([]*sandboxv1.SupervisorMiddlewareService, error) {
	if policy == nil || len(policy.GetNetworkMiddlewares()) == 0 {
		return nil, nil
	}
	registered := make(map[string]*sandboxv1.SupervisorMiddlewareService, len(configured))
	for _, service := range configured {
		if service != nil {
			registered[service.GetName()] = service
		}
	}
	selected := map[string]struct{}{}
	for _, middleware := range policy.GetNetworkMiddlewares() {
		if middleware == nil || strings.TrimSpace(middleware.GetMiddleware()) == "" {
			return nil, fmt.Errorf("network middleware registration name is missing")
		}
		selected[middleware.GetMiddleware()] = struct{}{}
	}
	services := make([]*sandboxv1.SupervisorMiddlewareService, 0, len(selected))
	for name := range selected {
		service, ok := registered[name]
		if !ok {
			return nil, fmt.Errorf("middleware %q is not registered", name)
		}
		services = append(services, service)
	}
	for i := 0; i < len(services); i++ {
		for j := i + 1; j < len(services); j++ {
			if services[j].GetName() < services[i].GetName() {
				services[i], services[j] = services[j], services[i]
			}
		}
	}
	return services, nil
}
