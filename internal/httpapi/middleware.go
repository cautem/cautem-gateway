package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	middlewarev1 "github.com/cautem/quarshell-gateway/internal/upstreamproto/middlewarev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// driverRegistry is the typed boundary for configured built-in and external
// OpenShell drivers. Built-ins keep their existing lazy Engine path; remote
// entries are represented by generated clients and are probed explicitly.
// Keeping this registry separate from the public gateway server is important:
// ComputeDriver and CredentialDriver are plugin-side contracts, not public
// OpenShell RPCs.

func openMiddlewareClient(service *sandboxv1.SupervisorMiddlewareService) (middlewarev1.SupervisorMiddlewareClient, *grpc.ClientConn, error) {
	endpoint := strings.TrimSpace(service.GetGrpcEndpoint())
	if endpoint == "" {
		return nil, nil, fmt.Errorf("grpc_endpoint is required")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, nil, fmt.Errorf("grpc_endpoint must be an http(s) URL without credentials")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, nil, fmt.Errorf("grpc_endpoint must not contain a path")
	}
	var opts []grpc.DialOption
	if u.Scheme == "http" {
		if !service.GetAllowInsecureTransport() {
			return nil, nil, fmt.Errorf("plain-text grpc_endpoint requires allow_insecure_transport=true")
		}
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if pemBytes := service.GetTlsCaCertPem(); len(pemBytes) > 0 {
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pemBytes) {
				return nil, nil, fmt.Errorf("tls_ca_cert_pem contains no certificates")
			}
			tlsConfig.RootCAs = roots
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}
	conn, err := grpc.NewClient(u.Host, opts...)
	if err != nil {
		return nil, nil, err
	}
	return middlewarev1.NewSupervisorMiddlewareClient(conn), conn, nil
}

func validateMiddlewareManifest(name string, service *sandboxv1.SupervisorMiddlewareService, manifest *middlewarev1.MiddlewareManifest) error {
	if manifest == nil {
		return fmt.Errorf("middleware %q Describe returned an empty manifest", name)
	}
	seen := map[string]struct{}{}
	for _, binding := range manifest.GetBindings() {
		if binding == nil {
			return fmt.Errorf("middleware %q Describe returned a nil binding", name)
		}
		key := fmt.Sprintf("%d/%d", binding.GetOperation(), binding.GetPhase())
		if _, exists := seen[key]; exists {
			return fmt.Errorf("middleware %q Describe returned duplicate binding %s", name, key)
		}
		seen[key] = struct{}{}
		if binding.GetMaxPayloadBytes() == 0 || binding.GetMaxPayloadBytes() > service.GetMaxPayloadBytes() {
			return fmt.Errorf("middleware %q binding %s exceeds configured max_payload_bytes", name, key)
		}
	}
	return nil
}

// validateMiddlewareConfigs asks every selected middleware to validate its
// service-specific policy before the sandbox receives the effective config.
// This keeps policy acceptance fail-closed and exercises the pinned related
// RPC instead of treating Describe as the whole integration.

// validateMiddlewareConfigs asks every selected middleware to validate its
// service-specific policy before the sandbox receives the effective config.
// This keeps policy acceptance fail-closed and exercises the pinned related
// RPC instead of treating Describe as the whole integration.
func (r *driverRegistry) validateMiddlewareConfigs(ctx context.Context, policy *sandboxv1.SandboxPolicy) error {
	if r == nil || policy == nil || len(policy.GetNetworkMiddlewares()) == 0 {
		return nil
	}
	names := make([]string, 0, len(policy.GetNetworkMiddlewares()))
	for _, config := range policy.GetNetworkMiddlewares() {
		if config != nil {
			names = append(names, config.GetMiddleware())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		r.mu.Lock()
		registration, ok := r.middleware[name]
		r.mu.Unlock()
		if !ok {
			return fmt.Errorf("middleware %q is not registered", name)
		}
		var config *structpb.Struct
		for _, candidate := range policy.GetNetworkMiddlewares() {
			if candidate != nil && candidate.GetMiddleware() == name {
				config = candidate.GetConfig()
				break
			}
		}
		requestTimeout := registration.service.GetRequestTimeout().AsDuration()
		if requestTimeout <= 0 {
			requestTimeout = 500 * time.Millisecond
		}
		callCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		response, err := registration.client.ValidateConfig(callCtx, &middlewarev1.ValidateConfigRequest{Config: config, MiddlewareName: name})
		cancel()
		if err != nil {
			return fmt.Errorf("middleware %q ValidateConfig: %w", name, err)
		}
		if response == nil || !response.GetValid() {
			reason := "middleware rejected policy configuration"
			if response != nil && strings.TrimSpace(response.GetReason()) != "" {
				reason = response.GetReason()
			}
			return fmt.Errorf("middleware %q: %s", name, reason)
		}
	}
	return nil
}
