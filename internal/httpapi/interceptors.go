package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cautem/cautem-gateway/internal/gatewayconfig"
	interceptorv1 "github.com/cautem/cautem-gateway/internal/upstreamproto/interceptorv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// driverRegistry is the typed boundary for configured built-in and external
// OpenShell drivers. Built-ins keep their existing lazy Engine path; remote
// entries are represented by generated clients and are probed explicitly.
// Keeping this registry separate from the public gateway server is important:
// ComputeDriver and CredentialDriver are plugin-side contracts, not public
// OpenShell RPCs.

// evaluateGatewayInterceptors runs the configured validate phase after the
// gateway has prepared an operation but before it performs durable or backend
// side effects. Only bindings selected by the service manifest are called.
// Failure policy is resolved per binding, then manifest, then registration.
func (r *driverRegistry) evaluateGatewayInterceptors(ctx context.Context, service, method string, principal map[string]string, operation proto.Message) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	registrations := make([]interceptorRegistration, 0, len(r.interceptor))
	for _, registration := range r.interceptor {
		registrations = append(registrations, registration)
	}
	r.mu.Unlock()
	if len(registrations) == 0 {
		return nil
	}
	raw, err := protojson.Marshal(operation)
	if err != nil {
		return fmt.Errorf("interceptor operation serialization: %w", err)
	}
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("interceptor operation conversion: %w", err)
	}
	proposed, err := structpb.NewStruct(values)
	if err != nil {
		return fmt.Errorf("interceptor operation struct: %w", err)
	}
	for _, registration := range registrations {
		for _, binding := range registration.manifest.GetBindings() {
			if !interceptorBindingMatches(binding, registration.config, service, method) || !interceptorBindingWantsValidate(binding) {
				continue
			}
			callCtx := ctx
			cancel := func() {}
			if timeout := interceptorTimeout(registration.config.timeout); timeout > 0 {
				callCtx, cancel = context.WithTimeout(ctx, timeout)
			}
			result, callErr := registration.client.Evaluate(callCtx, &interceptorv1.InterceptorEvaluation{
				InterceptorName: registration.config.name,
				BindingId:       binding.GetId(),
				Service:         service,
				Method:          method,
				Principal:       principal,
				Phase:           &interceptorv1.InterceptorEvaluation_Validate{Validate: &interceptorv1.ValidateEvaluation{ProposedOperation: proposed}},
			})
			cancel()
			if callErr != nil {
				if interceptorFailurePolicy(binding, registration) == "fail_open" {
					continue
				}
				return status.Errorf(codes.FailedPrecondition, "gateway interceptor %q failed: %v", registration.config.name, callErr)
			}
			if result == nil || !result.GetAllowed() {
				reason := "operation denied by gateway interceptor"
				if result != nil && strings.TrimSpace(result.GetReason()) != "" {
					reason = result.GetReason()
				}
				return status.Errorf(interceptorStatusCode(result.GetStatusCode()), "gateway interceptor %q denied %s/%s: %s", registration.config.name, service, method, reason)
			}
		}
	}
	return nil
}

// evaluateGatewayInterceptorPhases is the mutation-aware path used by
// gateway operations. It preserves the legacy validate helper above for
// callers that only need a decision.

// evaluateGatewayInterceptorPhases is the mutation-aware path used by
// gateway operations. It preserves the legacy validate helper above for
// callers that only need a decision.
func (r *driverRegistry) evaluateGatewayInterceptorPhases(ctx context.Context, service, method string, principal map[string]string, operation proto.Message, postCommit bool) (proto.Message, error) {
	if r == nil {
		return operation, nil
	}
	r.mu.Lock()
	registrations := make([]interceptorRegistration, 0, len(r.interceptor))
	for _, registration := range r.interceptor {
		registrations = append(registrations, registration)
	}
	r.mu.Unlock()
	sort.SliceStable(registrations, func(i, j int) bool {
		if registrations[i].config.order != registrations[j].config.order {
			return registrations[i].config.order < registrations[j].config.order
		}
		return registrations[i].config.name < registrations[j].config.name
	})
	working := proto.Clone(operation)
	for _, registration := range registrations {
		for _, binding := range registration.manifest.GetBindings() {
			if !interceptorBindingMatches(binding, registration.config, service, method) {
				continue
			}
			phases := make([]interceptorv1.GatewayInterceptorPhase, 0, 3)
			if !postCommit && interceptorBindingWantsPhase(binding, interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION) {
				phases = append(phases, interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION)
			}
			if !postCommit && interceptorBindingWantsValidate(binding) {
				phases = append(phases, interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_VALIDATE)
			}
			if postCommit && interceptorBindingWantsPhase(binding, interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT) {
				phases = append(phases, interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT)
			}
			for _, phase := range phases {
				proposed, err := interceptorProposedStruct(working)
				if err != nil {
					return nil, err
				}
				evaluation := &interceptorv1.InterceptorEvaluation{InterceptorName: registration.config.name, BindingId: binding.GetId(), Service: service, Method: method, Principal: principal}
				switch phase {
				case interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION:
					evaluation.Phase = &interceptorv1.InterceptorEvaluation_ModifyOperation{ModifyOperation: &interceptorv1.ModifyOperationEvaluation{ProposedOperation: proposed}}
				case interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT:
					evaluation.Phase = &interceptorv1.InterceptorEvaluation_PostCommit{PostCommit: &interceptorv1.PostCommitEvaluation{CommittedResponse: proposed}}
				default:
					evaluation.Phase = &interceptorv1.InterceptorEvaluation_Validate{Validate: &interceptorv1.ValidateEvaluation{ProposedOperation: proposed}}
				}
				callCtx := ctx
				cancel := func() {}
				if timeout := interceptorTimeout(registration.config.timeout); timeout > 0 {
					callCtx, cancel = context.WithTimeout(ctx, timeout)
				}
				result, callErr := registration.client.Evaluate(callCtx, evaluation)
				cancel()
				if callErr != nil {
					if phase == interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT || interceptorFailurePolicy(binding, registration) == "fail_open" {
						continue
					}
					return nil, status.Errorf(codes.FailedPrecondition, "gateway interceptor %q failed: %v", registration.config.name, callErr)
				}
				if phase == interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT {
					continue
				}
				if result == nil || !result.GetAllowed() {
					reason := "operation denied by gateway interceptor"
					if result != nil && strings.TrimSpace(result.GetReason()) != "" {
						reason = result.GetReason()
					}
					return nil, status.Errorf(interceptorStatusCode(result.GetStatusCode()), "gateway interceptor %q denied %s/%s: %s", registration.config.name, service, method, reason)
				}
				if phase == interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION {
					if err := applyInterceptorPatches(&working, result.GetPatches()); err != nil {
						if interceptorFailurePolicy(binding, registration) == "fail_open" {
							continue
						}
						return nil, status.Errorf(codes.FailedPrecondition, "gateway interceptor %q returned invalid patches: %v", registration.config.name, err)
					}
				}
			}
		}
	}
	return working, nil
}

func interceptorProposedStruct(message proto.Message) (*structpb.Struct, error) {
	raw, err := protojson.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("interceptor operation serialization: %w", err)
	}
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("interceptor operation conversion: %w", err)
	}
	return structpb.NewStruct(values)
}

func interceptorBindingWantsPhase(binding *interceptorv1.InterceptorBinding, phase interceptorv1.GatewayInterceptorPhase) bool {
	for _, candidate := range binding.GetPhases() {
		if candidate == phase {
			return true
		}
	}
	return false
}

func applyInterceptorPatches(target *proto.Message, patches []*interceptorv1.JsonPatch) error {
	if len(patches) == 0 {
		return nil
	}
	raw, err := protojson.Marshal(*target)
	if err != nil {
		return err
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return err
	}
	for _, patch := range patches {
		if patch == nil {
			return fmt.Errorf("nil patch")
		}
		parts, err := jsonPointerParts(patch.GetPath())
		if err != nil || len(parts) == 0 {
			if err != nil {
				return err
			}
			return fmt.Errorf("root JSON patches are not supported")
		}
		current := document
		for _, part := range parts[:len(parts)-1] {
			next, ok := current[part].(map[string]any)
			if !ok {
				return fmt.Errorf("JSON patch parent %q is missing or not an object", part)
			}
			current = next
		}
		leaf := parts[len(parts)-1]
		op := strings.ToLower(strings.TrimSpace(patch.GetOp()))
		_, exists := current[leaf]
		switch op {
		case "add":
			if patch.GetValue() == nil {
				return fmt.Errorf("JSON patch add value is missing")
			}
			current[leaf] = patch.GetValue().AsInterface()
		case "replace":
			if !exists || patch.GetValue() == nil {
				return fmt.Errorf("JSON patch replace target %q is missing", leaf)
			}
			current[leaf] = patch.GetValue().AsInterface()
		case "remove":
			if !exists {
				return fmt.Errorf("JSON patch remove target %q is missing", leaf)
			}
			delete(current, leaf)
		default:
			return fmt.Errorf("unsupported JSON patch operation %q", patch.GetOp())
		}
	}
	patched, err := json.Marshal(document)
	if err != nil {
		return err
	}
	updated := proto.Clone(*target)
	if err := protojson.Unmarshal(patched, updated); err != nil {
		return err
	}
	*target = updated
	return nil
}

func jsonPointerParts(path string) ([]string, error) {
	if path == "" || !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("JSON patch path must start with /")
	}
	parts := strings.Split(path[1:], "/")
	for i := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
	}
	return parts, nil
}

func interceptorBindingMatches(binding *interceptorv1.InterceptorBinding, config gatewayInterceptorConfig, service, method string) bool {
	if binding == nil || binding.GetSelector() == nil {
		return false
	}
	selector := binding.GetSelector()
	rpc := service + "/" + method
	if selector.GetRpc() != "" && selector.GetRpc() != rpc {
		return false
	}
	if selector.GetRpc() == "" && (selector.GetService() != service || selector.GetMethod() != method) {
		return false
	}
	if config.bindingPolicy == "exact" {
		for _, configured := range config.bindings {
			if !configured.disabled && configured.id == binding.GetId() {
				return true
			}
		}
		return false
	}
	return true
}

func interceptorBindingWantsValidate(binding *interceptorv1.InterceptorBinding) bool {
	for _, phase := range binding.GetPhases() {
		if phase == interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_VALIDATE {
			return true
		}
	}
	return false
}

func interceptorTimeout(configured string) time.Duration {
	raw := strings.TrimSpace(configured)
	if raw == "" {
		return 500 * time.Millisecond
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 500 * time.Millisecond
	}
	return d
}

func interceptorFailurePolicy(binding *interceptorv1.InterceptorBinding, registration interceptorRegistration) string {
	if value := strings.TrimSpace(binding.GetFailurePolicy()); value != "" {
		return value
	}
	if value := strings.TrimSpace(registration.manifest.GetFailurePolicy()); value != "" {
		return value
	}
	return registration.config.failurePolicy
}

func interceptorStatusCode(value string) codes.Code {
	switch strings.TrimSpace(value) {
	case "INVALID_ARGUMENT":
		return codes.InvalidArgument
	case "UNAUTHENTICATED":
		return codes.Unauthenticated
	case "PERMISSION_DENIED":
		return codes.PermissionDenied
	case "ABORTED":
		return codes.Aborted
	case "RESOURCE_EXHAUSTED":
		return codes.ResourceExhausted
	default:
		return codes.PermissionDenied
	}
}

func normalizeGatewayInterceptorConfig(config gatewayconfig.Interceptor) (gatewayInterceptorConfig, error) {
	value := func(p *string) string {
		if p == nil {
			return ""
		}
		return strings.TrimSpace(*p)
	}
	out := gatewayInterceptorConfig{
		name:          value(config.Name),
		endpoint:      value(config.GRPCEndpoint),
		tlsCACertPath: value(config.TLSCACertPath),
		audience:      value(config.Audience),
		allowInsecure: config.AllowInsecureTransport,
		order:         config.Order,
		failurePolicy: value(config.FailurePolicy),
		timeout:       value(config.Timeout),
		bindingPolicy: value(config.BindingPolicy),
	}
	if config.MaxResponseBytes != nil {
		out.maxResponseSize = *config.MaxResponseBytes
	}
	if config.MaxPatches != nil {
		out.maxPatches = *config.MaxPatches
	}
	if out.name == "" || out.endpoint == "" {
		return gatewayInterceptorConfig{}, fmt.Errorf("gateway interceptor name and grpc_endpoint are required")
	}
	if out.failurePolicy == "" {
		out.failurePolicy = "fail_closed"
	}
	if out.bindingPolicy == "" {
		out.bindingPolicy = "dynamic"
	}
	for _, binding := range config.Bindings {
		item := gatewayInterceptorBinding{id: value(binding.ID), rpc: value(binding.RPC), service: value(binding.Service), method: value(binding.Method), disabled: binding.Disabled, failurePolicy: value(binding.FailurePolicy)}
		if binding.Phases != nil {
			item.phases = append([]string(nil), (*binding.Phases)...)
		}
		out.bindings = append(out.bindings, item)
	}
	return out, nil
}

func openGatewayInterceptorClient(config gatewayInterceptorConfig) (interceptorv1.GatewayInterceptorClient, *grpc.ClientConn, error) {
	u, err := url.Parse(config.endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, nil, fmt.Errorf("grpc_endpoint must be an http(s) URL without credentials")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, nil, fmt.Errorf("grpc_endpoint must not contain a path")
	}
	var opts []grpc.DialOption
	if u.Scheme == "http" {
		if !config.allowInsecure {
			return nil, nil, fmt.Errorf("plain-text grpc_endpoint requires allow_insecure_transport=true")
		}
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if config.tlsCACertPath != "" {
			pemBytes, err := os.ReadFile(config.tlsCACertPath)
			if err != nil {
				return nil, nil, fmt.Errorf("tls_ca_cert_path: %w", err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pemBytes) {
				return nil, nil, fmt.Errorf("tls_ca_cert_path contains no certificates")
			}
			tlsConfig.RootCAs = roots
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}
	conn, err := grpc.NewClient(u.Host, opts...)
	if err != nil {
		return nil, nil, err
	}
	return interceptorv1.NewGatewayInterceptorClient(conn), conn, nil
}

func validateGatewayInterceptorManifest(config gatewayInterceptorConfig, manifest *interceptorv1.InterceptorManifest) error {
	if manifest == nil {
		return fmt.Errorf("interceptor %q Describe returned an empty manifest", config.name)
	}
	if expected := strings.TrimSpace(manifest.GetExpectedAudience()); expected != "" && expected != config.audience {
		return fmt.Errorf("interceptor %q expected_audience %q does not match configured audience", config.name, expected)
	}
	if policy := strings.TrimSpace(manifest.GetFailurePolicy()); policy != "" && policy != "fail_open" && policy != "fail_closed" {
		return fmt.Errorf("interceptor %q returned invalid failure_policy %q", config.name, policy)
	}
	seen := map[string]struct{}{}
	for _, binding := range manifest.GetBindings() {
		if binding == nil || strings.TrimSpace(binding.GetId()) == "" {
			return fmt.Errorf("interceptor %q Describe returned a binding without id", config.name)
		}
		if _, exists := seen[binding.GetId()]; exists {
			return fmt.Errorf("interceptor %q Describe returned duplicate binding %q", config.name, binding.GetId())
		}
		seen[binding.GetId()] = struct{}{}
		if binding.GetSelector() == nil || (binding.GetSelector().GetRpc() == "" && (binding.GetSelector().GetService() == "" || binding.GetSelector().GetMethod() == "")) {
			return fmt.Errorf("interceptor %q binding %q has an incomplete selector", config.name, binding.GetId())
		}
		if binding.GetFailurePolicy() != "" && binding.GetFailurePolicy() != "fail_open" && binding.GetFailurePolicy() != "fail_closed" {
			return fmt.Errorf("interceptor %q binding %q has invalid failure_policy", config.name, binding.GetId())
		}
		for _, phase := range binding.GetPhases() {
			if phase == interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT && binding.GetFailurePolicy() == "fail_closed" {
				return fmt.Errorf("interceptor %q binding %q cannot use fail_closed for post_commit", config.name, binding.GetId())
			}
		}
	}
	if config.bindingPolicy == "exact" {
		configured := map[string]struct{}{}
		for _, binding := range config.bindings {
			if !binding.disabled {
				configured[binding.id] = struct{}{}
			}
		}
		for id := range configured {
			if _, ok := seen[id]; !ok {
				return fmt.Errorf("interceptor %q exact binding %q is not declared by service", config.name, id)
			}
		}
	}
	return nil
}
