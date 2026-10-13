package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	corepolicy "github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

const maxPolicyMergeOperations = 128

func (s *openShellRPC) updateConfigPolicyMerge(ctx context.Context, req *openshellv1.UpdateConfigRequest) (*openshellv1.UpdateConfigResponse, error) {
	if req.GetGlobal() {
		return nil, status.Error(codes.InvalidArgument, "merge_operations are not supported for global policy updates")
	}
	if len(req.GetMergeOperations()) > maxPolicyMergeOperations {
		return nil, status.Errorf(codes.InvalidArgument, "merge_operations exceeds %d entries", maxPolicyMergeOperations)
	}
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalUser {
		return nil, status.Error(codes.Unauthenticated, "authenticated user required")
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required for sandbox policy updates")
	}
	sandbox, ok := s.runtime.st.GetSandbox(name)
	if !ok {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	if workspace := strings.TrimSpace(req.GetWorkspace()); workspace != "" && workspace != sandbox.Workspace {
		return nil, status.Error(codes.PermissionDenied, "sandbox does not belong to requested workspace")
	}
	if err := s.requireSandboxConfigWrite(p, sandbox.Workspace); err != nil {
		return nil, err
	}
	if globalYAML, _ := s.runtime.st.GlobalPolicySnapshot(); strings.TrimSpace(globalYAML) != "" {
		return nil, status.Error(codes.FailedPrecondition, "policy is managed globally; delete global policy before sandbox policy update")
	}
	if strings.TrimSpace(sandbox.BasePolicyYAML) == "" {
		return nil, status.Error(codes.FailedPrecondition, "sandbox has no stored base policy")
	}
	base, err := corepolicy.Parse([]byte(sandbox.BasePolicyYAML))
	if err != nil || base.Validate() != nil {
		return nil, status.Error(codes.FailedPrecondition, "stored sandbox policy is invalid")
	}
	merged, err := applyOpenShellPolicyMerge(base, req.GetMergeOperations())
	if err != nil {
		return nil, err
	}
	// Merge operations are evaluated against the sandbox's actual provider
	// attachments before they are persisted.  Keeping this check here (rather
	// than in the context-free merge helper) lets the helper remain useful for
	// structural operations while ensuring credential bindings cannot be
	// smuggled into a stored policy without a resolvable provider.
	if len(sandbox.AttachedProviders) > 0 {
		if _, err := composeStoredSandboxProviderPolicy(s.runtime.st, sandbox, merged, s.runtime.opt.ProviderProfileSources); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "sandbox provider policy validation failed: %v", err)
		}
	}
	policyYAML, err := yaml.Marshal(merged)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not serialize merged sandbox policy")
	}
	canonicalProto, err := policyDocumentToProto(merged)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not encode merged sandbox policy")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(canonicalProto)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not hash merged sandbox policy")
	}
	digest := sha256.Sum256(encoded)
	updated, _, err := s.runtime.st.ApplySandboxConfig(name, req.GetExpectedResourceVersion(), req.GetAnnotations(), "", "", false, policyYAMLString(policyYAML))
	if err != nil {
		if errors.Is(err, store.ErrResourceVersionConflict) {
			return nil, status.Error(codes.Aborted, "sandbox resource version changed")
		}
		if errors.Is(err, store.ErrSandboxPolicyManagedGlobally) {
			return nil, status.Error(codes.FailedPrecondition, "sandbox policy is managed by the global policy")
		}
		return nil, status.Error(codes.Internal, "could not store sandbox policy revision")
	}
	if err := s.syncSandboxRuntimePolicy(ctx, name, updated.PolicyRev); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "sandbox policy was stored but could not be delivered to the running runtime")
	}
	if err := s.waitSandboxPolicyApplied(ctx, name, updated.PolicyRev); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &openshellv1.UpdateConfigResponse{Version: uint32(updated.PolicyRev), PolicyHash: hex.EncodeToString(digest[:]), Annotations: updated.Annotations}, nil
}

func applyOpenShellPolicyMerge(base corepolicy.Document, operations []*openshellv1.PolicyMergeOperation) (corepolicy.Document, error) {
	serialized, err := yaml.Marshal(base)
	if err != nil {
		return corepolicy.Document{}, status.Error(codes.Internal, "could not copy sandbox policy")
	}
	merged, err := corepolicy.Parse(serialized)
	if err != nil {
		return corepolicy.Document{}, status.Error(codes.FailedPrecondition, "stored sandbox policy is invalid")
	}
	if merged.NetworkPolicies == nil {
		merged.NetworkPolicies = map[string]corepolicy.NetworkPolicy{}
	}
	for index, operation := range operations {
		if operation == nil || operation.GetOperation() == nil {
			return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d] is missing an operation", index)
		}
		switch value := operation.GetOperation().(type) {
		case *openshellv1.PolicyMergeOperation_AddRule:
			if value.AddRule == nil || strings.TrimSpace(value.AddRule.GetRuleName()) == "" {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].add_rule.rule_name is required", index)
			}
			name := strings.TrimSpace(value.AddRule.GetRuleName())
			if strings.HasPrefix(strings.ToLower(name), "_provider_") {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].add_rule.rule_name uses reserved _provider_ prefix", index)
			}
			if value.AddRule.GetRule() == nil || len(value.AddRule.GetRule().GetEndpoints()) == 0 {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].add_rule.rule must contain at least one endpoint", index)
			}
			fragment, err := parseMergeRule(name, value.AddRule.GetRule())
			if err != nil {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].add_rule.rule is invalid: %v", index, err)
			}
			for _, endpoint := range fragment.Endpoints {
				if mergeHostAlwaysBlocked(endpoint.Host) {
					return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].add_rule contains an always-blocked host", index)
				}
			}
			if err := addMergedNetworkRule(merged.NetworkPolicies, name, fragment); err != nil {
				return corepolicy.Document{}, status.Errorf(codes.FailedPrecondition, "merge_operations[%d]: %v", index, err)
			}
		case *openshellv1.PolicyMergeOperation_RemoveEndpoint:
			endpoint := value.RemoveEndpoint
			if endpoint == nil || strings.TrimSpace(endpoint.GetHost()) == "" || endpoint.GetPort() == 0 {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].remove_endpoint requires host and non-zero port", index)
			}
			removeMergedEndpoint(merged.NetworkPolicies, strings.TrimSpace(endpoint.GetRuleName()), strings.TrimSpace(endpoint.GetHost()), int(endpoint.GetPort()))
		case *openshellv1.PolicyMergeOperation_RemoveRule:
			if value.RemoveRule == nil || strings.TrimSpace(value.RemoveRule.GetRuleName()) == "" {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].remove_rule.rule_name is required", index)
			}
			delete(merged.NetworkPolicies, strings.TrimSpace(value.RemoveRule.GetRuleName()))
		case *openshellv1.PolicyMergeOperation_RemoveBinary:
			remove := value.RemoveBinary
			if remove == nil || strings.TrimSpace(remove.GetRuleName()) == "" || strings.TrimSpace(remove.GetBinaryPath()) == "" {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].remove_binary requires rule_name and binary_path", index)
			}
			name, path := strings.TrimSpace(remove.GetRuleName()), strings.TrimSpace(remove.GetBinaryPath())
			rule, exists := merged.NetworkPolicies[name]
			if exists && len(rule.Binaries) == 0 {
				return corepolicy.Document{}, status.Errorf(codes.FailedPrecondition, "merge_operations[%d] cannot remove a binary from a rule that allows all binaries", index)
			}
			if exists {
				filtered := rule.Binaries[:0]
				for _, binary := range rule.Binaries {
					if binary.Path != path {
						filtered = append(filtered, binary)
					}
				}
				rule.Binaries = filtered
				if len(filtered) == 0 {
					delete(merged.NetworkPolicies, name)
				} else {
					merged.NetworkPolicies[name] = rule
				}
			}
		case *openshellv1.PolicyMergeOperation_AddDenyRules:
			add := value.AddDenyRules
			if add == nil || strings.TrimSpace(add.GetHost()) == "" || add.GetPort() == 0 || len(add.GetDenyRules()) == 0 {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].add_deny_rules requires host, non-zero port, and at least one deny rule", index)
			}
			fragment, err := parseMergeEndpointRules(strings.TrimSpace(add.GetHost()), add.GetPort(), nil, add.GetDenyRules())
			if err != nil {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].add_deny_rules is invalid: %v", index, err)
			}
			if err := appendMergedEndpointRules(merged.NetworkPolicies, fragment, false); err != nil {
				return corepolicy.Document{}, status.Errorf(codes.FailedPrecondition, "merge_operations[%d]: %v", index, err)
			}
		case *openshellv1.PolicyMergeOperation_AddAllowRules:
			add := value.AddAllowRules
			if add == nil || strings.TrimSpace(add.GetHost()) == "" || add.GetPort() == 0 || len(add.GetRules()) == 0 {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].add_allow_rules requires host, non-zero port, and at least one allow rule", index)
			}
			for _, rule := range add.GetRules() {
				if rule == nil || rule.GetAllow() == nil {
					return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].add_allow_rules rules must include allow payloads", index)
				}
			}
			fragment, err := parseMergeEndpointRules(strings.TrimSpace(add.GetHost()), add.GetPort(), add.GetRules(), nil)
			if err != nil {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].add_allow_rules is invalid: %v", index, err)
			}
			if mergeHostAlwaysBlocked(fragment.Host) {
				return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d].add_allow_rules contains an always-blocked host", index)
			}
			if err := appendMergedEndpointRules(merged.NetworkPolicies, fragment, true); err != nil {
				return corepolicy.Document{}, status.Errorf(codes.FailedPrecondition, "merge_operations[%d]: %v", index, err)
			}
		default:
			return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d] has an unknown operation", index)
		}
		if err := merged.Validate(); err != nil {
			return corepolicy.Document{}, status.Errorf(codes.InvalidArgument, "merge_operations[%d] produces an invalid policy: %v", index, err)
		}
	}
	return merged, nil
}

func parseMergeRule(name string, rule *sandboxv1.NetworkPolicyRule) (corepolicy.NetworkPolicy, error) {
	doc, err := parseOpenShellSandboxPolicy(&sandboxv1.SandboxPolicy{Version: 1, NetworkPolicies: map[string]*sandboxv1.NetworkPolicyRule{name: rule}})
	if err != nil {
		return corepolicy.NetworkPolicy{}, err
	}
	return doc.NetworkPolicies[name], nil
}

func parseMergeEndpointRules(host string, port uint32, allows []*sandboxv1.L7Rule, denies []*sandboxv1.L7DenyRule) (corepolicy.AllowRule, error) {
	doc, err := parseOpenShellSandboxPolicy(&sandboxv1.SandboxPolicy{Version: 1, NetworkPolicies: map[string]*sandboxv1.NetworkPolicyRule{"merge": {Endpoints: []*sandboxv1.NetworkEndpoint{{Host: host, Port: port, Protocol: "rest", Rules: allows, DenyRules: denies}}}}})
	if err != nil {
		return corepolicy.AllowRule{}, err
	}
	return doc.NetworkPolicies["merge"].Endpoints[0], nil
}

func addMergedNetworkRule(policies map[string]corepolicy.NetworkPolicy, name string, incoming corepolicy.NetworkPolicy) error {
	if existing, ok := policies[name]; ok {
		if !sameMergeBinaryScope(existing.Binaries, incoming.Binaries) {
			return fmt.Errorf("rule %q has a different binary scope; refusing to widen authorization", name)
		}
		for _, endpoint := range incoming.Endpoints {
			if !containsPolicyEndpoint(existing.Endpoints, endpoint) {
				existing.Endpoints = append(existing.Endpoints, endpoint)
			}
		}
		policies[name] = existing
		return nil
	}
	incoming.Name = name
	policies[name] = incoming
	return nil
}

func sameMergeBinaryScope(left, right []corepolicy.NetworkBinary) bool {
	leftPaths := make([]string, len(left))
	rightPaths := make([]string, len(right))
	for i := range left {
		leftPaths[i] = left[i].Path
	}
	for i := range right {
		rightPaths[i] = right[i].Path
	}
	sort.Strings(leftPaths)
	sort.Strings(rightPaths)
	return reflect.DeepEqual(leftPaths, rightPaths)
}

func appendMergedEndpointRules(policies map[string]corepolicy.NetworkPolicy, incoming corepolicy.AllowRule, allow bool) error {
	type target struct {
		name string
		idx  int
	}
	var matches []target
	for name, rule := range policies {
		if strings.HasPrefix(strings.ToLower(name), "_provider_") {
			continue
		}
		for idx, endpoint := range rule.Endpoints {
			if endpointMatchesPolicyHostPort(endpoint, incoming.Host, incoming.Port) {
				matches = append(matches, target{name: name, idx: idx})
			}
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("endpoint %s:%d was not found", incoming.Host, incoming.Port)
	}
	if len(matches) > 1 {
		return fmt.Errorf("endpoint %s:%d matches more than one rule", incoming.Host, incoming.Port)
	}
	match := matches[0]
	rule := policies[match.name]
	endpoint := rule.Endpoints[match.idx]
	if !endpoint.NeedsL7() {
		return fmt.Errorf("endpoint %s:%d does not support L7 policy updates", incoming.Host, incoming.Port)
	}
	if allow {
		if endpoint.Access != "" {
			expanded, ok := expandMergeAccess(endpoint.Protocol, endpoint.Access)
			if !ok {
				return fmt.Errorf("endpoint %s:%d uses unsupported access preset %q", incoming.Host, incoming.Port, endpoint.Access)
			}
			for _, item := range expanded {
				endpoint.Rules = append(endpoint.Rules, corepolicy.L7Rule{Allow: &item})
			}
			endpoint.Access = ""
		}
		for _, item := range incoming.Rules {
			if !containsL7Rule(endpoint.Rules, item) {
				endpoint.Rules = append(endpoint.Rules, item)
			}
		}
	} else {
		if endpoint.Access == "" && len(endpoint.Rules) == 0 {
			return fmt.Errorf("endpoint %s:%d has no allow base", incoming.Host, incoming.Port)
		}
		for _, item := range incoming.DenyRules {
			if !containsL7DenyRule(endpoint.DenyRules, item) {
				endpoint.DenyRules = append(endpoint.DenyRules, item)
			}
		}
	}
	rule.Endpoints[match.idx] = endpoint
	policies[match.name] = rule
	return nil
}

func expandMergeAccess(protocol, access string) ([]corepolicy.L7Allow, bool) {
	methodRules := func(methods ...string) []corepolicy.L7Allow {
		out := make([]corepolicy.L7Allow, 0, len(methods))
		for _, method := range methods {
			out = append(out, corepolicy.L7Allow{Method: method, Path: "**"})
		}
		return out
	}
	switch strings.ToLower(strings.TrimSpace(access)) {
	case "full":
		return methodRules("*"), true
	case "read-only":
		if strings.EqualFold(strings.TrimSpace(protocol), "websocket") {
			return methodRules("GET"), true
		}
		return methodRules("GET", "HEAD", "OPTIONS"), true
	case "read-write":
		if strings.EqualFold(strings.TrimSpace(protocol), "websocket") {
			return methodRules("GET", "WEBSOCKET_TEXT"), true
		}
		return methodRules("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"), true
	default:
		return nil, false
	}
}

func mergeHostAlwaysBlocked(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" || host == "metadata.google.internal" || host == "metadata.google" || host == "metadata.azure.internal" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
}

func endpointMatchesPolicyHostPort(endpoint corepolicy.AllowRule, host string, port int) bool {
	if !strings.EqualFold(endpoint.Host, host) {
		return false
	}
	if len(endpoint.Ports) > 0 {
		for _, candidate := range endpoint.Ports {
			if candidate == port {
				return true
			}
		}
		return false
	}
	return endpoint.Port == port
}

func containsPolicyEndpoint(endpoints []corepolicy.AllowRule, wanted corepolicy.AllowRule) bool {
	for _, endpoint := range endpoints {
		if reflect.DeepEqual(endpoint, wanted) {
			return true
		}
	}
	return false
}

func containsL7Rule(rules []corepolicy.L7Rule, wanted corepolicy.L7Rule) bool {
	for _, rule := range rules {
		if reflect.DeepEqual(rule, wanted) {
			return true
		}
	}
	return false
}

func containsL7DenyRule(rules []corepolicy.L7DenyRule, wanted corepolicy.L7DenyRule) bool {
	for _, rule := range rules {
		if reflect.DeepEqual(rule, wanted) {
			return true
		}
	}
	return false
}

func removeMergedEndpoint(policies map[string]corepolicy.NetworkPolicy, ruleName, host string, port int) {
	for name, rule := range policies {
		if ruleName != "" && name != ruleName {
			continue
		}
		endpoints := rule.Endpoints[:0]
		for _, endpoint := range rule.Endpoints {
			if !strings.EqualFold(endpoint.Host, host) {
				endpoints = append(endpoints, endpoint)
				continue
			}
			if len(endpoint.Ports) > 0 {
				ports := endpoint.Ports[:0]
				for _, candidate := range endpoint.Ports {
					if candidate != port {
						ports = append(ports, candidate)
					}
				}
				endpoint.Ports = ports
				if len(ports) > 0 {
					endpoint.Port = ports[0]
					endpoints = append(endpoints, endpoint)
				}
				continue
			}
			if endpoint.Port != port {
				endpoints = append(endpoints, endpoint)
			}
		}
		rule.Endpoints = endpoints
		if len(rule.Endpoints) == 0 {
			delete(policies, name)
		} else {
			policies[name] = rule
		}
	}
}
