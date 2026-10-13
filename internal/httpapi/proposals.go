// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"gopkg.in/yaml.v3"
)

func approveProposal(ctx context.Context, st *store.Store, runtime *grpcRuntime, builtinDir, sandbox, id string) error {
	if runtime == nil {
		return fmt.Errorf("policy runtime is unavailable")
	}
	if globalPolicy, _ := st.GlobalPolicySnapshot(); strings.TrimSpace(globalPolicy) != "" {
		return fmt.Errorf("sandbox policy is managed by the global policy")
	}
	p, ok := st.GetProposal(id)
	if !ok || p.Sandbox != sandbox {
		return fmt.Errorf("proposal not found")
	}
	sb, ok := st.GetSandbox(sandbox)
	if !ok {
		return fmt.Errorf("sandbox not found")
	}
	base := sb.BasePolicyYAML
	if strings.TrimSpace(base) == "" {
		base = "version: 1\nnetwork_policies: {}\n"
	}
	merged, err := mergeProposalYAML(base, p.RuleName, p.RuleYAML)
	if err != nil {
		return err
	}
	if _, _, _, err := setSandboxBasePolicyWithSourcesExpected(st, builtinDir, sandbox, []byte(merged), nil, sb.PolicyRev); err != nil {
		return err
	}
	updated, ok := st.GetSandbox(sandbox)
	if !ok {
		return fmt.Errorf("sandbox not found")
	}
	rpc := &openShellRPC{options: runtime.opt, runtime: runtime}
	if err := rpc.syncSandboxRuntimePolicy(ctx, sandbox, updated.PolicyRev); err != nil {
		return fmt.Errorf("policy was stored but could not be delivered: %w", err)
	}
	if err := rpc.waitSandboxPolicyApplied(ctx, sandbox, updated.PolicyRev); err != nil {
		return fmt.Errorf("policy was stored but runtime did not acknowledge it: %w", err)
	}
	if p.Status == "approved" {
		return nil
	}
	_, err = st.DecideProposal(id, "approved", "")
	return err
}

func mergeProposalYAML(baseYAML, ruleName, ruleYAML string) (string, error) {
	baseDoc, err := policy.Parse([]byte(baseYAML))
	if err != nil {
		return "", fmt.Errorf("base policy: %w", err)
	}
	var frag struct {
		NetworkPolicies map[string]policy.NetworkPolicy `yaml:"network_policies"`
	}
	if err := yaml.Unmarshal([]byte(ruleYAML), &frag); err != nil {
		return "", fmt.Errorf("proposal rule: %w", err)
	}
	if baseDoc.NetworkPolicies == nil {
		baseDoc.NetworkPolicies = map[string]policy.NetworkPolicy{}
	}
	for k, v := range frag.NetworkPolicies {
		name := k
		if ruleName != "" {
			name = ruleName
			v.Name = ruleName
		}
		baseDoc.NetworkPolicies[name] = v
	}
	if err := baseDoc.Validate(); err != nil {
		return "", err
	}
	b, err := yaml.Marshal(baseDoc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
