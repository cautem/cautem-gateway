package store

import (
	"maps"
	"slices"
)

// Records crossing the store boundary must not share mutable state with callers.
func cloneSandbox(sb Sandbox) Sandbox {
	if sb.MainProcessExitCode != nil {
		code := *sb.MainProcessExitCode
		sb.MainProcessExitCode = &code
	}
	sb.Labels = maps.Clone(sb.Labels)
	sb.Settings = maps.Clone(sb.Settings)
	sb.Annotations = maps.Clone(sb.Annotations)
	sb.AttachedProviders = slices.Clone(sb.AttachedProviders)
	sb.PolicyRevisions = clonePolicyRevisions(sb.PolicyRevisions)
	return sb
}

func clonePolicyRevisions(revisions []PolicyRevision) []PolicyRevision {
	out := slices.Clone(revisions)
	for i := range out {
		out[i].Annotations = maps.Clone(out[i].Annotations)
		out[i].ExpectedSandboxes = slices.Clone(out[i].ExpectedSandboxes)
		out[i].AppliedSandboxes = slices.Clone(out[i].AppliedSandboxes)
	}
	return out
}

func cloneProvider(p ProviderRecord) ProviderRecord {
	p.Labels = maps.Clone(p.Labels)
	p.EnvVars = slices.Clone(p.EnvVars)
	p.Config = maps.Clone(p.Config)
	p.CredentialHandles = maps.Clone(p.CredentialHandles)
	for key, handle := range p.CredentialHandles {
		handle.Metadata = maps.Clone(handle.Metadata)
		p.CredentialHandles[key] = handle
	}
	p.CredentialExpiresAtMS = maps.Clone(p.CredentialExpiresAtMS)
	p.Refresh = maps.Clone(p.Refresh)
	for key, refresh := range p.Refresh {
		refresh.Material = maps.Clone(refresh.Material)
		refresh.MaterialSecretKeys = slices.Clone(refresh.MaterialSecretKeys)
		refresh.MaterialCredentialKeys = maps.Clone(refresh.MaterialCredentialKeys)
		refresh.Outputs = maps.Clone(refresh.Outputs)
		p.Refresh[key] = refresh
	}
	return p
}

func cloneTemplate(t TemplateRecord) TemplateRecord {
	t.Env = maps.Clone(t.Env)
	t.Labels = maps.Clone(t.Labels)
	t.Providers = slices.Clone(t.Providers)
	t.Forwards = slices.Clone(t.Forwards)
	return t
}

func cloneWorkspace(w WorkspaceRecord) WorkspaceRecord {
	w.Members = slices.Clone(w.Members)
	w.Labels = maps.Clone(w.Labels)
	return w
}

func cloneProposal(p Proposal) Proposal {
	p.Hosts = slices.Clone(p.Hosts)
	return p
}
