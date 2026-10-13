// Package store persists cautem-gateway registry state as JSON on disk.
package store

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// State is durable gateway registry state (JSON on disk).

// ApplySandboxConfig atomically applies a sandbox setting or base-policy update,
// annotation projection, and optimistic resource-version check.
func (s *Store) ApplySandboxConfig(name string, expectedResourceVersion uint64, annotations map[string]string, settingKey, settingValue string, deleteSetting bool, policyYAML *string) (Sandbox, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, false, fmt.Errorf("sandbox %q not found", name)
	}
	if expectedResourceVersion != 0 && expectedResourceVersion != sb.ResourceVersion {
		return Sandbox{}, false, ErrResourceVersionConflict
	}
	if policyYAML != nil && strings.TrimSpace(s.state.GlobalPolicyYAML) != "" {
		return Sandbox{}, false, ErrSandboxPolicyManagedGlobally
	}
	previous := cloneSandbox(sb)
	sb = cloneSandbox(sb)
	changed := false
	policyChanged := false
	deleted := false
	if policyYAML != nil {
		provenanceChanged := false
		if len(annotations) > 0 && len(sb.PolicyRevisions) > 0 {
			latest := sb.PolicyRevisions[len(sb.PolicyRevisions)-1].Annotations
			for key, value := range annotations {
				if latest[key] != value {
					provenanceChanged = true
					break
				}
			}
		}
		if sb.BasePolicyYAML != *policyYAML || sb.PolicyRev == 0 || len(sb.PolicyRevisions) == 0 || provenanceChanged {
			if sb.PolicyRev == int(^uint(0)>>1) {
				return Sandbox{}, false, fmt.Errorf("sandbox policy revision overflow")
			}
			sb.BasePolicyYAML = *policyYAML
			sb.PolicyRev++
			changed, policyChanged = true, true
		}
	} else if settingKey != "" {
		if deleteSetting {
			_, deleted = sb.Settings[settingKey]
			if deleted {
				delete(sb.Settings, settingKey)
				if sb.SettingsRevision == ^uint64(0) {
					return Sandbox{}, false, fmt.Errorf("sandbox settings revision overflow")
				}
				sb.SettingsRevision++
				changed = true
			}
		} else {
			if sb.Settings == nil {
				sb.Settings = map[string]string{}
			}
			if current, exists := sb.Settings[settingKey]; !exists || current != settingValue {
				if sb.SettingsRevision == ^uint64(0) {
					return Sandbox{}, false, fmt.Errorf("sandbox settings revision overflow")
				}
				sb.Settings[settingKey] = settingValue
				sb.SettingsRevision++
				changed = true
			}
		}
	}
	annotationChanged := false
	if len(annotations) > 0 {
		if sb.Annotations == nil {
			sb.Annotations = map[string]string{}
		}
		for key, value := range annotations {
			if old, exists := sb.Annotations[key]; !exists || old != value {
				sb.Annotations[key] = value
				annotationChanged = true
			}
		}
	}
	changed = changed || annotationChanged
	if changed {
		if sb.ResourceVersion == ^uint64(0) {
			return Sandbox{}, false, fmt.Errorf("sandbox resource version overflow")
		}
		sb.ResourceVersion++
		sb.UpdatedAt = time.Now().UTC()
		if policyChanged {
			rev := PolicyRevision{Rev: sb.PolicyRev, UpdatedAt: sb.UpdatedAt, Bytes: len(sb.BasePolicyYAML), Status: PolicyStatusPending, YAML: sb.BasePolicyYAML, Annotations: maps.Clone(annotations)}
			sb.PolicyRevisions = append(sb.PolicyRevisions, rev)
			if len(sb.PolicyRevisions) > MaxPolicyRevisions {
				sb.PolicyRevisions = sb.PolicyRevisions[len(sb.PolicyRevisions)-MaxPolicyRevisions:]
			}
		}
		s.state.Sandboxes[name] = sb
		if err := s.flushLocked(); err != nil {
			s.state.Sandboxes[name] = previous
			return Sandbox{}, false, err
		}
	}
	return cloneSandbox(sb), deleted, nil
}

// ApplySandboxProvider atomically updates the provider attachment list and its
// serialized sandbox spec under an optional resource-version precondition.

// ApplySandboxProvider atomically updates the provider attachment list and its
// serialized sandbox spec under an optional resource-version precondition.
func (s *Store) ApplySandboxProvider(name string, expectedResourceVersion uint64, provider string, attach bool) (Sandbox, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, false, fmt.Errorf("sandbox %q not found", name)
	}
	if expectedResourceVersion != 0 && expectedResourceVersion != sb.ResourceVersion {
		return Sandbox{}, false, ErrResourceVersionConflict
	}
	previous := cloneSandbox(sb)
	sb = cloneSandbox(sb)
	var spec map[string]json.RawMessage
	if strings.TrimSpace(sb.SpecJSON) != "" {
		if err := json.Unmarshal([]byte(sb.SpecJSON), &spec); err != nil {
			return Sandbox{}, false, fmt.Errorf("decode stored sandbox spec: %w", err)
		}
	}
	baseProviders := sb.AttachedProviders
	if baseProviders == nil && spec != nil {
		if encoded, exists := spec["providers"]; exists {
			if err := json.Unmarshal(encoded, &baseProviders); err != nil {
				return Sandbox{}, false, fmt.Errorf("decode stored sandbox providers: %w", err)
			}
		}
	}
	providers := make([]string, 0, len(baseProviders)+1)
	for _, current := range baseProviders {
		if !slices.Contains(providers, current) {
			providers = append(providers, current)
		}
	}
	changed := len(providers) != len(baseProviders)
	if attach {
		if !slices.Contains(providers, provider) {
			if len(providers) >= 32 {
				return Sandbox{}, false, ErrSandboxProviderLimit
			}
			providers = append(providers, provider)
			changed = true
		}
	} else {
		filtered := make([]string, 0, len(providers))
		for _, current := range providers {
			if current == provider {
				changed = true
				continue
			}
			if !slices.Contains(filtered, current) {
				filtered = append(filtered, current)
			}
		}
		providers = filtered
	}
	if !changed {
		return cloneSandbox(sb), false, nil
	}
	if sb.ResourceVersion == ^uint64(0) {
		return Sandbox{}, false, fmt.Errorf("sandbox resource version overflow")
	}
	sb.AttachedProviders = providers
	if spec == nil {
		spec = make(map[string]json.RawMessage)
	}
	providerJSON, err := json.Marshal(providers)
	if err != nil {
		return Sandbox{}, false, err
	}
	spec["providers"] = providerJSON
	updatedSpec, err := json.Marshal(spec)
	if err != nil {
		return Sandbox{}, false, err
	}
	sb.SpecJSON = string(updatedSpec)
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = sb
	if err := s.flushLocked(); err != nil {
		s.state.Sandboxes[name] = previous
		return Sandbox{}, false, err
	}
	return cloneSandbox(sb), true, nil
}

// MaxPolicyRevisions caps retained revision history per sandbox.

// UpsertSandbox records or updates a sandbox.
func (s *Store) UpsertSandbox(sb Sandbox) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.state.Sandboxes[sb.Name]; ok {
		if sb.ResourceVersion == 0 {
			sb.ResourceVersion = prev.ResourceVersion
		}
		if sb.Annotations == nil && prev.Annotations != nil {
			sb.Annotations = prev.Annotations
		}
		if sb.Workspace == "" {
			sb.Workspace = prev.Workspace
		}
		if sb.Settings == nil && prev.Settings != nil {
			sb.Settings = prev.Settings
		}
		if sb.SettingsRevision == 0 && prev.SettingsRevision > 0 {
			sb.SettingsRevision = prev.SettingsRevision
		}
		if len(sb.AttachedProviders) == 0 && len(prev.AttachedProviders) > 0 {
			sb.AttachedProviders = prev.AttachedProviders
		}
		if sb.BasePolicyYAML == "" && prev.BasePolicyYAML != "" {
			sb.BasePolicyYAML = prev.BasePolicyYAML
		}
		if sb.PolicyRev == 0 && prev.PolicyRev > 0 {
			sb.PolicyRev = prev.PolicyRev
		}
		if len(sb.PolicyRevisions) == 0 && len(prev.PolicyRevisions) > 0 {
			sb.PolicyRevisions = prev.PolicyRevisions
		}
		if sb.MainProcessInstanceID == "" {
			sb.MainProcessInstanceID = prev.MainProcessInstanceID
		}
		if sb.SupervisorInstanceID == "" {
			sb.SupervisorInstanceID = prev.SupervisorInstanceID
		}
		if sb.MainProcessExitCode == nil && prev.MainProcessExitCode != nil {
			code := *prev.MainProcessExitCode
			sb.MainProcessExitCode = &code
		}
		if prev.MainProcessFinalized {
			sb.MainProcessFinalized = true
		}
	} else if sb.ResourceVersion == 0 {
		sb.ResourceVersion = 1
	}
	if sb.CreatedAt.IsZero() {
		sb.CreatedAt = sb.UpdatedAt
	}
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[sb.Name] = cloneSandbox(sb)
	return s.flushLocked()
}

// RecordMainProcessExit durably stores the canonical process result. Repeated
// reports are idempotent; the first result wins if duplicate reports conflict.

// RecordMainProcessExit durably stores the canonical process result. Repeated
// reports are idempotent; the first result wins if duplicate reports conflict.
func (s *Store) RecordMainProcessExit(name, instanceID string, exitCode int32) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.MainProcessExitCode != nil {
		return cloneSandbox(sb), nil
	}
	code := exitCode
	sb.MainProcessInstanceID = instanceID
	sb.MainProcessExitCode = &code
	sb.MainProcessFinalized = false
	if !strings.EqualFold(sb.Status, "error") && !strings.EqualFold(sb.Status, "failed") {
		if exitCode == 0 {
			sb.Status = "completed"
		} else {
			sb.Status = "error"
		}
	}
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = cloneSandbox(sb)
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// BeginSandboxStart clears the previous process result before a restarted
// runtime can report an early exit under its new supervisor instance.

// BeginSandboxStart clears the previous process result before a restarted
// runtime can report an early exit under its new supervisor instance.
func (s *Store) BeginSandboxStart(name string) (Sandbox, error) {
	return s.BeginSandboxStartCAS(name, 0)
}

// BeginSandboxStartCAS rejects a stale UI transition atomically with the
// registry's starting transition. Zero retains OpenShell's legacy behavior.

// BeginSandboxStartCAS rejects a stale UI transition atomically with the
// registry's starting transition. Zero retains OpenShell's legacy behavior.
func (s *Store) BeginSandboxStartCAS(name string, expectedVersion uint64) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if expectedVersion != 0 && sb.ResourceVersion != expectedVersion {
		return Sandbox{}, ErrResourceVersionConflict
	}
	sb.Status = "starting"
	sb.SupervisorInstanceID = ""
	sb.MainProcessInstanceID = ""
	sb.MainProcessExitCode = nil
	sb.MainProcessFinalized = false
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = cloneSandbox(sb)
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// SetSupervisorInstance records the latest accepted control-session instance
// so reports from a disconnected, superseded supervisor cannot become canonical.

// SetSupervisorInstance records the latest accepted control-session instance
// so reports from a disconnected, superseded supervisor cannot become canonical.
func (s *Store) SetSupervisorInstance(name, instanceID string) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.SupervisorInstanceID != instanceID {
		sb.SupervisorInstanceID = instanceID
		sb.ResourceVersion++
		sb.UpdatedAt = time.Now().UTC()
		s.state.Sandboxes[name] = cloneSandbox(sb)
		if err := s.flushLocked(); err != nil {
			return Sandbox{}, err
		}
	}
	return cloneSandbox(sb), nil
}

// MarkSandboxRunning avoids overwriting a main-process exit reported while
// the runtime's supervisor readiness handshake was in progress.

// MarkSandboxRunning avoids overwriting a main-process exit reported while
// the runtime's supervisor readiness handshake was in progress.
func (s *Store) MarkSandboxRunning(name string) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.MainProcessExitCode == nil {
		sb.Status = "running"
		sb.ResourceVersion++
		sb.UpdatedAt = time.Now().UTC()
		s.state.Sandboxes[name] = cloneSandbox(sb)
		if err := s.flushLocked(); err != nil {
			return Sandbox{}, err
		}
	}
	return cloneSandbox(sb), nil
}

// BeginSandboxStop records the stopping transition before a backend stop call.
// Persisting the intermediate state lets recovery/watchers distinguish an
// intentional stop from a daemon outage or an unexpected process exit.

// BeginSandboxStop records the stopping transition before a backend stop call.
// Persisting the intermediate state lets recovery/watchers distinguish an
// intentional stop from a daemon outage or an unexpected process exit.
func (s *Store) BeginSandboxStop(name string) (Sandbox, error) {
	return s.BeginSandboxStopCAS(name, 0)
}

// BeginSandboxStopCAS checks the expected version under the store lock.

// BeginSandboxStopCAS checks the expected version under the store lock.
func (s *Store) BeginSandboxStopCAS(name string, expectedVersion uint64) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if expectedVersion != 0 && sb.ResourceVersion != expectedVersion {
		return Sandbox{}, ErrResourceVersionConflict
	}
	if strings.EqualFold(sb.Status, "stopping") {
		return Sandbox{}, fmt.Errorf("sandbox %q is already stopping", name)
	}
	sb.Status = "stopping"
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = cloneSandbox(sb)
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// RestoreSandboxStatusCAS rolls back a failed stop transition only when the
// registry still contains that transition. It preserves an earlier error
// state instead of claiming the runtime is running after a failed stop.

// RestoreSandboxStatusCAS rolls back a failed stop transition only when the
// registry still contains that transition. It preserves an earlier error
// state instead of claiming the runtime is running after a failed stop.
func (s *Store) RestoreSandboxStatusCAS(name string, transitionVersion uint64, previousStatus string) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.ResourceVersion != transitionVersion || !strings.EqualFold(sb.Status, "stopping") {
		return Sandbox{}, ErrResourceVersionConflict
	}
	if sb.ResourceVersion == ^uint64(0) {
		return Sandbox{}, fmt.Errorf("sandbox resource version overflow")
	}
	if strings.TrimSpace(previousStatus) == "" {
		previousStatus = "error"
	}
	sb.Status = previousStatus
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = sb
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// BeginSandboxDeleteCAS reserves a deletion before backend side effects.
// Zero expectedVersion retains OpenShell's legacy unversioned behavior.

// BeginSandboxDeleteCAS reserves a deletion before backend side effects.
// Zero expectedVersion retains OpenShell's legacy unversioned behavior.
func (s *Store) BeginSandboxDeleteCAS(name string, expectedVersion uint64) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if expectedVersion != 0 && sb.ResourceVersion != expectedVersion {
		return Sandbox{}, ErrResourceVersionConflict
	}
	if strings.EqualFold(sb.Status, "deleting") {
		return Sandbox{}, fmt.Errorf("sandbox %q is already deleting", name)
	}
	sb.Status = "deleting"
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = cloneSandbox(sb)
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// MarkSandboxStopped records a completed backend stop.

// MarkSandboxStopped records a completed backend stop.
func (s *Store) MarkSandboxStopped(name string) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	sb.Status = "stopped"
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = cloneSandbox(sb)
	if err := s.flushLocked(); err != nil {
		return Sandbox{}, err
	}
	return cloneSandbox(sb), nil
}

// FinalizeMainProcessExit marks terminal delivery complete after the result
// was recorded. Repeated finalization for the same instance is harmless.

// FinalizeMainProcessExit marks terminal delivery complete after the result
// was recorded. Repeated finalization for the same instance is harmless.
func (s *Store) FinalizeMainProcessExit(name, instanceID string) (Sandbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return Sandbox{}, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.MainProcessExitCode == nil {
		return Sandbox{}, fmt.Errorf("main-process exit has not been reported")
	}
	if sb.MainProcessInstanceID != "" && sb.MainProcessInstanceID != instanceID {
		return Sandbox{}, fmt.Errorf("main-process instance does not match the terminal result")
	}
	if !sb.MainProcessFinalized {
		sb.MainProcessFinalized = true
		sb.ResourceVersion++
		sb.UpdatedAt = time.Now().UTC()
		s.state.Sandboxes[name] = cloneSandbox(sb)
		if err := s.flushLocked(); err != nil {
			return Sandbox{}, err
		}
	}
	return cloneSandbox(sb), nil
}

// DeleteSandbox removes a sandbox by name.

// DeleteSandbox removes a sandbox by name.
func (s *Store) DeleteSandbox(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Sandboxes, name)
	delete(s.state.SandboxTokens, name)
	now := time.Now().UTC()
	for i := range s.state.GlobalPolicyRevisions {
		revision := &s.state.GlobalPolicyRevisions[i]
		if revision.Status != PolicyStatusPending && revision.Status != PolicyStatusFailed {
			continue
		}
		revision.ExpectedSandboxes = slices.DeleteFunc(revision.ExpectedSandboxes, func(candidate string) bool { return candidate == name })
		revision.AppliedSandboxes = slices.DeleteFunc(revision.AppliedSandboxes, func(candidate string) bool { return candidate == name })
		if len(revision.AppliedSandboxes) == len(revision.ExpectedSandboxes) {
			revision.Status = PolicyStatusLoaded
			revision.LoadError = ""
			revision.LoadedAt = now
		}
	}
	for id, sess := range s.state.SSHSessions {
		if sess.Sandbox == name {
			delete(s.state.SSHSessions, id)
		}
	}
	return s.flushLocked()
}

// GetSandbox returns a sandbox if present.

// GetSandbox returns a sandbox if present.
func (s *Store) GetSandbox(name string) (Sandbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	return cloneSandbox(sb), ok
}

// GetSandboxByID resolves the gateway's durable sandbox ID while retaining
// GetSandbox's name-keyed storage contract.

// GetSandboxByID resolves the gateway's durable sandbox ID while retaining
// GetSandbox's name-keyed storage contract.
func (s *Store) GetSandboxByID(id string) (Sandbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sb := range s.state.Sandboxes {
		if sb.ID == id {
			return cloneSandbox(sb), true
		}
	}
	return Sandbox{}, false
}

// ListSandboxes returns sandbox records in stable name order.

// ListSandboxes returns sandbox records in stable name order.
func (s *Store) ListSandboxes() []Sandbox {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.state.Sandboxes))
	for name := range s.state.Sandboxes {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]Sandbox, 0, len(names))
	for _, name := range names {
		out = append(out, cloneSandbox(s.state.Sandboxes[name]))
	}
	return out
}

// SetBasePolicy stores sandbox base policy YAML (OpenShell-style editable layer).
// Attached providers are unchanged; callers build effective policy via provider.EffectivePolicy.
// Each successful store appends a policy revision (capped at MaxPolicyRevisions).
