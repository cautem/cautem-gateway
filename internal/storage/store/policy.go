// Package store persists cautem-gateway registry state as JSON on disk.
package store

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// State is durable gateway registry state (JSON on disk).

// ErrResourceVersionConflict indicates that a config mutation used a stale resource version.
var ErrResourceVersionConflict = fmt.Errorf("sandbox resource version conflict")

var ErrSandboxPolicyManagedGlobally = fmt.Errorf("sandbox policy is managed by the global policy")

// ErrSandboxProviderLimit indicates a sandbox exceeds OpenShell's provider cap.

// ErrSandboxProviderLimit indicates a sandbox exceeds OpenShell's provider cap.
var ErrSandboxProviderLimit = fmt.Errorf("sandbox provider limit reached")

// ErrTemplateWorkspaceLimit is returned when a workspace already owns 1000 templates.

// ErrTemplateWorkspaceLimit is returned when a workspace already owns 1000 templates.
var ErrTemplateWorkspaceLimit = fmt.Errorf("workspace sandbox template limit reached")

// ApplySandboxConfig atomically applies a sandbox setting or base-policy update,
// annotation projection, and optimistic resource-version check.

// MaxPolicyRevisions caps retained revision history per sandbox.
const MaxPolicyRevisions = 32

// PolicyStatusLoaded is recorded after a successful base policy store.

// PolicyStatusLoaded is recorded after a successful base policy store.
const PolicyStatusLoaded = "loaded"

const PolicyStatusPending = "pending"

const PolicyStatusFailed = "failed"

const PolicyStatusSuperseded = "superseded"

// ReportPolicyStatus records the supervisor's load result for a stored policy revision.

// ReportPolicyStatus records the supervisor's load result for a stored policy revision.
func (s *Store) ReportPolicyStatus(sandboxID string, revision int, status, loadError string, loadedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := sandboxID
	if _, ok := s.state.Sandboxes[name]; !ok {
		for key, sandbox := range s.state.Sandboxes {
			if sandbox.ID == sandboxID {
				name = key
				break
			}
		}
	}
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return fmt.Errorf("sandbox %q not found", sandboxID)
	}
	found := false
	globalRevision := uint64(0)
	for i := range sb.PolicyRevisions {
		if sb.PolicyRevisions[i].Rev == revision {
			sb.PolicyRevisions[i].Status = status
			sb.PolicyRevisions[i].LoadError = loadError
			sb.PolicyRevisions[i].LoadedAt = loadedAt
			globalRevision = sb.PolicyRevisions[i].GlobalRevision
			found = true
		} else if status == PolicyStatusLoaded && sb.PolicyRevisions[i].Rev < revision && sb.PolicyRevisions[i].Status != PolicyStatusSuperseded {
			sb.PolicyRevisions[i].Status = PolicyStatusSuperseded
		}
	}
	if !found {
		return fmt.Errorf("sandbox %q policy revision %d not found", sandboxID, revision)
	}
	if status == PolicyStatusLoaded && uint32(revision) >= sb.ActivePolicyVersion {
		sb.ActivePolicyVersion = uint32(revision)
	}
	if globalRevision != 0 {
		for i := range s.state.GlobalPolicyRevisions {
			global := &s.state.GlobalPolicyRevisions[i]
			if uint64(global.Rev) != globalRevision || (global.Status != PolicyStatusPending && global.Status != PolicyStatusFailed) {
				continue
			}
			if status == PolicyStatusFailed {
				global.Status = PolicyStatusFailed
				global.LoadError = loadError
				continue
			}
			if status == PolicyStatusLoaded && !slices.Contains(global.AppliedSandboxes, name) {
				global.AppliedSandboxes = append(global.AppliedSandboxes, name)
				slices.Sort(global.AppliedSandboxes)
			}
			if status == PolicyStatusLoaded && len(global.AppliedSandboxes) == len(global.ExpectedSandboxes) {
				global.Status = PolicyStatusLoaded
				global.LoadError = ""
				global.LoadedAt = loadedAt
			}
		}
	}
	if sb.ResourceVersion == ^uint64(0) {
		return fmt.Errorf("sandbox resource version overflow")
	}
	sb.ResourceVersion++
	sb.UpdatedAt = time.Now().UTC()
	s.state.Sandboxes[name] = sb
	return s.flushLocked()
}

// ProfileRecord is a custom (imported) provider profile stored as YAML.

// SetBasePolicy stores sandbox base policy YAML (OpenShell-style editable layer).
// Attached providers are unchanged; callers build effective policy via provider.EffectivePolicy.
// Each successful store appends a policy revision (capped at MaxPolicyRevisions).
func (s *Store) SetBasePolicy(sandbox, yaml string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return fmt.Errorf("sandbox %q not found", sandbox)
	}
	if sb.BasePolicyYAML == yaml && sb.PolicyRev > 0 && len(sb.PolicyRevisions) > 0 {
		return nil
	}
	if sb.ResourceVersion == ^uint64(0) {
		return fmt.Errorf("sandbox resource version overflow")
	}
	if sb.PolicyRev == int(^uint(0)>>1) {
		return fmt.Errorf("sandbox policy revision overflow")
	}
	previous := cloneSandbox(sb)
	sb.ResourceVersion++
	sb.BasePolicyYAML = yaml
	sb.UpdatedAt = time.Now().UTC()
	sb.PolicyRev++
	rev := PolicyRevision{
		Rev:       sb.PolicyRev,
		UpdatedAt: sb.UpdatedAt,
		Bytes:     len(yaml),
		Status:    PolicyStatusPending,
		YAML:      yaml,
	}
	sb.PolicyRevisions = append(sb.PolicyRevisions, rev)
	if len(sb.PolicyRevisions) > MaxPolicyRevisions {
		sb.PolicyRevisions = sb.PolicyRevisions[len(sb.PolicyRevisions)-MaxPolicyRevisions:]
	}
	s.state.Sandboxes[sandbox] = sb
	if err := s.flushLocked(); err != nil {
		s.state.Sandboxes[sandbox] = previous
		return err
	}
	return nil
}

// SetBasePolicyIfRevision stores the policy only when the observed revision is current.

// SetBasePolicyIfRevision stores the policy only when the observed revision is current.
func (s *Store) SetBasePolicyIfRevision(sandbox, yaml string, expected int) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return 0, false, fmt.Errorf("sandbox %q not found", sandbox)
	}
	if strings.TrimSpace(s.state.GlobalPolicyYAML) != "" {
		return sb.PolicyRev, false, ErrSandboxPolicyManagedGlobally
	}
	if sb.PolicyRev != expected {
		return sb.PolicyRev, false, nil
	}
	if sb.BasePolicyYAML == yaml && sb.PolicyRev > 0 && len(sb.PolicyRevisions) > 0 {
		return sb.PolicyRev, true, nil
	}
	if sb.ResourceVersion == ^uint64(0) || sb.PolicyRev == int(^uint(0)>>1) {
		return sb.PolicyRev, false, fmt.Errorf("sandbox policy revision overflow")
	}
	previous := cloneSandbox(sb)
	sb.ResourceVersion++
	sb.BasePolicyYAML = yaml
	sb.UpdatedAt = time.Now().UTC()
	sb.PolicyRev++
	revision := PolicyRevision{Rev: sb.PolicyRev, UpdatedAt: sb.UpdatedAt, Bytes: len(yaml), Status: PolicyStatusPending, YAML: yaml}
	sb.PolicyRevisions = append(sb.PolicyRevisions, revision)
	if len(sb.PolicyRevisions) > MaxPolicyRevisions {
		sb.PolicyRevisions = sb.PolicyRevisions[len(sb.PolicyRevisions)-MaxPolicyRevisions:]
	}
	s.state.Sandboxes[sandbox] = sb
	if err := s.flushLocked(); err != nil {
		s.state.Sandboxes[sandbox] = previous
		return 0, false, err
	}
	return sb.PolicyRev, true, nil
}

// ListPolicyRevisions returns revision metadata (newest last).

// ListPolicyRevisions returns revision metadata (newest last).
func (s *Store) ListPolicyRevisions(sandbox string) ([]PolicyRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", sandbox)
	}
	out := make([]PolicyRevision, len(sb.PolicyRevisions))
	copy(out, sb.PolicyRevisions)
	return out, nil
}

// GetPolicyRevision returns base YAML for a revision number.

// GetPolicyRevision returns base YAML for a revision number.
func (s *Store) GetPolicyRevision(sandbox string, rev int) (PolicyRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[sandbox]
	if !ok {
		return PolicyRevision{}, fmt.Errorf("sandbox %q not found", sandbox)
	}
	for _, r := range sb.PolicyRevisions {
		if r.Rev == rev {
			return r, nil
		}
	}
	return PolicyRevision{}, fmt.Errorf("sandbox %q: policy revision %d not found", sandbox, rev)
}

// GetGlobalPolicy returns the stored global policy YAML (may be empty).

// GetGlobalPolicy returns the stored global policy YAML (may be empty).
func (s *Store) GetGlobalPolicy() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.GlobalPolicyYAML
}

// GlobalPolicySnapshot returns the global policy and its monotonic revision.

// GlobalPolicySnapshot returns the global policy and its monotonic revision.
func (s *Store) GlobalPolicySnapshot() (string, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.GlobalPolicyYAML, s.state.GlobalPolicyRevision
}

// SetGlobalPolicy stores global policy YAML bytes as a string.

// SetGlobalPolicy stores global policy YAML bytes as a string.
func (s *Store) SetGlobalPolicy(yaml string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.GlobalPolicyYAML == yaml {
		return nil
	}
	if s.state.GlobalPolicyRevision == ^uint64(0) {
		return fmt.Errorf("global policy revision overflow")
	}
	if s.state.GlobalPolicyRevision >= uint64(int(^uint(0)>>1)) {
		return fmt.Errorf("global policy revision overflow")
	}
	s.state.GlobalPolicyYAML = yaml
	s.state.GlobalPolicyRevision++
	updatedAt := time.Now().UTC()
	s.state.GlobalPolicyRevisions = append(s.state.GlobalPolicyRevisions, PolicyRevision{Rev: int(s.state.GlobalPolicyRevision), UpdatedAt: updatedAt, Bytes: len(yaml), Status: PolicyStatusLoaded, YAML: yaml})
	if len(s.state.GlobalPolicyRevisions) > MaxPolicyRevisions {
		s.state.GlobalPolicyRevisions = s.state.GlobalPolicyRevisions[len(s.state.GlobalPolicyRevisions)-MaxPolicyRevisions:]
	}
	return s.flushLocked()
}

// SetGlobalPolicyIfRevision atomically compares the current version and stores a new policy.

// SetGlobalPolicyIfRevision atomically compares the current version and stores a new policy.
func (s *Store) SetGlobalPolicyIfRevision(yaml string, expected uint64) (uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.GlobalPolicyRevision != expected {
		return s.state.GlobalPolicyRevision, false, nil
	}
	if s.state.GlobalPolicyYAML == yaml {
		return s.state.GlobalPolicyRevision, true, nil
	}
	if s.state.GlobalPolicyRevision == ^uint64(0) || s.state.GlobalPolicyRevision >= uint64(int(^uint(0)>>1)) {
		return s.state.GlobalPolicyRevision, false, fmt.Errorf("global policy revision overflow")
	}
	previousYAML := s.state.GlobalPolicyYAML
	previousRevision := s.state.GlobalPolicyRevision
	previousHistory := clonePolicyRevisions(s.state.GlobalPolicyRevisions)
	s.state.GlobalPolicyYAML = yaml
	s.state.GlobalPolicyRevision++
	updatedAt := time.Now().UTC()
	s.state.GlobalPolicyRevisions = append(s.state.GlobalPolicyRevisions, PolicyRevision{Rev: int(s.state.GlobalPolicyRevision), UpdatedAt: updatedAt, Bytes: len(yaml), Status: PolicyStatusLoaded, YAML: yaml})
	if len(s.state.GlobalPolicyRevisions) > MaxPolicyRevisions {
		s.state.GlobalPolicyRevisions = s.state.GlobalPolicyRevisions[len(s.state.GlobalPolicyRevisions)-MaxPolicyRevisions:]
	}
	if err := s.flushLocked(); err != nil {
		s.state.GlobalPolicyYAML = previousYAML
		s.state.GlobalPolicyRevision = previousRevision
		s.state.GlobalPolicyRevisions = previousHistory
		return 0, false, err
	}
	return s.state.GlobalPolicyRevision, true, nil
}

// GlobalPolicyHistory returns a detached oldest-first snapshot of retained global revisions.

// GlobalPolicyHistory returns a detached oldest-first snapshot of retained global revisions.
func (s *Store) GlobalPolicyHistory() []PolicyRevision {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clonePolicyRevisions(s.state.GlobalPolicyRevisions)
}

// GetGlobalPolicyRevision returns one retained global policy revision.

// GetGlobalPolicyRevision returns one retained global policy revision.
func (s *Store) GetGlobalPolicyRevision(revision int) (PolicyRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.state.GlobalPolicyRevisions {
		if item.Rev == revision {
			return clonePolicyRevisions([]PolicyRevision{item})[0], nil
		}
	}
	return PolicyRevision{}, fmt.Errorf("global policy revision %d not found", revision)
}

// UpsertProfile stores a custom profile YAML.
