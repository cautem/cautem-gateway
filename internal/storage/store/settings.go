// Package store persists cautem-gateway registry state as JSON on disk.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// State is durable gateway registry state (JSON on disk).

// CreateScopedTemplate atomically creates a workspace-owned template.
func (s *Store) CreateScopedTemplate(t TemplateRecord) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Templates == nil {
		s.state.Templates = map[string]TemplateRecord{}
	}
	key := scopedTemplateKey(t.Workspace, t.Name)
	if _, exists := s.state.Templates[key]; exists {
		return false, nil
	}
	count := 0
	for _, existing := range s.state.Templates {
		if existing.Workspace == t.Workspace {
			count++
		}
	}
	if count >= 1000 {
		return false, ErrTemplateWorkspaceLimit
	}
	if t.ResourceVersion == 0 {
		t.ResourceVersion = 1
	}
	s.state.Templates[key] = cloneTemplate(t)
	return true, s.flushLocked()
}

func scopedTemplateKey(workspace, name string) string { return workspace + "\x00" + name }

// GetScopedTemplate reads a workspace-owned template.

// GetScopedTemplate reads a workspace-owned template.
func (s *Store) GetScopedTemplate(workspace, name string) (TemplateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Templates[scopedTemplateKey(workspace, name)]
	return cloneTemplate(t), ok
}

// DeleteScopedTemplate removes only a template in the given workspace.

// DeleteScopedTemplate removes only a template in the given workspace.
func (s *Store) DeleteScopedTemplate(workspace, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopedTemplateKey(workspace, name)
	if _, ok := s.state.Templates[key]; !ok {
		return false, nil
	}
	delete(s.state.Templates, key)
	return true, s.flushLocked()
}

// ListScopedTemplates returns templates in deterministic name order.

// ListScopedTemplates returns templates in deterministic name order.
func (s *Store) ListScopedTemplates(workspace string) []TemplateRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TemplateRecord, 0)
	for _, t := range s.state.Templates {
		if workspace == "" || t.Workspace == workspace {
			out = append(out, cloneTemplate(t))
		}
	}
	slices.SortFunc(out, func(a, b TemplateRecord) int {
		if byName := strings.Compare(a.Name, b.Name); byName != 0 {
			return byName
		}
		return strings.Compare(a.Workspace, b.Workspace)
	})
	return out
}

// Sandbox is one registered sandbox record.

// SetSetting stores a gateway setting key.
func (s *Store) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Settings == nil {
		s.state.Settings = map[string]string{}
	}
	if current, exists := s.state.Settings[key]; exists && current == value {
		return nil
	}
	if s.state.SettingsRevision == ^uint64(0) {
		return fmt.Errorf("settings revision overflow")
	}
	s.state.Settings[key] = value
	s.state.SettingsRevision++
	return s.flushLocked()
}

// GetSetting returns a setting.

// GetSetting returns a setting.
func (s *Store) GetSetting(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.state.Settings[key]
	return v, ok
}

// DeleteSetting removes a setting.

// DeleteSetting removes a setting.
func (s *Store) DeleteSetting(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Settings[key]; !exists {
		return nil
	}
	if s.state.SettingsRevision == ^uint64(0) {
		return fmt.Errorf("settings revision overflow")
	}
	delete(s.state.Settings, key)
	s.state.SettingsRevision++
	return s.flushLocked()
}

// AllSettings returns a copy of settings.

// AllSettings returns a copy of settings.
func (s *Store) AllSettings() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	maps.Copy(out, s.state.Settings)
	return out
}

// SettingsSnapshot returns global settings and their monotonic revision from
// one consistent store snapshot.

// SettingsSnapshot returns global settings and their monotonic revision from
// one consistent store snapshot.
func (s *Store) SettingsSnapshot() (map[string]string, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	maps.Copy(out, s.state.Settings)
	return out, s.state.SettingsRevision
}

// SandboxSettingsSnapshot returns one sandbox's scoped settings and revision.

// SandboxSettingsSnapshot returns one sandbox's scoped settings and revision.
func (s *Store) SandboxSettingsSnapshot(name string) (map[string]string, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return nil, 0, false
	}
	return maps.Clone(sb.Settings), sb.SettingsRevision, true
}

// SetSandboxSetting writes one setting and increments its sandbox revision only
// when the value changes.

// SetSandboxSetting writes one setting and increments its sandbox revision only
// when the value changes.
func (s *Store) SetSandboxSetting(name, key, value string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.state.Sandboxes[name]
	if !ok {
		return 0, fmt.Errorf("sandbox %q not found", name)
	}
	if sb.Settings == nil {
		sb.Settings = map[string]string{}
	}
	if current, exists := sb.Settings[key]; exists && current == value {
		return sb.SettingsRevision, nil
	}
	if sb.SettingsRevision == ^uint64(0) {
		return sb.SettingsRevision, fmt.Errorf("sandbox settings revision overflow")
	}
	if sb.ResourceVersion == ^uint64(0) {
		return sb.SettingsRevision, fmt.Errorf("sandbox resource version overflow")
	}
	sb.Settings[key] = value
	sb.SettingsRevision++
	sb.ResourceVersion++
	s.state.Sandboxes[name] = sb
	return sb.SettingsRevision, s.flushLocked()
}

// UpsertTemplate stores a workload template.

// UpsertTemplate stores a workload template.
func (s *Store) UpsertTemplate(t TemplateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Templates == nil {
		s.state.Templates = map[string]TemplateRecord{}
	}
	s.state.Templates[t.Name] = cloneTemplate(t)
	return s.flushLocked()
}

// GetTemplate returns a template.

// GetTemplate returns a template.
func (s *Store) GetTemplate(name string) (TemplateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Templates[name]
	return cloneTemplate(t), ok
}

// DeleteTemplate removes a template.

// DeleteTemplate removes a template.
func (s *Store) DeleteTemplate(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Templates, name)
	return s.flushLocked()
}

// ListTemplates returns all templates.

// ListTemplates returns all templates.
func (s *Store) ListTemplates() []TemplateRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TemplateRecord, 0, len(s.state.Templates))
	for _, t := range s.state.Templates {
		out = append(out, cloneTemplate(t))
	}
	return out
}

// EnsureAuthToken returns (and creates if needed) a local-dev bearer token.

// EnsureAuthToken returns (and creates if needed) a local-dev bearer token.
func (s *Store) EnsureAuthToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.AuthToken == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		s.state.AuthToken = hex.EncodeToString(b[:])
		if err := s.flushLocked(); err != nil {
			return "", err
		}
	}
	return s.state.AuthToken, nil
}

// AuthToken returns the configured bearer token (may be empty).

// AuthToken returns the configured bearer token (may be empty).
func (s *Store) AuthToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.AuthToken
}

// AttachProvider appends a provider name to a sandbox attachment list.
