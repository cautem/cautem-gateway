// Package store persists cautem-gateway registry state as JSON or PostgreSQL JSONB.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// State is durable gateway registry state.

type State struct {
	GatewayID             string                     `json:"gateway_id"`
	UpdatedAt             time.Time                  `json:"updated_at"`
	Sandboxes             map[string]Sandbox         `json:"sandboxes"`
	Labels                map[string]string          `json:"labels,omitempty"`
	GlobalPolicyYAML      string                     `json:"global_policy_yaml,omitempty"`
	GlobalPolicyRevision  uint64                     `json:"global_policy_revision,omitempty"`
	GlobalPolicyRevisions []PolicyRevision           `json:"global_policy_revisions,omitempty"`
	Profiles              map[string]ProfileRecord   `json:"profiles,omitempty"`
	Providers             map[string]ProviderRecord  `json:"providers,omitempty"`
	Inference             *InferenceRoute            `json:"inference,omitempty"`
	Settings              map[string]string          `json:"settings,omitempty"`
	SettingsRevision      uint64                     `json:"settings_revision,omitempty"`
	AuthToken             string                     `json:"auth_token,omitempty"` // local-dev bearer
	Templates             map[string]TemplateRecord  `json:"templates,omitempty"`
	Services              map[string]ServiceRecord   `json:"services,omitempty"`
	Workspaces            map[string]WorkspaceRecord `json:"workspaces,omitempty"`
	Proposals             map[string]Proposal        `json:"proposals,omitempty"`
	// SandboxTokens holds sha256(supervisor token) per sandbox name.
	SandboxTokens map[string]SandboxToken `json:"sandbox_tokens,omitempty"`
	// SSHSessions is keyed by session id; tokens are stored as sha256 only.
	SSHSessions     map[string]SSHSession `json:"ssh_sessions,omitempty"`
	AuditEvents     []AuditEvent          `json:"audit_events,omitempty"`
	AuditNextID     uint64                `json:"audit_next_id,omitempty"`
	Operations      map[string]Operation  `json:"operations,omitempty"`
	OperationNextID uint64                `json:"operation_next_id,omitempty"`
}

// InferenceRoute is the gateway-scoped inference.local backend (OpenShell inference set).

// InferenceRoute is the gateway-scoped inference.local backend (OpenShell inference set).
type InferenceRoute struct {
	Provider   string `json:"provider"`
	Model      string `json:"model,omitempty"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
	Version    int    `json:"version,omitempty"`
}

// TemplateRecord is a gateway-stored workload template.

// TemplateRecord is a gateway-stored workload template.
type TemplateRecord struct {
	Name            string            `json:"name"`
	Workspace       string            `json:"workspace,omitempty"`
	ID              string            `json:"id,omitempty"`
	SpecJSON        string            `json:"spec_json,omitempty"`
	CreatedAt       time.Time         `json:"created_at,omitempty"`
	ResourceVersion uint64            `json:"resource_version,omitempty"`
	Image           string            `json:"image,omitempty"`
	From            string            `json:"from,omitempty"`
	Policy          string            `json:"policy,omitempty"`
	CPU             float64           `json:"cpu,omitempty"`
	Memory          string            `json:"memory,omitempty"`
	Env             map[string]string `json:"env,omitempty"`
	Providers       []string          `json:"providers,omitempty"`
	Forwards        []int             `json:"forwards,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	YAML            string            `json:"yaml,omitempty"` // optional raw
}

// CreateScopedTemplate atomically creates a workspace-owned template.

// Sandbox is one registered sandbox record.
type Sandbox struct {
	Name                  string            `json:"name"`
	ID                    string            `json:"id,omitempty"`
	RuntimeID             string            `json:"runtime_id,omitempty"`
	ComputeDriver         string            `json:"compute_driver,omitempty"`
	Image                 string            `json:"image,omitempty"`
	Workspace             string            `json:"workspace,omitempty"`
	Network               string            `json:"network,omitempty"`
	Status                string            `json:"status,omitempty"`
	ResourceCPUMilli      uint64            `json:"resource_cpu_millicores,omitempty"`
	ResourceMemoryBytes   uint64            `json:"resource_memory_bytes,omitempty"`
	ResourceGPUCount      uint32            `json:"resource_gpu_count,omitempty"`
	ResourceKnown         bool              `json:"resource_known,omitempty"`
	SupervisorInstanceID  string            `json:"supervisor_instance_id,omitempty"`
	MainProcessInstanceID string            `json:"main_process_instance_id,omitempty"`
	MainProcessExitCode   *int32            `json:"main_process_exit_code,omitempty"`
	MainProcessFinalized  bool              `json:"main_process_finalized,omitempty"`
	SpecJSON              string            `json:"spec_json,omitempty"`
	Labels                map[string]string `json:"labels,omitempty"`
	Settings              map[string]string `json:"settings,omitempty"`
	SettingsRevision      uint64            `json:"settings_revision,omitempty"`
	ResourceVersion       uint64            `json:"resource_version,omitempty"`
	Annotations           map[string]string `json:"annotations,omitempty"`
	CreatedAt             time.Time         `json:"created_at,omitempty"`
	BasePolicyYAML        string            `json:"base_policy_yaml,omitempty"`
	AttachedProviders     []string          `json:"attached_providers,omitempty"`
	PolicyRev             int               `json:"policy_rev,omitempty"`
	ActivePolicyVersion   uint32            `json:"active_policy_version,omitempty"`
	PolicyRevisions       []PolicyRevision  `json:"policy_revisions,omitempty"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// PolicyRevision is one loaded base-policy generation (OpenShell policy list).

// PolicyRevision is one loaded base-policy generation (OpenShell policy list).
type PolicyRevision struct {
	Rev               int               `json:"rev"`
	GlobalRevision    uint64            `json:"global_revision,omitempty"`
	Cleared           bool              `json:"cleared,omitempty"`
	UpdatedAt         time.Time         `json:"updated_at"`
	LoadedAt          time.Time         `json:"loaded_at,omitempty"`
	Bytes             int               `json:"bytes"`
	Status            string            `json:"status"`
	LoadError         string            `json:"load_error,omitempty"`
	YAML              string            `json:"yaml,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	ExpectedSandboxes []string          `json:"expected_sandboxes,omitempty"`
	AppliedSandboxes  []string          `json:"applied_sandboxes,omitempty"`
}

// ErrResourceVersionConflict indicates that a config mutation used a stale resource version.

// ProfileRecord is a custom (imported) provider profile stored as YAML.
type ProfileRecord struct {
	ID              string `json:"id"`
	Scope           string `json:"scope,omitempty"`
	Workspace       string `json:"workspace,omitempty"`
	YAML            string `json:"yaml"`
	ResourceVersion string `json:"resource_version,omitempty"`
	Version         uint64 `json:"version,omitempty"`
}

// ProviderRecord is a named instance referencing a profile.
// EnvVars are key names only; values live in the encrypted secrets store.

// ProviderRecord is a named instance referencing a profile.
// EnvVars are key names only; values live in the encrypted secrets store.
type ProviderRecord struct {
	Name                  string                           `json:"name"`
	Type                  string                           `json:"type"`
	Workspace             string                           `json:"workspace,omitempty"`
	Labels                map[string]string                `json:"labels,omitempty"`
	EnvVars               []string                         `json:"env_vars,omitempty"`
	CredentialDriver      string                           `json:"credential_driver,omitempty"`
	CredentialHandles     map[string]CredentialHandle      `json:"credential_handles,omitempty"`
	CredentialExpiresAtMS map[string]int64                 `json:"credential_expires_at_ms,omitempty"`
	RuntimeCredentials    bool                             `json:"runtime_credentials,omitempty"`
	Config                map[string]string                `json:"config,omitempty"`
	Refresh               map[string]ProviderRefreshConfig `json:"refresh,omitempty"`
}

// CredentialHandle is the durable non-secret reference owned by a configured
// CredentialDriver. Values are never persisted here.

// CredentialHandle is the durable non-secret reference owned by a configured
// CredentialDriver. Values are never persisted here.
type CredentialHandle struct {
	Driver   string            `json:"driver"`
	Handle   string            `json:"handle"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ProviderRefreshConfig is gateway-managed credential refresh metadata (OpenShell).

// ProviderRefreshConfig is gateway-managed credential refresh metadata (OpenShell).
type ProviderRefreshConfig struct {
	CredentialKey          string            `json:"credential_key"`
	Strategy               string            `json:"strategy"` // env | oauth2-refresh-token | oauth2-client-credentials | aws-sts-assume-role
	Material               map[string]string `json:"material,omitempty"`
	MaterialSecretKeys     []string          `json:"material_secret_keys,omitempty"`
	MaterialCredentialKeys map[string]string `json:"material_credential_keys,omitempty"`
	Outputs                map[string]string `json:"outputs,omitempty"` // response field -> provider env key
	RefreshBeforeSeconds   int64             `json:"refresh_before_seconds,omitempty"`
	MaxLifetimeSeconds     int64             `json:"max_lifetime_seconds,omitempty"`
	ExpiresAtMS            int64             `json:"expires_at_ms,omitempty"`
}

// Store persists State under DataDir/state.json.

// Store persists State under DataDir/state.json.
type Store struct {
	mu               sync.Mutex
	DataDir          string
	path             string
	initialGatewayID string
	state            State
	db               *pgx.Conn
	dbKey            string
}

// Open loads or initializes state in dataDir.

// Open loads or initializes state in dataDir.
func Open(dataDir, gatewayID string) (*Store, error) {
	s, err := newStore(dataDir, gatewayID)
	if err != nil {
		return nil, err
	}
	if err := s.loadFileState(); err != nil {
		return nil, err
	}
	return s, s.flushLocked()
}

func newStore(dataDir, gatewayID string) (*Store, error) {
	// State carries provider metadata, auth and session hashes: owner-only.
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	if err := restrictOwnerAccess(dataDir, true); err != nil {
		return nil, err
	}
	s := &Store{
		DataDir:          dataDir,
		path:             filepath.Join(dataDir, "state.json"),
		initialGatewayID: gatewayID,
		state: State{
			GatewayID:  gatewayID,
			Sandboxes:  map[string]Sandbox{},
			Labels:     map[string]string{},
			Profiles:   map[string]ProfileRecord{},
			Providers:  map[string]ProviderRecord{},
			Settings:   map[string]string{},
			Templates:  map[string]TemplateRecord{},
			Services:   map[string]ServiceRecord{},
			Workspaces: map[string]WorkspaceRecord{},
			Proposals:  map[string]Proposal{},
			Operations: map[string]Operation{},

			SandboxTokens: map[string]SandboxToken{},
			SSHSessions:   map[string]SSHSession{},
		},
	}
	return s, nil
}

func (s *Store) loadFileState() error {
	b, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(b, &s.state); err != nil {
			return fmt.Errorf("gateway store: parse: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	s.normalizeState()
	return nil
}

func (s *Store) normalizeState() {
	if s.state.GatewayID == "" {
		s.state.GatewayID = s.initialGatewayID
	}
	if s.state.Sandboxes == nil {
		s.state.Sandboxes = map[string]Sandbox{}
	}
	for name, sandbox := range s.state.Sandboxes {
		if sandbox.ResourceVersion == 0 {
			sandbox.ResourceVersion = 1
		}
		if sandbox.SettingsRevision == 0 && len(sandbox.Settings) > 0 {
			sandbox.SettingsRevision = 1
		}
		s.state.Sandboxes[name] = sandbox
	}
	if s.state.Profiles == nil {
		s.state.Profiles = map[string]ProfileRecord{}
	}
	if s.state.Providers == nil {
		s.state.Providers = map[string]ProviderRecord{}
	}
	if s.state.Settings == nil {
		s.state.Settings = map[string]string{}
	}
	if s.state.SettingsRevision == 0 && len(s.state.Settings) > 0 {
		s.state.SettingsRevision = 1
	}
	if s.state.GlobalPolicyRevision == 0 && strings.TrimSpace(s.state.GlobalPolicyYAML) != "" {
		s.state.GlobalPolicyRevision = 1
	}
	if len(s.state.GlobalPolicyRevisions) == 0 && strings.TrimSpace(s.state.GlobalPolicyYAML) != "" {
		s.state.GlobalPolicyRevisions = []PolicyRevision{{Rev: int(s.state.GlobalPolicyRevision), UpdatedAt: time.Now().UTC(), Bytes: len(s.state.GlobalPolicyYAML), Status: PolicyStatusLoaded, YAML: s.state.GlobalPolicyYAML}}
	}
	if s.state.Templates == nil {
		s.state.Templates = map[string]TemplateRecord{}
	}
	if s.state.Services == nil {
		s.state.Services = map[string]ServiceRecord{}
	}
	if s.state.Workspaces == nil {
		s.state.Workspaces = map[string]WorkspaceRecord{}
	}
	if s.state.Proposals == nil {
		s.state.Proposals = map[string]Proposal{}
	}
	if s.state.Operations == nil {
		s.state.Operations = map[string]Operation{}
	}
	for id, operation := range s.state.Operations {
		if operation.State == OperationRunning {
			operation.State = OperationUncertain
			operation.UpdatedAt = time.Now().UTC()
			s.state.Operations[id] = operation
		}
	}
	if s.state.SandboxTokens == nil {
		s.state.SandboxTokens = map[string]SandboxToken{}
	}
	if s.state.SSHSessions == nil {
		s.state.SSHSessions = map[string]SSHSession{}
	}
}

func (s *Store) flushLocked() error {
	s.state.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if s.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result, err := s.db.Exec(ctx, `UPDATE cautem_gateway_state SET state = $1::jsonb, updated_at = now() WHERE installation_key = $2`, string(b), s.dbKey)
		if err != nil {
			return fmt.Errorf("gateway store: persist PostgreSQL state: %w", err)
		}
		if result.RowsAffected() != 1 {
			return fmt.Errorf("gateway store: PostgreSQL state row is missing")
		}
		return nil
	}
	return writeOwnerOnlyAtomic(s.path, b)
}

// OpenPostgres uses a PostgreSQL row as the durable registry and keeps a
// session advisory lock for this installation key so only one Gateway process
// can write it at a time. Existing state.json is imported on first use.
func OpenPostgres(ctx context.Context, dataDir, gatewayID, installationKey, databaseURL string) (*Store, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	startupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if strings.TrimSpace(installationKey) == "" {
		installationKey = "default"
	}
	s, err := newStore(dataDir, gatewayID)
	if err != nil {
		return nil, err
	}
	conn, err := pgx.Connect(startupCtx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("gateway store: PostgreSQL connection failed")
	}
	closeOnError := func(err error) (*Store, error) {
		_ = conn.Close(context.Background())
		return nil, err
	}
	var locked bool
	if err := conn.QueryRow(startupCtx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, installationKey).Scan(&locked); err != nil {
		return closeOnError(fmt.Errorf("gateway store: PostgreSQL lock failed"))
	}
	if !locked {
		return closeOnError(fmt.Errorf("gateway store: another Gateway process owns PostgreSQL installation key %q", installationKey))
	}
	if _, err := conn.Exec(startupCtx, `CREATE TABLE IF NOT EXISTS cautem_gateway_state (
		installation_key text PRIMARY KEY,
		state jsonb NOT NULL,
		updated_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return closeOnError(fmt.Errorf("gateway store: PostgreSQL schema initialization failed"))
	}
	var raw []byte
	err = conn.QueryRow(startupCtx, `SELECT state FROM cautem_gateway_state WHERE installation_key = $1`, installationKey).Scan(&raw)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &s.state); err != nil {
			return closeOnError(fmt.Errorf("gateway store: PostgreSQL state is invalid JSON"))
		}
		s.normalizeState()
	case err == pgx.ErrNoRows:
		if err := s.loadFileState(); err != nil {
			return closeOnError(err)
		}
		b, marshalErr := json.Marshal(s.state)
		if marshalErr != nil {
			return closeOnError(marshalErr)
		}
		if _, err := conn.Exec(startupCtx, `INSERT INTO cautem_gateway_state (installation_key, state) VALUES ($1, $2::jsonb)`, installationKey, string(b)); err != nil {
			return closeOnError(fmt.Errorf("gateway store: import initial PostgreSQL state failed"))
		}
	case err != nil:
		return closeOnError(fmt.Errorf("gateway store: PostgreSQL state read failed"))
	}
	s.db, s.dbKey = conn, installationKey
	if err := s.flushLocked(); err != nil {
		return closeOnError(err)
	}
	if err := s.archiveImportedFileState(); err != nil {
		return closeOnError(fmt.Errorf("gateway store: PostgreSQL is initialized but legacy state file could not be archived: %w", err))
	}
	return s, nil
}

func (s *Store) archiveImportedFileState() error {
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	archived := fmt.Sprintf("%s.migrated-%s", s.path, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := restrictOwnerAccess(s.path, false); err != nil {
		return err
	}
	return os.Rename(s.path, archived)
}

// Close releases the PostgreSQL advisory lock and connection, if configured.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close(context.Background())
	s.db = nil
	return err
}

// Snapshot returns an independent copy of registry state without authentication secrets.

// Snapshot returns an independent copy of registry state without authentication secrets.
func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state
	out.Sandboxes = map[string]Sandbox{}
	for name, sb := range s.state.Sandboxes {
		out.Sandboxes[name] = cloneSandbox(sb)
	}
	out.Profiles = map[string]ProfileRecord{}
	maps.Copy(out.Profiles, s.state.Profiles)
	out.Providers = map[string]ProviderRecord{}
	for name, rec := range s.state.Providers {
		out.Providers[name] = cloneProvider(rec)
	}
	out.Settings = map[string]string{}
	maps.Copy(out.Settings, s.state.Settings)
	out.Templates = map[string]TemplateRecord{}
	for name, record := range s.state.Templates {
		out.Templates[name] = cloneTemplate(record)
	}
	out.Services = map[string]ServiceRecord{}
	maps.Copy(out.Services, s.state.Services)
	out.Workspaces = map[string]WorkspaceRecord{}
	for name, ws := range s.state.Workspaces {
		out.Workspaces[name] = cloneWorkspace(ws)
	}
	if s.state.Inference != nil {
		inf := *s.state.Inference
		out.Inference = &inf
	}
	out.Labels = maps.Clone(s.state.Labels)
	out.GlobalPolicyRevisions = clonePolicyRevisions(s.state.GlobalPolicyRevisions)
	out.AuditEvents = slices.Clone(s.state.AuditEvents)
	out.Operations = maps.Clone(s.state.Operations)
	out.Proposals = maps.Clone(s.state.Proposals)
	for id, proposal := range out.Proposals {
		out.Proposals[id] = cloneProposal(proposal)
	}
	out.AuthToken = ""
	out.SandboxTokens = nil
	out.SSHSessions = nil
	return out
}

// UpsertSandbox records or updates a sandbox.

// defaultInferenceTimeoutSeconds is the default provider request deadline.
const defaultInferenceTimeoutSeconds = 60
