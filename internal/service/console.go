package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"strings"

	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

const (
	DefaultConsolePageSize uint32 = 50
	MaxConsolePageSize     uint32 = 100
)

var ErrInvalidConsolePageToken = errors.New("invalid page token")
var ErrInvalidConsoleFilter = errors.New("invalid sandbox filter")

type ConsoleListOptions struct {
	Workspace      string
	PageSize       uint32
	PageToken      string
	NamePrefix     string
	RegistryStatus string
	ComputeDriver  string
	Labels         map[string]string
}

type consoleCursor struct {
	Workspace      string            `json:"workspace"`
	NamePrefix     string            `json:"name_prefix"`
	RegistryStatus string            `json:"registry_status"`
	ComputeDriver  string            `json:"compute_driver"`
	Labels         map[string]string `json:"labels,omitempty"`
	After          string            `json:"after"`
}

// ConsoleStore is the read side shared by REST and the user-facing client API.
type ConsoleStore interface {
	ListSandboxes() []store.Sandbox
	GetSandbox(name string) (store.Sandbox, bool)
}

type ConsoleReader struct {
	Store ConsoleStore
}

func (r ConsoleReader) ListRecords() []store.Sandbox {
	return r.Store.ListSandboxes()
}

func (r ConsoleReader) GetRecord(name string) (store.Sandbox, bool) {
	return r.Store.GetSandbox(name)
}

// ListWorkspace returns a stable name-ordered page. The cursor is bound to
// the workspace and filters so they cannot change between pages.
func (r ConsoleReader) ListWorkspace(options ConsoleListOptions) ([]store.Sandbox, string, error) {
	if len(options.Workspace) > 128 || len(options.NamePrefix) > 128 || len(options.RegistryStatus) > 64 || len(options.ComputeDriver) > 128 {
		return nil, "", ErrInvalidConsoleFilter
	}
	if len(options.Labels) > 64 {
		return nil, "", ErrInvalidConsoleFilter
	}
	for key, value := range options.Labels {
		if len(key) == 0 || len(key) > 128 || len(value) > 256 {
			return nil, "", ErrInvalidConsoleFilter
		}
	}
	if options.PageSize == 0 {
		options.PageSize = DefaultConsolePageSize
	}
	if options.PageSize > MaxConsolePageSize {
		options.PageSize = MaxConsolePageSize
	}
	after := ""
	if options.PageToken != "" {
		if len(options.PageToken) > 4096 {
			return nil, "", ErrInvalidConsolePageToken
		}
		decoded, err := base64.RawURLEncoding.DecodeString(options.PageToken)
		if err != nil {
			return nil, "", ErrInvalidConsolePageToken
		}
		var cursor consoleCursor
		if err := json.Unmarshal(decoded, &cursor); err != nil || cursor.Workspace != options.Workspace || cursor.NamePrefix != options.NamePrefix || cursor.RegistryStatus != options.RegistryStatus || cursor.ComputeDriver != options.ComputeDriver || !maps.Equal(cursor.Labels, options.Labels) || cursor.After == "" {
			return nil, "", ErrInvalidConsolePageToken
		}
		after = cursor.After
	}
	page := make([]store.Sandbox, 0, options.PageSize)
	hasMore := false
	for _, sandbox := range r.Store.ListSandboxes() {
		if EffectiveSandboxWorkspace(sandbox) != options.Workspace || sandbox.Name <= after || !strings.HasPrefix(sandbox.Name, options.NamePrefix) || options.RegistryStatus != "" && !strings.EqualFold(sandbox.Status, options.RegistryStatus) || options.ComputeDriver != "" && sandbox.ComputeDriver != options.ComputeDriver || !matchesLabels(sandbox.Labels, options.Labels) {
			continue
		}
		if uint32(len(page)) == options.PageSize {
			hasMore = true
			break
		}
		page = append(page, sandbox)
	}
	if !hasMore || len(page) == 0 {
		return page, "", nil
	}
	cursor := consoleCursor{
		Workspace: options.Workspace, NamePrefix: options.NamePrefix,
		RegistryStatus: options.RegistryStatus, ComputeDriver: options.ComputeDriver, Labels: options.Labels,
		After: page[len(page)-1].Name,
	}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return nil, "", err
	}
	return page, base64.RawURLEncoding.EncodeToString(encoded), nil
}

func matchesLabels(actual, required map[string]string) bool {
	for key, value := range required {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func (r ConsoleReader) GetWorkspace(workspace, name string) (store.Sandbox, bool) {
	sandbox, ok := r.Store.GetSandbox(name)
	return sandbox, ok && EffectiveSandboxWorkspace(sandbox) == workspace
}

func (r ConsoleReader) WorkspaceCounts(workspace string) (total, registryRunning uint64) {
	for _, sandbox := range r.Store.ListSandboxes() {
		if EffectiveSandboxWorkspace(sandbox) != workspace {
			continue
		}
		total++
		if sandbox.Status == "running" || sandbox.Status == "ready" {
			registryRunning++
		}
	}
	return total, registryRunning
}

// EffectiveSandboxWorkspace maps legacy records without a workspace to the
// default workspace used by the operator API.
func EffectiveSandboxWorkspace(sandbox store.Sandbox) string {
	if sandbox.Workspace == "" {
		return "default"
	}
	return sandbox.Workspace
}
