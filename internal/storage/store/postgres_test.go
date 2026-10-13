package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestOpenPostgresImportsPersistsAndLocksInstallation(t *testing.T) {
	databaseURL := os.Getenv("CAUTEM_TEST_POSTGRES_URL")
	if databaseURL == "" {
		t.Skip("CAUTEM_TEST_POSTGRES_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	installationKey := fmt.Sprintf("store-test-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		conn, err := pgx.Connect(cleanupCtx, databaseURL)
		if err != nil {
			return
		}
		defer conn.Close(cleanupCtx)
		_, _ = conn.Exec(cleanupCtx, `DELETE FROM cautem_gateway_state WHERE installation_key = $1`, installationKey)
	})

	dataDir := t.TempDir()
	local, err := Open(dataDir, "gateway-from-file")
	if err != nil {
		t.Fatal(err)
	}
	if err := local.SetSetting("migrated", "from-file"); err != nil {
		t.Fatal(err)
	}
	if err := local.UpsertSandbox(Sandbox{Name: "desktop", Workspace: "team-a", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := local.CreateWorkspace(WorkspaceRecord{Name: "team-a", Members: []WorkspaceMember{{Subject: "alice", Role: "admin"}}}); err != nil {
		t.Fatal(err)
	}
	quota := WorkspaceQuota{CPUMilliCores: 2500, MemoryBytes: 4 << 30, GPUCount: 1, ConcurrentSandboxes: 5, ConcurrentGUISessions: 2}
	if _, err := local.UpdateWorkspaceQuota("team-a", 1, quota); err != nil {
		t.Fatal(err)
	}
	if err := local.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := OpenPostgres(ctx, dataDir, "generated-id-is-ignored-after-migration", installationKey, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	state := st.Snapshot()
	if state.GatewayID != "gateway-from-file" || state.Settings["migrated"] != "from-file" || state.Sandboxes["desktop"].Workspace != "team-a" || state.Workspaces["team-a"].Quota != quota {
		t.Fatalf("state.json migration lost data: gateway=%q settings=%v sandboxes=%v", state.GatewayID, state.Settings, state.Sandboxes)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("legacy state.json remains authoritative after import: %v", err)
	}
	archived, err := filepath.Glob(filepath.Join(dataDir, "state.json.migrated-*"))
	if err != nil || len(archived) != 1 {
		t.Fatalf("legacy state backup=%v err=%v", archived, err)
	}
	if _, err := OpenPostgres(ctx, t.TempDir(), "parallel-process", installationKey, databaseURL); err == nil {
		t.Fatal("a second writer acquired the same PostgreSQL installation lock")
	}
	if err := st.SetSetting("migrated", "saved-in-postgres"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenPostgres(ctx, t.TempDir(), "new-generated-id", installationKey, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	state = reopened.Snapshot()
	if state.GatewayID != "gateway-from-file" || state.Settings["migrated"] != "saved-in-postgres" || state.Sandboxes["desktop"].Workspace != "team-a" || state.Workspaces["team-a"].Quota != quota {
		t.Fatalf("PostgreSQL restart state mismatch: gateway=%q settings=%v sandboxes=%v", state.GatewayID, state.Settings, state.Sandboxes)
	}
}
