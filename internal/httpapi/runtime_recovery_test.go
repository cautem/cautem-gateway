package httpapi

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"log/slog"
)

type recoveryEngine struct {
	rows      []driver.Info
	deleted   []core.ID
	stopped   []core.ID
	deleteErr error
}

func (e *recoveryEngine) Create(context.Context, driver.Spec) (driver.Handle, error) {
	return driver.Handle{}, nil
}
func (e *recoveryEngine) Start(context.Context, core.ID) error { return nil }
func (e *recoveryEngine) Stop(_ context.Context, id core.ID) error {
	e.stopped = append(e.stopped, id)
	return nil
}
func (e *recoveryEngine) Exec(context.Context, core.ID, driver.ExecRequest) (driver.ExecResult, error) {
	return driver.ExecResult{}, nil
}
func (e *recoveryEngine) Delete(_ context.Context, id core.ID) error {
	e.deleted = append(e.deleted, id)
	return e.deleteErr
}

func TestReconcileRuntimeStateRetriesFailedOrphanCleanup(t *testing.T) {
	st, err := store.Open(t.TempDir(), "recovery-retry")
	if err != nil {
		t.Fatal(err)
	}
	engine := &recoveryEngine{rows: []driver.Info{{ID: "runtime-orphan", Name: "orphan"}}, deleteErr: errors.New("daemon unavailable")}
	registry := &computeRegistry{configured: map[string]map[string]any{"docker": {}}, engines: map[string]driver.Engine{"docker": engine}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	reconcileRuntimeState(context.Background(), st, registry, log)
	reconcileRuntimeState(context.Background(), st, registry, log)
	if len(engine.stopped) != 2 || len(engine.deleted) != 2 {
		t.Fatalf("orphan cleanup attempts: stopped=%v deleted=%v; want retry on next reconciliation", engine.stopped, engine.deleted)
	}
}
func (e *recoveryEngine) List(context.Context) ([]driver.Info, error) {
	return append([]driver.Info(nil), e.rows...), nil
}
func (e *recoveryEngine) Inspect(context.Context, string) (driver.Info, error) {
	return driver.Info{}, nil
}
func (e *recoveryEngine) Logs(context.Context, core.ID, bool, io.Writer) error        { return nil }
func (e *recoveryEngine) CopyTo(context.Context, core.ID, string, string) error       { return nil }
func (e *recoveryEngine) CopyFrom(context.Context, core.ID, string, string) error     { return nil }
func (e *recoveryEngine) EnsureSSHDaemon(context.Context, core.ID) error              { return nil }
func (e *recoveryEngine) Health(context.Context) driver.Probe                         { return driver.Probe{OK: true} }
func (e *recoveryEngine) ImagePresent(context.Context, string) bool                   { return true }
func (e *recoveryEngine) RunProbe(context.Context, string) (string, error)            { return "", nil }
func (e *recoveryEngine) PolicyHostPath(context.Context, string) (string, error)      { return "", nil }
func (e *recoveryEngine) ContainerIP(context.Context, string, string) (string, error) { return "", nil }

func TestReconcileRuntimeStateMarksMissingAndSweepsOnlyDriverOrphans(t *testing.T) {
	st, err := store.Open(t.TempDir(), "recovery")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "missing", ID: "sb-missing", ComputeDriver: "docker", RuntimeID: "runtime-missing", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	engine := &recoveryEngine{rows: []driver.Info{{ID: "runtime-orphan", Name: "orphan"}}}
	registry := &computeRegistry{configured: map[string]map[string]any{"docker": {}}, engines: map[string]driver.Engine{"docker": engine}}
	reconcileRuntimeState(context.Background(), st, registry, slog.New(slog.NewTextHandler(io.Discard, nil)))
	missing, ok := st.GetSandbox("missing")
	if !ok || missing.Status != "error" || missing.RuntimeID != "" {
		t.Fatalf("missing runtime record=%+v ok=%v", missing, ok)
	}
	if len(engine.deleted) != 1 || engine.deleted[0] != "runtime-orphan" {
		t.Fatalf("deleted runtimes=%v; want only labeled orphan", engine.deleted)
	}
}
