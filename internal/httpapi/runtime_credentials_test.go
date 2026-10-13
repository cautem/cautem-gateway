package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/storage/store"
)

type runtimeCredentialRefreshTestEngine struct {
	driver.Engine
	calls []core.ID
	err   error
}

func (engine *runtimeCredentialRefreshTestEngine) RefreshSandboxRuntimeCredentials(_ context.Context, id core.ID) error {
	engine.calls = append(engine.calls, id)
	return engine.err
}

func TestRefreshRuntimeCredentialsOnlyVisitsRunningSandboxes(t *testing.T) {
	st, err := store.Open(t.TempDir(), "runtime-credential-refresh")
	if err != nil {
		t.Fatal(err)
	}
	for _, sandbox := range []store.Sandbox{
		{Name: "running", RuntimeID: "k8s:team/demo/uid-1", ComputeDriver: "kubernetes", Status: "running"},
		{Name: "stopped", RuntimeID: "k8s:team/paused/uid-2", ComputeDriver: "kubernetes", Status: "stopped"},
		{Name: "missing", ComputeDriver: "kubernetes", Status: "running"},
		{Name: "docker", RuntimeID: "docker-id", ComputeDriver: "docker", Status: "running"},
	} {
		if err := st.UpsertSandbox(sandbox); err != nil {
			t.Fatal(err)
		}
	}
	engine := &runtimeCredentialRefreshTestEngine{}
	registry := &computeRegistry{engines: map[string]driver.Engine{"kubernetes": engine}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := refreshRuntimeCredentials(context.Background(), st, registry, log); err != nil {
		t.Fatal(err)
	}
	if len(engine.calls) != 1 || engine.calls[0] != core.ID("k8s:team/demo/uid-1") {
		t.Fatalf("credential refresh calls = %v; want only the running sandbox", engine.calls)
	}
}

func TestRefreshRuntimeCredentialsContinuesAfterBackendFailure(t *testing.T) {
	st, err := store.Open(t.TempDir(), "runtime-credential-refresh-errors")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		if err := st.UpsertSandbox(store.Sandbox{
			Name: name, RuntimeID: "k8s:team/" + name + "/uid", ComputeDriver: "kubernetes", Status: "running",
		}); err != nil {
			t.Fatal(err)
		}
	}
	engine := &runtimeCredentialRefreshTestEngine{err: errors.New("API unavailable")}
	registry := &computeRegistry{engines: map[string]driver.Engine{"kubernetes": engine}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := refreshRuntimeCredentials(context.Background(), st, registry, log); err == nil {
		t.Fatal("refreshRuntimeCredentials() error = nil; want backend failures")
	}
	if len(engine.calls) != 2 {
		t.Fatalf("credential refresh calls = %v; want both sandboxes attempted", engine.calls)
	}
}
