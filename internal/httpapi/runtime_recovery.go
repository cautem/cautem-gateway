package httpapi

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/cautem/quarshell-driver/driver"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"github.com/cautem/quarshell-slogx"
)

// reconcileRuntimeState repairs the durable gateway view after a gateway or
// backend restart. It only acts after a successful backend List call, so a
// temporary daemon outage cannot turn a healthy registry into false orphans.
func reconcileRuntimeState(ctx context.Context, st *store.Store, registry *computeRegistry, log *slog.Logger) {
	if st == nil || registry == nil {
		return
	}
	reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	registry.mu.Lock()
	names := make([]string, 0, len(registry.configured))
	for name := range registry.configured {
		names = append(names, name)
	}
	registry.mu.Unlock()
	for _, name := range names {
		backend, err := registry.backend(name)
		if err != nil {
			log.Warn("runtime reconciliation skipped", slog.String("op", "gateway.runtime.reconcile"), slog.String("driver", name), slogx.Err(err))
			continue
		}
		rows, err := backend.List(reconcileCtx)
		if err != nil {
			log.Warn("runtime reconciliation skipped while backend is unavailable", slog.String("op", "gateway.runtime.reconcile"), slog.String("driver", name), slogx.Err(err))
			continue
		}
		seen := make(map[string]driver.Info, len(rows))
		for _, row := range rows {
			if strings.TrimSpace(row.Name) != "" {
				seen[row.Name] = row
			}
			if _, ok := st.GetSandbox(row.Name); ok {
				continue
			}
			// Only delete objects returned by the driver's own sandbox label
			// filter. This is the narrow orphan target; unrelated containers are
			// never enumerated or touched here.
			deleted, cleanupErr := cleanupSandboxRuntime(reconcileCtx, backend, row.ID, true)
			if !deleted {
				log.Warn("orphan runtime cleanup failed; it will be retried", slog.String("op", "gateway.runtime.orphan_sweep"), slog.String("driver", name), slog.String("sandbox", row.Name), slog.String("runtime_id", string(row.ID)), slogx.Err(cleanupErr))
				continue
			}
			if cleanupErr != nil {
				log.Warn("orphan runtime was deleted after a stop error", slog.String("op", "gateway.runtime.orphan_sweep"), slog.String("driver", name), slog.String("sandbox", row.Name), slog.String("runtime_id", string(row.ID)), slogx.Err(cleanupErr))
				continue
			}
			log.Info("removed orphan runtime", slog.String("op", "gateway.runtime.orphan_sweep"), slog.String("driver", name), slog.String("sandbox", row.Name), slog.String("runtime_id", string(row.ID)))
		}
		for _, sandbox := range st.ListSandboxes() {
			if !strings.EqualFold(strings.TrimSpace(sandbox.ComputeDriver), name) || sandbox.RuntimeID == "" {
				continue
			}
			if _, ok := seen[sandbox.Name]; ok {
				continue
			}
			sandbox.Status = "error"
			sandbox.RuntimeID = ""
			sandbox.UpdatedAt = time.Now().UTC()
			if err := st.UpsertSandbox(sandbox); err != nil {
				log.Warn("could not persist missing runtime", slog.String("op", "gateway.runtime.reconcile"), slog.String("sandbox", sandbox.Name), slogx.Err(err))
			} else {
				log.Warn("marked sandbox runtime missing", slog.String("op", "gateway.runtime.reconcile"), slog.String("sandbox", sandbox.Name), slog.String("driver", name))
			}
		}
	}
}
