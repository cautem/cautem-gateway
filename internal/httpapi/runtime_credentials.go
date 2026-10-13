package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/slogx"
)

const (
	runtimeCredentialRefreshInterval = 24 * time.Hour
	runtimeCredentialRefreshTimeout  = 3 * time.Minute
)

func runRuntimeCredentialRefresh(ctx context.Context, st *store.Store, registry *computeRegistry, log *slog.Logger) {
	ticker := time.NewTicker(runtimeCredentialRefreshInterval)
	defer ticker.Stop()
	if err := refreshRuntimeCredentials(ctx, st, registry, log); err != nil && ctx.Err() == nil {
		log.Warn("runtime credential refresh pass failed", slog.String("op", "gateway.runtime.credentials"), slogx.Err(err))
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := refreshRuntimeCredentials(ctx, st, registry, log); err != nil && ctx.Err() == nil {
				log.Warn("runtime credential refresh pass failed", slog.String("op", "gateway.runtime.credentials"), slogx.Err(err))
			}
		}
	}
}

func refreshRuntimeCredentials(ctx context.Context, st *store.Store, registry *computeRegistry, log *slog.Logger) error {
	if st == nil || registry == nil {
		return nil
	}
	var failures []error
	for _, sandbox := range st.ListSandboxes() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if sandbox.RuntimeID == "" || !strings.EqualFold(strings.TrimSpace(sandbox.Status), "running") || !isKubernetesComputeDriver(sandbox.ComputeDriver) {
			continue
		}
		engine, err := registry.engine(sandbox.ComputeDriver)
		if err != nil {
			failures = append(failures, err)
			log.Warn("runtime credential refresh skipped", slog.String("op", "gateway.runtime.credentials"), slog.String("driver", sandbox.ComputeDriver), slog.String("sandbox", sandbox.Name), slogx.Err(err))
			continue
		}
		refresher, ok := engine.(driver.SandboxRuntimeCredentialRefresher)
		if !ok {
			continue
		}
		refreshCtx, cancel := context.WithTimeout(ctx, runtimeCredentialRefreshTimeout)
		err = refresher.RefreshSandboxRuntimeCredentials(refreshCtx, core.ID(sandbox.RuntimeID))
		cancel()
		if err != nil {
			failures = append(failures, fmt.Errorf("refresh credentials for sandbox %q: %w", sandbox.Name, err))
			log.Warn("runtime credential refresh failed", slog.String("op", "gateway.runtime.credentials"), slog.String("driver", sandbox.ComputeDriver), slog.String("sandbox", sandbox.Name), slogx.Err(err))
		}
	}
	return errors.Join(failures...)
}
