package httpapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/storage/store"
)

const sandboxCleanupTimeout = 30 * time.Second

type sandboxStopDeleter interface {
	Stop(context.Context, core.ID) error
	Delete(context.Context, core.ID) error
}

// cleanupSandboxRuntime keeps cleanup running after the request is canceled.
// The bool reports whether Delete succeeded; a Stop failure alone does not
// mean the runtime still exists if Delete completed successfully.
func cleanupSandboxRuntime(ctx context.Context, backend sandboxStopDeleter, id core.ID, stop bool) (bool, error) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sandboxCleanupTimeout)
	defer cancel()

	var stopErr error
	if stop {
		stopErr = backend.Stop(cleanupCtx, id)
	}
	deleteErr := backend.Delete(cleanupCtx, id)
	return deleteErr == nil, errors.Join(stopErr, deleteErr)
}

func (s *compatRPCAdapter) rollbackSandboxCreate(ctx context.Context, backend driver.Backend, record store.Sandbox, handle driver.Handle) error {
	backendDeleted := true
	var cleanupErr error
	if handle.ID != "" {
		backendDeleted, cleanupErr = cleanupSandboxRuntime(ctx, backend, handle.ID, true)
	}

	record.RuntimeID = string(handle.ID)
	record.Network = handle.Network
	record.Status = "error"
	record.UpdatedAt = time.Now().UTC()
	if !backendDeleted {
		return errors.Join(cleanupErr, s.runtime.st.UpsertSandbox(record))
	}

	if err := os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", record.Name)); err != nil {
		record.RuntimeID = ""
		return errors.Join(cleanupErr, fmt.Errorf("remove sandbox runtime state: %w", err), s.runtime.st.UpsertSandbox(record))
	}
	if err := s.runtime.st.DeleteSandbox(record.Name); err != nil {
		record.RuntimeID = ""
		return errors.Join(cleanupErr, fmt.Errorf("remove sandbox registry record: %w", err), s.runtime.st.UpsertSandbox(record))
	}
	return cleanupErr
}

func withSandboxCleanupError(cause, cleanupErr error) error {
	if cleanupErr == nil {
		return cause
	}
	return fmt.Errorf("%w; rollback cleanup failed: %v", cause, cleanupErr)
}
