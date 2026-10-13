package httpapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var errGatewayDataDirLocked = errors.New("gateway data directory is locked")

type gatewayDataDirLock struct {
	file *os.File
}

func acquireGatewayDataDirLock(dataDir string) (*gatewayDataDirLock, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("gateway data directory: %w", err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure gateway data directory: %w", err)
	}
	path := filepath.Join(dataDir, "gateway.lock")
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return nil, fmt.Errorf("gateway data directory lock is not a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect gateway data directory lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("gateway data directory lock: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("gateway data directory lock permissions: %w", err)
	}
	if err := lockGatewayDataFile(file); err != nil {
		_ = file.Close()
		if errors.Is(err, errGatewayDataDirLocked) {
			return nil, fmt.Errorf("gateway data directory %q is already in use by another gateway process", dataDir)
		}
		return nil, fmt.Errorf("lock gateway data directory %q: %w", dataDir, err)
	}
	return &gatewayDataDirLock{file: file}, nil
}

func (l *gatewayDataDirLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockGatewayDataFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
