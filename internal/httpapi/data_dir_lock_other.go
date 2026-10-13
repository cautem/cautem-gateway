//go:build !windows && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package httpapi

import (
	"fmt"
	"os"
)

func lockGatewayDataFile(_ *os.File) error {
	return fmt.Errorf("gateway data directory locking is unsupported on this platform")
}

func unlockGatewayDataFile(_ *os.File) error { return nil }
