//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package httpapi

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockGatewayDataFile(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return errGatewayDataDirLocked
	}
	return err
}

func unlockGatewayDataFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
