//go:build !linux

package main

import (
	"errors"
	"os"
)

// Non-Linux builds exist only for protocol/storage tests. Linux is the host.
func guardOwner(expected int) error {
	if expected != 0 && os.Getppid() != expected {
		return errors.New("Owner unavailable")
	}
	return nil
}
