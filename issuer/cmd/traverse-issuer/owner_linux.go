package main

import (
	"errors"
	"os"
	"syscall"
)

func guardOwner(expected int) error {
	parent := os.Getppid()
	if parent <= 1 || (expected != 0 && expected != parent) {
		return errors.New("Owner unavailable")
	}
	_, _, err := syscall.RawSyscall6(syscall.SYS_PRCTL, 1, uintptr(syscall.SIGTERM), 0, 0, 0, 0)
	if err != 0 || os.Getppid() != parent {
		return errors.New("Owner unavailable")
	}
	return nil
}
