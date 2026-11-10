//go:build !linux

package main

// Non-Linux builds exist only for protocol/storage tests. Linux is the host.
func guardOwner() error { return nil }
