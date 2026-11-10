package main

import "syscall"

func stdinReady() (bool, error) {
	var read syscall.FdSet
	read.Bits[0] = 1
	timeout := syscall.Timeval{Usec: 100000}
	n, err := syscall.Select(1, &read, nil, nil, &timeout)
	return n > 0, err
}
