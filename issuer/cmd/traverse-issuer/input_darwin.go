package main

import "syscall"

func stdinReady() (bool, error) {
	var read syscall.FdSet
	read.Bits[0] = 1
	timeout := syscall.Timeval{Usec: 100000}
	err := syscall.Select(1, &read, nil, nil, &timeout)
	return read.Bits[0]&1 != 0, err
}
