package main

import (
	"context"
	"io"
	"syscall"
)

// Inherited blocking stdin is not registered with Go's runtime poller. Closing
// it cannot interrupt a pending read. Wait before each read instead; no reader
// goroutine, changed descriptor flags or background operation survives Stop.
type contextInput struct{ ctx context.Context }

func (r contextInput) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	for {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		ready, err := stdinReady()
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if !ready {
			continue
		}
		n, err := syscall.Read(0, buffer)
		if err == syscall.EINTR {
			continue
		}
		if n == 0 && err == nil {
			return 0, io.EOF
		}
		return n, err
	}
}
