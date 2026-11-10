package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestOwnerInvocationIsExplicitAndStrict(t *testing.T) {
	for _, arguments := range [][]string{nil, {"--supervisor-pid", strconv.Itoa(os.Getppid())}} {
		if _, err := ownerArgument(arguments); err != nil {
			t.Fatal(err)
		}
	}
	for _, arguments := range [][]string{{"--unknown", "1"}, {"--supervisor-pid"}, {"--supervisor-pid", "0"}, {"--supervisor-pid", "1"}, {"--supervisor-pid", "-1"}, {"--supervisor-pid", "+2"}, {"--supervisor-pid", "2147483648"}, {"--supervisor-pid", "2", "--supervisor-pid", "3"}} {
		if _, err := ownerArgument(arguments); err == nil {
			t.Fatal("Invalid invocation accepted")
		}
	}
	if err := guardOwner(os.Getppid() + 1); err == nil {
		t.Fatal("Different owner admitted")
	}
}

func TestIssuerChild(t *testing.T) {
	if os.Getenv("TRAVERSE_ISSUER_TEST_CHILD") != "1" {
		return
	}
	os.Exit(runReady(func() { ready := os.NewFile(3, "owned-ready"); ready.Write([]byte{'r'}); ready.Close() }))
}

func TestCLIStdinCancellationAndSafeSchema(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid-request", true: "stdin-cancellation"}[interrupt], func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			command := exec.Command(os.Args[0], "-test.run=^TestIssuerChild$")
			command.Env = append(os.Environ(), "TRAVERSE_ISSUER_TEST_CHILD=1")
			command.ExtraFiles = []*os.File{writer}
			stdin, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			var output, errors bytes.Buffer
			command.Stdout = &output
			command.Stderr = &errors
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			finished := false
			defer func() {
				if !finished {
					command.Process.Kill()
					<-done
				}
			}()
			ready := make(chan bool, 1)
			go func() { var byte [1]byte; _, e := io.ReadFull(reader, byte[:]); ready <- e == nil && byte[0] == 'r' }()
			select {
			case ok := <-ready:
				if !ok {
					t.Fatal("Child readiness absent")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Owned child did not initialize")
			}
			if interrupt {
				if err = command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			} else {
				stdin.Write([]byte(`{"private-marker":"never-export"}`))
				stdin.Close()
			}
			select {
			case err = <-done:
				finished = true
				if err == nil {
					t.Fatal("Failure exited successfully")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Owned helper retained stdin after cancellation")
			}
			var result map[string]any
			if json.Unmarshal(output.Bytes(), &result) != nil || result["status"] != "failed" {
				t.Fatal("Output not fixed JSON", output.String())
			}
			if bytes.Contains(output.Bytes(), []byte("marker")) || errors.Len() != 0 {
				t.Fatal("Private input or internal logging escaped")
			}
			if interrupt && result["code"] != "cancelled" {
				t.Fatal("Cancellation was not reported", output.String())
			}
		})
	}
}
