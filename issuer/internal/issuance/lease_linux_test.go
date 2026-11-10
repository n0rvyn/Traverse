package issuance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func brokerFixture(t *testing.T, reply []byte) (string, <-chan map[string]any, <-chan bool) {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "broker.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	requests := make(chan map[string]any, 1)
	closed := make(chan bool, 1)
	t.Cleanup(func() { listener.Close() })
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			closed <- false
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(4 * time.Second))
		var size [4]byte
		if _, err = io.ReadFull(connection, size[:]); err != nil {
			closed <- false
			return
		}
		n := binary.BigEndian.Uint32(size[:])
		if n > 1024 {
			closed <- false
			return
		}
		data := make([]byte, n)
		if _, err = io.ReadFull(connection, data); err != nil {
			closed <- false
			return
		}
		var request map[string]any
		if json.Unmarshal(data, &request) != nil {
			closed <- false
			return
		}
		requests <- request
		binary.BigEndian.PutUint32(size[:], uint32(len(reply)))
		if _, err = connection.Write(append(size[:], reply...)); err != nil {
			closed <- false
			return
		}
		var byte [1]byte
		_, err = connection.Read(byte[:])
		closed <- err == io.EOF
	}()
	return path, requests, closed
}

func TestLeaseUsesCanonicalDigestAndCancellationRevokes(t *testing.T) {
	path, requests, closed := brokerFixture(t, []byte(`{"ready":true}`))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	expires := time.Now().Add(time.Minute).Truncate(time.Second)
	lease, err := presentChallenge(ctx, path, "example.test", "synthetic-key-authorization", expires)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	select {
	case request := <-requests:
		digest := sha256.Sum256([]byte("synthetic-key-authorization"))
		if len(request) != 4 || request["version"] != float64(1) || request["domain"] != "example.test" || request["sha256"] != base64.RawURLEncoding.EncodeToString(digest[:]) || request["expires"] != float64(expires.Unix()) {
			t.Fatal("Lease wire contract differs from native")
		}
	case <-time.After(time.Second):
		t.Fatal("No actual framed request")
	}
	select {
	case <-closed:
		t.Fatal("Lease ended before cancellation")
	default:
	}
	cancel()
	select {
	case eof := <-closed:
		if !eof {
			t.Fatal("Lease did not close cleanly")
		}
	case <-time.After(time.Second):
		t.Fatal("Cancellation retained native proof")
	}
}

func TestLeaseRejectsNegativeOrMalformedAcknowledgment(t *testing.T) {
	for _, reply := range []string{`{"ready":false}`, `{"ready":true,"extra":1}`, `{"ready":null}`, `not-json`} {
		t.Run(reply, func(t *testing.T) {
			path, _, _ := brokerFixture(t, []byte(reply))
			if lease, err := presentChallenge(context.Background(), path, "example.test", "synthetic", time.Now().Add(time.Minute)); err == nil {
				lease.Close()
				t.Fatal("Invalid broker response accepted")
			}
		})
	}
}

func TestLeaseRejectsUnsafeSocketAndExpiredAuthorization(t *testing.T) {
	path, _, _ := brokerFixture(t, []byte(`{"ready":true}`))
	if lease, err := presentChallenge(context.Background(), path, "example.test", "synthetic", time.Now().Add(-time.Second)); err == nil {
		lease.Close()
		t.Fatal("Expired authorization accepted")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if lease, err := presentChallenge(context.Background(), path, "example.test", "synthetic", time.Now().Add(time.Minute)); err == nil {
		lease.Close()
		t.Fatal("Unsafe socket accepted")
	}
}
