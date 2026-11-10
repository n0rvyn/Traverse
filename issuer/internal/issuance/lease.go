package issuance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type challengeLease struct {
	connection net.Conn
	stop       func() bool
}

func (l *challengeLease) Close() error { l.stop(); return l.connection.Close() }

func presentChallenge(ctx context.Context, path, domain, keyAuthorization string, expires time.Time) (io.Closer, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !expires.After(time.Now()) {
		return nil, authError("broker_lease_invalid")
	}
	for _, entry := range []struct {
		path   string
		socket bool
	}{{filepath.Dir(path), false}, {path, true}} {
		info, err := os.Lstat(entry.path)
		if err != nil {
			return nil, authError("broker_unavailable")
		}
		identity, ok := info.Sys().(*syscall.Stat_t)
		if !ok || identity.Uid != uint32(os.Geteuid()) {
			return nil, authError("broker_owner_invalid")
		}
		if entry.socket {
			if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
				return nil, authError("broker_socket_unsafe")
			}
		} else if !info.IsDir() || info.Mode().Perm() != 0700 {
			return nil, authError("broker_directory_unsafe")
		}
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, authError("broker_connect_failed")
	}
	lease := &challengeLease{connection: connection, stop: context.AfterFunc(ctx, func() { connection.Close() })}
	failed := true
	defer func() {
		if failed {
			lease.Close()
		}
	}()
	if err = verifyBrokerPeer(connection); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(keyAuthorization))
	message, err := json.Marshal(struct {
		Version int    `json:"version"`
		Domain  string `json:"domain"`
		Digest  string `json:"sha256"`
		Expires int64  `json:"expires"`
	}{1, domain, base64.RawURLEncoding.EncodeToString(digest[:]), expires.Unix()})
	if err != nil {
		return nil, authError("broker_encoding_failed")
	}
	if err = connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, authError("broker_deadline_failed")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(message)))
	if _, err = io.Copy(connection, io.MultiReader(bytes.NewReader(size[:]), bytes.NewReader(message))); err != nil {
		return nil, authError("broker_send_failed")
	}
	if _, err = io.ReadFull(connection, size[:]); err != nil {
		return nil, authError("broker_ack_missing")
	}
	n := binary.BigEndian.Uint32(size[:])
	if n != uint32(len(`{"ready":true}`)) && n != uint32(len(`{"ready":false}`)) {
		return nil, authError("broker_ack_invalid")
	}
	reply := make([]byte, n)
	if _, err = io.ReadFull(connection, reply); err != nil {
		return nil, authError("broker_ack_incomplete")
	}
	if string(reply) != `{"ready":true}` {
		return nil, authError("broker_lease_rejected")
	}
	if err = connection.SetDeadline(time.Time{}); err != nil {
		return nil, authError("broker_retention_failed")
	}
	if ctx.Err() != nil {
		return nil, authError("broker_cancelled")
	}
	failed = false
	return lease, nil
}
