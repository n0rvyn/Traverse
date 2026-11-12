package issuance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testDirectory = "https://ca.example.test/directory"

func TestRestartRetiresOnlyOwnedInterruptedTemporary(t *testing.T) {
	path := statePath(t)
	s := openTestStore(t, path)
	key, err := s.AccountKey()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	temporary := filepath.Join(path, ".pending-0123456789abcdef0123456789abcdef")
	other := filepath.Join(path, ".pending-user-note")
	if err = os.WriteFile(temporary, []byte("interrupted private write"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(other, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path)
	if _, err = os.Lstat(temporary); !os.IsNotExist(err) {
		t.Fatal("Interrupted temporary retained")
	}
	if data, e := os.ReadFile(other); e != nil || string(data) != "preserve" {
		t.Fatal("Other state changed")
	}
	recovered, err := s.AccountKey()
	if err != nil || recovered.D.Cmp(key.D) != 0 {
		t.Fatal("Account identity changed")
	}
	s.Close()
	if err = os.Symlink(other, temporary); err != nil {
		t.Fatal(err)
	}
	if unsafe, e := OpenStore(path, testDirectory); e == nil {
		unsafe.Close()
		t.Fatal("Unsafe interrupted link accepted")
	}
	if data, e := os.ReadFile(other); e != nil || string(data) != "preserve" {
		t.Fatal("Link target changed")
	}
}

func statePath(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(p, "state")
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := OpenStore(path, testDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func testMaterial(t *testing.T, domain string, serial int64) ([]byte, []byte, *x509.CertPool) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Private fixture CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{domain}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), roots
}

func TestExclusiveLockAndDurableAccountRecovery(t *testing.T) {
	path := statePath(t)
	s := openTestStore(t, path)
	key, err := s.AccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if other, err := OpenStore(path, testDirectory); err == nil {
		other.Close()
		t.Fatal("Concurrent operation accepted")
	}
	info, err := os.Stat(filepath.Join(path, "account-key.pem"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("Account key is not private")
	}
	s.Close()
	s = openTestStore(t, path)
	restored, err := s.AccountKey()
	if err != nil || restored.D.Cmp(key.D) != 0 {
		t.Fatal("Account key changed after restart")
	}
	s.Close()
	if other, err := OpenStore(path, "https://another-ca.example/dir"); err == nil {
		other.Close()
		t.Fatal("Cross-CA state reuse accepted")
	}
}

func TestUnsafeStateNeverFollowsLinksOrChangesPermissions(t *testing.T) {
	for _, kind := range []string{"directory-link", "directory-mode", "lock-link", "lock-mode", "key-link"} {
		t.Run(kind, func(t *testing.T) {
			path := statePath(t)
			marker := filepath.Join(filepath.Dir(path), "marker")
			os.WriteFile(marker, []byte("preserve-private-marker"), 0600)
			if kind == "directory-link" {
				os.Symlink(filepath.Dir(path), path)
			} else {
				os.Mkdir(path, 0700)
			}
			switch kind {
			case "directory-mode":
				os.Chmod(path, 0755)
			case "lock-link":
				os.Symlink(marker, filepath.Join(path, "issuer.lock"))
			case "lock-mode":
				lock := filepath.Join(path, "issuer.lock")
				if err := os.WriteFile(lock, nil, 0600); err != nil {
					t.Fatal(err)
				}
				// Set the deliberately unsafe mode explicitly; a private caller
				// umask must not silently turn this into the positive0600 case.
				if err := os.Chmod(lock, 0644); err != nil {
					t.Fatal(err)
				}
			case "key-link":
				os.Symlink(marker, filepath.Join(path, "account-key.pem"))
			}
			s, err := OpenStore(path, testDirectory)
			if kind == "key-link" && err == nil {
				_, err = s.AccountKey()
			}
			if s != nil {
				s.Close()
			}
			if err == nil {
				t.Fatal("Unsafe state accepted")
			}
			if bytes.Contains([]byte(err.Error()), []byte("preserve-private-marker")) {
				t.Fatal("Private bytes in error")
			}
			data, e := os.ReadFile(marker)
			if e != nil || string(data) != "preserve-private-marker" {
				t.Fatal("Existing marker changed")
			}
		})
	}
}

func TestUncertainAccountKeyIsConfirmedBeforeUse(t *testing.T) {
	s := openTestStore(t, statePath(t))
	s.fault = func(stage string) error {
		if stage == "account-key.pem:directory-sync" {
			return errors.New("injected")
		}
		return nil
	}
	if _, err := s.AccountKey(); err == nil {
		t.Fatal("Uncertain key allowed for registration")
	}
	saved, err := s.read("account-key.pem")
	if err != nil {
		t.Fatal("Committed account key lost")
	}
	s.fault = func(stage string) error {
		if stage == "account-key.pem:confirm-sync" {
			return errors.New("injected")
		}
		return nil
	}
	if _, err := s.AccountKey(); err == nil {
		t.Fatal("Durability confirmation failure ignored")
	}
	s.fault = nil
	if _, err := s.AccountKey(); err != nil {
		t.Fatal(err)
	}
	after, err := s.read("account-key.pem")
	if err != nil || !bytes.Equal(saved, after) {
		t.Fatal("Recovery generated a different account key")
	}
}

func TestPublicationCommitAndDurabilityAreDistinct(t *testing.T) {
	for _, stage := range []string{"before-rename", "after-rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			path := statePath(t)
			s := openTestStore(t, path)
			cert, key, roots := testMaterial(t, "example.test", 2)
			first, err := s.Publish(cert, key, "example.test", roots, time.Now())
			if err != nil || !first.Committed || !first.Durable {
				t.Fatal(first, err)
			}
			old, err := os.ReadFile(filepath.Join(path, "bundle.pem"))
			if err != nil {
				t.Fatal(err)
			}
			next, nextKey, nextRoots := testMaterial(t, "example.test", 3)
			s.fault = func(point string) error {
				if point == "bundle.pem:"+stage {
					return errors.New("injected")
				}
				return nil
			}
			result, err := s.Publish(next, nextKey, "example.test", nextRoots, time.Now())
			if err == nil || result.Durable {
				t.Fatal("Injected failure hidden", result)
			}
			actual, e := os.ReadFile(filepath.Join(path, "bundle.pem"))
			if e != nil {
				t.Fatal(e)
			}
			if stage == "before-rename" {
				if result.Committed || !bytes.Equal(actual, old) {
					t.Fatal("Precommit failure changed published material")
				}
			} else if !result.Committed || bytes.Equal(actual, old) {
				t.Fatal("Postcommit result contradicts readback")
			}
			previous, e := os.ReadFile(filepath.Join(path, "previous-bundle.pem"))
			if e != nil || !bytes.Equal(previous, old) {
				t.Fatal("Prior valid material was lost")
			}
			entries, e := os.ReadDir(path)
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				if len(entry.Name()) >= 9 && entry.Name()[:9] == ".pending-" {
					t.Fatal("Owned temporary leaked")
				}
			}
			s.Close()
			s = openTestStore(t, path)
			recovered, e := s.read("bundle.pem")
			if e != nil || !bytes.Equal(actual, recovered) {
				t.Fatal("Restart disagrees with committed readback")
			}
		})
	}
}

func TestInvalidCertificateNeverReplacesValidBundle(t *testing.T) {
	path := statePath(t)
	s := openTestStore(t, path)
	cert, key, roots := testMaterial(t, "example.test", 2)
	if _, err := s.Publish(cert, key, "example.test", roots, time.Now()); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(filepath.Join(path, "bundle.pem"))
	other, otherKey, _ := testMaterial(t, "other.test", 3)
	for _, input := range []struct {
		cert, key []byte
		domain    string
		roots     *x509.CertPool
		now       time.Time
	}{
		{cert, otherKey, "example.test", roots, time.Now()},
		{other, key, "example.test", roots, time.Now()},
		{cert, key, "wrong.test", roots, time.Now()},
		{cert, key, "example.test", x509.NewCertPool(), time.Now()},
		{cert, key, "example.test", roots, time.Now().Add(2 * time.Hour)},
	} {
		result, err := s.Publish(input.cert, input.key, input.domain, input.roots, input.now)
		if err == nil || result.Committed {
			t.Fatal("Invalid material published")
		}
		actual, _ := os.ReadFile(filepath.Join(path, "bundle.pem"))
		if !bytes.Equal(actual, old) {
			t.Fatal("Valid material replaced")
		}
	}
	if err := os.Remove(filepath.Join(path, "bundle.pem")); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(path, "marker.pem")
	if err := os.WriteFile(marker, old, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("marker.pem", filepath.Join(path, "bundle.pem")); err != nil {
		t.Fatal(err)
	}
	if result, err := s.Publish(cert, key, "example.test", roots, time.Now()); err == nil || result.Committed {
		t.Fatal("Symlink publication accepted")
	}
	actual, _ := os.ReadFile(marker)
	if !bytes.Equal(actual, old) {
		t.Fatal("Symlink target changed")
	}
}
