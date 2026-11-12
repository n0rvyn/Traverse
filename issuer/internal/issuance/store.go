package issuance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Store owns one CA's account state and one managed endpoint's material.
// Callers retain the exclusive lock for the entire account/order operation.
type Store struct {
	root      *os.Root
	lock      *os.File
	directory string
	fault     func(string) error // Private failure-injection seam; never a request option.
}

type Publication struct {
	Committed bool `json:"committed"`
	Durable   bool `json:"durable"`
}

func secureInfo(info fs.FileInfo, mode fs.FileMode) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && info.Mode().IsRegular() && info.Mode().Perm() == mode
}

func validateHTTPS(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return errors.New("Invalid CA HTTPS address")
	}
	return nil
}

func OpenStore(path, directory string) (_ *Store, failure error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Absolute clean state path required")
	}
	if err := validateHTTPS(directory); err != nil {
		return nil, err
	}
	return openOwnedStore(path, directory)
}

// Policy-specific callers validate authority identity before this common owned
// filesystem boundary. Public OpenStore remains HTTPS-only.
func openOwnedStore(path, directory string) (_ *Store, failure error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Absolute clean state path required")
	}
	// Reject symlink ancestors. Root then pins the checked leaf across renames.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("Unsafe state ancestor")
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return nil, errors.New("Writable state ancestor")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, errors.New("Cannot create private state")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0700 {
		return nil, errors.New("State directory must be private")
	}
	identity, ok := before.Sys().(*syscall.Stat_t)
	if !ok || identity.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("State directory owner invalid")
	}
	parent, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("Cannot open state parent")
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return nil, errors.New("Cannot confirm state directory durability")
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, errors.New("Cannot open private state")
	}
	s := &Store{root: r, directory: directory}
	defer func() {
		if failure != nil {
			s.Close()
		}
	}()
	after, err := r.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("State directory changed")
	}
	s.lock, err = r.OpenFile("issuer.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("Cannot open issuer lock")
	}
	info, err := s.lock.Stat()
	if err != nil || !secureInfo(info, 0600) {
		return nil, errors.New("Issuer lock is unsafe")
	}
	if syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, errors.New("Certificate operation already active")
	}
	data, err := s.read("directory.json")
	if errors.Is(err, fs.ErrNotExist) {
		data, _ = json.Marshal(struct {
			Directory string `json:"directory"`
		}{directory})
		if _, err = s.atomic("directory.json", data); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	var saved struct {
		Directory string `json:"directory"`
	}
	if json.Unmarshal(data, &saved) != nil || saved.Directory != directory {
		return nil, errors.New("State belongs to another CA")
	}
	if err = s.clearInterruptedTemporaries(); err != nil {
		return nil, err
	}
	return s, nil
}

// Only after acquiring the exclusive lock and confirming CA ownership, retire
// our exact temporary names left by a killed writer. Never follow a link or
// remove other state, even if its name shares the prefix.
func (s *Store) clearInterruptedTemporaries() error {
	directory, err := s.root.Open(".")
	if err != nil {
		return errors.New("Cannot inspect interrupted writes")
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return errors.New("Cannot inspect interrupted writes")
	}
	changed := false
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".pending-") || len(name) != len(".pending-")+32 {
			continue
		}
		suffix := strings.TrimPrefix(name, ".pending-")
		if _, err = hex.DecodeString(suffix); err != nil || suffix != strings.ToLower(suffix) {
			continue
		}
		info, e := s.root.Lstat(name)
		if e != nil || !secureInfo(info, 0600) {
			return errors.New("Interrupted write is unsafe")
		}
		if e = s.root.Remove(name); e != nil {
			return errors.New("Cannot retire interrupted write")
		}
		changed = true
	}
	if changed && directory.Sync() != nil {
		return errors.New("Interrupted write cleanup durability uncertain")
	}
	return nil
}

func (s *Store) Close() {
	if s.lock != nil {
		s.lock.Close()
		s.lock = nil
	}
	if s.root != nil {
		s.root.Close()
		s.root = nil
	}
}

func (s *Store) read(name string) ([]byte, error) {
	before, err := s.root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, errors.New("Cannot inspect private state")
	}
	if !secureInfo(before, 0600) {
		return nil, errors.New("Unsafe private state file")
	}
	f, err := s.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("Cannot open private state file")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !secureInfo(after, 0600) || !os.SameFile(before, after) {
		return nil, errors.New("Private state changed")
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, errors.New("Cannot read private state")
	}
	return data, nil
}

func (s *Store) inject(stage string) error {
	if s.fault != nil {
		return s.fault(stage)
	}
	return nil
}

func (s *Store) atomic(name string, data []byte) (result Publication, failure error) {
	if _, err := s.read(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return result, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return result, errors.New("Cannot name private temporary")
	}
	temp := ".pending-" + hex.EncodeToString(random[:])
	f, err := s.root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return result, errors.New("Cannot create private temporary")
	}
	defer func() {
		f.Close()
		if !result.Committed {
			s.root.Remove(temp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return result, errors.New("Cannot write private material")
	}
	if err = f.Sync(); err != nil {
		return result, errors.New("Cannot sync private material")
	}
	if err = f.Close(); err != nil {
		return result, errors.New("Cannot close private material")
	}
	if err = s.inject(name + ":before-rename"); err != nil {
		return result, errors.New("Publication failed before commit")
	}
	if err = s.root.Rename(temp, name); err != nil {
		return result, errors.New("Cannot publish private material")
	}
	result.Committed = true
	if err = s.inject(name + ":after-rename"); err != nil {
		return result, errors.New("Published material durability uncertain")
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return result, errors.New("Published material durability uncertain")
	}
	defer dir.Close()
	if err = s.inject(name + ":directory-sync"); err == nil {
		err = dir.Sync()
	}
	if err != nil {
		return result, errors.New("Published material durability uncertain")
	}
	result.Durable = true
	return result, nil
}

func (s *Store) AccountKey() (*ecdsa.PrivateKey, error) {
	data, err := s.read("account-key.pem")
	if errors.Is(err, fs.ErrNotExist) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, errors.New("Cannot create account key")
		}
		der, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return nil, errors.New("Cannot encode account key")
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if _, e = s.atomic("account-key.pem", data); e != nil {
			return nil, e
		}
	} else if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("Invalid saved account key")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := value.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("Invalid saved account key")
	}
	// A previous attempt can have committed this key but failed to sync the
	// directory. Confirm persistence before allowing account registration.
	if err := s.confirmDirectory("account-key.pem"); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *Store) confirmDirectory(name string) error {
	directory, err := s.root.Open(".")
	if err != nil {
		return errors.New("Cannot confirm private state durability")
	}
	defer directory.Close()
	if err = s.inject(name + ":confirm-sync"); err == nil {
		err = directory.Sync()
	}
	if err != nil {
		return errors.New("Cannot confirm private state durability")
	}
	return nil
}

// Publish validates before touching either managed generation. Both native
// certificate/key arguments refer to bundle.pem, making replacement indivisible.
func (s *Store) Publish(certPEM, keyPEM []byte, domain string, roots *x509.CertPool, now time.Time) (Publication, error) {
	return s.publish(certPEM, keyPEM, domain, roots, now, func(leaf *x509.Certificate) bool {
		return len(leaf.DNSNames) == 1 && leaf.DNSNames[0] == domain && len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) == 0
	})
}

func (s *Store) publish(certPEM, keyPEM []byte, domain string, roots *x509.CertPool, now time.Time, matches func(*x509.Certificate) bool) (Publication, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Publication{}, errors.New("Certificate does not match private key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !matches(leaf) {
		return Publication{}, errors.New("Issued certificate identity mismatch")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return Publication{}, errors.New("Invalid issued chain")
		}
		intermediates.AddCert(c)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: domain, Roots: roots, Intermediates: intermediates, CurrentTime: now}); err != nil {
		return Publication{}, errors.New("Issued certificate is not trusted or current")
	}
	old, err := s.read("bundle.pem")
	if err == nil {
		if _, err = s.atomic("previous-bundle.pem", old); err != nil {
			return Publication{}, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Publication{}, err
	}
	bundle := append(append(append([]byte{}, certPEM...), '\n'), keyPEM...)
	return s.atomic("bundle.pem", bundle)
}
