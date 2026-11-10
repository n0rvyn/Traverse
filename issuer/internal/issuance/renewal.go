package issuance

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-acme/lego/v5/acme/api"
)

// Public leaf metadata only. No key, account, order or raw CA error is exported.
type RenewalMetadata struct {
	Material         string `json:"material"`
	Fingerprint      string `json:"fingerprint,omitempty"`
	ValidFrom        int64  `json:"validFrom,omitempty"`
	ValidUntil       int64  `json:"validUntil,omitempty"`
	ARI              string `json:"ari"`
	WindowStart      int64  `json:"windowStart,omitempty"`
	WindowEnd        int64  `json:"windowEnd,omitempty"`
	RetryAfterStatus string `json:"retryAfterStatus"`
	RetryAt          int64  `json:"retryAt,omitempty"`
}

// Unlike OpenStore this path cannot create state/locks, fsync it or retire
// interrupted writes. Atomic bundle replacement is observed through one fd.
func readOnlyStore(path, directory string) (_ *Store, failure error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || validateHTTPS(directory) != nil {
		return nil, errors.New("Invalid managed state identity")
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			(info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return nil, errors.New("Unsafe state ancestor")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	identity, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.IsDir() || before.Mode().Perm() != 0700 || identity.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("Unsafe managed state directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errors.New("Cannot inspect managed state")
	}
	store := &Store{root: root, directory: directory}
	defer func() {
		if failure != nil {
			store.Close()
		}
	}()
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("Managed state changed")
	}
	data, err := store.read("directory.json")
	if err != nil {
		return nil, errors.New("Managed CA identity unavailable")
	}
	var saved struct {
		Directory string `json:"directory"`
	}
	if json.Unmarshal(data, &saved) != nil || saved.Directory != directory {
		return nil, errors.New("Managed CA identity mismatch")
	}
	return store, nil
}

func renewalInfo(ctx context.Context, request Request, now time.Time) Result {
	metadata := &RenewalMetadata{Material: "absent", ARI: "not_applicable", RetryAfterStatus: "absent"}
	result := Result{Version: 1, Status: "renewal-info", Renewal: metadata}
	store, err := readOnlyStore(request.StateDirectory, request.Directory)
	if errors.Is(err, fs.ErrNotExist) {
		return result
	}
	if err != nil {
		return failed("storage_unavailable")
	}
	defer store.Close()
	bundle, err := store.read("bundle.pem")
	if errors.Is(err, fs.ErrNotExist) {
		return result
	}
	if err != nil {
		return failed("managed_material_invalid")
	}
	certificates, err := readCertificates(bundle)
	if err != nil {
		return failed("managed_material_invalid")
	}
	pair, err := tls.X509KeyPair(bundle, bundle)
	if err != nil || len(pair.Certificate) != len(certificates) {
		return failed("managed_material_invalid")
	}
	leaf := certificates[0]
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != request.Domain ||
		len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 || !leaf.NotBefore.Before(leaf.NotAfter) {
		return failed("managed_material_invalid")
	}
	roots, err := readRoots(request.CertificateTrustFile)
	if err != nil {
		return failed("certificate_trust_unavailable")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	// Verify expired/future material at its validity boundary to retain honest
	// metadata without querying ARI for a leaf that cannot currently be served.
	verifyAt := now
	if now.Before(leaf.NotBefore) {
		verifyAt = leaf.NotBefore
	}
	if !now.Before(leaf.NotAfter) {
		verifyAt = leaf.NotAfter.Add(-time.Nanosecond)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: request.Domain, Roots: roots,
		Intermediates: intermediates, CurrentTime: verifyAt}); err != nil {
		return failed("managed_material_untrusted")
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	metadata.Fingerprint = hex.EncodeToString(fingerprint[:])
	metadata.ValidFrom, metadata.ValidUntil = leaf.NotBefore.Unix(), leaf.NotAfter.Unix()
	metadata.Material = "current"
	if now.Before(leaf.NotBefore) {
		metadata.Material = "not_yet_valid"
		return result
	}
	if !now.Before(leaf.NotAfter) {
		metadata.Material = "expired"
		return result
	}
	core, observer, close, err := newCore(ctx, request, "", nil)
	defer close()
	if ctx.Err() != nil {
		return failed("cancelled")
	}
	if err != nil {
		metadata.ARI = "unavailable"
		return result
	}
	terms := core.GetDirectory().Meta.TermsOfService
	if validateTermsURI(terms) != nil {
		return failed("invalid_ca_terms")
	}
	result.TermsURL = terms
	endpoint := core.GetDirectory().RenewalInfo
	if endpoint == "" {
		metadata.ARI = "unsupported"
		return result
	}
	endpointURL, err := url.Parse(endpoint)
	if err != nil || validateHTTPS(endpoint) != nil || endpointURL.RawQuery != "" {
		metadata.ARI = "invalid"
		return result
	}
	if len(leaf.AuthorityKeyId) == 0 {
		metadata.ARI = "invalid_certificate_id"
		return result
	}
	id, err := api.MakeARICertID(leaf)
	if err != nil {
		metadata.ARI = "invalid_certificate_id"
		return result
	}
	info, err := core.Certificates.GetRenewalInfo(ctx, id)
	if ctx.Err() != nil {
		return failed("cancelled")
	}
	retry := observer.renewalRetry(endpoint + "/" + id)
	metadata.RetryAfterStatus = retry.status
	if retry.status == "valid" {
		metadata.RetryAt = retry.at.Unix()
	}
	if err != nil {
		metadata.ARI = "unavailable"
		if errors.Is(err, api.ErrNoARI) {
			metadata.ARI = "invalid"
		}
		return result
	}
	if info.SuggestedWindow.Start.IsZero() || info.SuggestedWindow.End.IsZero() ||
		!info.SuggestedWindow.Start.Before(info.SuggestedWindow.End) ||
		(info.ExplanationURL != "" && !validExplanation(info.ExplanationURL)) {
		metadata.ARI = "invalid"
		return result
	}
	metadata.ARI = "valid"
	metadata.WindowStart, metadata.WindowEnd = info.SuggestedWindow.Start.Unix(), info.SuggestedWindow.End.Unix()
	return result
}

func validExplanation(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.Opaque == ""
}
