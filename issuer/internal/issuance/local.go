package issuance

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"time"
)

const localAuthorityFile = "local-authority.pem"
const localAuthorityRecord = "local-authority.json"
const localPublicCAFile = "local-ca.pem"

// Approved defaults. The clock is injected only into private Go functions by
// tests; it is never supplied by the inherited-pipe protocol.
const localLeafLifetime = 90 * 24 * time.Hour
const localLeafRenewAfter = 60 * 24 * time.Hour

type LocalMetadata struct {
	Authority string                    `json:"authority"`
	Material  string                    `json:"material"`
	Root      *localCertificateMetadata `json:"root,omitempty"`
	Leaf      *localLeafMetadata        `json:"leaf,omitempty"`
}

type localCertificateMetadata struct {
	Fingerprint string `json:"fingerprint"`
	ValidFrom   int64  `json:"validFrom"`
	ValidUntil  int64  `json:"validUntil"`
}

type localLeafMetadata struct {
	localCertificateMetadata
	RenewAt int64 `json:"renewAt"`
}

type localAuthorityIdentity struct {
	Version         int    `json:"version"`
	Domain          string `json:"domain"`
	RootFingerprint string `json:"rootFingerprint"`
}

func localOperation(operation string) bool {
	return operation == "local-ensure" || operation == "local-info"
}

func canonicalLocalHost(host string) (string, error) {
	if address, err := netip.ParseAddr(host); err == nil && address.Zone() == "" {
		return address.Unmap().String(), nil
	}
	return canonicalDNS(host)
}

func localStoreIdentity(host string) string { return "local-hostname:v1:" + host }

func certificateFingerprint(certificate *x509.Certificate) string {
	value := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(value[:])
}

func serialNumber() (*big.Int, error) {
	maximum := new(big.Int).Lsh(big.NewInt(1), 159) // RFC5280 positive, at most20octets.
	for {
		value, err := rand.Int(rand.Reader, maximum)
		if err != nil || value.Sign() != 0 {
			return value, err
		}
	}
}

func localConstraints(host string) ([]string, []string, []*net.IPNet, []*net.IPNet) {
	if address, err := netip.ParseAddr(host); err == nil {
		ip := net.IP(address.AsSlice())
		bits := 128
		if ip.To4() != nil {
			ip, bits = ip.To4(), 32
		}
		// The same permitted and excluded DNS subtree makes their intersection
		// empty, without an invalid empty-name constraint. IPs have a separate
		// exact permitted range. This marker grants no DNS hostname authority.
		return []string{"traverse-denied.invalid"}, []string{"traverse-denied.invalid"}, []*net.IPNet{{IP: ip, Mask: net.CIDRMask(bits, bits)}}, nil
	}
	return []string{host}, []string{"." + host}, nil, []*net.IPNet{
		{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	}
}

func localIdentityMatches(leaf *x509.Certificate, host string) bool {
	if len(leaf.EmailAddresses)+len(leaf.URIs) != 0 {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 1 && leaf.IPAddresses[0].Equal(net.IP(address.AsSlice()))
	}
	return len(leaf.DNSNames) == 1 && leaf.DNSNames[0] == host && len(leaf.IPAddresses) == 0
}

func newLocalAuthority(host string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, nil, err
	}
	permittedDNS, excludedDNS, permittedIP, excludedIP := localConstraints(host)
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Traverse local CA"},
		NotBefore: now, NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: permittedDNS, ExcludedDNSDomains: excludedDNS,
		PermittedIPRanges: permittedIP, ExcludedIPRanges: excludedIP,
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	id := sha256.Sum256(public)
	template.SubjectKeyId, template.AuthorityKeyId = id[:], id[:]
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})...)
	return certificate, key, data, nil
}

func equalIPRanges(a, b []*net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].IP.Equal(b[i].IP) || !bytes.Equal(a[i].Mask, b[i].Mask) {
			return false
		}
	}
	return true
}

func parseLocalAuthority(data []byte, host string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certificateBlock, rest := pem.Decode(data)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(certificateBlock.Headers) != 0 {
		return nil, nil, errors.New("Invalid local authority")
	}
	keyBlock, rest := pem.Decode(rest)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(keyBlock.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("Invalid local authority")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, nil, errors.New("Invalid local authority")
	}
	value, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	key, ok := value.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, nil, errors.New("Invalid local authority key")
	}
	public, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	permittedDNS, excludedDNS, permittedIP, excludedIP := localConstraints(host)
	if !ok || !public.Equal(&key.PublicKey) || certificate.CheckSignatureFrom(certificate) != nil ||
		!certificate.IsCA || !certificate.BasicConstraintsValid || !certificate.MaxPathLenZero || certificate.MaxPathLen != 0 ||
		certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || certificate.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
		!slices.Equal(certificate.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) || len(certificate.UnknownExtKeyUsage) != 0 ||
		!certificate.PermittedDNSDomainsCritical || !slices.Equal(certificate.PermittedDNSDomains, permittedDNS) ||
		!slices.Equal(certificate.ExcludedDNSDomains, excludedDNS) || !equalIPRanges(certificate.PermittedIPRanges, permittedIP) ||
		!equalIPRanges(certificate.ExcludedIPRanges, excludedIP) || len(certificate.UnhandledCriticalExtensions) != 0 ||
		len(certificate.OCSPServer)+len(certificate.IssuingCertificateURL)+len(certificate.CRLDistributionPoints) != 0 ||
		!certificate.NotAfter.Equal(certificate.NotBefore.AddDate(10, 0, 0)) ||
		len(certificate.SubjectKeyId) == 0 || !bytes.Equal(certificate.AuthorityKeyId, certificate.SubjectKeyId) {
		return nil, nil, errors.New("Local authority policy mismatch")
	}
	return certificate, key, nil
}

func localRecord(data []byte) (localAuthorityIdentity, error) {
	var result localAuthorityIdentity
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return result, errors.New("Invalid local authority identity")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		key, e := decoder.Token()
		name, ok := key.(string)
		if e != nil || !ok || (name != "version" && name != "domain" && name != "rootFingerprint") {
			return result, errors.New("Invalid local authority identity")
		}
		if _, exists := fields[name]; exists {
			return result, errors.New("Invalid local authority identity")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return result, errors.New("Invalid local authority identity")
		}
		fields[name] = value
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || decoder.Decode(new(any)) != io.EOF || len(fields) != 3 {
		return result, errors.New("Invalid local authority identity")
	}
	encoded, _ := json.Marshal(fields)
	if json.Unmarshal(encoded, &result) != nil || result.Version != 1 {
		return result, errors.New("Invalid local authority identity")
	}
	return result, nil
}

// Record/exposure agreement is checked before a missing authority can be
// treated as a never-initialized store. No account key is ever read here.
func (s *Store) localAuthority(host string, create bool, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	identity, identityErr := s.read(localAuthorityRecord)
	if identityErr != nil && !errors.Is(identityErr, fs.ErrNotExist) {
		return nil, nil, identityErr
	}
	data, err := s.read(localAuthorityFile)
	if errors.Is(err, fs.ErrNotExist) {
		if identityErr == nil {
			return nil, nil, errors.New("Initialized local authority missing")
		}
		for _, name := range []string{localPublicCAFile, "bundle.pem", "previous-bundle.pem"} {
			if _, e := s.read(name); !errors.Is(e, fs.ErrNotExist) {
				return nil, nil, errors.New("Exposed local authority missing")
			}
		}
		// A partial wipe can remove all CA material while leaving a manager
		// schedule or unrelated state behind. It is not a fresh authority. The
		// native manager must not save a schedule before first local issuance.
		directory, e := s.root.Open(".")
		if e != nil {
			return nil, nil, errors.New("Cannot inspect local initialization")
		}
		entries, e := directory.ReadDir(-1)
		directory.Close()
		if e != nil {
			return nil, nil, errors.New("Cannot inspect local initialization")
		}
		for _, entry := range entries {
			if name := entry.Name(); name != "directory.json" && name != "issuer.lock" && name != "manager.lock" {
				return nil, nil, errors.New("Ambiguous local authority initialization")
			}
			info, err := s.root.Lstat(entry.Name())
			if err != nil || !secureInfo(info, 0600) {
				return nil, nil, errors.New("Unsafe local authority initialization")
			}
		}
		if !create {
			return nil, nil, fs.ErrNotExist
		}
		_, _, data, err = newLocalAuthority(host, now)
		if err != nil {
			return nil, nil, err
		}
		if _, err = s.atomic(localAuthorityFile, data); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}
	certificate, key, err := parseLocalAuthority(data, host)
	if err != nil {
		return nil, nil, err
	}
	expected := localAuthorityIdentity{Version: 1, Domain: host, RootFingerprint: certificateFingerprint(certificate)}
	if identityErr == nil {
		saved, err := localRecord(identity)
		if err != nil || saved != expected {
			return nil, nil, errors.New("Local authority identity mismatch")
		}
	} else if create {
		// Authority may have committed before a failed directory sync. Confirm
		// its persistence before committing identity or exposing its public CA.
		if err = s.confirmDirectory(localAuthorityFile); err != nil {
			return nil, nil, err
		}
		if err = s.saveJSON(localAuthorityRecord, expected); err != nil {
			return nil, nil, err
		}
	} else {
		return certificate, nil, nil // Unexposed interrupted creation; ensure reconciles it.
	}
	if create {
		for _, name := range []string{localAuthorityFile, localAuthorityRecord} {
			if err = s.confirmDirectory(name); err != nil {
				return nil, nil, err
			}
		}
	}
	return certificate, key, nil
}

func (s *Store) localExport(root *x509.Certificate, create bool) error {
	expected := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	actual, err := s.read(localPublicCAFile)
	if errors.Is(err, fs.ErrNotExist) && create {
		_, err = s.atomic(localPublicCAFile, expected)
	} else if err == nil && !bytes.Equal(actual, expected) {
		err = errors.New("Local public CA does not match authority")
	}
	if err == nil && create {
		err = s.confirmDirectory(localPublicCAFile)
	}
	return err
}

func newLocalLeaf(host string, root *x509.Certificate, authority *ecdsa.PrivateKey, now time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, err
	}
	until := now.Add(localLeafLifetime)
	if until.After(root.NotAfter) {
		until = root.NotAfter
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Traverse host"},
		NotBefore: now, NotAfter: until, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if address, e := netip.ParseAddr(host); e == nil {
		template.IPAddresses = []net.IP{net.IP(address.AsSlice())}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, authority)
	if err != nil {
		return nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
}

func localLeaf(data []byte, root *x509.Certificate, host string, now time.Time) (*localLeafMetadata, string, error) {
	certificates, keys := 0, 0
	for rest := data; len(bytes.TrimSpace(rest)) != 0; {
		block, remaining := pem.Decode(rest)
		if block == nil || len(block.Headers) != 0 {
			return nil, "", errors.New("Invalid local leaf bundle")
		}
		switch block.Type {
		case "CERTIFICATE":
			certificates++
		case "PRIVATE KEY":
			keys++
		default:
			return nil, "", errors.New("Invalid local leaf bundle")
		}
		rest = remaining
	}
	pair, err := tls.X509KeyPair(data, data)
	if err != nil || certificates != 2 || keys != 1 || len(pair.Certificate) != 2 || !bytes.Equal(pair.Certificate[1], root.Raw) {
		return nil, "", errors.New("Local leaf authority mismatch")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	key, keyOK := pair.PrivateKey.(*ecdsa.PrivateKey)
	if err != nil || !keyOK || key.Curve != elliptic.P256() || !localIdentityMatches(leaf, host) ||
		leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		!slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) || len(leaf.UnknownExtKeyUsage) != 0 ||
		leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 || len(leaf.OCSPServer)+len(leaf.IssuingCertificateURL)+len(leaf.CRLDistributionPoints) != 0 {
		return nil, "", errors.New("Invalid local leaf identity or policy")
	}
	expectedUntil := leaf.NotBefore.Add(localLeafLifetime)
	if expectedUntil.After(root.NotAfter) {
		expectedUntil = root.NotAfter
	}
	if !leaf.NotAfter.Equal(expectedUntil) || !leaf.NotBefore.Before(leaf.NotAfter) || leaf.NotBefore.Before(root.NotBefore) {
		return nil, "", errors.New("Invalid local leaf validity")
	}
	verifyAt := now
	if verifyAt.Before(leaf.NotBefore) {
		verifyAt = leaf.NotBefore
	} else if !verifyAt.Before(leaf.NotAfter) {
		verifyAt = leaf.NotAfter.Add(-time.Nanosecond)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, CurrentTime: verifyAt}); err != nil {
		return nil, "", errors.New("Local leaf chain is not trusted")
	}
	renew := leaf.NotBefore.Add(localLeafRenewAfter)
	if renew.After(leaf.NotAfter) {
		renew = leaf.NotAfter
	}
	metadata := &localLeafMetadata{localCertificateMetadata: localCertificateMetadata{
		Fingerprint: certificateFingerprint(leaf), ValidFrom: leaf.NotBefore.Unix(), ValidUntil: leaf.NotAfter.Unix()}, RenewAt: renew.Unix()}
	material := "current"
	if now.Before(leaf.NotBefore) {
		material = "not_yet_valid"
	} else if !now.Before(leaf.NotAfter) {
		material = "expired"
	}
	return metadata, material, nil
}

func localMetadata(store *Store, root *x509.Certificate, host string, now time.Time) (*LocalMetadata, error) {
	metadata := &LocalMetadata{Authority: "current", Material: "absent", Root: &localCertificateMetadata{
		Fingerprint: certificateFingerprint(root), ValidFrom: root.NotBefore.Unix(), ValidUntil: root.NotAfter.Unix()}}
	if now.Before(root.NotBefore) {
		metadata.Authority = "not_yet_valid"
	} else if !now.Before(root.NotAfter) {
		metadata.Authority = "expired"
	}
	data, err := store.read("bundle.pem")
	if errors.Is(err, fs.ErrNotExist) {
		return metadata, nil
	}
	if err != nil {
		return nil, err
	}
	metadata.Leaf, metadata.Material, err = localLeaf(data, root, host, now)
	return metadata, err
}

func localCertificates(ctx context.Context, request Request, now time.Time) Result {
	if ctx.Err() != nil {
		return failed("cancelled")
	}
	now = now.UTC().Truncate(time.Second)
	if now.Unix() < 0 || now.Year() > 9999 {
		return failed("local_clock_invalid")
	}
	create := request.Operation == "local-ensure"
	var store *Store
	var err error
	if create {
		store, err = openOwnedStore(request.StateDirectory, localStoreIdentity(request.Domain))
	} else {
		store, err = readOnlyOwnedStore(request.StateDirectory, localStoreIdentity(request.Domain))
	}
	if !create && errors.Is(err, fs.ErrNotExist) {
		return Result{Version: 1, Status: "local-info", Local: &LocalMetadata{Authority: "absent", Material: "absent"}}
	}
	if err != nil {
		return failed("storage_unavailable")
	}
	defer store.Close()
	return localCertificateOperation(ctx, store, request, now, create)
}

// The store's existing private fault seam exercises real publication/recovery;
// neither faults nor clocks are accepted through the inherited JSON protocol.
func localCertificateOperation(ctx context.Context, store *Store, request Request, now time.Time, create bool) Result {
	root, key, err := store.localAuthority(request.Domain, create, now)
	if !create && errors.Is(err, fs.ErrNotExist) {
		return Result{Version: 1, Status: "local-info", Local: &LocalMetadata{Authority: "absent", Material: "absent"}}
	}
	if err != nil {
		return failed("local_authority_unavailable")
	}
	if ctx.Err() != nil {
		return failed("cancelled")
	}
	metadata, err := localMetadata(store, root, request.Domain, now)
	if err != nil {
		return failed("local_material_invalid")
	}
	if !create {
		if key == nil {
			metadata.Authority = "initializing"
		} else if err := store.localExport(root, false); errors.Is(err, fs.ErrNotExist) {
			metadata.Authority = "initializing"
		} else if err != nil {
			return failed("local_export_invalid")
		}
		return Result{Version: 1, Status: "local-info", Local: metadata}
	}
	if metadata.Authority != "current" {
		return failed("local_ca_" + metadata.Authority)
	}
	if metadata.Material == "not_yet_valid" {
		return failed("local_leaf_not_yet_valid")
	}
	if err = store.localExport(root, true); err != nil {
		return failed("local_export_unavailable")
	}
	if ctx.Err() != nil {
		return failed("cancelled")
	}
	if metadata.Material == "current" && now.Unix() < metadata.Leaf.RenewAt {
		if err = store.confirmDirectory("bundle.pem"); err != nil {
			return failed("local_publication_uncertain")
		}
		return Result{Version: 1, Status: "local-ready", Local: metadata}
	}
	certificates, private, err := newLocalLeaf(request.Domain, root, key, now)
	if err != nil {
		return failed("local_generation_failed")
	}
	if ctx.Err() != nil {
		return failed("cancelled")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	publication, err := store.publish(certificates, private, request.Domain, roots, now, func(leaf *x509.Certificate) bool {
		return localIdentityMatches(leaf, request.Domain)
	})
	if err != nil {
		if publication.Committed {
			return Result{Version: 1, Status: "published_durability_uncertain", Code: "local_publication_uncertain", Publication: &publication}
		}
		return failed("local_publication_failed")
	}
	metadata, err = localMetadata(store, root, request.Domain, now)
	if err != nil || metadata.Material != "current" {
		return failed("local_material_invalid")
	}
	return Result{Version: 1, Status: "local-issued", Publication: &publication, Local: metadata}
}
