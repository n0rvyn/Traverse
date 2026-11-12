package issuance

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var localTestNow = time.Date(2026, 11, 12, 3, 4, 5, 0, time.UTC)

func localTestRequest(t *testing.T, host string) Request {
	t.Helper()
	return Request{Version: 1, Operation: "local-ensure", Domain: host, StateDirectory: statePath(t)}
}

func readLocalTestFile(t *testing.T, request Request, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(request.StateDirectory, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func requireLocalReady(t *testing.T, result Result) *LocalMetadata {
	t.Helper()
	if result.Status != "local-issued" && result.Status != "local-ready" {
		t.Fatalf("Local generation failed: %+v", result)
	}
	if result.Local == nil || result.Local.Authority != "current" || result.Local.Material != "current" {
		t.Fatalf("Incomplete local metadata: %+v", result.Local)
	}
	return result.Local
}

func adversarialLeaf(t *testing.T, root *x509.Certificate, key *ecdsa.PrivateKey, names []string, ips []net.IP, usage x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(91), Subject: pkix.Name{CommonName: "Adversarial fixture"},
		NotBefore: localTestNow, NotAfter: localTestNow.Add(time.Hour), DNSNames: names, IPAddresses: ips,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestLocalGeneratedAuthorityActuallyRestrictsNames(t *testing.T) {
	for _, host := range []string{"host.test", "127.0.0.1", "2001:db8::1", "::ffff:192.0.2.1"} {
		t.Run(host, func(t *testing.T) {
			request := localTestRequest(t, host)
			metadata := requireLocalReady(t, localCertificates(context.Background(), request, localTestNow))
			root, key, err := parseLocalAuthority(readLocalTestFile(t, request, localAuthorityFile), host)
			if err != nil || !root.NotAfter.Equal(localTestNow.AddDate(10, 0, 0)) || metadata.Root.Fingerprint != certificateFingerprint(root) {
				t.Fatal("Authority validity/identity mismatch", err)
			}
			if metadata.Leaf.ValidUntil != localTestNow.Add(localLeafLifetime).Unix() || metadata.Leaf.RenewAt != localTestNow.Add(localLeafRenewAfter).Unix() {
				t.Fatal("Approved leaf/renewal boundaries differ")
			}
			pool := x509.NewCertPool()
			pool.AddCert(root)
			bundle := readLocalTestFile(t, request, "bundle.pem")
			if _, material, err := localLeaf(bundle, root, host, localTestNow); err != nil || material != "current" {
				t.Fatal("Generated positive leaf did not verify", err)
			}
			for _, forbidden := range []string{"other.test", "child.host.test", "host.test.evil", "traverse-denied.invalid", "127.0.0.2", "2001:db8::2"} {
				var names []string
				var ips []net.IP
				if ip := net.ParseIP(forbidden); ip != nil {
					ips = []net.IP{ip}
				} else {
					names = []string{forbidden}
				}
				malicious := adversarialLeaf(t, root, key, names, ips, x509.ExtKeyUsageServerAuth)
				if _, err := malicious.Verify(x509.VerifyOptions{DNSName: forbidden, Roots: pool, CurrentTime: localTestNow}); err == nil {
					t.Fatalf("Stolen CA key could certify forbidden name %s", forbidden)
				}
			}
			if net.ParseIP(host) == nil {
				malicious := adversarialLeaf(t, root, key, []string{host, "other.test"}, nil, x509.ExtKeyUsageServerAuth)
				if _, err := malicious.Verify(x509.VerifyOptions{DNSName: host, Roots: pool, CurrentTime: localTestNow}); err == nil {
					t.Fatal("Allowed name hid an additional forbidden SAN")
				}
				client := adversarialLeaf(t, root, key, []string{host}, nil, x509.ExtKeyUsageClientAuth)
				if _, err := client.Verify(x509.VerifyOptions{DNSName: host, Roots: pool, CurrentTime: localTestNow, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
					t.Fatal("Local server authority admitted client-auth certificate")
				}
			}
			public := readLocalTestFile(t, request, localPublicCAFile)
			block, rest := pem.Decode(public)
			if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(block.Bytes, root.Raw) || bytes.Contains(public, []byte("PRIVATE KEY")) {
				t.Fatal("Public export included wrong material")
			}
		})
	}
}

func TestLocalRenewalBoundaryAndStableAuthority(t *testing.T) {
	request := localTestRequest(t, "host.test")
	first := requireLocalReady(t, localCertificates(context.Background(), request, localTestNow))
	authority := readLocalTestFile(t, request, localAuthorityFile)
	public := readLocalTestFile(t, request, localPublicCAFile)
	oldBundle := readLocalTestFile(t, request, "bundle.pem")
	before := requireLocalReady(t, localCertificates(context.Background(), request, localTestNow.Add(localLeafRenewAfter-time.Second)))
	if before.Leaf.Fingerprint != first.Leaf.Fingerprint || !bytes.Equal(oldBundle, readLocalTestFile(t, request, "bundle.pem")) {
		t.Fatal("Leaf renewed before approved boundary")
	}
	after := requireLocalReady(t, localCertificates(context.Background(), request, localTestNow.Add(localLeafRenewAfter)))
	if after.Root.Fingerprint != first.Root.Fingerprint || after.Leaf.Fingerprint == first.Leaf.Fingerprint ||
		!bytes.Equal(authority, readLocalTestFile(t, request, localAuthorityFile)) || !bytes.Equal(public, readLocalTestFile(t, request, localPublicCAFile)) ||
		!bytes.Equal(oldBundle, readLocalTestFile(t, request, "previous-bundle.pem")) {
		t.Fatal("Renewal changed root or lost previous generation")
	}
	request.Operation = "local-info"
	current := localCertificates(context.Background(), request, localTestNow.Add(localLeafRenewAfter))
	if current.Status != "local-info" || current.Local.Leaf.Fingerprint != after.Leaf.Fingerprint {
		t.Fatal("Readonly metadata failed after restart")
	}
}

func TestLocalExpiredLeafReplacedButRootNeverRotates(t *testing.T) {
	request := localTestRequest(t, "host.test")
	first := requireLocalReady(t, localCertificates(context.Background(), request, localTestNow))
	refreshed := requireLocalReady(t, localCertificates(context.Background(), request, localTestNow.Add(localLeafLifetime+time.Second)))
	if refreshed.Root.Fingerprint != first.Root.Fingerprint || refreshed.Leaf.Fingerprint == first.Leaf.Fingerprint {
		t.Fatal("Expired leaf recovery changed trust identity")
	}
	expired := localCertificates(context.Background(), request, localTestNow.AddDate(10, 0, 0))
	if expired.Status != "failed" || expired.Code != "local_ca_expired" {
		t.Fatal("Expired CA was renewed or treated as ready")
	}
	if got := readLocalTestFile(t, request, localPublicCAFile); bytes.Contains(got, []byte("PRIVATE KEY")) {
		t.Fatal("Private export after expiry")
	}
}

func TestLocalAuthorityLossCorruptionAndCrossModeAreFailures(t *testing.T) {
	for _, corrupt := range []string{"remove-root", "wrong-marker", "wrong-export", "unsafe-mode", "wrong-provider"} {
		t.Run(corrupt, func(t *testing.T) {
			request := localTestRequest(t, "host.test")
			requireLocalReady(t, localCertificates(context.Background(), request, localTestNow))
			oldBundle := readLocalTestFile(t, request, "bundle.pem")
			switch corrupt {
			case "remove-root":
				if err := os.Remove(filepath.Join(request.StateDirectory, localAuthorityFile)); err != nil {
					t.Fatal(err)
				}
			case "wrong-marker":
				if err := os.WriteFile(filepath.Join(request.StateDirectory, localAuthorityRecord), []byte(`{"version":1,"domain":"other.test","rootFingerprint":"bad"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-export":
				if err := os.WriteFile(filepath.Join(request.StateDirectory, localPublicCAFile), []byte("unrelated public file"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsafe-mode":
				if err := os.Chmod(filepath.Join(request.StateDirectory, localAuthorityFile), 0644); err != nil {
					t.Fatal(err)
				}
			case "wrong-provider":
				if err := os.WriteFile(filepath.Join(request.StateDirectory, "directory.json"), []byte(`{"directory":"https://ca.example.test/directory"}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			result := localCertificates(context.Background(), request, localTestNow.Add(time.Hour))
			if result.Status != "failed" || !bytes.Equal(oldBundle, readLocalTestFile(t, request, "bundle.pem")) {
				t.Fatal("Unsafe authority replaced trust or active leaf")
			}
		})
	}
}

func TestLocalPublicationFaultsReuseAnyCommittedAuthority(t *testing.T) {
	for _, name := range []string{localAuthorityFile, localAuthorityRecord, localPublicCAFile, "bundle.pem"} {
		for _, stage := range []string{":before-rename", ":after-rename", ":directory-sync"} {
			t.Run(name+stage, func(t *testing.T) {
				request := localTestRequest(t, "host.test")
				store, err := openOwnedStore(request.StateDirectory, localStoreIdentity(request.Domain))
				if err != nil {
					t.Fatal(err)
				}
				fired := false
				store.fault = func(value string) error {
					if value == name+stage {
						fired = true
						return errors.New("private fault")
					}
					return nil
				}
				result := localCertificateOperation(context.Background(), store, request, localTestNow, true)
				store.Close()
				if !fired || result.Status == "local-issued" || result.Status == "local-ready" {
					t.Fatal("Publication fault was admitted", result)
				}
				authority, readErr := os.ReadFile(filepath.Join(request.StateDirectory, localAuthorityFile))
				resumed := requireLocalReady(t, localCertificates(context.Background(), request, localTestNow))
				if readErr == nil && !bytes.Equal(authority, readLocalTestFile(t, request, localAuthorityFile)) {
					t.Fatal("Committed authority rotated after interruption")
				}
				if resumed.Root.Fingerprint == "" {
					t.Fatal("Missing recovered identity")
				}
			})
		}
	}
}

func TestLocalActualRunProtocolAndCancellation(t *testing.T) {
	path := statePath(t)
	request := map[string]any{"version": 1, "operation": "local-ensure", "domain": "host.test", "stateDirectory": path}
	data, _ := json.Marshal(request)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	if Run(ctx, bytes.NewReader(data), &output) != 1 || !strings.Contains(output.String(), `"code":"cancelled"`) {
		t.Fatal("Cancellation ignored")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("Cancelled request created state")
	}
	output.Reset()
	if Run(context.Background(), bytes.NewReader(data), &output) != 0 {
		t.Fatal("Actual Run local dispatch failed", output.String())
	}
	if strings.Contains(output.String(), "PRIVATE KEY") || strings.Contains(output.String(), path) {
		t.Fatal("Protocol leaked private material/path")
	}
	var result Result
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Local == nil || result.Local.Root == nil || result.Local.Leaf == nil {
		t.Fatal("Missing actual protocol result")
	}
}

func TestLocalReadonlyMetadataAndPublicExportRecovery(t *testing.T) {
	request := localTestRequest(t, "host.test")
	request.Operation = "local-info"
	absent := localCertificates(context.Background(), request, localTestNow)
	if absent.Status != "local-info" || absent.Local.Authority != "absent" {
		t.Fatal("Uninitialized metadata incorrect")
	}
	if _, err := os.Lstat(request.StateDirectory); !os.IsNotExist(err) {
		t.Fatal("Readonly inspection created state")
	}
	request.Operation = "local-ensure"
	first := requireLocalReady(t, localCertificates(context.Background(), request, localTestNow))
	type snapshot struct {
		data     []byte
		modified time.Time
	}
	before := map[string]snapshot{}
	entries, err := os.ReadDir(request.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		before[entry.Name()] = snapshot{readLocalTestFile(t, request, entry.Name()), info.ModTime()}
	}
	request.Operation = "local-info"
	result := localCertificates(context.Background(), request, localTestNow.Add(time.Hour))
	if result.Status != "local-info" || result.Local.Root.Fingerprint != first.Root.Fingerprint {
		t.Fatal("Root metadata changed")
	}
	for name, old := range before {
		info, err := os.Stat(filepath.Join(request.StateDirectory, name))
		if err != nil || !bytes.Equal(old.data, readLocalTestFile(t, request, name)) || !old.modified.Equal(info.ModTime()) {
			t.Fatal("Readonly metadata wrote state")
		}
	}
	public := before[localPublicCAFile].data
	if err := os.Remove(filepath.Join(request.StateDirectory, localPublicCAFile)); err != nil {
		t.Fatal(err)
	}
	pending := localCertificates(context.Background(), request, localTestNow.Add(time.Hour))
	if pending.Status != "local-info" || pending.Local.Authority != "initializing" {
		t.Fatal("Missing export falsely ready")
	}
	request.Operation = "local-ensure"
	restored := requireLocalReady(t, localCertificates(context.Background(), request, localTestNow.Add(time.Hour)))
	if restored.Root.Fingerprint != first.Root.Fingerprint || restored.Leaf.Fingerprint != first.Leaf.Fingerprint || !bytes.Equal(public, readLocalTestFile(t, request, localPublicCAFile)) {
		t.Fatal("Export recovery rotated root or leaf")
	}
	if store, err := OpenStore(request.StateDirectory, localStoreIdentity(request.Domain)); err == nil {
		store.Close()
		t.Fatal("Online store accepted local authority identifier")
	}
}

func TestLocalClockRollbackAndNearRootExpiry(t *testing.T) {
	request := localTestRequest(t, "host.test")
	first := requireLocalReady(t, localCertificates(context.Background(), request, localTestNow))
	authority := readLocalTestFile(t, request, localAuthorityFile)
	rollback := localCertificates(context.Background(), request, localTestNow.Add(-time.Second))
	if rollback.Status != "failed" || rollback.Code != "local_ca_not_yet_valid" || !bytes.Equal(authority, readLocalTestFile(t, request, localAuthorityFile)) {
		t.Fatal("Clock rollback rotated authority")
	}
	near := localTestNow.AddDate(10, 0, 0).Add(-time.Hour)
	leaf := requireLocalReady(t, localCertificates(context.Background(), request, near))
	if leaf.Root.Fingerprint != first.Root.Fingerprint || leaf.Leaf.ValidUntil != leaf.Root.ValidUntil || leaf.Leaf.RenewAt != leaf.Root.ValidUntil {
		t.Fatal("Leaf extended past root or promised impossible renewal")
	}
}

func TestLocalPartialWipeAndUnknownStateNeverCreateNewAuthority(t *testing.T) {
	request := localTestRequest(t, "host.test")
	requireLocalReady(t, localCertificates(context.Background(), request, localTestNow))
	for _, name := range []string{localAuthorityFile, localAuthorityRecord, localPublicCAFile, "bundle.pem"} {
		if err := os.Remove(filepath.Join(request.StateDirectory, name)); err != nil {
			t.Fatal(err)
		}
	}
	marker := []byte(`{"privateFixture":"preserve previous manager state"}`)
	if err := os.WriteFile(filepath.Join(request.StateDirectory, "schedule.json"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	result := localCertificates(context.Background(), request, localTestNow.Add(time.Hour))
	if result.Status != "failed" || result.Code != "local_authority_unavailable" {
		t.Fatal("Partial wipe silently created another authority")
	}
	if _, err := os.Lstat(filepath.Join(request.StateDirectory, localAuthorityFile)); !os.IsNotExist(err) {
		t.Fatal("Authority regenerated")
	}
	if !bytes.Equal(marker, readLocalTestFile(t, request, "schedule.json")) {
		t.Fatal("Unknown state changed")
	}
	request.Operation = "local-info"
	if inspected := localCertificates(context.Background(), request, localTestNow.Add(time.Hour)); inspected.Status != "failed" {
		t.Fatal("Readonly metadata treated a partial wipe as fresh state")
	}
}
