// Copied only into an owned test-source tree, never built into the runtime.
// Emit a valid authority/leaf whose real 60-day renewal boundary is approaching.
package issuance

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestEmitLocalCertificateFixture(t *testing.T) {
	var input struct {
		Domain           string `json:"domain"`
		StateDirectory   string `json:"stateDirectory"`
		RenewAt          int64  `json:"renewAt"`
		ExpiredAuthority bool   `json:"expiredAuthority"`
	}
	decoder := json.NewDecoder(os.Stdin)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		t.Fatal(err)
	}
	host, err := canonicalLocalHost(input.Domain)
	if err != nil || host != input.Domain {
		t.Fatal("Canonical fixture hostname required", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	renewAt := time.Unix(input.RenewAt, 0).UTC()
	leafFrom := renewAt.Add(-localLeafRenewAfter)
	if !input.ExpiredAuthority && (!renewAt.After(now) || !leafFrom.Before(now)) {
		t.Fatal("Future fixture renewal boundary required")
	}
	store, err := openOwnedStore(input.StateDirectory, localStoreIdentity(host))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rootFrom := now.AddDate(-1, 0, 0)
	if input.ExpiredAuthority {
		rootFrom = now.AddDate(-11, 0, 0)
	}
	root, key, err := store.localAuthority(host, true, rootFrom)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.localExport(root, true); err != nil {
		t.Fatal(err)
	}
	if input.ExpiredAuthority {
		metadata, err := localMetadata(store, root, host, now)
		if err != nil || metadata.Authority != "expired" || metadata.Material != "absent" {
			t.Fatal("Expired authority fixture failed", err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(Result{Version: 1, Status: "local-info", Local: metadata}); err != nil {
			t.Fatal(err)
		}
		return
	}
	certificates, private, err := newLocalLeaf(host, root, key, leafFrom)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	publication, err := store.publish(certificates, private, host, roots, now,
		func(leaf *x509.Certificate) bool { return localIdentityMatches(leaf, host) })
	if err != nil || !publication.Committed || !publication.Durable {
		t.Fatal("Fixture publication failed", err)
	}
	result := localCertificateOperation(context.Background(), store,
		Request{Version: 1, Operation: "local-ensure", Domain: host, StateDirectory: input.StateDirectory}, now, true)
	if result.Status != "local-ready" || result.Local == nil || result.Local.Leaf.RenewAt != input.RenewAt {
		t.Fatal("Fixture is not ready at the requested natural renewal boundary")
	}
	// Only public identities/times leave this fixture. Private material remains
	// in the host's owned directory, unreadable by the separate Chrome UID.
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		t.Fatal(err)
	}
}
