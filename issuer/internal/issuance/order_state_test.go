package issuance

import (
	"errors"
	"testing"
)

func TestPendingOrderRetainsKeyAndOrderAcrossRestart(t *testing.T) {
	path := statePath(t)
	s := openTestStore(t, path)
	first, key, err := s.pending("example.test")
	if err != nil {
		t.Fatal(err)
	}
	first.OrderURL = "https://ca.example.test/order/1"
	if err = s.saveJSON("pending.json", first); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = openTestStore(t, path)
	restored, restoredKey, err := s.pending("example.test")
	if err != nil || restored.OrderURL != first.OrderURL || restoredKey.D.Cmp(key.D) != 0 {
		t.Fatal("Interrupted order identity lost")
	}
	if _, _, err = s.pending("other.test"); err == nil {
		t.Fatal("An unrelated endpoint took over a pending order")
	}
	restored.Completed = true
	if err = s.saveJSON("pending.json", restored); err != nil {
		t.Fatal(err)
	}
	next, nextKey, err := s.pending("example.test")
	if err != nil || next.OrderURL != "" || next.Completed || nextKey.D.Cmp(key.D) == 0 {
		t.Fatal("Completed order did not allow a fresh key")
	}
}

func TestUncertainPendingRecordRequiresDurabilityBeforeUse(t *testing.T) {
	s := openTestStore(t, statePath(t))
	s.fault = func(stage string) error {
		if stage == "pending.json:directory-sync" {
			return errors.New("injected")
		}
		return nil
	}
	if _, _, err := s.pending("example.test"); err == nil {
		t.Fatal("Uncertain pending key allowed")
	}
	s.fault = func(stage string) error {
		if stage == "pending.json:confirm-sync" {
			return errors.New("injected")
		}
		return nil
	}
	if _, _, err := s.pending("example.test"); err == nil {
		t.Fatal("Unconfirmed pending key allowed")
	}
	s.fault = nil
	if _, _, err := s.pending("example.test"); err != nil {
		t.Fatal("Pending order could not recover", err)
	}
}

func TestAccountMetadataBindsKeyAndCA(t *testing.T) {
	s := openTestStore(t, statePath(t))
	key, err := s.AccountKey()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := keyFingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	state := accountState{Version: 1, Directory: testDirectory, KID: "https://ca.example.test/account/1", KeyFingerprint: fingerprint, TermsURL: "https://ca.example.test/terms"}
	if err = s.saveJSON("account.json", state); err != nil {
		t.Fatal(err)
	}
	if loaded, err := s.loadAccount(key); err != nil || loaded.KID != state.KID {
		t.Fatal("Saved account did not recover", err)
	}
	state.KeyFingerprint = "wrong"
	if err = s.saveJSON("account.json", state); err != nil {
		t.Fatal(err)
	}
	if _, err = s.loadAccount(key); err == nil {
		t.Fatal("Account metadata accepted another key")
	}
}
