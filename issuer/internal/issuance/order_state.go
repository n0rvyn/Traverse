package issuance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
)

type accountState struct {
	Version        int    `json:"version"`
	Directory      string `json:"directory"`
	KID            string `json:"kid"`
	KeyFingerprint string `json:"keyFingerprint"`
	TermsURL       string `json:"termsURL"`
}

type pendingOrder struct {
	Version   int    `json:"version"`
	Domain    string `json:"domain"`
	Key       string `json:"key"`
	OrderURL  string `json:"orderURL,omitempty"`
	Completed bool   `json:"completed"`
}

func keyFingerprint(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", errors.New("Cannot identify account key")
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), nil
}

func (s *Store) saveJSON(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return errors.New("Cannot encode private operation state")
	}
	_, err = s.atomic(name, data)
	return err
}

func (s *Store) loadAccount(key *ecdsa.PrivateKey) (accountState, error) {
	var state accountState
	data, err := s.read("account.json")
	if errors.Is(err, fs.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	fingerprint, err := keyFingerprint(key)
	if err != nil {
		return state, err
	}
	if json.Unmarshal(data, &state) != nil || state.Version != 1 || state.Directory != s.directory || state.KeyFingerprint != fingerprint || validateHTTPS(state.KID) != nil {
		return accountState{}, errors.New("Saved account identity invalid")
	}
	if err = s.confirmDirectory("account.json"); err != nil {
		return accountState{}, err
	}
	return state, nil
}

func (s *Store) pending(domain string) (pendingOrder, *ecdsa.PrivateKey, error) {
	var pending pendingOrder
	data, err := s.read("pending.json")
	if err == nil {
		if json.Unmarshal(data, &pending) != nil || pending.Version != 1 {
			return pending, nil, errors.New("Saved order invalid")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return pending, nil, err
	}
	if err != nil || pending.Completed {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return pending, nil, errors.New("Cannot create certificate key")
		}
		der, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return pending, nil, errors.New("Cannot encode certificate key")
		}
		pending = pendingOrder{Version: 1, Domain: domain, Key: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}
		if e = s.saveJSON("pending.json", pending); e != nil {
			return pending, nil, e
		}
		return pending, key, nil
	}
	if pending.Domain != domain || (pending.OrderURL != "" && validateHTTPS(pending.OrderURL) != nil) {
		return pending, nil, errors.New("Saved order identity mismatch")
	}
	block, rest := pem.Decode([]byte(pending.Key))
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return pending, nil, errors.New("Saved certificate key invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return pending, nil, errors.New("Saved certificate key invalid")
	}
	if err = s.confirmDirectory("pending.json"); err != nil {
		return pending, nil, err
	}
	return pending, key, nil
}
