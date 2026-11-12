package issuance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
)

// Request is an internal inherited-pipe protocol, never a public HTTP API.
// Trust files are explicit per-instance roots, chiefly for the private CA test.
type Request struct {
	Version              int    `json:"version"`
	Operation            string `json:"operation"`
	Domain               string `json:"domain"`
	Directory            string `json:"directory"`
	StateDirectory       string `json:"stateDirectory"`
	ChallengeSocket      string `json:"challengeSocket"`
	TermsURL             string `json:"termsURL"`
	TermsAgreed          bool   `json:"termsAgreed"`
	APITrustFile         string `json:"apiTrustFile,omitempty"`
	CertificateTrustFile string `json:"certificateTrustFile,omitempty"`
}

type Result struct {
	Version     int              `json:"version"`
	Status      string           `json:"status"`
	Code        string           `json:"code,omitempty"`
	Reason      string           `json:"reason,omitempty"`
	CAProblem   string           `json:"caProblem,omitempty"`
	TermsURL    string           `json:"termsURL,omitempty"`
	Publication *Publication     `json:"publication,omitempty"`
	Renewal     *RenewalMetadata `json:"renewal,omitempty"`
	Local       *LocalMetadata   `json:"local,omitempty"`
}

func canonicalDNS(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if len(domain) == 0 || len(domain) > 253 || net.ParseIP(domain) != nil {
		return "", errors.New("DNS domain required")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("Invalid DNS domain")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("Invalid DNS domain")
			}
		}
	}
	return domain, nil
}

func DecodeRequest(input io.Reader) (Request, error) {
	var result Request
	decoder := json.NewDecoder(input)
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return result, errors.New("Invalid issuer request")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return result, errors.New("Invalid issuer request")
		}
		name, ok := key.(string)
		if !ok {
			return result, errors.New("Invalid issuer request")
		}
		if _, exists := fields[name]; exists {
			return result, errors.New("Duplicate issuer request field")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return result, errors.New("Invalid issuer request")
		}
		fields[name] = value
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') {
		return result, errors.New("Invalid issuer request")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return result, errors.New("Trailing issuer request data")
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return result, errors.New("Invalid issuer request")
	}
	typed := json.NewDecoder(bytes.NewReader(data))
	typed.DisallowUnknownFields()
	if typed.Decode(&result) != nil || result.Version != 1 || (result.Operation != "describe" && result.Operation != "issue" && result.Operation != "renewal-info" && !localOperation(result.Operation)) {
		return Request{}, errors.New("Invalid issuer request schema")
	}
	if localOperation(result.Operation) {
		for name := range fields {
			if name != "version" && name != "operation" && name != "domain" && name != "stateDirectory" {
				return Request{}, errors.New("Unexpected local certificate field")
			}
		}
		if result.Domain, err = canonicalLocalHost(result.Domain); err != nil {
			return Request{}, err
		}
		if !filepath.IsAbs(result.StateDirectory) || filepath.Clean(result.StateDirectory) != result.StateDirectory || strings.ContainsRune(result.StateDirectory, '\x00') {
			return Request{}, errors.New("Absolute clean local state path required")
		}
		return result, nil
	}
	if err = validateHTTPS(result.Directory); err != nil {
		return Request{}, err
	}
	if result.Domain, err = canonicalDNS(result.Domain); err != nil {
		return Request{}, err
	}
	for _, p := range []string{result.APITrustFile, result.CertificateTrustFile} {
		if p != "" && (!filepath.IsAbs(p) || filepath.Clean(p) != p) {
			return Request{}, errors.New("Absolute trust file required")
		}
	}
	if result.Operation == "renewal-info" && (!filepath.IsAbs(result.StateDirectory) || filepath.Clean(result.StateDirectory) != result.StateDirectory) {
		return Request{}, errors.New("Absolute owned state path required")
	}
	if result.Operation == "issue" {
		for _, p := range []string{result.StateDirectory, result.ChallengeSocket} {
			if !filepath.IsAbs(p) || filepath.Clean(p) != p {
				return Request{}, errors.New("Absolute owned state and socket paths required")
			}
		}
		if !result.TermsAgreed {
			return Request{}, errors.New("CA terms approval required")
		}
		if result.TermsURL != "" {
			if err = validateTermsURI(result.TermsURL); err != nil {
				return Request{}, err
			}
		}
	}
	return result, nil
}
