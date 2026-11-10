package issuance

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Terms are a document reference, not an ACME request endpoint. An inline
// plain-text document arrives inside the authenticated directory response.
// Never treat HTML, script or local-file references as displayable terms.
func validateTermsURI(value string) error {
	if value == "" {
		return nil
	}
	u, err := url.Parse(value)
	if err != nil {
		return errors.New("Invalid CA terms reference")
	}
	if u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" {
		return nil
	}
	if u.Scheme != "data" || u.Fragment != "" {
		return errors.New("Unsupported CA terms reference")
	}
	header, encoded, ok := strings.Cut(value[len(u.Scheme)+1:], ",")
	if !ok {
		return errors.New("Invalid inline CA terms")
	}
	parts := strings.Split(strings.ToLower(header), ";")
	if parts[0] != "" && parts[0] != "text/plain" {
		return errors.New("CA inline terms must be plain text")
	}
	utf8Charset, encodedBase64 := false, false
	seen := map[string]bool{}
	for _, part := range parts[1:] {
		name, _, _ := strings.Cut(part, "=")
		if seen[name] {
			return errors.New("Duplicate CA terms parameter")
		}
		seen[name] = true
		switch part {
		case "charset=utf-8":
			utf8Charset = true
		case "charset=us-ascii":
		case "base64":
			encodedBase64 = true
		default:
			return errors.New("Unsupported CA terms text encoding")
		}
	}
	text, err := url.PathUnescape(encoded)
	if err != nil {
		return errors.New("Invalid inline CA terms encoding")
	}
	if encodedBase64 {
		data, e := base64.StdEncoding.Strict().DecodeString(text)
		if e != nil {
			return errors.New("Invalid inline CA terms base64")
		}
		text = string(data)
	}
	if !utf8.ValidString(text) {
		return errors.New("Invalid inline CA terms text")
	}
	if !utf8Charset {
		for _, c := range text {
			if c > 127 {
				return errors.New("CA terms charset mismatch")
			}
		}
	}
	return nil
}
