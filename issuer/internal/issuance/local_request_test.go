package issuance

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestLocalRequestStrictOperationIsolation(t *testing.T) {
	for _, operation := range []string{"local-ensure", "local-info"} {
		for input, canonical := range map[string]string{
			"EXAMPLE.test.": "example.test", "127.0.0.1": "127.0.0.1",
			"2001:0DB8::1": "2001:db8::1", "::ffff:192.0.2.1": "192.0.2.1",
		} {
			path := statePath(t)
			value := map[string]any{"version": 1, "operation": operation, "domain": input, "stateDirectory": path}
			data, _ := json.Marshal(value)
			request, err := DecodeRequest(strings.NewReader(string(data)))
			if err != nil || request.Domain != canonical || request.StateDirectory != path {
				t.Fatalf("Local identity rejected: %s: %v", input, err)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("Decoding created local state")
			}
			for field, extra := range map[string]any{
				"directory": testDirectory, "termsURL": "", "termsAgreed": false,
				"challengeSocket": "", "apiTrustFile": "", "certificateTrustFile": "",
				"clock": 1, "rootYears": 100, "extra": true,
			} {
				value[field] = extra
				invalid, _ := json.Marshal(value)
				if _, err := DecodeRequest(strings.NewReader(string(invalid))); err == nil {
					t.Fatalf("Local request accepted mixed field %s", field)
				}
				delete(value, field)
			}
		}
	}
}

func TestLocalRequestRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	base := `{"version":1,"operation":"local-ensure","domain":"host.test","stateDirectory":"/private/local-state"}`
	for _, raw := range []string{
		base + `{}`, strings.Replace(base, `"version":1`, `"version":2`, 1),
		strings.Replace(base, `"domain":"host.test"`, `"domain":"*.host.test"`, 1),
		strings.Replace(base, `"domain":"host.test"`, `"domain":"host.test/path"`, 1),
		strings.Replace(base, `"domain":"host.test"`, `"domain":"private-marker@host.test"`, 1),
		strings.Replace(base, `"stateDirectory":"/private/local-state"`, `"stateDirectory":"relative"`, 1),
		strings.Replace(base, `"stateDirectory":"/private/local-state"`, `"stateDirectory":"/private/../state"`, 1),
		strings.Replace(base, `{`, `{"domain":"other.test",`, 1),
	} {
		if _, err := DecodeRequest(strings.NewReader(raw)); err == nil || strings.Contains(err.Error(), "private-marker") {
			t.Fatal("Unsafe input accepted or private input echoed")
		}
	}
}
