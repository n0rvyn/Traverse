package issuance

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRequestConsentAndStrictSchema(t *testing.T) {
	base := Request{Version: 1, Operation: "issue", Domain: "EXAMPLE.test.", Directory: testDirectory, StateDirectory: "/private/state", ChallengeSocket: "/private/runtime/challenge.sock", TermsURL: "https://ca.example.test/terms", TermsAgreed: true}
	data, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeRequest(strings.NewReader(string(data)))
	if err != nil || request.Domain != "example.test" {
		t.Fatal("Canonical request rejected", err)
	}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.TermsAgreed = false }, func(r *Request) { r.Version = 2 }, func(r *Request) { r.Operation = "shell" },
		func(r *Request) { r.Domain = "*.example.test" }, func(r *Request) { r.Domain = "127.0.0.1" }, func(r *Request) { r.Domain = "example.test/path" },
		func(r *Request) { r.StateDirectory = "relative" }, func(r *Request) { r.ChallengeSocket = "/private/../socket" },
		func(r *Request) { r.Directory = "http://ca.example.test" }, func(r *Request) { r.Directory = "https://secret-marker@ca.example.test" },
		func(r *Request) { r.Directory = "https://ca.example.test/#fragment" }, func(r *Request) { r.APITrustFile = "relative" },
	} {
		changed := base
		mutate(&changed)
		raw, _ := json.Marshal(changed)
		if _, err := DecodeRequest(strings.NewReader(string(raw))); err == nil {
			t.Fatal("Invalid request accepted")
		} else if strings.Contains(err.Error(), "secret-marker") {
			t.Fatal("Private input echoed")
		}
	}
	for _, raw := range []string{string(data) + " {}", strings.Replace(string(data), "{", "{\"version\":1,", 1), strings.Replace(string(data), "{", "{\"extra\":true,", 1), "[]", "null"} {
		if _, err := DecodeRequest(strings.NewReader(raw)); err == nil {
			t.Fatal("Malformed or duplicate request accepted")
		}
	}
	base.Operation = "describe"
	base.TermsAgreed = false
	base.StateDirectory = ""
	base.ChallengeSocket = ""
	raw, _ := json.Marshal(base)
	if _, err := DecodeRequest(strings.NewReader(string(raw))); err != nil {
		t.Fatal("Metadata inspection incorrectly requires enrollment", err)
	}
}
