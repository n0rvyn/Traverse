package issuance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
)

func TestNoConsentDoesNotReachCAOrCreateState(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	request := serverRequest(t, server)
	request.Operation = "issue"
	request.StateDirectory = statePath(t)
	request.ChallengeSocket = "/private/runtime/challenge.sock"
	data, _ := json.Marshal(request)
	var output bytes.Buffer
	if Run(context.Background(), bytes.NewReader(data), &output) != 1 {
		t.Fatal("Unconsented request accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("CA contacted before consent")
	}
	if _, err := os.Stat(request.StateDirectory); !os.IsNotExist(err) {
		t.Fatal("Unconsented request changed state")
	}
	var result Result
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Status != "failed" {
		t.Fatal("Result is not fixed JSON")
	}
}

func TestChangedTermsDoNotReachAccountEndpoint(t *testing.T) {
	var accounts atomic.Int64
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/directory" {
			accounts.Add(1)
			w.WriteHeader(500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"newNonce": server.URL + "/nonce", "newAccount": server.URL + "/accounts", "newOrder": server.URL + "/orders", "meta": map[string]string{"termsOfService": server.URL + "/new-terms"}})
	}))
	defer server.Close()
	request := serverRequest(t, server)
	request.Operation = "issue"
	request.TermsAgreed = true
	request.TermsURL = server.URL + "/old-terms"
	request.StateDirectory = statePath(t)
	request.ChallengeSocket = "/private/runtime/challenge.sock"
	data, _ := json.Marshal(request)
	var output bytes.Buffer
	if Run(context.Background(), bytes.NewReader(data), &output) != 1 {
		t.Fatal("Changed terms accepted")
	}
	var result Result
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Code != "ca_terms_changed" || accounts.Load() != 0 {
		t.Fatal("Changed terms reached account/order", output.String())
	}
}

func TestRawCAErrorIsNotExported(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte(`{"type":"private-type-marker","detail":"private-key-authorization-marker"}`))
	}))
	defer server.Close()
	request := serverRequest(t, server)
	data, _ := json.Marshal(request)
	var output bytes.Buffer
	if Run(context.Background(), bytes.NewReader(data), &output) != 1 {
		t.Fatal("CA failure hidden")
	}
	if bytes.Contains(output.Bytes(), []byte("marker")) {
		t.Fatal("Raw CA response escaped")
	}
	var result Result
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Code != "ca_unavailable" {
		t.Fatal("Invalid safe error result")
	}
}

func TestLeaseExpiryUsesCAOrderAndOptionalAuthorizationExpiry(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	order := acme.Order{Expires: now.Add(time.Hour).Format(time.RFC3339)}
	authorization := acme.Authorization{}
	expires, err := leaseExpiry(order, authorization, now)
	if err != nil || !expires.Equal(now.Add(time.Hour)) {
		t.Fatal("Absent pending authz expiry did not use CA order expiry")
	}
	authorization.Expires = now.Add(time.Minute)
	expires, err = leaseExpiry(order, authorization, now)
	if err != nil || !expires.Equal(authorization.Expires) {
		t.Fatal("Earlier authorization expiry ignored")
	}
	order.Expires = ""
	if _, err = leaseExpiry(order, authorization, now); err == nil {
		t.Fatal("Invented missing CA order expiry")
	}
	order.Expires = now.Add(-time.Second).Format(time.RFC3339)
	if _, err = leaseExpiry(order, authorization, now); err == nil {
		t.Fatal("Expired order accepted")
	}
}

func TestOrderAndAuthorizationIdentityAreExact(t *testing.T) {
	order := acme.Order{Identifiers: []acme.Identifier{{Type: "dns", Value: "EXAMPLE.test."}}}
	if !orderMatches(order, "example.test") {
		t.Fatal("Canonical order identity rejected")
	}
	order.Identifiers = append(order.Identifiers, acme.Identifier{Type: "dns", Value: "other.test"})
	if orderMatches(order, "example.test") {
		t.Fatal("Extra order identity accepted")
	}
	authorization := acme.Authorization{Identifier: acme.Identifier{Type: "dns", Value: "example.test"}}
	if !authorizationMatches(authorization, "example.test") {
		t.Fatal("Configured authorization rejected")
	}
	authorization.Wildcard = true
	if authorizationMatches(authorization, "example.test") {
		t.Fatal("Wildcard authorization accepted")
	}
}
