package issuance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme/api"
)

func renewalFixture(t *testing.T, request Request) Request {
	t.Helper()
	request.Operation = "renewal-info"
	request.StateDirectory = statePath(t)
	store, err := OpenStore(request.StateDirectory, request.Directory)
	if err != nil {
		t.Fatal(err)
	}
	certificate, key, roots := testMaterial(t, request.Domain, 124)
	if _, err = store.Publish(certificate, key, request.Domain, roots, time.Now()); err != nil {
		t.Fatal(err)
	}
	store.Close()
	// A read-only operation must not recreate this lock or clean this writer's
	// abandoned temporary. There is intentionally no account key in this state.
	if err = os.Remove(filepath.Join(request.StateDirectory, "issuer.lock")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(request.StateDirectory, ".pending-0123456789abcdef0123456789abcdef"), []byte("preserve during metadata read"), 0600); err != nil {
		t.Fatal(err)
	}
	request.CertificateTrustFile = filepath.Join(filepath.Dir(request.StateDirectory), "leaf-trust.pem")
	if err = os.WriteFile(request.CertificateTrustFile, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	return request
}

func stateSnapshot(t *testing.T, path string) map[string]string {
	t.Helper()
	result := map[string]string{}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = string(data)
	}
	return result
}

func TestRenewalMetadataActualTLSAndReadOnlyState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, scenario := range []string{"valid", "unsupported", "equal-window", "missing-window", "unsafe-explanation", "unsafe-endpoint", "failed", "invalid-retry", "absent-retry", "zero-retry", "multiple-retry"} {
		t.Run(scenario, func(t *testing.T) {
			var directoryCalls, ariCalls, unexpected atomic.Int64
			var requestedID string
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.Header.Get("Authorization") != "" {
					unexpected.Add(1)
				}
				switch {
				case r.URL.Path == "/directory":
					directoryCalls.Add(1)
					directory := map[string]any{"newNonce": server.URL + "/nonce", "newAccount": server.URL + "/account", "newOrder": server.URL + "/orders"}
					if scenario != "unsupported" {
						directory["renewalInfo"] = server.URL + "/renewal"
					}
					if scenario == "unsafe-endpoint" {
						directory["renewalInfo"] = "http://127.0.0.1/forbidden"
					}
					json.NewEncoder(w).Encode(directory)
				case strings.HasPrefix(r.URL.Path, "/renewal/"):
					ariCalls.Add(1)
					requestedID = strings.TrimPrefix(r.URL.Path, "/renewal/")
					switch scenario {
					case "absent-retry":
					case "zero-retry":
						w.Header().Set("Retry-After", "0")
					case "invalid-retry":
						w.Header().Set("Retry-After", "not-a-time")
					case "multiple-retry":
						w.Header().Add("Retry-After", "60")
						w.Header().Add("Retry-After", "120")
					default:
						w.Header().Set("Retry-After", "60")
					}
					if scenario == "failed" {
						w.WriteHeader(503)
						w.Write([]byte("private-ca-error-marker"))
						return
					}
					start, end := now.Add(time.Minute), now.Add(2*time.Minute)
					if scenario == "equal-window" {
						end = start
					}
					body := map[string]any{"suggestedWindow": map[string]time.Time{"start": start, "end": end}}
					if scenario == "missing-window" {
						body = map[string]any{}
					}
					if scenario == "unsafe-explanation" {
						body["explanationURL"] = "https://secret-marker@ca.example.test"
					}
					json.NewEncoder(w).Encode(body)
				default:
					unexpected.Add(1)
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			request := renewalFixture(t, serverRequest(t, server))
			before := stateSnapshot(t, request.StateDirectory)
			input, _ := json.Marshal(request)
			var output bytes.Buffer
			if code := Run(context.Background(), bytes.NewReader(input), &output); code != 0 {
				t.Fatal(code, output.String())
			}
			var result Result
			if json.Unmarshal(output.Bytes(), &result) != nil || result.Renewal == nil {
				t.Fatal(output.String())
			}
			metadata := result.Renewal
			expected := "valid"
			switch scenario {
			case "unsupported":
				expected = "unsupported"
			case "equal-window", "missing-window", "unsafe-explanation", "unsafe-endpoint":
				expected = "invalid"
			case "failed":
				expected = "unavailable"
			}
			if metadata.Material != "current" || metadata.ARI != expected || len(metadata.Fingerprint) != 64 || metadata.ValidFrom >= metadata.ValidUntil {
				t.Fatal(metadata)
			}
			retryStatus := "valid"
			switch scenario {
			case "unsupported", "unsafe-endpoint":
				retryStatus = "absent"
			case "invalid-retry", "multiple-retry":
				retryStatus = "invalid"
			case "absent-retry":
				retryStatus = "absent"
			}
			if metadata.RetryAfterStatus != retryStatus {
				t.Fatal(metadata)
			}
			if retryStatus != "valid" && metadata.RetryAt != 0 {
				t.Fatal("Invented Retry-After", metadata)
			}
			if retryStatus == "valid" && (metadata.RetryAt < now.Unix() || metadata.RetryAt > time.Now().Add(61*time.Second).Unix()) {
				t.Fatal(metadata)
			}
			if directoryCalls.Load() != 1 || unexpected.Load() != 0 {
				t.Fatal("Read-only metadata reached account/order/nonce", unexpected.Load())
			}
			if scenario != "unsupported" && scenario != "unsafe-endpoint" {
				if ariCalls.Load() != 1 {
					t.Fatal("Actual ARI TLS GET was not observed")
				}
				bundle := []byte(before["bundle.pem"])
				certificates, err := readCertificates(bundle)
				if err != nil {
					t.Fatal(err)
				}
				id, err := api.MakeARICertID(certificates[0])
				if err != nil || requestedID != id {
					t.Fatal("Incorrect ARI certificate identity", requestedID, id, err)
				}
			} else if ariCalls.Load() != 0 {
				t.Fatal("Invalid/absent endpoint was requested")
			}
			after := stateSnapshot(t, request.StateDirectory)
			beforeJSON, _ := json.Marshal(before)
			afterJSON, _ := json.Marshal(after)
			if !bytes.Equal(beforeJSON, afterJSON) {
				t.Fatal("Metadata created/cleaned/changed owned state")
			}
			if bytes.Contains(output.Bytes(), []byte("marker")) || bytes.Contains(output.Bytes(), []byte("PRIVATE KEY")) {
				t.Fatal("Raw/private metadata exported")
			}
		})
	}
}

func TestRenewalAbsentExpiredFutureAndUnsafeMaterialDoNotQueryCA(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	request := serverRequest(t, server)
	request.Operation = "renewal-info"
	request.StateDirectory = statePath(t)
	result := renewalInfo(context.Background(), request, time.Now())
	if result.Renewal == nil || result.Renewal.Material != "absent" {
		t.Fatal(result)
	}
	if _, err := os.Lstat(request.StateDirectory); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("Absent metadata created state", err)
	}
	request = renewalFixture(t, request)
	bundle, err := os.ReadFile(filepath.Join(request.StateDirectory, "bundle.pem"))
	if err != nil {
		t.Fatal(err)
	}
	certificates, err := readCertificates(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		at       time.Time
		material string
	}{
		{certificates[0].NotAfter.Add(time.Second), "expired"},
		{certificates[0].NotBefore.Add(-time.Second), "not_yet_valid"},
	} {
		result = renewalInfo(context.Background(), request, test.at)
		if result.Renewal == nil || result.Renewal.Material != test.material || result.Renewal.ARI != "not_applicable" {
			t.Fatal(result)
		}
	}
	for _, path := range []string{"directory.json", "bundle.pem"} {
		actual := filepath.Join(request.StateDirectory, path)
		original, err := os.ReadFile(actual)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(actual, 0644); err != nil {
			t.Fatal(err)
		}
		if result = renewalInfo(context.Background(), request, time.Now()); result.Status != "failed" {
			t.Fatal("Unsafe state accepted", path, result)
		}
		if err = os.Chmod(actual, 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Remove(actual); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(filepath.Dir(request.StateDirectory), path+"-target")
		if err = os.WriteFile(target, original, 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(target, actual); err != nil {
			t.Fatal(err)
		}
		if result = renewalInfo(context.Background(), request, time.Now()); result.Status != "failed" {
			t.Fatal("State symlink accepted", path, result)
		}
		if err = os.Remove(actual); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(actual, original, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("Absent/expired/future/unsafe material queried CA")
	}
}

func TestRenewalRequestAndRetryHeaderValidity(t *testing.T) {
	request := Request{Version: 1, Operation: "renewal-info", Domain: "example.test", Directory: testDirectory, StateDirectory: "/private/state"}
	for _, path := range []string{"/private/state", "relative", "/private/../state", ""} {
		request.StateDirectory = path
		data, _ := json.Marshal(request)
		_, err := DecodeRequest(bytes.NewReader(data))
		if (path == "/private/state") != (err == nil) {
			t.Fatal("Invalid metadata request schema", path, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, header := range []string{"0", "60", now.Add(time.Minute).Format(http.TimeFormat)} {
		at, valid := retryDeadline(header, now)
		if !valid || at.Before(now) {
			t.Fatal(header, at, valid)
		}
	}
	for _, header := range []string{"", "-1", "+1", "1.0", "invalid", "9223372036854775807"} {
		if _, valid := retryDeadline(header, now); valid {
			t.Fatal("Invalid Retry-After accepted", header)
		}
	}
}

func TestRenewalUsesReplacementAndCancelsActualARIRequest(t *testing.T) {
	var pending atomic.Bool
	entered := make(chan struct{})
	var server *httptest.Server
	ids := make(chan string, 3)
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/directory" {
			json.NewEncoder(w).Encode(map[string]string{"newNonce": server.URL + "/nonce", "newAccount": server.URL + "/account", "newOrder": server.URL + "/orders", "renewalInfo": server.URL + "/renewal"})
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/renewal/") {
			w.WriteHeader(500)
			return
		}
		ids <- strings.TrimPrefix(r.URL.Path, "/renewal/")
		if pending.Load() {
			close(entered)
			<-r.Context().Done()
			return
		}
		now := time.Now()
		json.NewEncoder(w).Encode(map[string]any{"suggestedWindow": map[string]time.Time{"start": now, "end": now.Add(time.Hour)}})
	}))
	defer server.Close()
	request := renewalFixture(t, serverRequest(t, server))
	first := renewalInfo(context.Background(), request, time.Now())
	if first.Renewal == nil || first.Renewal.ARI != "valid" {
		t.Fatal(first)
	}
	firstID := <-ids
	certificate, key, _ := testMaterial(t, request.Domain, 200)
	replacement := append(append([]byte{}, certificate...), key...)
	if err := os.WriteFile(filepath.Join(request.StateDirectory, "bundle.pem"), replacement, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(request.CertificateTrustFile, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	next := renewalInfo(context.Background(), request, time.Now())
	if next.Renewal == nil || next.Renewal.ARI != "valid" || first.Renewal.Fingerprint == next.Renewal.Fingerprint || firstID == <-ids {
		t.Fatal("Replaced certificate was queried instead of current material", next)
	}
	pending.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan Result, 1)
	go func() { finished <- renewalInfo(ctx, request, time.Now()) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("Actual pending ARI request was not observed")
	}
	cancel()
	select {
	case result := <-finished:
		if result.Code != "cancelled" {
			t.Fatal(result)
		}
	case <-time.After(time.Second):
		t.Fatal("ARI ignored operation cancellation")
	}
}
