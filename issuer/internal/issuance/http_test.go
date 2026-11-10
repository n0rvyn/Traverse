package issuance

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func serverRequest(t *testing.T, server *httptest.Server) Request {
	t.Helper()
	trust := filepath.Join(t.TempDir(), "api-root.pem")
	if err := os.WriteFile(trust, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return Request{Version: 1, Operation: "describe", Domain: "example.test", Directory: server.URL + "/directory", APITrustFile: trust}
}

func TestCoreDirectoryFetchAndBodyAreCancellable(t *testing.T) {
	for _, phase := range []string{"headers", "body"} {
		t.Run(phase, func(t *testing.T) {
			entered := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "body" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(200)
					w.Write([]byte(`{"newNonce":`))
					w.(http.Flusher).Flush()
				}
				close(entered)
				<-r.Context().Done()
			}))
			defer server.Close()
			request := serverRequest(t, server)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finished := make(chan error, 1)
			go func() { _, _, close, err := newCore(ctx, request, "", nil); close(); finished <- err }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("Actual TLS request not observed")
			}
			cancel()
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("Cancelled directory succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("Constructor/body ignored operation cancellation")
			}
		})
	}
}

func TestDirectoryRequiresTrustedTLS(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"newNonce": server.URL + "/nonce", "newAccount": server.URL + "/accounts", "newOrder": server.URL + "/orders"})
	}))
	defer server.Close()
	request := serverRequest(t, server)
	core, _, close, err := newCore(context.Background(), request, "", nil)
	close()
	if err != nil || core.GetDirectory().NewOrderURL != server.URL+"/orders" {
		t.Fatal("Trusted actual directory unavailable", err)
	}
	request.APITrustFile = ""
	if _, _, close, err := newCore(context.Background(), request, "", nil); err == nil {
		close()
		t.Fatal("Untrusted API TLS accepted")
	}
}

func TestRetryAfterParsingAndCancellation(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, test := range []struct {
		header  string
		seconds int64
	}{{"2", 2}, {"0", 5}, {"-1", 5}, {"invalid", 5}, {"9223372036854775807", 5}, {now.Add(10 * time.Second).UTC().Format(http.TimeFormat), 10}, {now.Add(-time.Second).UTC().Format(http.TimeFormat), 0}} {
		if got := retryTime(test.header, now).Sub(now); got != time.Duration(test.seconds)*time.Second {
			t.Fatal("Retry-After changed units or overflowed")
		}
	}
	observer := &operationTransport{retryAt: map[string]time.Time{"test": time.Now().Add(time.Hour)}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := observer.wait(ctx, "test"); err == nil {
		t.Fatal("Retry wait ignored cancellation")
	}
}
