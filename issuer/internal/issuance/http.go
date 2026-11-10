package issuance

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/go-acme/lego/v5/acme/api"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type operationTransport struct {
	ctx       context.Context
	transport http.RoundTripper
	mutex     sync.Mutex
	retryAt   map[string]time.Time
}
type operationBody struct {
	io.ReadCloser
	release func()
}

func (b *operationBody) Close() error { defer b.release(); return b.ReadCloser.Close() }
func (t *operationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if validateHTTPS(request.URL.String()) != nil {
		return nil, errors.New("Invalid CA request address")
	}
	ctx, cancel := context.WithCancel(request.Context())
	stop := context.AfterFunc(t.ctx, cancel)
	release := func() { stop(); cancel() }
	if t.ctx.Err() != nil {
		release()
		return nil, t.ctx.Err()
	}
	response, err := t.transport.RoundTrip(request.Clone(ctx))
	if err != nil {
		release()
		return nil, err
	}
	t.mutex.Lock()
	if t.retryAt == nil {
		t.retryAt = map[string]time.Time{}
	}
	t.retryAt[request.URL.String()] = retryTime(response.Header.Get("Retry-After"), time.Now())
	t.mutex.Unlock()
	response.Body = &operationBody{response.Body, release}
	return response, nil
}

func retryTime(value string, now time.Time) time.Time {
	// Same five-second fallback as Lego's supported challenge resolver.
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 && seconds <= int64((1<<63-1)/time.Second) {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if date, err := http.ParseTime(value); err == nil {
		if date.Before(now) {
			return now
		}
		return date
	}
	return now.Add(5 * time.Second)
}

func (t *operationTransport) wait(ctx context.Context, uri string) error {
	t.mutex.Lock()
	at, ok := t.retryAt[uri]
	t.mutex.Unlock()
	if !ok {
		at = time.Now().Add(5 * time.Second)
	}
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func readRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("Configured trust file unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("Configured trust file invalid")
	}
	return roots, nil
}

func newCore(ctx context.Context, request Request, kid string, key crypto.Signer) (*api.Core, *operationTransport, func(), error) {
	roots, err := readRoots(request.APITrustFile)
	if err != nil {
		return nil, nil, func() {}, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	observer := &operationTransport{ctx: ctx, transport: transport}
	client := &http.Client{Timeout: 30 * time.Second, Transport: observer}
	core, err := api.New(client, "Traverse certificate issuer", request.Directory, kid, key)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, func() {}, errors.New("CA directory unavailable")
	}
	return core, observer, transport.CloseIdleConnections, nil
}
