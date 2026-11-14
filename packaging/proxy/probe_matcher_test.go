package traverseproxy

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestNamespaceClassificationKeepsNativeAdmission(t *testing.T) {
	lease := "traverse-probe/" + strings.Repeat("a", 64)
	for _, row := range []struct {
		name      string
		protocols []string
		probe     bool
	}{
		{"no ALPN stays available to HTTPS and TURN", nil, false},
		{"HTTPS", []string{"h2", "http/1.1"}, false},
		{"public ACME stays at Caddy", []string{"acme-tls/1"}, false},
		{"unrelated", []string{"other/" + lease}, false},
		{"case sensitive namespace", []string{"Traverse-probe/a"}, false},
		{"active or revoked lease still reaches native owner", []string{lease}, true},
		{"unknown lease still reaches native owner", []string{"traverse-probe/" + strings.Repeat("b", 64)}, true},
		{"empty lease rejected by native owner", []string{"traverse-probe/"}, true},
		{"malformed lease rejected by native owner", []string{"traverse-probe/bad"}, true},
		{"mixed first rejected by native owner", []string{lease, "http/1.1"}, true},
		{"mixed last rejected by native owner", []string{"h2", lease}, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := (ProbeNamespace{}).Match(&tls.ClientHelloInfo{SupportedProtos: row.protocols}); got != row.probe {
				t.Fatalf("classification = %v, want %v", got, row.probe)
			}
		})
	}
	if (ProbeNamespace{}).Match(nil) {
		t.Fatal("missing ClientHello classified as a probe")
	}
}

func TestCaddyfileContract(t *testing.T) {
	for _, row := range []struct {
		text string
		bad  bool
	}{
		{"traverse_probe\n", false},
		{"traverse_probe extra\n", true},
		{"traverse_probe {\n target arbitrary\n}\n", true},
	} {
		err := (ProbeNamespace{}).UnmarshalCaddyfile(caddyfile.NewTestDispenser(row.text))
		if (err != nil) != row.bad {
			t.Fatalf("configuration %q: error = %v", row.text, err)
		}
	}
	if id := (ProbeNamespace{}).CaddyModule().ID; id != "tls.handshake_match.traverse_probe" {
		t.Fatalf("unexpected module identifier %q", id)
	}
}
