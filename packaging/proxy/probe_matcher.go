// Package traverseproxy classifies the native probe namespace without admitting leases.
package traverseproxy

import (
	"crypto/tls"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() { caddy.RegisterModule(ProbeNamespace{}) }

// ProbeNamespace sends even malformed or mixed probe offers to native admission.
// The native owner alone validates the lease and can revoke established sessions.
type ProbeNamespace struct{}

func (ProbeNamespace) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.handshake_match.traverse_probe",
		New: func() caddy.Module { return new(ProbeNamespace) },
	}
}

func (ProbeNamespace) Match(hello *tls.ClientHelloInfo) bool {
	if hello == nil {
		return false
	}
	for _, protocol := range hello.SupportedProtos {
		if strings.HasPrefix(protocol, "traverse-probe/") {
			return true
		}
	}
	return false
}

func (ProbeNamespace) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.CountRemainingArgs() != 0 || d.NextBlock(d.Nesting()) {
			return d.Err("traverse_probe takes no arguments or options")
		}
	}
	return nil
}

var (
	_ caddytls.ConnectionMatcher = ProbeNamespace{}
	_ caddyfile.Unmarshaler      = ProbeNamespace{}
)
