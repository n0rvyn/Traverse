//go:build !linux

package issuance

import (
	"net"
)

// The packaged host is Linux. No unauthenticated peer fallback on other OSes.
func verifyBrokerPeer(net.Conn) error {
	return authError("broker_host_unsupported")
}
