package issuance

import (
	"net"
	"os"
	"syscall"
)

func verifyBrokerPeer(connection net.Conn) error {
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return authError("broker_socket_type_invalid")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return authError("broker_peer_unavailable")
	}
	var identity *syscall.Ucred
	var credentialError error
	if err = raw.Control(func(fd uintptr) {
		identity, credentialError = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credentialError != nil || identity == nil || identity.Uid != uint32(os.Geteuid()) {
		return authError("broker_peer_denied")
	}
	return nil
}
