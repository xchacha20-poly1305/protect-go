package protect

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// ControlContext returns a function for net.Dialer.Control or net.ListenConfig.Control
// that submits each new IP socket to the server listening on path, before the
// socket connects. Sockets dialing a loopback address are not submitted,
// because loopback traffic does not enter the tunnel.
//
// The returned error wraps ErrRejected when the server rejects the socket.
// To use such sockets anyway, wrap the function and drop that error.
func ControlContext(path string) func(ctx context.Context, network, address string, conn syscall.RawConn) error {
	return func(ctx context.Context, network, address string, conn syscall.RawConn) error {
		if strings.HasPrefix(network, "unix") || isLoopback(address) {
			return nil
		}
		var protectErr error
		err := conn.Control(func(fd uintptr) {
			protectErr = Protect(path, int(fd))
		})
		if err != nil {
			return err
		}
		return protectErr
	}
}

func isLoopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// Control returns a control function without context parameter.
// See ControlContext.
func Control(path string) func(network, address string, conn syscall.RawConn) error {
	return func(network, address string, conn syscall.RawConn) error {
		control := ControlContext(path)
		return control(context.Background(), network, address, conn)
	}
}
