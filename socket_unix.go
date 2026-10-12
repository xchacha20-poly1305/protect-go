//go:build unix

package protect

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// SocketNetwork returns the Go network name of fd: "tcp4", "tcp6", "udp4" or
// "udp6". Any other kind of socket is an error. An ICMP datagram socket is
// reported as "udp4" or "udp6", because not every system exposes the
// protocol of a socket.
func SocketNetwork(fd int) (string, error) {
	socketType, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return "", fmt.Errorf("protect: get socket type: %w", err)
	}
	var network string
	switch socketType {
	case unix.SOCK_STREAM:
		network = "tcp"
	case unix.SOCK_DGRAM:
		network = "udp"
	default:
		return "", fmt.Errorf("protect: unsupported socket type %d", socketType)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return "", fmt.Errorf("protect: get socket address: %w", err)
	}
	switch address.(type) {
	case *unix.SockaddrInet4:
		return network + "4", nil
	case *unix.SockaddrInet6:
		return network + "6", nil
	default:
		return "", fmt.Errorf("protect: unsupported socket family %T", address)
	}
}
