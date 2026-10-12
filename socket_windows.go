package protect

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// soProtocolInfoW is SO_PROTOCOL_INFOW from winsock2.h.
const soProtocolInfoW = 0x2005

// SocketNetwork returns the Go network name of the socket handle fd: "tcp4",
// "tcp6", "udp4", "udp6", or "ip4" and "ip6" for a raw socket, such as one
// that sends ICMP echoes. The protocol of a raw socket is not reported. Any
// other kind of socket is an error.
func SocketNetwork(fd int) (string, error) {
	info, err := protocolInfo(windows.Handle(fd))
	if err != nil {
		return "", err
	}
	var network string
	switch info.SocketType {
	case windows.SOCK_STREAM:
		network = "tcp"
	case windows.SOCK_DGRAM:
		network = "udp"
	case windows.SOCK_RAW:
		network = "ip"
	default:
		return "", fmt.Errorf("protect: unsupported socket type %d", info.SocketType)
	}
	switch info.AddressFamily {
	case windows.AF_INET:
		return network + "4", nil
	case windows.AF_INET6:
		return network + "6", nil
	default:
		return "", fmt.Errorf("protect: unsupported socket family %d", info.AddressFamily)
	}
}

// protocolInfo reads the protocol of a socket. Unlike getsockname, it also
// works on a socket that is not bound yet.
func protocolInfo(handle windows.Handle) (*windows.WSAProtocolInfo, error) {
	var info windows.WSAProtocolInfo
	size := int32(unsafe.Sizeof(info))
	err := windows.Getsockopt(handle, windows.SOL_SOCKET, soProtocolInfoW, (*byte)(unsafe.Pointer(&info)), &size)
	if err != nil {
		return nil, fmt.Errorf("protect: get socket protocol: %w", err)
	}
	return &info, nil
}
