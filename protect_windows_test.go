package protect

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

var socketKinds = map[string]struct{ domain, socketType, protocol int }{
	"tcp4": {windows.AF_INET, windows.SOCK_STREAM, 0},
	"udp4": {windows.AF_INET, windows.SOCK_DGRAM, 0},
	"tcp6": {windows.AF_INET6, windows.SOCK_STREAM, 0},
	"udp6": {windows.AF_INET6, windows.SOCK_DGRAM, 0},
	"ip4":  {windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_ICMP},
	"ip6":  {windows.AF_INET6, windows.SOCK_RAW, windows.IPPROTO_ICMPV6},
	"unix": {windows.AF_UNIX, windows.SOCK_STREAM, 0},
}

// newSocket creates an unconnected socket of the named kind, closed when the test ends.
func newSocket(t *testing.T, network string) int {
	t.Helper()
	kind := socketKinds[network]
	handle, err := windows.Socket(kind.domain, kind.socketType, kind.protocol)
	if errors.Is(err, windows.WSAEAFNOSUPPORT) {
		t.Skip("address family not supported")
	}
	if errors.Is(err, windows.WSAEACCES) {
		t.Skip("raw sockets require administrator")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.Closesocket(handle) })
	return int(handle)
}

func setKeepAlive(fd int) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_KEEPALIVE, 1)
}

func keepAlive(t *testing.T, fd int) bool {
	t.Helper()
	value, err := windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_KEEPALIVE)
	if err != nil {
		t.Fatal(err)
	}
	return value != 0
}

func TestServerRejectsMalformedRequest(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
	}{
		{"short request", []byte{0x01, 0x02, 0x03, 0x04}},
		{"invalid handle", binary.LittleEndian.AppendUint64(nil, 0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := startServer(t, &Server{Protector: forbiddenProtector(t)})
			reply := exchangeRaw(t, path, 0, func(conn *net.UnixConn) error {
				if _, err := conn.Write(test.request); err != nil {
					return err
				}
				return conn.CloseWrite()
			})
			if reply != ReplyFailure {
				t.Errorf("got reply %#02x", reply)
			}
		})
	}
}

func TestServerRejectsNonSocketHandle(t *testing.T) {
	path := startServer(t, &Server{Protector: forbiddenProtector(t)})
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(event)
	if err := Protect(path, int(event)); !errors.Is(err, ErrRejected) {
		t.Fatalf("got %v, want ErrRejected", err)
	}
}

func TestRawSocket(t *testing.T) {
	for _, network := range []string{"ip4", "ip6"} {
		t.Run(network, func(t *testing.T) {
			fd := newSocket(t, network)
			got, err := SocketNetwork(fd)
			if err != nil {
				t.Fatal(err)
			}
			if got != network {
				t.Errorf("got %q, want %q", got, network)
			}
			path := startServer(t, &Server{})
			if err := Protect(path, fd); err != nil {
				t.Fatal(err)
			}
		})
	}
}
