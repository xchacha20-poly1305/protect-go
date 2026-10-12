//go:build unix

package protect

import (
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

var socketKinds = map[string]struct{ domain, socketType int }{
	"tcp4": {unix.AF_INET, unix.SOCK_STREAM},
	"udp4": {unix.AF_INET, unix.SOCK_DGRAM},
	"tcp6": {unix.AF_INET6, unix.SOCK_STREAM},
	"udp6": {unix.AF_INET6, unix.SOCK_DGRAM},
	"unix": {unix.AF_UNIX, unix.SOCK_STREAM},
}

// newSocket creates an unconnected socket of the named kind, closed when the test ends.
func newSocket(t *testing.T, network string) int {
	t.Helper()
	kind := socketKinds[network]
	fd, err := unix.Socket(kind.domain, kind.socketType, 0)
	if errors.Is(err, unix.EAFNOSUPPORT) {
		t.Skip("address family not supported")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func setKeepAlive(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1)
}

func keepAlive(t *testing.T, fd int) bool {
	t.Helper()
	value, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE)
	if err != nil {
		t.Fatal(err)
	}
	return value != 0
}

func TestServerRejectsMalformedRequest(t *testing.T) {
	tests := []struct {
		name string
		oob  func(t *testing.T) []byte
	}{
		{"two descriptors", func(t *testing.T) []byte {
			return unix.UnixRights(newSocket(t, "udp4"), newSocket(t, "udp4"))
		}},
		{"no descriptor", func(*testing.T) []byte { return nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := startServer(t, &Server{Protector: forbiddenProtector(t)})
			oob := test.oob(t)
			reply := exchangeRaw(t, path, 0, func(conn *net.UnixConn) error {
				_, _, err := conn.WriteMsgUnix([]byte{requestPayload}, oob, nil)
				return err
			})
			if reply != ReplyFailure {
				t.Errorf("got reply %#02x", reply)
			}
		})
	}
}

func TestServerRejectsNonSocket(t *testing.T) {
	path := startServer(t, &Server{Verify: func(*Request) error {
		t.Error("verify called for a rejected request")
		return nil
	}, Protector: forbiddenProtector(t)})
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := Protect(path, int(reader.Fd())); !errors.Is(err, ErrRejected) {
		t.Fatalf("got %v, want ErrRejected", err)
	}
}
