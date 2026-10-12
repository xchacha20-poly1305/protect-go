//go:build unix

package protect

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func newSocket(t *testing.T, domain, socketType int) int {
	t.Helper()
	fd, err := unix.Socket(domain, socketType, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func newUDPSocket(t *testing.T) int {
	return newSocket(t, unix.AF_INET, unix.SOCK_DGRAM)
}

// startServer serves server on a fresh path and returns that path.
func startServer(t *testing.T, server *Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "protect_path")
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = listener.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return path
}

// exchangeRaw sends one hand-built message after delay and returns the reply.
func exchangeRaw(t *testing.T, path string, delay time.Duration, payload, oob []byte) byte {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(delay)
	_, _, err = conn.(*net.UnixConn).WriteMsgUnix(payload, oob, nil)
	if err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 1)
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatal(err)
	}
	return reply[0]
}

func forbiddenProtector(t *testing.T) Protector {
	return ProtectorFunc(func(int) error {
		t.Error("protector called for a rejected request")
		return nil
	})
}

func TestSocketNetwork(t *testing.T) {
	tests := []struct {
		domain     int
		socketType int
		network    string
	}{
		{unix.AF_INET, unix.SOCK_STREAM, "tcp4"},
		{unix.AF_INET, unix.SOCK_DGRAM, "udp4"},
		{unix.AF_INET6, unix.SOCK_STREAM, "tcp6"},
		{unix.AF_INET6, unix.SOCK_DGRAM, "udp6"},
	}
	for _, test := range tests {
		t.Run(test.network, func(t *testing.T) {
			fd, err := unix.Socket(test.domain, test.socketType, 0)
			if errors.Is(err, unix.EAFNOSUPPORT) {
				t.Skip("address family not supported")
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })

			network, err := SocketNetwork(fd)
			if err != nil {
				t.Fatal(err)
			}
			if network != test.network {
				t.Errorf("got %q, want %q", network, test.network)
			}
		})
	}
}

func TestServerProtectsDescriptorSentByClient(t *testing.T) {
	protected := make(chan uint64, 1)
	path := startServer(t, &Server{Protector: ProtectorFunc(func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		protected <- uint64(stat.Ino)
		return nil
	})})

	fd := newUDPSocket(t)
	if err := Protect(path, fd); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	if got := <-protected; got != uint64(stat.Ino) {
		t.Errorf("protector received inode %d, want %d", got, stat.Ino)
	}
}

func TestServerWithoutProtectorRepliesSuccess(t *testing.T) {
	path := startServer(t, &Server{})
	if err := Protect(path, newUDPSocket(t)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyReceivesRequest(t *testing.T) {
	var request Request
	path := startServer(t, &Server{Verify: func(r *Request) error {
		request = *r
		return nil
	}})
	if err := Protect(path, newSocket(t, unix.AF_INET, unix.SOCK_STREAM)); err != nil {
		t.Fatal(err)
	}
	if request.Network != "tcp4" || request.Conn == nil {
		t.Errorf("unexpected request %+v", request)
	}
}

func TestClientReportsRejection(t *testing.T) {
	errVerify := errors.New("unexpected peer")
	errExempt := errors.New("exempt failed")
	tests := []struct {
		name   string
		server *Server
		want   error
	}{
		{"verify", &Server{Verify: func(*Request) error { return errVerify }, Protector: forbiddenProtector(t)}, errVerify},
		{"protector", &Server{Protector: ProtectorFunc(func(int) error { return errExempt })}, errExempt},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reported := make(chan error, 1)
			test.server.OnError = func(err error) { reported <- err }
			path := startServer(t, test.server)

			err := Protect(path, newUDPSocket(t))
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("got %v, want ErrRejected", err)
			}
			if err := <-reported; !errors.Is(err, test.want) {
				t.Errorf("server reported %v, want %v", err, test.want)
			}
		})
	}
}

func TestServerRejectsNonIPSocket(t *testing.T) {
	path := startServer(t, &Server{Verify: func(*Request) error {
		t.Error("verify called for a rejected request")
		return nil
	}, Protector: forbiddenProtector(t)})
	err := Protect(path, newSocket(t, unix.AF_UNIX, unix.SOCK_STREAM))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("got %v, want ErrRejected", err)
	}
}

func TestServerWaitsForSlowClient(t *testing.T) {
	path := startServer(t, &Server{})
	reply := exchangeRaw(t, path, 100*time.Millisecond, []byte{requestPayload}, unix.UnixRights(newUDPSocket(t)))
	if reply != ReplySuccess {
		t.Errorf("got reply %#02x", reply)
	}
}

func TestServerRejectsMalformedRequest(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		oob     func(t *testing.T) []byte
	}{
		{"two descriptors", []byte{requestPayload}, func(t *testing.T) []byte {
			return unix.UnixRights(newUDPSocket(t), newUDPSocket(t))
		}},
		{"no descriptor", []byte{requestPayload}, func(*testing.T) []byte { return nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := startServer(t, &Server{Protector: forbiddenProtector(t)})
			reply := exchangeRaw(t, path, 0, test.payload, test.oob(t))
			if reply != ReplyFailure {
				t.Errorf("got reply %#02x", reply)
			}
		})
	}
}

func TestProtectContextStopsAtDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protect_path")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Accept and never reply.
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn)
		}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err = ProtectContext(ctx, path, newUDPSocket(t))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want DeadlineExceeded", err)
	}
}

func TestListenKeepsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protect_path")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("Listen replaced a regular file")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestControl(t *testing.T) {
	protected := make(chan struct{}, 1)
	path := startServer(t, &Server{Protector: ProtectorFunc(func(int) error {
		protected <- struct{}{}
		return nil
	})})
	control := ControlContext(path)

	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()

	t.Run("loopback", func(t *testing.T) {
		dialer := net.Dialer{
			ControlContext: func(ctx context.Context, network, address string, conn syscall.RawConn) error {
				if err := control(ctx, network, address, conn); err != nil {
					return err
				}
				select {
				case <-protected:
					t.Error("loopback socket submitted")
				default:
				}
				return nil
			},
		}
		conn, err := dialer.DialContext(t.Context(), "udp4", packetConn.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	})

	t.Run("listen", func(t *testing.T) {
		listenConfig := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				return control(t.Context(), network, address, c)
			},
		}
		conn, err := listenConfig.ListenPacket(t.Context(), "udp4", "")
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		<-protected
	})
}
