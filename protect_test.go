//go:build unix || windows

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
)

// socketPath returns a fresh path for a Unix-domain socket. t.TempDir embeds
// the test name, which can exceed the 104-byte sun_path limit on macOS.
// See https://github.com/golang/go/issues/62614
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "protect")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "protect_path")
}

// startServer serves server on a fresh path and returns that path.
func startServer(t *testing.T, server *Server) string {
	t.Helper()
	path := socketPath(t)
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

// exchangeRaw runs write on a fresh connection after delay and returns the reply.
func exchangeRaw(t *testing.T, path string, delay time.Duration, write func(conn *net.UnixConn) error) byte {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(delay)
	err = write(conn.(*net.UnixConn))
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
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			got, err := SocketNetwork(newSocket(t, network))
			if err != nil {
				t.Fatal(err)
			}
			if got != network {
				t.Errorf("got %q, want %q", got, network)
			}
		})
	}
}

func TestServerProtectsSocketSentByClient(t *testing.T) {
	path := startServer(t, &Server{Protector: ProtectorFunc(setKeepAlive)})

	fd := newSocket(t, "tcp4")
	if err := Protect(path, fd); err != nil {
		t.Fatal(err)
	}
	// The option set on the server's reference shows on the client's socket.
	if !keepAlive(t, fd) {
		t.Error("protector did not receive the client socket")
	}
}

func TestServerWithoutProtectorRepliesSuccess(t *testing.T) {
	path := startServer(t, &Server{})
	if err := Protect(path, newSocket(t, "udp4")); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyReceivesRequest(t *testing.T) {
	var request Request
	path := startServer(t, &Server{Verify: func(r *Request) error {
		request = *r
		return nil
	}})
	if err := Protect(path, newSocket(t, "tcp4")); err != nil {
		t.Fatal(err)
	}
	if request.Conn == nil || request.FD < 0 {
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

			err := Protect(path, newSocket(t, "udp4"))
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("got %v, want ErrRejected", err)
			}
			if err := <-reported; !errors.Is(err, test.want) {
				t.Errorf("server reported %v, want %v", err, test.want)
			}
		})
	}
}

func TestServerAcceptsNonIPSocket(t *testing.T) {
	protected := make(chan struct{}, 1)
	path := startServer(t, &Server{Protector: ProtectorFunc(func(int) error {
		protected <- struct{}{}
		return nil
	})})
	if err := Protect(path, newSocket(t, "unix")); err != nil {
		t.Fatal(err)
	}
	<-protected
}

func TestServerWaitsForSlowClient(t *testing.T) {
	path := startServer(t, &Server{})
	fd := newSocket(t, "udp4")
	reply := exchangeRaw(t, path, 100*time.Millisecond, func(conn *net.UnixConn) error {
		return writeRequest(conn, fd)
	})
	if reply != ReplySuccess {
		t.Errorf("got reply %#02x", reply)
	}
}

func TestProtectContextStopsAtDeadline(t *testing.T) {
	path := socketPath(t)
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
	err = ProtectContext(ctx, path, newSocket(t, "udp4"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want DeadlineExceeded", err)
	}
}

func TestListenKeepsRegularFile(t *testing.T) {
	path := socketPath(t)
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
