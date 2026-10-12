//go:build unix || windows

package protect

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"
)

// Listen listens on path and opens it to clients running as other users: mode
// 0777 on Unix, and on Windows a DACL that lets every user connect. A stale
// socket file at path is removed first; any other kind of file is left in
// place and reported as an error.
func Listen(path string) (*net.UnixListener, error) {
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode().Type() == fs.ModeSocket:
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("protect: remove stale socket: %w", err)
		}
	case err == nil:
		return nil, fmt.Errorf("protect: %s exists and is not a socket", path)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("protect: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("protect: %w", err)
	}
	if err := allowAllUsers(path); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("protect: %w", err)
	}
	return listener, nil
}

// Serve accepts connections on listener and handles each in its own
// goroutine. It returns nil once listener is closed, or the error that
// stopped it from accepting.
func (s *Server) Serve(listener *net.UnixListener) error {
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("protect: accept: %w", err)
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.timeout()))
	reply := ReplySuccess
	if err := s.serve(conn); err != nil {
		reply = ReplyFailure
		s.reportError(err)
	}
	if _, err := conn.Write([]byte{reply}); err != nil {
		s.reportError(fmt.Errorf("protect: write reply: %w", err))
	}
}

func (s *Server) serve(conn *net.UnixConn) error {
	fd, err := receiveSocket(conn)
	if err != nil {
		return err
	}
	// The received socket is our own reference, and exemption is synchronous.
	defer closeSocket(fd)
	network, err := SocketNetwork(fd)
	if err != nil {
		return err
	}
	if s.Verify != nil {
		err = s.Verify(&Request{Conn: conn, FD: fd, Network: network})
		if err != nil {
			return fmt.Errorf("protect: verify: %w", err)
		}
	}
	if s.Protector == nil {
		return nil
	}
	err = s.Protector.Protect(fd)
	if err != nil {
		return fmt.Errorf("protect: exempt: %w", err)
	}
	return nil
}
