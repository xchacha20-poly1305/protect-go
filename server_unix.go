//go:build unix

package protect

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Listen listens on path with mode 0777, so that clients running as other
// users can connect. A stale socket file at path is removed first; any other
// kind of file is left in place and reported as an error.
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
	if err := os.Chmod(path, 0o777); err != nil {
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
	fd, err := receiveDescriptor(conn)
	if err != nil {
		return err
	}
	// The received descriptor is our own reference, and exemption is synchronous.
	defer unix.Close(fd)
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

// receiveDescriptor reads the one message a client sends and returns the single
// descriptor it carries. A message of any other shape is rejected, and every
// descriptor it carried is closed.
func receiveDescriptor(conn *net.UnixConn) (int, error) {
	payload := make([]byte, 1)
	const descriptorSize = 4
	oob := make([]byte, unix.CmsgSpace(descriptorSize))
	n, oobn, flags, _, err := conn.ReadMsgUnix(payload, oob)
	if err != nil {
		return -1, fmt.Errorf("protect: read request: %w", err)
	}
	controlMessages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("protect: parse control messages: %w", err)
	}
	var fds []int
	for i := range controlMessages {
		rights, err := unix.ParseUnixRights(&controlMessages[i])
		if err != nil {
			closeAll(fds)
			return -1, fmt.Errorf("protect: parse unix rights: %w", err)
		}
		fds = append(fds, rights...)
	}
	// Check the shape only after collecting every descriptor, so all of them get closed.
	switch {
	case flags&unix.MSG_CTRUNC != 0:
		err = errors.New("protect: control message truncated")
	case n != 1:
		err = fmt.Errorf("protect: invalid payload length %d", n)
	case len(controlMessages) != 1:
		err = fmt.Errorf("protect: invalid control message count %d", len(controlMessages))
	case len(fds) != 1:
		err = fmt.Errorf("protect: invalid descriptor count %d", len(fds))
	}
	if err != nil {
		closeAll(fds)
		return -1, err
	}
	return fds[0], nil
}

func closeAll(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}
