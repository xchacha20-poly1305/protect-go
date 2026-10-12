//go:build unix

package protect

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func allowAllUsers(path string) error {
	return os.Chmod(path, 0o777)
}

// receiveSocket reads the one message a client sends and returns the single
// socket it carries. A message of any other shape, or a descriptor that is not
// a socket, is rejected, and every descriptor it carried is closed.
func receiveSocket(conn *net.UnixConn) (int, error) {
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
	_, err = unix.GetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		closeSocket(fds[0])
		return -1, fmt.Errorf("protect: descriptor is not a socket: %w", err)
	}
	return fds[0], nil
}

func closeSocket(fd int) {
	_ = unix.Close(fd)
}

func closeAll(fds []int) {
	for _, fd := range fds {
		closeSocket(fd)
	}
}
