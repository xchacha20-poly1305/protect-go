//go:build unix

package protect

import (
	"net"

	"golang.org/x/sys/unix"
)

// requestPayload is the octet that carries the descriptor. Its value has no meaning.
const requestPayload byte = 0x01

// writeRequest sends fd as the single SCM_RIGHTS descriptor of a one-octet message.
func writeRequest(conn *net.UnixConn, fd int) error {
	_, _, err := conn.WriteMsgUnix([]byte{requestPayload}, unix.UnixRights(fd), nil)
	return err
}
