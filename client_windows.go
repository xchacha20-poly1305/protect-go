package protect

import (
	"encoding/binary"
	"net"
)

// requestLength is the length of a Windows request: the handle value of the
// socket as an unsigned little-endian integer. Every architecture Windows runs
// on is little-endian, so the request is the in-memory form of the value.
const requestLength = 8

// writeRequest sends the handle value of fd. The server duplicates the handle
// out of this process, so fd must stay open until the reply arrives.
func writeRequest(conn *net.UnixConn, fd int) error {
	_, err := conn.Write(binary.LittleEndian.AppendUint64(nil, uint64(fd)))
	return err
}
