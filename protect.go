// Package protect implements the socket protect path protocol.
//
// A tunnel that captures a host's IP traffic also captures sockets of other
// local processes. A client hands each socket that must stay outside the tunnel
// to the server that owns it over a Unix-domain stream socket. The server
// exempts the socket and replies with one octet: [ReplySuccess] or
// [ReplyFailure].
//
// On Unix the socket travels as one SCM_RIGHTS descriptor. Windows AF_UNIX
// sockets carry no descriptors, so there the client sends the value of its
// SOCKET handle, and the server duplicates that handle out of the client
// process. On other systems every operation returns [errors.ErrUnsupported].
package protect

import (
	"errors"
	"net"
	"time"
)

// Reply octets, as defined by shadowsocks-android in
// https://github.com/shadowsocks/shadowsocks-android/commit/7c31f5e5b4a6c806f44fb518a2612c3e3291f74a.
// Any octet other than ReplySuccess is a failure.
const (
	ReplySuccess byte = 0x00
	ReplyFailure byte = 0x01
)

// DefaultTimeout bounds one exchange when the caller sets no other limit.
const DefaultTimeout = 5 * time.Second

// ErrRejected reports that the server replied with an octet other than
// ReplySuccess. The socket is still usable, but its packets may enter the
// tunnel. A client that accepts this checks for it with [errors.Is].
//
// The reply does not always mean that exemption failed. Deployed servers
// disagree on the reply octets, so a successful exemption by such a
// server also yields ErrRejected.
var ErrRejected = errors.New("protect: server rejected the descriptor")

// Protector exempts a socket so that its packets stay outside the tunnel.
// fd is a descriptor on Unix and a SOCKET handle on Windows. It is owned by
// the server and is closed after Protect returns.
type Protector interface {
	Protect(fd int) error
}

// ProtectorFunc adapts a plain function into a Protector.
type ProtectorFunc func(fd int) error

func (f ProtectorFunc) Protect(fd int) error {
	return f(fd)
}

// Request is a valid request received by a Server.
type Request struct {
	// Conn is the connection the request arrived on. It can be used to
	// inspect the credentials of the peer, for example with SO_PEERCRED, or
	// with SIO_AF_UNIX_GETPEERPID on Windows.
	// The reply must not be written to it.
	Conn *net.UnixConn
	// FD is the received descriptor, or on Windows the duplicated SOCKET
	// handle. It is closed after the exchange.
	FD int
	// Network is one of "tcp4", "tcp6", "udp4" and "udp6".
	Network string
}

// Server accepts protect exchanges. The zero value replies success to every
// valid request without changing the socket.
type Server struct {
	// Verify, if set, is called for every valid request before Protector.
	// A non-nil error rejects the request. The server always rejects a
	// descriptor that is not an AF_INET or AF_INET6 socket of type
	// SOCK_STREAM or SOCK_DGRAM, before Verify is called.
	Verify func(request *Request) error
	// Protector exempts the descriptor of each accepted request. If nil,
	// the socket is left unchanged and the server replies success.
	Protector Protector
	// Timeout bounds each exchange. Zero means DefaultTimeout.
	Timeout time.Duration
	// OnError, if set, receives the reason for every failed exchange.
	OnError func(err error)
}

func (s *Server) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return DefaultTimeout
}

func (s *Server) reportError(err error) {
	if s.OnError != nil {
		s.OnError(err)
	}
}
