# protect-go

[![Go Reference](https://pkg.go.dev/badge/github.com/xchacha20-poly1305/protect-go.svg)](https://pkg.go.dev/github.com/xchacha20-poly1305/protect-go)

A Go implementation of the socket protect path protocol: a client hands a
socket descriptor over a Unix-domain socket to the program that owns a tunnel,
and that program exempts the socket from the tunnel before any packet is sent.

The only dependency is `golang.org/x/sys`. On Unix the socket travels as an
`SCM_RIGHTS` descriptor. Windows `AF_UNIX` sockets carry no descriptors, so on
Windows (10 version 1803 or later) the client sends its `SOCKET` handle value
and the server duplicates the handle out of the client process; see the
[Windows draft](https://github.com/xchacha20-poly1305/husi/blob/dev/docs/protect_windows.md).
On other systems every call returns `errors.ErrUnsupported`.

## Client

```go
err := protect.Protect(path, fd)
```

Submit the socket after it is created and before it connects. On Windows, `fd`
is the `SOCKET` handle, and it must stay open until `Protect` returns. To protect every
socket of a `net.Dialer` or `net.ListenConfig`:

```go
dialer := net.Dialer{Control: protect.Control(path)}
```

Sockets dialing a loopback address are not submitted.

When the server replies with a failure, the error wraps `protect.ErrRejected`.
The socket is still usable, but its packets may enter the tunnel. Some deployed
servers reply with a non-standard octet on success, so a client that prefers to
keep working can ignore the rejection:

```go
control := protect.Control(path)
dialer := net.Dialer{Control: func(network, address string, conn syscall.RawConn) error {
	err := control(network, address, conn)
	if errors.Is(err, protect.ErrRejected) {
		return nil
	}
	return err
}}
```

## Server

```go
listener, err := protect.Listen(path) // open to all users; replaces a stale socket file
if err != nil {
	return err
}
defer listener.Close()

server := &protect.Server{
	// Optional. Called for every valid request; an error rejects it.
	Verify: func(request *protect.Request) error {
		// Inspect request.Conn (peer credentials) or request.FD.
		return nil
	},
	// Exempts the socket, e.g. VpnService.protect, SO_BINDTODEVICE or SO_MARK.
	// If nil, the socket is left unchanged and the server replies success.
	Protector: protect.ProtectorFunc(func(fd int) error {
		return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)
	}),
	OnError: func(err error) { log.Print(err) },
}
return server.Serve(listener) // returns nil once listener is closed
```

The protocol accepts a socket of any family, type and protocol, such as a TCP,
UDP, ICMP, raw or packet socket; the `Protector` rejects what it cannot exempt.
`protect.SocketNetwork(fd)` classifies an IP socket for it. The server always
rejects a descriptor that is not a socket, before calling `Verify`. Each
exchange is bounded by `Server.Timeout` (default 5 seconds).

On Windows, `Listen` gives every user read and write access to the socket file,
and the server needs `PROCESS_DUP_HANDLE` access to each client process, which
a server running as `LocalSystem` has. Exemption usually sets `IP_UNICAST_IF`
or `IPV6_UNICAST_IF`.
