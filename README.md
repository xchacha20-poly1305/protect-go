# protect-go

[![Go Reference](https://pkg.go.dev/badge/github.com/xchacha20-poly1305/protect-go.svg)](https://pkg.go.dev/github.com/xchacha20-poly1305/protect-go)

A Go implementation of the socket protect path protocol: a client hands a
socket descriptor over a Unix-domain socket to the program that owns a tunnel,
and that program exempts the socket from the tunnel before any packet is sent.

The only dependency is `golang.org/x/sys`. The protocol needs `SCM_RIGHTS`, so it
works on Unix systems only; elsewhere every call returns `errors.ErrUnsupported`.

## Client

```go
err := protect.Protect(path, fd)
```

Submit the socket after it is created and before it connects. To protect every
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
listener, err := protect.Listen(path) // mode 0777; replaces a stale socket file
if err != nil {
	return err
}
defer listener.Close()

server := &protect.Server{
	// Optional. Called for every valid request; an error rejects it.
	Verify: func(request *protect.Request) error {
		// Inspect request.Conn (peer credentials), request.FD, request.Network.
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

The server always rejects a descriptor that is not an `AF_INET` or `AF_INET6`
socket of type `SOCK_STREAM` or `SOCK_DGRAM`, before calling `Verify`. Each
exchange is bounded by `Server.Timeout` (default 5 seconds).
