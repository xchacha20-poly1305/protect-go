//go:build !unix && !windows

package protect

import (
	"context"
	"errors"
	"net"
)

func Protect(path string, fd int) error {
	return errors.ErrUnsupported
}

func ProtectContext(ctx context.Context, path string, fd int) error {
	return errors.ErrUnsupported
}

func Listen(path string) (*net.UnixListener, error) {
	return nil, errors.ErrUnsupported
}

func (s *Server) Serve(listener *net.UnixListener) error {
	return errors.ErrUnsupported
}

func SocketNetwork(fd int) (string, error) {
	return "", errors.ErrUnsupported
}
