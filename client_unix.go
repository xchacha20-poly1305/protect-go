//go:build unix

package protect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Protect submits fd to the server listening on path, bounded by DefaultTimeout.
// See ProtectContext.
func Protect(path string, fd int) error {
	return ProtectContext(context.Background(), path, fd)
}

// ProtectContext submits fd to the server listening on path and returns nil
// once the server has exempted it. If the server replies with a failure, the
// error wraps ErrRejected. If ctx has no deadline, DefaultTimeout applies.
//
// fd must be submitted after the socket is created and before it connects or
// sends anything.
func ProtectContext(ctx context.Context, path string, fd int) (err error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	defer func() {
		// The connection deadline follows ctx, so its expiry means ctx is done
		// or about to be. Report the cause instead of an I/O timeout.
		if errors.Is(err, os.ErrDeadlineExceeded) {
			<-ctx.Done()
		}
		if err != nil && ctx.Err() != nil {
			err = fmt.Errorf("protect: %w", ctx.Err())
		}
	}()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return fmt.Errorf("protect: connect: %w", err)
	}
	defer conn.Close()
	unixConn := conn.(*net.UnixConn)
	deadline, _ := ctx.Deadline()
	_ = unixConn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() {
		_ = unixConn.SetDeadline(time.Unix(1, 0))
	})
	defer stop()

	_, _, err = unixConn.WriteMsgUnix([]byte{requestPayload}, unix.UnixRights(fd), nil)
	if err != nil {
		return fmt.Errorf("protect: send descriptor: %w", err)
	}
	reply := make([]byte, 1)
	_, err = io.ReadFull(unixConn, reply)
	if err != nil {
		return fmt.Errorf("protect: read reply: %w", err)
	}
	if reply[0] != ReplySuccess {
		return fmt.Errorf("%w (reply %#02x)", ErrRejected, reply[0])
	}
	return nil
}
