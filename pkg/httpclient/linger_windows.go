//go:build windows

package httpclient

import "syscall"

func setSocketLinger(c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptLinger(
			syscall.Handle(fd),
			syscall.SOL_SOCKET,
			syscall.SO_LINGER,
			&syscall.Linger{Onoff: 1, Linger: 0},
		)
	})
	if err != nil {
		return err
	}
	return sockErr
}
