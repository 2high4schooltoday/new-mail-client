//go:build linux

package pamreset

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerCredentials(conn *net.UnixConn) (uid int, gid int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Ucred
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, ctrlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if ctrlErr != nil {
		return 0, 0, ctrlErr
	}
	if cred == nil {
		return 0, 0, fmt.Errorf("missing peer credentials")
	}
	return int(cred.Uid), int(cred.Gid), nil
}
