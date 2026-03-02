//go:build !linux

package pamreset

import (
	"net"
	"os"
)

// Non-linux fallback for local development and tests.
func peerCredentials(conn *net.UnixConn) (uid int, gid int, err error) {
	_ = conn
	return os.Getuid(), os.Getgid(), nil
}
