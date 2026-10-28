package probe

import (
	"net"
	"syscall"
)

func setDontFragment(c *net.UDPConn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		// IP_DONTFRAGMENT = 14.
		sockErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 14, 1)
	})
	return err == nil && sockErr == nil
}
