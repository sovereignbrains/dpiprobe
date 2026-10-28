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
		// IP_MTU_DISCOVER = 10, IP_PMTUDISC_DO = 2.
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 10, 2)
	})
	return err == nil && sockErr == nil
}
