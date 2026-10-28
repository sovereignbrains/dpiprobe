//go:build !windows && !linux

package probe

import "net"

func setDontFragment(*net.UDPConn) bool { return false }
