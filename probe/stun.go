package probe

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"time"
)

// stunMinRTT is the shortest round trip that can be a real server.
// Half a millisecond is something local, not the host we asked.
const stunMinRTT = 5 * time.Millisecond

var errStunTooFast = errors.New("ответ слишком быстрый")

func stunPlausible(rtt time.Duration) bool { return rtt >= stunMinRTT }

// STUN binding (RFC 5389) tells a closed UDP path from a path that only
// dislikes QUIC. A QUIC server that stays silent while STUN to the same
// network answers is not "all UDP is blocked".

var stunMagic = []byte{0x21, 0x12, 0xa4, 0x42}

var stunServers = []struct {
	Name string
	Host string
	Port int
}{
	{"Google", "stun.l.google.com", 19302},
	{"Cloudflare", "stun.cloudflare.com", 3478},
}

type STUNResult struct {
	Name string
	Addr string
	OK   bool
	RTT  time.Duration
	Err  string
	// ReplyAddr is the UDP source of the binding response (ip:port).
	// A reply that is too fast to be the host we asked often comes from
	// someone else nearby.
	ReplyAddr string
	// MappedAddr is XOR-MAPPED-ADDRESS (RFC 5389, attribute 0x0020):
	// the address the responder says it sees.
	MappedAddr string
}

func (p *Prober) CheckSTUN(ctx context.Context) []STUNResult {
	out := make([]STUNResult, len(stunServers))
	p.forEach(len(stunServers), func(i int) {
		s := stunServers[i]
		r := STUNResult{Name: s.Name, Addr: net.JoinHostPort(s.Host, strconv.Itoa(s.Port))}
		ips, err := p.LookupHost(ctx, s.Host)
		if err != nil || len(ips) == 0 {
			r.Err = shortErr(err)
			if r.Err == "" {
				r.Err = "нет адреса"
			}
			out[i] = r
			return
		}
		rtt, from, mapped, ok, err := p.stun(ctx, ips[0].String(), s.Port)
		r.OK, r.RTT, r.ReplyAddr, r.MappedAddr = ok, rtt, from, mapped
		if !ok && err != nil {
			r.Err = shortErr(err)
		}
		out[i] = r
	})
	return out
}

func (p *Prober) stun(ctx context.Context, ip string, port int) (time.Duration, string, string, bool, error) {
	req := make([]byte, 20)
	req[0], req[1] = 0x00, 0x01
	copy(req[4:8], stunMagic)
	if _, err := rand.Read(req[8:20]); err != nil {
		return 0, "", "", false, err
	}
	dstIP := net.ParseIP(ip)
	if dstIP == nil {
		return 0, "", "", false, errors.New("нет адреса")
	}
	// Unconnected socket: the source of a too-fast reply may not be the host we asked.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return 0, "", "", false, err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: dstIP, Port: port}
	window := p.silenceWindow(125 * time.Millisecond)
	deadline := time.Now().Add(window)
	_ = conn.SetDeadline(deadline)
	t0 := time.Now()
	if _, err := conn.WriteToUDP(req, dst); err != nil {
		return 0, "", "", false, err
	}
	// One resend, same as QUIC: a single lost datagram is not a block.
	resend := t0.Add(window / 2)
	resent := false
	buf := make([]byte, 512)
	for {
		if !resent {
			_ = conn.SetReadDeadline(resend)
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err == nil && stunReply(buf[:n], req[8:20]) {
			if !stunFromAsked(addr, dstIP) {
				continue
			}
			rtt := time.Since(t0)
			from := ""
			if addr != nil {
				from = addr.String()
			}
			mapped := stunMapped(buf[:n])
			if !stunPlausible(rtt) {
				return rtt, from, mapped, false, errStunTooFast
			}
			return rtt, from, mapped, true, nil
		}
		if err == nil {
			continue
		}
		if resent || ctx.Err() != nil || time.Now().After(deadline) {
			return 0, "", "", false, err
		}
		resent = true
		_ = conn.SetReadDeadline(deadline)
		_, _ = conn.WriteToUDP(req, dst)
	}
}

func stunReply(b, txid []byte) bool {
	return len(b) >= 20 && b[0] == 0x01 && b[1] == 0x01 &&
		string(b[4:8]) == string(stunMagic) && string(b[8:20]) == string(txid)
}

// stunFromAsked is true when the UDP source IP is the host we queried.
// A matching txid from someone else is not an answer from that host.
func stunFromAsked(got *net.UDPAddr, asked net.IP) bool {
	if got == nil || asked == nil || got.IP == nil {
		return false
	}
	return got.IP.Equal(asked)
}

// stunMapped reads XOR-MAPPED-ADDRESS (RFC 5389, 0x0020). Empty if it is absent.
func stunMapped(b []byte) string {
	if len(b) < 20 {
		return ""
	}
	msgLen := int(b[2])<<8 | int(b[3])
	end := 20 + msgLen
	if end > len(b) {
		end = len(b)
	}
	for off := 20; off+4 <= end; {
		typ := int(b[off])<<8 | int(b[off+1])
		ln := int(b[off+2])<<8 | int(b[off+3])
		off += 4
		if ln < 0 || off+ln > end {
			break
		}
		val := b[off : off+ln]
		padded := ln
		if ln%4 != 0 {
			padded += 4 - ln%4
		}
		off += padded
		if typ != 0x0020 {
			continue
		}
		return xorMapped(val, b[8:20])
	}
	return ""
}

func xorMapped(val, txid []byte) string {
	if len(val) < 4 {
		return ""
	}
	xport := int(val[2])<<8 | int(val[3])
	port := xport ^ 0x2112
	switch val[1] {
	case 0x01:
		if len(val) < 8 {
			return ""
		}
		ip := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			ip[i] = val[4+i] ^ stunMagic[i]
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(port))
	case 0x02:
		if len(val) < 20 || len(txid) < 12 {
			return ""
		}
		ip := make(net.IP, 16)
		mask := append(append([]byte{}, stunMagic...), txid...)
		for i := 0; i < 16; i++ {
			ip[i] = val[4+i] ^ mask[i]
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(port))
	default:
		return ""
	}
}
