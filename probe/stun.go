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
		rtt, ok, err := p.stun(ctx, ips[0].String(), s.Port)
		r.OK, r.RTT = ok, rtt
		if !ok && err != nil {
			r.Err = shortErr(err)
		}
		out[i] = r
	})
	return out
}

func (p *Prober) stun(ctx context.Context, ip string, port int) (time.Duration, bool, error) {
	req := make([]byte, 20)
	req[0], req[1] = 0x00, 0x01
	copy(req[4:8], stunMagic)
	if _, err := rand.Read(req[8:20]); err != nil {
		return 0, false, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return 0, false, err
	}
	defer c.Close()
	window := p.silenceWindow(125 * time.Millisecond)
	_ = c.SetDeadline(time.Now().Add(window))
	t0 := time.Now()
	if _, err := c.Write(req); err != nil {
		return 0, false, err
	}
	// One resend, same as QUIC: a single lost datagram is not a block.
	resend := time.Now().Add(window / 2)
	resent := false
	buf := make([]byte, 512)
	for {
		if !resent {
			_ = c.SetReadDeadline(resend)
		}
		n, err := c.Read(buf)
		if err == nil && stunReply(buf[:n], req[8:20]) {
			rtt := time.Since(t0)
			if !stunPlausible(rtt) {
				return rtt, false, errStunTooFast
			}
			return rtt, true, nil
		}
		if err == nil {
			continue
		}
		if resent || ctx.Err() != nil || time.Now().After(t0.Add(window)) {
			return 0, false, err
		}
		resent = true
		_ = c.SetReadDeadline(t0.Add(window))
		_, _ = c.Write(req)
	}
}

func stunReply(b, txid []byte) bool {
	return len(b) >= 20 && b[0] == 0x01 && b[1] == 0x01 &&
		string(b[4:8]) == string(stunMagic) && string(b[8:20]) == string(txid)
}
