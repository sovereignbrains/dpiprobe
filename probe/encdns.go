package probe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// encServers: encrypted DNS a user could switch to. The check answers two
// questions per server: does it get through, and does it tell the truth
// about a blocked domain.
var encServers = []struct{ Name, Kind, Addr string }{
	{"Cloudflare", "DoH", "https://1.1.1.1/dns-query"},
	{"Cloudflare", "DoT", "1.1.1.1"},
	{"Google", "DoH", "https://dns.google/dns-query"},
	{"Google", "DoT", "dns.google"},
	{"Quad9", "DoH", "https://dns.quad9.net/dns-query"},
	{"Quad9", "DoT", "dns.quad9.net"},
	{"AdGuard", "DoH", "https://dns.adguard-dns.com/dns-query"},
	{"AdGuard", "DoT", "dns.adguard-dns.com"},
	{"NextDNS", "DoH", "https://dns.nextdns.io/dns-query"},
	{"NextDNS", "DoT", "dns.nextdns.io"},
	{"Mullvad", "DoH", "https://dns.mullvad.net/dns-query"},
	{"Mullvad", "DoT", "dns.mullvad.net"},
	{"DNS.SB", "DoH", "https://doh.dns.sb/dns-query"},
	{"DNS.SB", "DoT", "dot.sb"},
	{"Comss.one", "DoH", "https://dns.comss.one/dns-query"},
	{"Comss.one", "DoT", "dns.comss.one"},
	{"XboxDNS", "DoH", "https://xbox-dns.ru/dns-query"},
	{"XboxDNS", "DoT", "xbox-dns.ru"},
	{"Yandex", "DoH", "https://common.dot.dns.yandex.net/dns-query"},
	{"Yandex", "DoT", "common.dot.dns.yandex.net"},
}

const (
	EncHonest   = "честный"
	EncFiltered = "фильтрует"
)

type EncResult struct {
	Name, Kind, Addr string
	Status           string // OK or why it doesn't get through
	RTT              time.Duration
	Truth            string // EncHonest / EncFiltered / "" when unknown
	Detail           string
}

func (p *Prober) checkEncrypted(ctx context.Context, truth map[string]*domainTruth) []EncResult {
	out := make([]EncResult, len(encServers))
	p.forEach(len(encServers), func(i int) {
		s := encServers[i]
		r := EncResult{Name: s.Name, Kind: s.Kind, Addr: s.Addr}
		query := func(name string) (dnsAnswer, time.Duration, error) {
			qctx, cancel := p.quick(ctx)
			defer cancel()
			if s.Kind == "DoT" {
				return p.DoT(qctx, s.Addr, name, typeA)
			}
			return p.DoH(qctx, s.Addr, name, typeA)
		}
		a, rtt, err := query(dnsControl)
		if err != nil {
			r.Status, r.Detail = statusFor(stageTLS, err), shortErr(err)
			out[i] = r
			return
		}
		if len(a.ips) == 0 {
			r.Status, r.Detail = "NO ANSWER", describeAnswer(a, ASInfo{})
			out[i] = r
			return
		}
		r.Status, r.RTT = "OK", rtt
		// One blocked domain with known truth is enough to see filtering.
		for _, d := range dnsForbidden {
			t := truth[d]
			if !t.has() {
				continue
			}
			if a, _, err := query(d); err == nil {
				if ok, as := p.answerOK(ctx, t, a); ok {
					r.Truth = EncHonest
				} else {
					r.Truth, r.Detail = EncFiltered, d+": "+describeAnswer(a, as)
				}
			}
			break
		}
		out[i] = r
	})
	return out
}

// DoT asks over DNS-over-TLS (RFC 7858). An IP-literal addr is verified
// against the certificate's IP SANs.
func (p *Prober) DoT(ctx context.Context, addr, name string, qtype uint16) (dnsAnswer, time.Duration, error) {
	ip := addr
	if net.ParseIP(addr) == nil {
		ips, err := p.LookupHost(ctx, addr)
		if err != nil {
			return dnsAnswer{}, 0, err
		}
		ip = ips[0].String()
	}
	t0 := time.Now()
	dialTimeout := p.Timeout
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left > 0 && left < dialTimeout {
			dialTimeout = left
		}
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: &tls.Config{ServerName: addr}}
	conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, "853"))
	if err != nil {
		return dnsAnswer{}, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	q := buildQuery(name, qtype)
	if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
		return dnsAnswer{}, 0, err
	}
	var n [2]byte
	if _, err := io.ReadFull(conn, n[:]); err != nil {
		return dnsAnswer{}, 0, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return dnsAnswer{}, 0, err
	}
	a, err := parseResponse(msg, q)
	return a, time.Since(t0), err
}
