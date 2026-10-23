package probe

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

// QUIC is where UDP-based VPN protocols live (Hysteria2, TUIC, and HTTP/3
// itself): an ISP can drop it by SNI, by address, or all UDP to port 443.
// Many sites don't speak QUIC at all, so silence alone proves nothing — the
// same cross-probes as for TLS tell the cases apart.

// quicForeignControls answer QUIC to any name: a blocked name sent there
// shows DPI on the name alone.
var quicForeignControls = []string{"www.google.com", "www.youtube.com", "cloudflare.com"}

type QUICResult struct {
	Domain  string
	IP      string
	Status  string // OK, NO REPLY, FAKE, ICMP, or a socket/packet error
	Verdict string
	RTT     time.Duration
	// PassesToRU: the blocked name got a reply from a Russian address.
	PassesToRU bool
}

type QUICReport struct {
	// Control: a foreign QUIC server with its own name; empty when none answered.
	Control    string
	ControlRTT time.Duration
	// ControlName is set when the usual controls were silent and a site
	// that answered stands in for them.
	ControlName string
	// RUControl answered QUIC from Russia.
	RUControl bool
	Sites     []QUICResult
	Targets   []QUICResult
}

func (p *Prober) quicWait() time.Duration { return min(p.Timeout, 3*time.Second) }

// quicProbe sends one Initial and waits for the server's reply. A second copy
// goes out after a second: a single lost datagram is not a block. "FAKE":
// only QUIC-looking datagrams not addressed to us came back — something on
// the way answers instead of the server.
func (p *Prober) quicProbe(ctx context.Context, ip string, port int, sni string) (string, time.Duration) {
	pkt, scid, err := buildQUICInitial(ctx, sni, []string{"h3"})
	if err != nil {
		return "ERR", 0
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return statusFor(stageTCP, err), 0
	}
	defer c.Close()
	t0 := time.Now()
	deadline := t0.Add(p.quicWait())
	_ = c.SetDeadline(deadline)
	if _, err := c.Write(pkt); err != nil {
		return "ERR", 0
	}
	resend := t0.Add(min(time.Second, p.quicWait()/2))
	resent, fake := false, false
	buf := make([]byte, 2048)
	for {
		if !resent {
			_ = c.SetReadDeadline(resend)
		} else {
			_ = c.SetReadDeadline(deadline)
		}
		n, err := c.Read(buf)
		if err == nil {
			if quicReply(buf[:n], scid) {
				return "OK", time.Since(t0)
			}
			fake = fake || quicLongHeader(buf[:n])
			continue
		}
		if kindOf(err) == kUnreach || kindOf(err) == kRefused || kindOf(err) == kReset {
			// ICMP port unreachable comes back as a refused/reset read on Windows.
			return "ICMP", 0
		}
		if resent || ctx.Err() != nil || time.Now().After(deadline) {
			if fake {
				return "FAKE", 0
			}
			return "NO REPLY", 0
		}
		resent = true
		_, _ = c.Write(pkt)
	}
}

func (p *Prober) quicControl(ctx context.Context) (string, time.Duration) {
	for _, h := range quicForeignControls {
		ips, err := p.LookupHost(ctx, h)
		if err != nil {
			continue
		}
		if rtt, ok := p.quicAnyName(ctx, ips[0].String(), h); ok {
			return ips[0].String(), rtt
		}
	}
	return "", 0
}

// quicAnyName: the server answers its own name and a neutral one alike.
// Only such a server can show that a blocked name is cut on the way —
// some (Cloudflare among them) stay silent to a name they don't host.
func (p *Prober) quicAnyName(ctx context.Context, ip, own string) (time.Duration, bool) {
	st, rtt := p.quicProbe(ctx, ip, 443, own)
	if st != "OK" {
		return 0, false
	}
	neutral, _ := p.quicProbe(ctx, ip, 443, tlsRUControl)
	return rtt, neutral == "OK"
}

// CheckQUIC probes the sites over QUIC and, separately, the user's own
// servers on their ports (Hysteria2, TUIC).
func (p *Prober) CheckQUIC(ctx context.Context, domains []string, targets []Target) QUICReport {
	var r QUICReport
	var ru string
	// Own servers alone need no controls: they get no cross-probes.
	if len(domains) > 0 {
		r.Control, r.ControlRTT = p.quicControl(ctx)
		if ips, err := p.LookupHost(ctx, tlsRUControl); err == nil {
			ru = ips[0].String()
			st, _ := p.quicProbe(ctx, ru, 443, tlsRUControl)
			r.RUControl = st == "OK"
		}
	}
	r.Sites = make([]QUICResult, len(domains))
	r.Targets = make([]QUICResult, len(targets))
	// First every site with its own name; the cross-probes need a control,
	// and when the usual ones are silent (a VPN client rejecting QUIC to
	// Google, say) any foreign site that answered serves as one.
	n := len(domains) + len(targets)
	var done atomic.Int64
	report := func() {
		if p.Progress != nil {
			p.Progress(int(done.Add(1)), n)
		}
	}
	p.forEach(len(domains), func(i int) {
		r.Sites[i] = p.quicFirst(ctx, domains[i])
		if r.Sites[i].Status == "OK" || r.Sites[i].IP == "" {
			report()
		}
	})
	if r.Control == "" {
		for _, s := range r.Sites {
			if s.Status != "OK" || p.russian(ctx, s.IP) {
				continue
			}
			if _, ok := p.quicAnyName(ctx, s.IP, s.Domain); ok {
				r.Control, r.ControlRTT, r.ControlName = s.IP, s.RTT, s.Domain
				break
			}
		}
	}
	p.forEach(n, func(i int) {
		if i >= len(domains) {
			r.Targets[i-len(domains)] = p.checkQUICTarget(ctx, targets[i-len(domains)])
			report()
		} else if s := &r.Sites[i]; s.Status != "OK" && s.IP != "" {
			p.quicCross(ctx, s, r.Control, ru)
			report()
		}
	})
	return r
}

// russian: the address is announced from Russia, useless as a foreign control.
func (p *Prober) russian(ctx context.Context, ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed == nil || p.ASOf(ctx, parsed).CC == "RU"
}

func (p *Prober) quicFirst(ctx context.Context, domain string) QUICResult {
	r := QUICResult{Domain: domain}
	ips, err := p.LookupHost(ctx, domain)
	if err != nil {
		r.Status, r.Verdict = "DNS FAIL", shortErr(err)
		return r
	}
	r.IP = ips[0].String()
	r.Status, r.RTT = p.quicProbe(ctx, r.IP, 443, domain)
	return r
}

// quicCross explains a site that stayed silent with its own name.
func (p *Prober) quicCross(ctx context.Context, r *QUICResult, control, ru string) {
	if r.Status == "FAKE" {
		r.Verdict = "ответил не сервер: пакет на чужой запрос, QUIC перехватывают по пути"
		return
	}
	domain := r.Domain
	sameIP, _ := p.quicProbe(ctx, r.IP, 443, tlsRUControl)
	if ru != "" {
		st, _ := p.quicProbe(ctx, ru, 443, domain)
		r.PassesToRU = st == "OK"
	}
	if control == "" {
		if sameIP == "OK" {
			r.Verdict = "похоже на DPI по SNI (нет зарубежного QUIC-сервера для сверки)"
		} else {
			r.Verdict = "нет ответа и с нейтральным SNI"
		}
		return
	}
	foreign, _ := p.quicProbe(ctx, control, 443, domain)
	switch {
	case sameIP == "OK" && foreign != "OK":
		r.Verdict = "DPI по SNI: имя режется и на чистом адресе"
	case sameIP != "OK" && foreign != "OK":
		r.Verdict = "имя режется; адрес по QUIC не отвечает"
	case sameIP != "OK":
		r.Verdict = "адрес не отвечает по QUIC (QUIC у сайта нет или UDP к адресу закрыт)"
	default:
		if again, _ := p.quicProbe(ctx, r.IP, 443, domain); again == "OK" {
			r.Status, r.Verdict = "OK", "нестабильно: со второй попытки прошло"
		} else {
			r.Verdict = "по отдельности адрес и имя проходят — блок только на их сочетание"
		}
	}
}

// checkQUICTarget: does the user's own UDP server answer at all. Hysteria2
// with obfuscation (salamander) answers nothing to a plain Initial — that is
// reported, not judged.
func (p *Prober) checkQUICTarget(ctx context.Context, t Target) QUICResult {
	r := QUICResult{Domain: net.JoinHostPort(t.ID, strconv.Itoa(t.Port))}
	ips, err := p.LookupHost(ctx, t.IP)
	if err != nil {
		r.Status, r.Verdict = "DNS FAIL", shortErr(err)
		return r
	}
	r.IP = ips[0].String()
	sni := t.SNI
	if sni == "" {
		sni = t.IP
		if net.ParseIP(sni) != nil {
			sni = defaultSNI
		}
	}
	r.Status, r.RTT = p.quicProbe(ctx, r.IP, t.Port, sni)
	switch r.Status {
	case "OK":
		r.Verdict = "сервер отвечает по UDP"
	case "ICMP":
		r.Verdict = "порт закрыт: на этом порту UDP-сервера нет"
	case "FAKE":
		r.Verdict = "ответил не сервер: QUIC к нему перехватывают по пути"
	default:
		if sni != tlsRUControl {
			if st, _ := p.quicProbe(ctx, r.IP, t.Port, tlsRUControl); st == "OK" {
				r.Verdict = "отвечает только с другим SNI — имя " + sni + " режут"
				return r
			}
		}
		r.Verdict = "нет ответа: UDP к серверу режут, сервер не QUIC или с обфускацией"
	}
	return r
}
