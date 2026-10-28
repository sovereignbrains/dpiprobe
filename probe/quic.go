package probe

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	STUN      []STUNResult
	// FatStatus is the 1400-byte Initial with DF, sent to a server that
	// already answered the 1200-byte one. Empty when nothing answered.
	FatStatus string
	FatDF     bool
}

// quicShot is one Initial. kind selects the packet shape.
type quicShot struct {
	ip   string
	port int
	sni  string
	kind int
}

type quicHit struct {
	status string
	rtt    time.Duration
}

func shotKey(s quicShot) string {
	return s.ip + "/" + strconv.Itoa(s.port) + "/" + s.sni + "/" + strconv.Itoa(s.kind)
}

type hitMap map[string]quicHit

func indexHits(shots []quicShot, hits []quicHit) hitMap {
	m := hitMap{}
	for i, s := range shots {
		if i < len(hits) {
			m[shotKey(s)] = hits[i]
		}
	}
	return m
}

func (m hitMap) get(ip, sni string, port, kind int) (quicHit, bool) {
	h, ok := m[shotKey(quicShot{ip: ip, port: port, sni: sni, kind: kind})]
	return h, ok
}

func mustSpeakQUIC(domain string) bool {
	switch strings.TrimPrefix(domain, "www.") {
	case "google.com", "youtube.com":
		return true
	}
	return false
}

// quicBurst sends every Initial, three copies inside one silence window,
// and reads the replies on a single socket. df sets the don't-fragment bit
// so a 1400-byte datagram can show an MTU black hole.
func (p *Prober) quicBurst(ctx context.Context, shots []quicShot, rtt time.Duration, df bool) ([]quicHit, bool) {
	hits := make([]quicHit, len(shots))
	for i := range hits {
		hits[i].status = "NO REPLY"
	}
	if len(shots) == 0 {
		return hits, false
	}
	type pending struct {
		i    int
		addr *net.UDPAddr
		pkt  []byte
		scid []byte
		fake bool
	}
	var ps []pending
	for i, s := range shots {
		ip := net.ParseIP(s.ip)
		if ip == nil || s.port == 0 {
			hits[i].status = "ERR"
			continue
		}
		pkt, scid, err := buildQUICInitialKind(ctx, s.sni, []string{"h3"}, s.kind)
		if err != nil {
			hits[i].status = "ERR"
			continue
		}
		ps = append(ps, pending{i: i, addr: &net.UDPAddr{IP: ip, Port: s.port}, pkt: pkt, scid: scid})
	}
	if len(ps) == 0 || ctx.Err() != nil {
		return hits, false
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		for i := range hits {
			if hits[i].status == "NO REPLY" {
				hits[i].status = "ERR"
			}
		}
		return hits, false
	}
	defer conn.Close()
	dfOK := false
	if df {
		dfOK = setDontFragment(conn)
	}
	if rtt <= 0 {
		rtt = 125 * time.Millisecond // unknown path: about a second, not three
	}
	window := p.silenceWindow(rtt)
	start := time.Now()
	deadline := start.Add(window)
	marks := []time.Time{start, start.Add(window / 3), start.Add(2 * window / 3)}
	sent := 0
	send := func() {
		for i := range ps {
			if hits[ps[i].i].status == "OK" || hits[ps[i].i].status == "TOO BIG" {
				continue
			}
			if _, err := conn.WriteToUDP(ps[i].pkt, ps[i].addr); err != nil && isMsgSize(err) {
				hits[ps[i].i].status = "TOO BIG"
			}
		}
	}
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		now := time.Now()
		for sent < len(marks) && !now.Before(marks[sent]) {
			send()
			sent++
		}
		if allAnswered(hits) {
			break
		}
		wait := deadline.Sub(time.Now())
		if sent < len(marks) {
			if until := marks[sent].Sub(time.Now()); until < wait {
				wait = until
			}
		}
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		matched := false
		for i := range ps {
			if addr == nil || !addr.IP.Equal(ps[i].addr.IP) || addr.Port != ps[i].addr.Port {
				continue
			}
			if quicReply(buf[:n], ps[i].scid) {
				hits[ps[i].i] = quicHit{status: "OK", rtt: time.Since(start)}
				matched = true
				break
			}
		}
		if !matched && quicLongHeader(buf[:n]) && addr != nil {
			for i := range ps {
				if addr.IP.Equal(ps[i].addr.IP) && addr.Port == ps[i].addr.Port {
					ps[i].fake = true
				}
			}
		}
	}
	for _, s := range ps {
		if hits[s.i].status == "NO REPLY" && s.fake {
			hits[s.i].status = "FAKE"
		}
	}
	return hits, dfOK
}

func allAnswered(hits []quicHit) bool {
	for _, h := range hits {
		if h.status != "OK" && h.status != "TOO BIG" && h.status != "ERR" {
			return false
		}
	}
	return true
}

func isMsgSize(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.EMSGSIZE || errno == 10040) {
		return true
	}
	return false
}

func (p *Prober) quicProbe(ctx context.Context, ip string, port int, sni string) (string, time.Duration) {
	hits, _ := p.quicBurst(ctx, []quicShot{{ip: ip, port: port, sni: sni}}, 0, false)
	if len(hits) == 0 {
		return "ERR", 0
	}
	return hits[0].status, hits[0].rtt
}

// CheckQUIC probes the sites over QUIC and, separately, the user's own
// servers on their ports (Hysteria2, TUIC).
func (p *Prober) CheckQUIC(ctx context.Context, domains []string, targets []Target) QUICReport {
	var r QUICReport
	var stunWG sync.WaitGroup
	var stun []STUNResult
	stunWG.Add(1)
	go func() {
		defer stunWG.Done()
		stun = p.CheckSTUN(ctx)
	}()

	names := append([]string{}, domains...)
	names = append(names, quicForeignControls...)
	names = append(names, tlsRUControl)
	for _, t := range targets {
		if net.ParseIP(t.IP) == nil && t.IP != "" {
			names = append(names, t.IP)
		}
	}
	ips := map[string]string{}
	ipErr := map[string]string{}
	var mu sync.Mutex
	uniq := uniqueStrings(names)
	p.forEach(len(uniq), func(i int) {
		host := uniq[i]
		got, err := p.LookupHost(ctx, host)
		mu.Lock()
		defer mu.Unlock()
		if err != nil || len(got) == 0 {
			if err != nil {
				ipErr[host] = shortErr(err)
			}
			return
		}
		ips[host] = got[0].String()
	})

	total := len(domains) + len(targets)
	p.tick("QUIC", 0, max(total, 1))

	var first []quicShot
	add := func(dst *[]quicShot, seen map[string]bool, s quicShot) {
		if s.ip == "" || s.port == 0 || s.sni == "" {
			return
		}
		k := shotKey(s)
		if seen[k] {
			return
		}
		seen[k] = true
		*dst = append(*dst, s)
	}
	seen := map[string]bool{}
	for _, h := range quicForeignControls {
		add(&first, seen, quicShot{ip: ips[h], port: 443, sni: h})
		add(&first, seen, quicShot{ip: ips[h], port: 443, sni: tlsRUControl})
	}
	for _, d := range domains {
		add(&first, seen, quicShot{ip: ips[d], port: 443, sni: d})
		add(&first, seen, quicShot{ip: ips[d], port: 443, sni: tlsRUControl})
	}
	ru := ips[tlsRUControl]
	add(&first, seen, quicShot{ip: ru, port: 443, sni: tlsRUControl})

	type tgtPlan struct {
		domain, ip, sni string
		port            int
	}
	var plans []tgtPlan
	for _, t := range targets {
		ip := t.IP
		if net.ParseIP(ip) == nil {
			ip = ips[t.IP]
		}
		sni := t.SNI
		if sni == "" {
			sni = t.IP
			if net.ParseIP(sni) != nil || sni == "" {
				sni = defaultSNI
			}
		}
		port := t.Port
		if port == 0 {
			port = 443
		}
		plans = append(plans, tgtPlan{domain: net.JoinHostPort(t.ID, strconv.Itoa(port)), ip: ip, sni: sni, port: port})
		add(&first, seen, quicShot{ip: ip, port: port, sni: sni})
		if sni != tlsRUControl {
			add(&first, seen, quicShot{ip: ip, port: port, sni: tlsRUControl})
		}
	}

	hits, _ := p.quicBurst(ctx, first, 0, false)
	m := indexHits(first, hits)

	r.RUControl = false
	if h, ok := m.get(ru, tlsRUControl, 443, quicPacketStd); ok && h.status == "OK" {
		r.RUControl = true
	}
	for _, h := range quicForeignControls {
		ip := ips[h]
		own, ok1 := m.get(ip, h, 443, quicPacketStd)
		neu, ok2 := m.get(ip, tlsRUControl, 443, quicPacketStd)
		if ok1 && ok2 && own.status == "OK" && neu.status == "OK" {
			r.Control, r.ControlRTT = ip, own.rtt
			break
		}
	}

	r.Sites = make([]QUICResult, len(domains))
	for i, d := range domains {
		res := QUICResult{Domain: d, IP: ips[d]}
		if res.IP == "" {
			res.Status = "DNS FAIL"
			res.Verdict = ipErr[d]
			if res.Verdict == "" {
				res.Verdict = "нет A-записи"
			}
			r.Sites[i] = res
			continue
		}
		if h, ok := m.get(res.IP, d, 443, quicPacketStd); ok {
			res.Status, res.RTT = h.status, h.rtt
		}
		r.Sites[i] = res
	}
	if r.Control == "" {
		for _, s := range r.Sites {
			if s.Status != "OK" || p.russian(ctx, s.IP) {
				continue
			}
			if h, ok := m.get(s.IP, tlsRUControl, 443, quicPacketStd); ok && h.status == "OK" {
				r.Control, r.ControlRTT, r.ControlName = s.IP, s.RTT, s.Domain
				break
			}
		}
	}

	var second []quicShot
	seen2 := map[string]bool{}
	for i := range r.Sites {
		s := &r.Sites[i]
		if s.IP == "" || s.Status == "OK" || s.Status == "FAKE" || s.Status == "DNS FAIL" {
			continue
		}
		if r.Control != "" {
			add(&second, seen2, quicShot{ip: r.Control, port: 443, sni: s.Domain})
		}
		if ru != "" {
			add(&second, seen2, quicShot{ip: ru, port: 443, sni: s.Domain})
		}
		if same, ok := m.get(s.IP, tlsRUControl, 443, quicPacketStd); ok && same.status == "OK" {
			add(&second, seen2, quicShot{ip: s.IP, port: 443, sni: s.Domain}) // lost datagram, one more try
		}
		if mustSpeakQUIC(s.Domain) {
			if same, ok := m.get(s.IP, tlsRUControl, 443, quicPacketStd); !ok || same.status == "NO REPLY" {
				if s.Status == "NO REPLY" {
					add(&second, seen2, quicShot{ip: s.IP, port: 443, sni: s.Domain, kind: quicPacketGrease})
					add(&second, seen2, quicShot{ip: s.IP, port: 443, sni: tlsRUControl, kind: quicPacketGrease})
				}
			}
		}
	}
	var secondHits []quicHit
	if len(second) > 0 {
		secondHits, _ = p.quicBurst(ctx, second, r.ControlRTT, false)
	}
	m2 := indexHits(second, secondHits)

	for i := range r.Sites {
		s := &r.Sites[i]
		if s.IP == "" || s.Status == "OK" || s.Status == "DNS FAIL" {
			continue
		}
		if h, ok := m2.get(s.IP, s.Domain, 443, quicPacketStd); ok && h.status == "OK" {
			s.Status, s.RTT = "OK", h.rtt
			s.Verdict = "нестабильно: со второй попытки прошло"
			continue
		}
		if h, ok := m2.get(s.IP, s.Domain, 443, quicPacketGrease); ok && h.status == "OK" {
			s.Status, s.RTT = "OK", h.rtt
			s.Verdict = "обычный Initial проигнорирован, пакет с grease прошёл"
			continue
		}
		if h, ok := m2.get(s.IP, tlsRUControl, 443, quicPacketGrease); ok && h.status == "OK" && s.Status == "NO REPLY" {
			// The address answers a browser-like packet. Own-name silence
			// with that packet is handled below if it stayed NO REPLY.
			_ = h
		}
		same, _ := m.get(s.IP, tlsRUControl, 443, quicPacketStd)
		foreign := quicHit{status: "NO REPLY"}
		if r.Control != "" {
			if h, ok := m2.get(r.Control, s.Domain, 443, quicPacketStd); ok {
				foreign = h
			}
		}
		if ru != "" {
			if h, ok := m2.get(ru, s.Domain, 443, quicPacketStd); ok && h.status == "OK" {
				s.PassesToRU = true
			}
		}
		p.fillQUIC(s, same.status, foreign.status, r.Control)
	}

	// ICMP on one datagram separates "port closed" from a black hole.
	var silentIPs []string
	seenIP := map[string]bool{}
	for _, s := range r.Sites {
		if s.Status == "NO REPLY" && s.IP != "" && !seenIP[s.IP] {
			seenIP[s.IP] = true
			silentIPs = append(silentIPs, s.IP)
		}
	}
	icmp := map[string]string{}
	var icmpMu sync.Mutex
	p.forEach(len(silentIPs), func(i int) {
		st := p.udpFeel(ctx, silentIPs[i], 443)
		icmpMu.Lock()
		icmp[silentIPs[i]] = st
		icmpMu.Unlock()
	})
	stunWG.Wait()
	r.STUN = stun
	googleSTUN, googleSilent := false, false
	for _, s := range stun {
		if s.Name != "Google" {
			continue
		}
		switch {
		case s.OK:
			googleSTUN = true
		case s.RTT == 0:
			googleSilent = true
		}
	}
	for i := range r.Sites {
		s := &r.Sites[i]
		if s.Status != "NO REPLY" {
			continue
		}
		p.refineSilence(s, icmp[s.IP], googleSTUN, googleSilent)
	}

	r.Targets = make([]QUICResult, len(plans))
	for i, tp := range plans {
		res := QUICResult{Domain: tp.domain, IP: tp.ip}
		if tp.ip == "" {
			res.Status, res.Verdict = "DNS FAIL", "нет адреса"
			r.Targets[i] = res
			continue
		}
		if h, ok := m.get(tp.ip, tp.sni, tp.port, quicPacketStd); ok {
			res.Status, res.RTT = h.status, h.rtt
		}
		switch res.Status {
		case "OK":
			res.Verdict = "сервер отвечает по UDP"
		case "FAKE":
			res.Verdict = "ответил не сервер: QUIC к нему перехватывают по пути"
		default:
			if tp.sni != tlsRUControl {
				if h, ok := m.get(tp.ip, tlsRUControl, tp.port, quicPacketStd); ok && h.status == "OK" {
					res.Verdict = "отвечает только с другим SNI — имя " + tp.sni + " режут"
					break
				}
			}
			if p.udpFeel(ctx, tp.ip, tp.port) == "ICMP" {
				res.Status = "ICMP"
				res.Verdict = "порт закрыт: на этом порту UDP-сервера нет"
			} else {
				res.Verdict = "нет ответа: UDP к серверу режут, сервер не QUIC или с обфускацией"
			}
		}
		r.Targets[i] = res
	}

	if ip, sni, port, okRTT := firstQUICAnswer(r, m); ip != "" {
		fat, dfOK := p.quicBurst(ctx, []quicShot{{ip: ip, port: port, sni: sni, kind: quicPacketFat}}, okRTT, true)
		if len(fat) > 0 {
			r.FatStatus = fat[0].status
			r.FatDF = dfOK
		}
	}
	p.tick("QUIC", max(total, 1), max(total, 1))
	return r
}

func firstQUICAnswer(r QUICReport, m hitMap) (ip, sni string, port int, rtt time.Duration) {
	for _, s := range r.Sites {
		if s.Status == "OK" && s.IP != "" {
			return s.IP, s.Domain, 443, s.RTT
		}
	}
	for _, h := range quicForeignControls {
		// Control may have answered even when no site did.
		if r.Control != "" && r.ControlRTT > 0 {
			return r.Control, tlsRUControl, 443, r.ControlRTT
		}
		_ = h
		_ = m
	}
	if r.Control != "" {
		return r.Control, tlsRUControl, 443, r.ControlRTT
	}
	return "", "", 0, 0
}

func (p *Prober) fillQUIC(r *QUICResult, sameIP, foreign, control string) {
	if r.Status == "FAKE" {
		r.Verdict = "ответил не сервер: пакет на чужой запрос, QUIC перехватывают по пути"
		return
	}
	if r.Status == "OK" {
		return
	}
	if control == "" {
		if sameIP == "OK" {
			r.Verdict = "похоже на DPI по SNI (нет зарубежного QUIC-сервера для сверки)"
		} else {
			r.Verdict = "нет ответа и с нейтральным SNI"
		}
		return
	}
	switch {
	case sameIP == "OK" && foreign != "OK":
		r.Verdict = "DPI по SNI: имя режется и на чистом адресе"
	case sameIP != "OK" && foreign != "OK":
		r.Verdict = "имя режется; адрес по QUIC не отвечает"
	case sameIP != "OK":
		r.Verdict = "адрес не отвечает по QUIC (QUIC у сайта нет или UDP к адресу закрыт)"
	default:
		r.Verdict = "по отдельности адрес и имя проходят — блок только на их сочетание"
	}
}

func (p *Prober) refineSilence(r *QUICResult, icmp string, googleSTUN, googleSilent bool) {
	if icmp == "ICMP" {
		if strings.Contains(r.Verdict, "имя режется") {
			r.Verdict = "имя режется; QUIC у сайта нет (порт закрыт)"
			return
		}
		r.Status = "ICMP"
		r.Verdict = "QUIC у сайта нет: порт закрыт"
		return
	}
	if !mustSpeakQUIC(r.Domain) {
		return
	}
	switch {
	case googleSTUN:
		r.Verdict = "UDP до Google проходит (STUN), QUIC молчит — режут QUIC, не весь UDP"
	case googleSilent:
		r.Verdict = "UDP до Google молчит и по STUN, и по QUIC"
	}
}

// udpFeel sends a datagram that is not QUIC. ICMP port unreachable means
// the host has nothing on that port; silence means a black hole or a host
// that ignores junk.
func (p *Prober) udpFeel(ctx context.Context, ip string, port int) string {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "ERR"
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(p.silenceWindow(125 * time.Millisecond)))
	if _, err := c.Write([]byte{0, 1, 2, 3, 4, 5, 6, 7}); err != nil {
		return "ERR"
	}
	buf := make([]byte, 256)
	_, err = c.Read(buf)
	if err == nil {
		return "REPLY"
	}
	switch kindOf(err) {
	case kUnreach, kRefused, kReset:
		return "ICMP"
	default:
		return "NO REPLY"
	}
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// russian: the address is announced from Russia, useless as a foreign control.
func (p *Prober) russian(ctx context.Context, ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed == nil || p.ASOf(ctx, parsed).CC == "RU"
}
