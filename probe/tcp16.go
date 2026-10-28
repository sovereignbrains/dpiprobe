package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The freeze hits after ~16–20 KB on the wire; the window is wider to
// absorb TLS overhead and the size of the server's certificate.
const (
	fatChunk     = 4000
	fatTotal     = 64 * 1024
	blockMinKB   = 10.0
	blockMaxKB   = 45.0
	fatMaxReqs   = 40
	defaultSNI   = "example.com"
	sniSearchMax = 15
	sniBatch     = 5
	sniWanted    = 3
)

type Target struct {
	ID       string `json:"id"`
	ASN      string `json:"asn"`
	Provider string `json:"provider"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	SNI      string `json:"sni,omitempty"`
}

type FatResult struct {
	Status string // OK, DETECTED, SMALL, CLOSED, STALL, … or a connect/handshake status
	SentKB float64
	RecvKB float64
	Detail string
}

type TCP16Result struct {
	Target   Target
	Up       FatResult
	Down     FatResult
	Verdict  string
	WhiteSNI []string
}

type countConn struct {
	net.Conn
	r, w atomic.Int64
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.r.Add(int64(n))
	return n, err
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.w.Add(int64(n))
	return n, err
}

// fatConn is one TCP connection the probe owns end to end. No pool: if the
// server closes it, the probe sees that instead of silently reconnecting
// and restarting the byte count.
type fatConn struct {
	cc   *countConn
	conn net.Conn
	br   *bufio.Reader
}

func kb(n int64) float64 { return float64(n) / 1024 }

func (f *fatConn) result(status, detail string) FatResult {
	return FatResult{Status: status, SentKB: kb(f.cc.w.Load()), RecvKB: kb(f.cc.r.Load()), Detail: detail}
}

func (f *fatConn) totalKB() float64 { return kb(f.cc.w.Load() + f.cc.r.Load()) }

func (p *Prober) dialFat(ctx context.Context, ip string, port int, sni string) (*fatConn, *FatResult) {
	d := net.Dialer{Timeout: p.Timeout}
	raw, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, &FatResult{Status: statusFor(stageTCP, err), Detail: shortErr(err)}
	}
	cc := &countConn{Conn: raw}
	var conn net.Conn = cc
	if port != 80 {
		if tcp, ok := raw.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}
		_ = raw.SetDeadline(time.Now().Add(p.handshakeWait()))
		tc := tls.Client(cc, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) //nolint:gosec // probe, not a client
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, &FatResult{Status: statusFor(stageTLS, err), Detail: shortErr(err), SentKB: kb(cc.w.Load()), RecvKB: kb(cc.r.Load())}
		}
		conn = tc
	}
	return &fatConn{cc: cc, conn: conn, br: bufio.NewReader(conn)}, nil
}

func (p *Prober) fatWait(rtt time.Duration) time.Duration {
	if rtt == 0 {
		return p.Timeout
	}
	return min(max(4*rtt, 2*time.Second), p.Timeout)
}

func (f *fatConn) fail(err error) FatResult {
	k := kindOf(err)
	total := f.totalKB()
	if (k == kTimeout || k == kReset || k == kEOF) && total >= blockMinKB && total <= blockMaxKB {
		return f.result("DETECTED", fmt.Sprintf("%s на %.0f КБ", statusFor(stageData, err), total))
	}
	return f.result(statusFor(stageData, err), shortErr(err))
}

func hostFor(ip, sni string) string {
	if sni != "" {
		return sni
	}
	return ip
}

// fatUp pushes padding to the server inside HEAD requests on one connection.
func (p *Prober) fatUp(ctx context.Context, ip string, port int, sni string) FatResult {
	f, failed := p.dialFat(ctx, ip, port, sni)
	if failed != nil {
		return *failed
	}
	defer f.conn.Close()
	pad := make([]byte, fatChunk)
	_, _ = rand.Read(pad)
	for i := range pad {
		pad[i] = 'a' + pad[i]%26
	}
	var rtt time.Duration
	for i := 0; f.cc.w.Load() < fatTotal && i < fatMaxReqs; i++ {
		var b bytes.Buffer
		fmt.Fprintf(&b, "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n", hostFor(ip, sni), userAgent)
		if i > 0 {
			b.WriteString("X-Pad: ")
			b.Write(pad)
			b.WriteString("\r\n")
		}
		b.WriteString("\r\n")
		_ = f.conn.SetDeadline(time.Now().Add(p.fatWait(rtt)))
		t0 := time.Now()
		if _, err := f.conn.Write(b.Bytes()); err != nil {
			return f.fail(err)
		}
		resp, err := http.ReadResponse(f.br, &http.Request{Method: http.MethodHead})
		if err != nil {
			return f.fail(err)
		}
		resp.Body.Close()
		if i == 0 {
			rtt = time.Since(t0)
		}
		if resp.Close {
			return f.result("CLOSED", "сервер закрывает соединение — не определить")
		}
	}
	return f.result("OK", "")
}

// fatDown pulls responses until enough has come back from the server.
func (p *Prober) fatDown(ctx context.Context, ip string, port int, sni string) FatResult {
	f, failed := p.dialFat(ctx, ip, port, sni)
	if failed != nil {
		return *failed
	}
	defer f.conn.Close()
	var rtt time.Duration
	for i := 0; f.cc.r.Load() < fatTotal && i < fatMaxReqs; i++ {
		_ = f.conn.SetDeadline(time.Now().Add(p.fatWait(rtt)))
		t0 := time.Now()
		if _, err := fmt.Fprintf(f.conn, "GET /?%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\n\r\n",
			i, hostFor(ip, sni), userAgent); err != nil {
			return f.fail(err)
		}
		resp, err := http.ReadResponse(f.br, &http.Request{Method: http.MethodGet})
		if err != nil {
			return f.fail(err)
		}
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			return f.fail(err)
		}
		if i == 0 {
			rtt = time.Since(t0)
		}
		if resp.Close {
			break
		}
	}
	if f.cc.r.Load() >= fatTotal {
		return f.result("OK", "")
	}
	return f.result("SMALL", "сервер отдаёт мало — направление «вниз» не проверить")
}

// confirm repeats a DETECTED probe on a fresh connection: one stall is
// not proof, a slow server can stall too.
func (p *Prober) confirm(first FatResult, probe func() FatResult) (FatResult, bool) {
	if first.Status != "DETECTED" {
		return first, false
	}
	second := probe()
	if second.Status == "DETECTED" {
		return first, true
	}
	first.Status = "FLAKY"
	first.Detail += "; повтор: " + second.Status
	return first, false
}

func reachableStatus(s string) bool {
	switch s {
	case "OK", "DETECTED", "FLAKY", "CLOSED", "STALL":
		return true
	}
	return false
}

func applyVerdict(r *TCP16Result, upHit, downHit bool) {
	switch {
	case upHit || downHit:
		r.Verdict = "DETECTED"
	// 64 KB through one connection in either direction is far past the
	// freeze point: a single stall elsewhere is the server, not the ISP.
	case r.Up.Status == "OK" || r.Down.Status == "OK":
		r.Verdict = "OK"
	case r.Up.Status == "FLAKY" || r.Down.Status == "FLAKY":
		r.Verdict = "FLAKY"
	default:
		r.Verdict = r.Up.Status
	}
}

func (p *Prober) endpoint(ctx context.Context, t Target) (ip string, port int, sni string, err error) {
	ip = t.IP
	if net.ParseIP(ip) == nil {
		ips, e := p.LookupHost(ctx, ip)
		if e != nil {
			return "", 0, "", e
		}
		ip = ips[0].String()
	}
	sni = t.SNI
	if sni == "" && t.Port != 80 {
		sni = defaultSNI
	}
	return ip, t.Port, sni, nil
}

// measureTarget probes once in each direction. A freeze on the way up is
// not confirmed here: CheckTCP16 confirms one address per network.
func (p *Prober) measureTarget(ctx context.Context, t Target) TCP16Result {
	r := TCP16Result{Target: t}
	ip, port, sni, err := p.endpoint(ctx, t)
	if err != nil {
		r.Up = FatResult{Status: "DNS FAIL", Detail: shortErr(err)}
		r.Verdict = "DNS FAIL"
		return r
	}
	r.Up = p.fatUp(ctx, ip, port, sni)
	if reachableStatus(r.Up.Status) && r.Up.Status != "DETECTED" {
		r.Down = p.fatDown(ctx, ip, port, sni)
		if r.Down.Status == "DETECTED" {
			var hit bool
			r.Down, hit = p.confirm(r.Down, func() FatResult { return p.fatDown(ctx, ip, port, sni) })
			applyVerdict(&r, false, hit)
			return r
		}
	}
	applyVerdict(&r, r.Up.Status == "DETECTED", false)
	return r
}

// confirmUp repeats a freeze on the way up. One stall is not proof.
func (p *Prober) confirmUp(ctx context.Context, r TCP16Result) TCP16Result {
	if r.Up.Status != "DETECTED" {
		return r
	}
	ip, port, sni, err := p.endpoint(ctx, r.Target)
	if err != nil {
		return r
	}
	up, hit := p.confirm(r.Up, func() FatResult { return p.fatUp(ctx, ip, port, sni) })
	r.Up = up
	if hit {
		r.Verdict = "DETECTED"
		return r
	}
	var downHit bool
	if reachableStatus(r.Up.Status) {
		r.Down, downHit = p.confirm(p.fatDown(ctx, ip, port, sni), func() FatResult { return p.fatDown(ctx, ip, port, sni) })
	}
	applyVerdict(&r, false, downHit)
	return r
}

func (p *Prober) CheckTarget(ctx context.Context, t Target) TCP16Result {
	return p.confirmUp(ctx, p.measureTarget(ctx, t))
}

func (p *Prober) CheckTCP16(ctx context.Context, targets []Target, whitelist []string) []TCP16Result {
	out := make([]TCP16Result, len(targets))
	p.forEachCounted("16 КБ", len(targets), func(i int) { out[i] = p.measureTarget(ctx, targets[i]) })
	groups := map[string][]int{}
	var order []string
	for i, r := range out {
		if r.Up.Status != "DETECTED" {
			continue
		}
		key := r.Target.ASN
		if key == "" {
			key = r.Target.ID
		}
		if key == "" {
			key = r.Target.IP
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], i)
	}
	var retry []int
	var mu sync.Mutex
	p.forEach(len(order), func(j int) {
		g := groups[order[j]]
		out[g[0]] = p.confirmUp(ctx, out[g[0]])
		if out[g[0]].Verdict != "DETECTED" {
			mu.Lock()
			retry = append(retry, g[1:]...)
			mu.Unlock()
		}
	})
	p.forEach(len(retry), func(j int) { out[retry[j]] = p.confirmUp(ctx, out[retry[j]]) })
	if len(whitelist) == 0 {
		return out
	}
	// One representative per network: the SNI rule is per network, and
	// hammering every address of it only earns a ban.
	first := map[string]int{}
	var reps []int
	for i, r := range out {
		key := r.Target.ASN
		if key == "" {
			key = r.Target.ID
		}
		if _, seen := first[key]; !seen && r.Verdict == "DETECTED" && r.Target.Port != 80 {
			first[key] = i
			reps = append(reps, i)
		}
	}
	p.forEachCounted("SNI", len(reps), func(j int) {
		i := reps[j]
		out[i].WhiteSNI = p.findWhiteSNI(ctx, out[i].Target, whitelist)
	})
	for i := range out {
		key := out[i].Target.ASN
		if j, ok := first[key]; ok && j != i && key != "" && out[i].Verdict == "DETECTED" {
			out[i].WhiteSNI = out[j].WhiteSNI
		}
	}
	return out
}

func (p *Prober) findWhiteSNI(ctx context.Context, t Target, whitelist []string) []string {
	ip := t.IP
	if net.ParseIP(ip) == nil {
		ips, err := p.LookupHost(ctx, ip)
		if err != nil {
			return nil
		}
		ip = ips[0].String()
	}
	var found []string
	cands := whitelist[:min(len(whitelist), sniSearchMax)]
	for start := 0; start < len(cands) && len(found) < sniWanted && ctx.Err() == nil; start += sniBatch {
		batch := cands[start:min(start+sniBatch, len(cands))]
		ok := make([]bool, len(batch))
		var wg sync.WaitGroup
		for i, sni := range batch {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok[i] = p.fatUp(ctx, ip, t.Port, sni).Status == "OK"
			}()
		}
		wg.Wait()
		for i, sni := range batch {
			if ok[i] {
				found = append(found, sni)
			}
		}
	}
	return found[:min(len(found), sniWanted)]
}
