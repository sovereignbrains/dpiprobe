// Package probe measures how an ISP interferes with traffic: DNS rewriting,
// TLS blocking by SNI or by IP, the 16–20 KB freeze towards foreign hosting
// and Telegram reachability.
package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

// bootstrapDoH resolves every hostname the tool itself needs. IP-literal
// endpoints: the system resolver may be rewritten by the ISP.
var bootstrapDoH = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
}

type Prober struct {
	Timeout  time.Duration
	Parallel int
	// Progress, if set, is called from several goroutines as long checks advance.
	Progress func(done, total int)

	http *http.Client

	mu    sync.Mutex
	hosts map[string][]net.IP
	asns  map[string]ASInfo
	names map[int]string
}

func New(timeout time.Duration, parallel int) *Prober {
	p := &Prober{
		Timeout:  timeout,
		Parallel: max(parallel, 1),
		hosts:    map[string][]net.IP{},
		asns:     map[string]ASInfo{},
		names:    map[int]string{},
	}
	p.http = &http.Client{
		Transport: &http.Transport{
			DialContext:           p.dialHost,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			MaxIdleConnsPerHost:   2,
			ForceAttemptHTTP2:     true,
		},
		Timeout: 3 * timeout,
	}
	return p
}

func (p *Prober) dnsTimeout() time.Duration { return min(p.Timeout, 5*time.Second) }

// forEach runs fn for every index with at most p.Parallel at a time.
func (p *Prober) forEach(n int, fn func(i int)) {
	sem := make(chan struct{}, p.Parallel)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			fn(i)
		}()
	}
	wg.Wait()
}

// forEachCounted is forEach that reports progress.
func (p *Prober) forEachCounted(n int, fn func(i int)) {
	var done atomic.Int64
	p.forEach(n, func(i int) {
		fn(i)
		if p.Progress != nil {
			p.Progress(int(done.Add(1)), n)
		}
	})
}

func (p *Prober) dialHost(ctx context.Context, _, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips := []net.IP{net.ParseIP(host)}
	if ips[0] == nil {
		if ips, err = p.LookupHost(ctx, host); err != nil {
			return nil, err
		}
	}
	d := net.Dialer{Timeout: p.Timeout}
	for _, ip := range ips {
		var c net.Conn
		if c, err = d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port)); err == nil {
			return c, nil
		}
	}
	return nil, err
}

// LookupHost resolves an A record over DoH, bypassing the system resolver.
func (p *Prober) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	p.mu.Lock()
	ips, ok := p.hosts[host]
	p.mu.Unlock()
	if ok {
		return ips, nil
	}
	var last error
	for _, u := range bootstrapDoH {
		a, _, err := p.DoH(ctx, u, host, typeA)
		if err == nil && a.rcode == 0 && len(a.ips) > 0 {
			p.mu.Lock()
			p.hosts[host] = a.ips
			p.mu.Unlock()
			return a.ips, nil
		}
		if err == nil {
			err = fmt.Errorf("%s: нет A-записи (rcode %d)", host, a.rcode)
		}
		last = err
	}
	return nil, last
}

func (p *Prober) DoH(ctx context.Context, url, name string, qtype uint16) (dnsAnswer, time.Duration, error) {
	q := buildQuery(name, qtype)
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(q))
	if err != nil {
		return dnsAnswer{}, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	t0 := time.Now()
	resp, err := p.http.Do(req)
	if err != nil {
		return dnsAnswer{}, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	rtt := time.Since(t0)
	if err != nil {
		return dnsAnswer{}, rtt, err
	}
	if resp.StatusCode != http.StatusOK {
		return dnsAnswer{}, rtt, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	a, err := parseResponse(body, q)
	return a, rtt, err
}

// udpResult keeps every reply to one query: an ISP injecting a fake answer
// races the real one, so a second reply is evidence by itself.
type udpResult struct {
	answer dnsAnswer
	rtt    time.Duration
	extra  []dnsAnswer
}

const injectWait = 400 * time.Millisecond

func udpQuery(ctx context.Context, server, name string, qtype uint16, timeout time.Duration) (udpResult, error) {
	var res udpResult
	q := buildQuery(name, qtype)
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", net.JoinHostPort(server, "53"))
	if err != nil {
		return res, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	t0 := time.Now()
	if _, err := c.Write(q); err != nil {
		return res, err
	}
	buf := make([]byte, 4096)
	got := false
	for {
		n, err := c.Read(buf)
		if err != nil {
			if got {
				return res, nil
			}
			return res, err
		}
		a, perr := parseResponse(buf[:n], q)
		if perr != nil {
			continue
		}
		if !got {
			got = true
			res.answer, res.rtt = a, time.Since(t0)
			_ = c.SetDeadline(time.Now().Add(injectWait))
			continue
		}
		res.extra = append(res.extra, a)
	}
}

type ASInfo struct {
	ASN    int
	Prefix string
	CC     string
	Name   string
}

func (a ASInfo) String() string {
	if a.ASN == 0 {
		return "AS?"
	}
	if a.Name == "" {
		return "AS" + strconv.Itoa(a.ASN)
	}
	return fmt.Sprintf("AS%d %s", a.ASN, a.Name)
}

// ASOf asks Team Cymru over DoH which network announces ip.
func (p *Prober) ASOf(ctx context.Context, ip net.IP) ASInfo {
	ip4 := ip.To4()
	if ip4 == nil {
		return ASInfo{}
	}
	key := ip4.String()
	p.mu.Lock()
	info, ok := p.asns[key]
	p.mu.Unlock()
	if ok {
		return info
	}
	q := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", ip4[3], ip4[2], ip4[1], ip4[0])
	if f := cymruFields(p.txt(ctx, q)); len(f) >= 3 {
		if asn := strings.Fields(f[0]); len(asn) > 0 {
			info.ASN, _ = strconv.Atoi(asn[0])
		}
		info.Prefix, info.CC = f[1], f[2]
	}
	if info.ASN != 0 {
		info.Name = p.asName(ctx, info.ASN)
	}
	p.mu.Lock()
	p.asns[key] = info
	p.mu.Unlock()
	return info
}

func (p *Prober) asName(ctx context.Context, asn int) string {
	p.mu.Lock()
	name, ok := p.names[asn]
	p.mu.Unlock()
	if ok {
		return name
	}
	// "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"
	if f := cymruFields(p.txt(ctx, fmt.Sprintf("AS%d.asn.cymru.com", asn))); len(f) >= 5 {
		name = f[4]
	}
	p.mu.Lock()
	p.names[asn] = name
	p.mu.Unlock()
	return name
}

func (p *Prober) txt(ctx context.Context, name string) string {
	for _, u := range bootstrapDoH {
		if a, _, err := p.DoH(ctx, u, name, typeTXT); err == nil && len(a.txt) > 0 {
			return a.txt[0]
		}
	}
	return ""
}

func cymruFields(s string) []string {
	if s == "" {
		return nil
	}
	f := strings.Split(s, "|")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}

func net24(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.Mask(net.CIDRMask(24, 32)).String()
	}
	return ip.String()
}

type failKind int

const (
	kOther failKind = iota
	kTimeout
	kReset
	kRefused
	kEOF
	kAlert
	kUnreach
)

// Windows reports socket errors as raw WSA codes.
const (
	wsaeConnReset   = 10054
	wsaeConnRefused = 10061
	wsaeNetUnreach  = 10051
	wsaeHostUnreach = 10065
)

func kindOf(err error) failKind {
	var errno syscall.Errno
	isErrno := errors.As(err, &errno)
	var ne net.Error
	msg := err.Error()
	switch {
	case isErrno && (errno == syscall.ECONNRESET || errno == wsaeConnReset),
		strings.Contains(msg, "connection reset"), strings.Contains(msg, "forcibly closed"):
		return kReset
	case isErrno && (errno == syscall.ECONNREFUSED || errno == wsaeConnRefused):
		return kRefused
	case isErrno && (errno == syscall.ENETUNREACH || errno == syscall.EHOSTUNREACH ||
		errno == wsaeNetUnreach || errno == wsaeHostUnreach):
		return kUnreach
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return kTimeout
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return kEOF
	case strings.Contains(msg, "remote error"):
		return kAlert
	}
	return kOther
}

type stage int

const (
	stageTCP stage = iota
	stageTLS
	stageData
)

func statusFor(st stage, err error) string {
	k := kindOf(err)
	switch st {
	case stageTCP:
		switch k {
		case kTimeout:
			return "SYN DROP"
		case kRefused:
			return "REFUSED"
		case kReset:
			return "TCP RST"
		case kUnreach:
			return "UNREACH"
		}
		return "TCP ERR"
	case stageTLS:
		switch k {
		case kTimeout:
			return "TLS DROP"
		case kReset:
			return "TLS RST"
		case kEOF:
			return "TLS EOF"
		case kAlert:
			return "TLS ALERT"
		}
		return "TLS ERR"
	}
	switch k {
	case kTimeout:
		return "STALL"
	case kReset:
		return "RST"
	case kEOF:
		return "CLOSED"
	}
	return "ERR"
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		s = s[i+2:]
	}
	if r := []rune(s); len(r) > 60 {
		s = string(r[:60]) + "…"
	}
	return s
}
