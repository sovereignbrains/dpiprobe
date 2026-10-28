package probe

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Domains blocked in Russia by DNS; the control domain is never blocked.
var (
	dnsForbidden = []string{"rutor.info", "flibusta.is", "rezka.ag", "nnmclub.to", "clubtone.do.am"}
	dnsControl   = "vk.ru"
)

// truthServers are non-filtering DoH resolvers. Filtering ones (family,
// security, Russian) are left out on purpose: a stub they return would
// become "truth" and hide the ISP's rewriting.
var truthServers = []struct{ Name, URL string }{
	{"Cloudflare", "https://1.1.1.1/dns-query"},
	{"Google", "https://8.8.8.8/dns-query"},
	{"Quad9 без фильтра", "https://dns10.quad9.net/dns-query"},
	{"AdGuard без фильтра", "https://unfiltered.adguard-dns.com/dns-query"},
	{"DNS.SB", "https://doh.dns.sb/dns-query"},
	{"Mullvad", "https://dns.mullvad.net/dns-query"},
}

// udpResolvers: ASNs lists the networks the resolver's egress may belong to;
// empty means "don't judge, just show".
var udpResolvers = []struct {
	Name, Addr string
	ASNs       []int
}{
	{"Google", "8.8.8.8", []int{15169}},
	{"Cloudflare", "1.1.1.1", []int{13335}},
	{"Quad9", "9.9.9.10", nil},
	{"OpenDNS", "208.67.222.222", []int{36692}},
	{"AdGuard", "94.140.14.140", nil},
	{"Yandex", "77.88.8.8", []int{13238}},
	{"MSK-IX", "62.76.76.62", nil},
	{"НСДИ", "195.208.4.1", nil},
}

const (
	VerdictOK       = "ok"
	VerdictSpoofed  = "подмена"
	VerdictInjected = "вброс"
	VerdictSilent   = "молчит"
	VerdictNoReply  = "нет ответа"
	VerdictNoTruth  = "нет эталона"
)

type TruthStatus struct {
	Name string
	OK   bool
	RTT  time.Duration
	Err  string
}

type DNSDomainResult struct {
	Domain  string
	Verdict string
	IPs     []string
	Detail  string
}

type DNSServerResult struct {
	Name, Addr string
	Alive      bool
	RTT        time.Duration
	Egress     string
	EgressAS   ASInfo
	Hijacked   bool
	Domains    []DNSDomainResult
}

type DNSReport struct {
	Truth     []TruthStatus
	Servers   []DNSServerResult
	Encrypted []EncResult
}

type domainTruth struct {
	ips  map[string]bool
	nets map[string]bool
	asns map[int]bool
}

func (t *domainTruth) has() bool { return t != nil && len(t.ips) > 0 }

func (p *Prober) CheckDNS(ctx context.Context) DNSReport {
	var rep DNSReport
	truth := map[string]*domainTruth{}
	var mu sync.Mutex
	rep.Truth = make([]TruthStatus, len(truthServers))
	p.tick("DNS", 0, 3)
	p.forEach(len(truthServers), func(i int) {
		s := truthServers[i]
		st := TruthStatus{Name: s.Name}
		for _, d := range dnsForbidden {
			qctx, cancel := p.quick(ctx)
			a, rtt, err := p.DoH(qctx, s.URL, d, typeA)
			cancel()
			if err != nil {
				if st.Err == "" {
					st.Err = statusFor(stageTLS, err) + ": " + shortErr(err)
				}
				if !st.OK {
					break // unreachable server: don't wait out every domain
				}
				continue
			}
			st.OK = true
			if st.RTT == 0 || rtt < st.RTT {
				st.RTT = rtt
			}
			if a.rcode != 0 || len(a.ips) == 0 {
				continue
			}
			mu.Lock()
			t := truth[d]
			if t == nil {
				t = &domainTruth{ips: map[string]bool{}, nets: map[string]bool{}, asns: map[int]bool{}}
				truth[d] = t
			}
			for _, ip := range a.ips {
				t.ips[ip.String()] = true
				t.nets[net24(ip)] = true
			}
			mu.Unlock()
		}
		if st.OK {
			st.Err = ""
		}
		rep.Truth[i] = st
	})
	for _, t := range truth {
		for s := range t.ips {
			if as := p.ASOf(ctx, net.ParseIP(s)); as.ASN != 0 {
				t.asns[as.ASN] = true
			}
		}
	}
	p.tick("DNS", 1, 3)

	rep.Servers = make([]DNSServerResult, len(udpResolvers)+1)
	p.forEach(len(rep.Servers), func(i int) {
		if i == len(udpResolvers) {
			rep.Servers[i] = p.checkSystemResolver(ctx, truth)
			return
		}
		rep.Servers[i] = p.checkUDPResolver(ctx, i, truth)
	})
	p.tick("DNS", 2, 3)
	rep.Encrypted = p.checkEncrypted(ctx, truth)
	p.tick("DNS", 3, 3)
	return rep
}

func (p *Prober) checkUDPResolver(ctx context.Context, i int, truth map[string]*domainTruth) DNSServerResult {
	s := udpResolvers[i]
	r := DNSServerResult{Name: s.Name, Addr: s.Addr}
	if ctl, err := udpQuery(ctx, s.Addr, dnsControl, typeA, p.dnsTimeout()); err == nil && len(ctl.answer.ips) > 0 {
		r.Alive, r.RTT = true, ctl.rtt
	}
	if eg, err := udpQuery(ctx, s.Addr, "whoami.akamai.net", typeA, p.dnsTimeout()); err == nil && len(eg.answer.ips) > 0 {
		r.Egress = eg.answer.ips[0].String()
		r.EgressAS = p.ASOf(ctx, eg.answer.ips[0])
		r.Hijacked = len(s.ASNs) > 0 && r.EgressAS.ASN != 0 && !slices.Contains(s.ASNs, r.EgressAS.ASN)
	}
	if !r.Alive && r.Egress == "" {
		return r
	}
	for _, d := range dnsForbidden {
		res, err := udpQuery(ctx, s.Addr, d, typeA, p.dnsTimeout())
		r.Domains = append(r.Domains, p.judge(ctx, d, truth[d], res, err, r.Alive))
	}
	return r
}

func (p *Prober) checkSystemResolver(ctx context.Context, truth map[string]*domainTruth) DNSServerResult {
	r := DNSServerResult{Name: "Системный DNS", Addr: "ОС"}
	lookup := func(name string) (udpResult, error) {
		c, cancel := context.WithTimeout(ctx, p.dnsTimeout())
		defer cancel()
		t0 := time.Now()
		ips, err := net.DefaultResolver.LookupIP(c, "ip4", name)
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return udpResult{answer: dnsAnswer{rcode: rcodeNXDomain}, rtt: time.Since(t0)}, nil
		}
		return udpResult{answer: dnsAnswer{ips: ips}, rtt: time.Since(t0)}, err
	}
	if res, err := lookup(dnsControl); err == nil && len(res.answer.ips) > 0 {
		r.Alive, r.RTT = true, res.rtt
	}
	if res, err := lookup("whoami.akamai.net"); err == nil && len(res.answer.ips) > 0 {
		r.Egress = res.answer.ips[0].String()
		r.EgressAS = p.ASOf(ctx, res.answer.ips[0])
	}
	for _, d := range dnsForbidden {
		res, err := lookup(d)
		r.Domains = append(r.Domains, p.judge(ctx, d, truth[d], res, err, r.Alive))
	}
	return r
}

func (p *Prober) judge(ctx context.Context, d string, t *domainTruth, res udpResult, err error, alive bool) DNSDomainResult {
	r := DNSDomainResult{Domain: d}
	if err != nil {
		r.Verdict = VerdictNoReply
		if alive {
			r.Verdict, r.Detail = VerdictSilent, "на обычный домен отвечает, на запрещённый — нет"
		}
		return r
	}
	for _, ip := range res.answer.ips {
		r.IPs = append(r.IPs, ip.String())
	}
	if !t.has() {
		r.Verdict = VerdictNoTruth
		return r
	}
	ok, as := p.answerOK(ctx, t, res.answer)
	if ok {
		r.Verdict = VerdictOK
	} else {
		r.Verdict, r.Detail = VerdictSpoofed, describeAnswer(res.answer, as)
	}
	for _, ex := range res.extra {
		if exOK, _ := p.answerOK(ctx, t, ex); !ok && exOK {
			r.Verdict = VerdictInjected
			r.Detail = "первым пришёл поддельный ответ (" + describeAnswer(res.answer, as) + "), настоящий — следом"
			break
		}
	}
	return r
}

// answerOK matches by exact IP, then /24, then ASN: CDN-hosted sites
// legitimately resolve to different addresses from different resolvers.
func (p *Prober) answerOK(ctx context.Context, t *domainTruth, a dnsAnswer) (bool, ASInfo) {
	if a.rcode != 0 || len(a.ips) == 0 {
		return false, ASInfo{}
	}
	for _, ip := range a.ips {
		if t.ips[ip.String()] || t.nets[net24(ip)] {
			return true, ASInfo{}
		}
	}
	first := p.ASOf(ctx, a.ips[0])
	for i, ip := range a.ips {
		as := first
		if i > 0 {
			as = p.ASOf(ctx, ip)
		}
		if as.ASN != 0 && t.asns[as.ASN] {
			return true, as
		}
	}
	return false, first
}

func describeAnswer(a dnsAnswer, as ASInfo) string {
	switch {
	case a.rcode == rcodeNXDomain:
		return "NXDOMAIN"
	case a.rcode != 0:
		return "rcode " + strconv.Itoa(a.rcode)
	case len(a.ips) == 0:
		return "пустой ответ"
	}
	return a.ips[0].String() + " (" + as.String() + ")"
}
