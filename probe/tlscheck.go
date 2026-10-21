package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

// A blocked name is sent to a clean address to tell DPI-by-name from
// blocking-by-address. The clean address must be foreign: on a Russian home
// ISP in October 2026 blocked names went through to ya.ru's address
// untouched — traffic to Russian addresses was not inspected. The Russian control is kept to report
// exactly that. ya.ru doubles as the neutral name for a suspicious address.
const tlsRUControl = "ya.ru"

var tlsForeignControls = []string{"www.intel.com", "hub.docker.com", "www.google.com"}

type TLSResult struct {
	Domain  string
	IP      string
	SysIP   string // system resolver's answer when it disagrees with DoH
	Status  string
	Detail  string
	Verdict string
	// PassesToRU: the blocked name reached a Russian address untouched.
	PassesToRU bool
	Elapsed    time.Duration
	HTTP       string // plain HTTP on port 80: OK, BLOCKED, REDIRECT or a failure
	HTTPDetail string
}

type hsResult struct {
	status, detail string
	certs          []*x509.Certificate
}

// reached: the server itself answered, even with a refusal.
func (h hsResult) reached() bool { return h.status == "OK" || h.status == "TLS ALERT" }

func (p *Prober) handshake(ctx context.Context, ip, sni string) hsResult {
	d := net.Dialer{Timeout: p.Timeout}
	raw, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, "443"))
	if err != nil {
		return hsResult{status: statusFor(stageTCP, err), detail: shortErr(err)}
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(p.Timeout))
	// Verification is done separately in verifyCert: a probe must finish the
	// handshake to see what certificate comes back.
	c := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) //nolint:gosec
	if err := c.HandshakeContext(ctx); err != nil {
		return hsResult{status: statusFor(stageTLS, err), detail: shortErr(err)}
	}
	return hsResult{status: "OK", certs: c.ConnectionState().PeerCertificates}
}

type tlsControls struct{ ru, foreign string }

func (p *Prober) tlsControls(ctx context.Context) tlsControls {
	var c tlsControls
	if ips, err := p.LookupHost(ctx, tlsRUControl); err == nil {
		c.ru = ips[0].String()
	}
	for _, h := range tlsForeignControls {
		if ips, err := p.LookupHost(ctx, h); err == nil && p.handshake(ctx, ips[0].String(), h).status == "OK" {
			c.foreign = ips[0].String()
			break
		}
	}
	return c
}

func (p *Prober) CheckTLS(ctx context.Context, domains []string) []TLSResult {
	ctl := p.tlsControls(ctx)
	out := make([]TLSResult, len(domains))
	p.forEachCounted(len(domains), func(i int) { out[i] = p.checkTLSDomain(ctx, domains[i], ctl) })
	return out
}

func (p *Prober) checkTLSDomain(ctx context.Context, domain string, ctl tlsControls) TLSResult {
	r := TLSResult{Domain: domain}
	ips, err := p.LookupHost(ctx, domain)
	if err != nil {
		r.Status, r.Detail = "DNS FAIL", shortErr(err)
		return r
	}
	r.IP = ips[0].String()
	c, cancel := context.WithTimeout(ctx, p.dnsTimeout())
	if sys, err := net.DefaultResolver.LookupIP(c, "ip4", domain); err == nil && len(sys) > 0 &&
		net24(sys[0]) != net24(ips[0]) && p.ASOf(ctx, sys[0]).ASN != p.ASOf(ctx, ips[0]).ASN {
		r.SysIP = sys[0].String()
	}
	cancel()
	r.HTTP, r.HTTPDetail = p.httpProbe(ctx, r.IP, domain)

	t0 := time.Now()
	h := p.handshake(ctx, r.IP, domain)
	r.Elapsed = time.Since(t0)
	r.Status, r.Detail = h.status, h.detail
	if h.status == "OK" {
		if msg := verifyCert(h.certs, domain); msg != "" {
			r.Status, r.Detail = "CERT", msg
			r.Verdict = "сертификат не прошёл проверку — возможна подмена (MITM)"
		}
		return r
	}

	// Cross-probes: the same address with a neutral name, and the blocked
	// name on clean addresses abroad and in Russia.
	sameIP := p.handshake(ctx, r.IP, tlsRUControl)
	var foreign hsResult
	if ctl.foreign != "" {
		foreign = p.handshake(ctx, ctl.foreign, domain)
	}
	if ctl.ru != "" {
		r.PassesToRU = p.handshake(ctx, ctl.ru, domain).reached()
	}
	switch {
	case ctl.foreign == "" && sameIP.reached():
		r.Verdict = "похоже на DPI по SNI (нет чистого зарубежного адреса для сверки)"
	case ctl.foreign == "":
		r.Verdict = "адрес недоступен и с нейтральным SNI"
	case !sameIP.reached() && foreign.reached():
		r.Verdict = "блок по IP: адрес недоступен с любым SNI"
	case sameIP.reached() && !foreign.reached():
		r.Verdict = "DPI по SNI: имя режется и на чистом адресе (" + foreign.status + ")"
	case !sameIP.reached() && !foreign.reached():
		r.Verdict = "режут и адрес, и имя"
	default:
		if again := p.handshake(ctx, r.IP, domain); again.status == "OK" {
			r.Verdict = "нестабильно: со второй попытки прошло"
		} else {
			r.Verdict = "по отдельности адрес и имя проходят — блок только на их сочетание"
		}
	}
	return r
}

func verifyCert(certs []*x509.Certificate, host string) string {
	if len(certs) == 0 {
		return "сервер не прислал сертификат"
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err != nil {
		return shortErr(err) + " (выдан: " + certs[0].Issuer.CommonName + ")"
	}
	return ""
}
