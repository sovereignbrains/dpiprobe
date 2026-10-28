package probe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// BypassReport is one blocked name tried three ways: a ClientHello split
// across two TCP segments, the same hello split across two TLS records
// before the SNI, and Encrypted Client Hello when a config is published.
type BypassReport struct {
	Domain string
	IP     string
	Probes []BypassProbe
}

type BypassProbe struct {
	Name   string
	Status string
	Detail string
	Worked bool
}

func (b BypassReport) Line() string {
	if b.Domain == "" {
		return ""
	}
	var frag, ech bool
	var okNames []string
	for _, pr := range b.Probes {
		if !pr.Worked {
			continue
		}
		okNames = append(okNames, pr.Name)
		if pr.Name == "ECH" {
			ech = true
		} else {
			frag = true
		}
	}
	if len(okNames) == 0 {
		return fmt.Sprintf("Обход SNI (%s): дробление ClientHello и ECH не помогли.", b.Domain)
	}
	msg := fmt.Sprintf("Обход SNI (%s): сработало %s.", b.Domain, strings.Join(okNames, ", "))
	if frag {
		msg += " DPI режет целый ClientHello в одном сегменте."
	} else if ech {
		msg += " Помогает только шифрование имени."
	}
	return msg
}

// CheckBypass runs the three probes against the first name TLS already
// called DPI-by-SNI. Nothing is probed when every name connected.
func (p *Prober) CheckBypass(ctx context.Context, sites []TLSResult) BypassReport {
	var domain, ip string
	for _, s := range sites {
		if s.IP != "" && strings.HasPrefix(s.Verdict, "DPI по SNI") {
			domain, ip = s.Domain, s.IP
			break
		}
	}
	if domain == "" {
		for _, s := range sites {
			if s.IP != "" && strings.Contains(s.Verdict, "сочетание") {
				domain, ip = s.Domain, s.IP
				break
			}
		}
	}
	if domain == "" {
		return BypassReport{}
	}
	out := BypassReport{Domain: domain, IP: ip, Probes: make([]BypassProbe, 3)}
	p.forEachCounted("Обход", 3, func(i int) {
		switch i {
		case 0:
			out.Probes[i] = p.probeSegment(ctx, ip, 443, domain)
		case 1:
			out.Probes[i] = p.probeRecord(ctx, ip, 443, domain)
		default:
			out.Probes[i] = p.probeECH(ctx, domain, ip)
		}
	})
	return out
}

func (p *Prober) probeSegment(ctx context.Context, ip string, port int, sni string) BypassProbe {
	h := p.dialTLS(ctx, ip, port, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"http/1.1"},
	}, func(c net.Conn) net.Conn { return &oneByteConn{Conn: c} })
	pr := BypassProbe{Name: "сегмент 1 байт", Status: h.status, Detail: h.detail}
	pr.Worked = h.status == "OK" || h.status == "TLS ALERT"
	if pr.Worked && pr.Detail == "" {
		pr.Detail = "рукопожатие прошло"
	}
	return pr
}

func (p *Prober) probeRecord(ctx context.Context, ip string, port int, sni string) BypassProbe {
	pr := BypassProbe{Name: "запись до SNI"}
	flight, err := clientHelloFlight(sni)
	if err != nil {
		pr.Status, pr.Detail = "ERR", shortErr(err)
		return pr
	}
	first, second, err := splitRecordBefore(flight, []byte(sni))
	if err != nil {
		pr.Status, pr.Detail = "ERR", shortErr(err)
		return pr
	}
	d := net.Dialer{Timeout: p.Timeout}
	raw, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		pr.Status, pr.Detail = statusFor(stageTCP, err), shortErr(err)
		return pr
	}
	defer raw.Close()
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	_ = raw.SetDeadline(time.Now().Add(p.handshakeWait()))
	conn := net.Conn(raw)
	if _, err := conn.Write(first); err != nil {
		pr.Status, pr.Detail = statusFor(stageTLS, err), shortErr(err)
		return pr
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := conn.Write(second); err != nil {
		pr.Status, pr.Detail = statusFor(stageTLS, err), shortErr(err)
		return pr
	}
	var b [1]byte
	n, err := conn.Read(b[:])
	pr.Status, pr.Detail = reachedByte(n, b[0], err)
	pr.Worked = pr.Status == "OK"
	return pr
}

func reachedByte(n int, b byte, err error) (status, detail string) {
	if n > 0 {
		switch b {
		case 0x16:
			return "OK", "сервер ответил"
		case 0x15:
			return "OK", "сервер прислал alert — пакет дошёл"
		default:
			return "OK", "сервер прислал данные"
		}
	}
	if err == nil {
		return "OK", "сервер ответил"
	}
	return statusFor(stageTLS, err), shortErr(err)
}

func (p *Prober) probeECH(ctx context.Context, domain, ip string) BypassProbe {
	pr := BypassProbe{Name: "ECH"}
	cfg := p.lookupECH(ctx, domain)
	target, name := ip, domain
	if cfg == nil {
		cfg = p.lookupECH(ctx, "cloudflare-ech.com")
		name = "cloudflare-ech.com"
		if cfg != nil {
			ips, err := p.LookupHost(ctx, name)
			if err != nil || len(ips) == 0 {
				pr.Status, pr.Detail = "НЕТ", "нет конфигурации ECH"
				return pr
			}
			target = ips[0].String()
			pr.Detail = name
		}
	}
	if cfg == nil {
		pr.Status, pr.Detail = "НЕТ", "нет конфигурации ECH"
		return pr
	}
	h := p.dialTLS(ctx, target, 443, &tls.Config{
		ServerName:                     name,
		MinVersion:                     tls.VersionTLS13,
		InsecureSkipVerify:             true, //nolint:gosec
		NextProtos:                     []string{"http/1.1"},
		EncryptedClientHelloConfigList: cfg,
	}, nil)
	pr.Status = h.status
	if h.detail != "" {
		if pr.Detail != "" {
			pr.Detail += ": "
		}
		pr.Detail += h.detail
	}
	pr.Worked = h.status == "OK"
	return pr
}

func (p *Prober) lookupECH(ctx context.Context, name string) []byte {
	qctx, cancel := p.quick(ctx)
	defer cancel()
	for _, u := range bootstrapDoH {
		a, _, err := p.DoH(qctx, u, name, typeHTTPS)
		if err == nil && len(a.ech) > 0 {
			return a.ech
		}
	}
	return nil
}

type oneByteConn struct {
	net.Conn
	done bool
}

func (c *oneByteConn) Write(b []byte) (int, error) {
	if !c.done && len(b) > 1 {
		c.done = true
		if _, err := c.Conn.Write(b[:1]); err != nil {
			return 0, err
		}
		time.Sleep(15 * time.Millisecond)
		n, err := c.Conn.Write(b[1:])
		return n + 1, err
	}
	return c.Conn.Write(b)
}

type captureConn struct{ buf []byte }

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Write(b []byte) (int, error)      { c.buf = append(c.buf, b...); return len(b), nil }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return stubAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return stubAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type stubAddr struct{}

func (stubAddr) Network() string { return "tcp" }
func (stubAddr) String() string  { return "127.0.0.1:0" }

func clientHelloFlight(sni string) ([]byte, error) {
	raw := &captureConn{}
	c := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"http/1.1"},
	})
	_ = c.HandshakeContext(context.Background())
	if len(raw.buf) < 5 {
		return nil, io.ErrUnexpectedEOF
	}
	return raw.buf, nil
}

// SplitTLSRecordBefore cuts the first TLS record so marker starts the second.
func SplitTLSRecordBefore(flight, marker []byte) (first, second []byte, err error) {
	return splitRecordBefore(flight, marker)
}

// splitRecordBefore cuts the first TLS record so the marker (the SNI)
// starts the second record. Handshake fragmentation is legal; a DPI that
// only reads the first record then misses the name.
func splitRecordBefore(flight, marker []byte) (first, second []byte, err error) {
	if len(flight) < 5 || flight[0] != 0x16 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint16(flight[3:5]))
	if 5+n > len(flight) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	payload := flight[5 : 5+n]
	rest := flight[5+n:]
	at := indexBytes(payload, marker)
	if at < 1 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	rec := func(p []byte) []byte {
		h := []byte{0x16, flight[1], flight[2], 0, 0}
		binary.BigEndian.PutUint16(h[3:], uint16(len(p)))
		return append(h, p...)
	}
	return rec(payload[:at]), append(rec(payload[at:]), rest...), nil
}

func indexBytes(b, sub []byte) int {
	if len(sub) == 0 || len(sub) > len(b) {
		return -1
	}
	for i := 0; i+len(sub) <= len(b); i++ {
		ok := true
		for j := range sub {
			if b[i+j] != sub[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
