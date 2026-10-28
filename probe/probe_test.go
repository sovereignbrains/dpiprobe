package probe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// reply builds a response to q with the given A records and rcode.
func reply(q []byte, rcode byte, ips ...string) []byte {
	m := append([]byte(nil), q...)
	m[2] |= 0x80
	m[3] = rcode
	binary.BigEndian.PutUint16(m[6:], uint16(len(ips)))
	for _, s := range ips {
		m = append(m, 0xc0, 12, 0, typeA, 0, 1, 0, 0, 0, 60, 0, 4)
		m = append(m, net.ParseIP(s).To4()...)
	}
	return m
}

func TestParseResponse(t *testing.T) {
	q := buildQuery("rutor.info", typeA)
	a, err := parseResponse(reply(q, 0, "1.2.3.4", "5.6.7.8"), q)
	if err != nil || a.rcode != 0 || len(a.ips) != 2 || a.ips[1].String() != "5.6.7.8" {
		t.Fatalf("got %+v, %v", a, err)
	}
	if a, err := parseResponse(reply(q, rcodeNXDomain), q); err != nil || a.rcode != rcodeNXDomain {
		t.Fatalf("NXDOMAIN: %+v, %v", a, err)
	}
	other := buildQuery("rutor.info", typeA)
	other[0], other[1] = q[0]^0xff, q[1]
	if _, err := parseResponse(reply(other, 0, "1.2.3.4"), q); err == nil {
		t.Fatal("reply with a foreign ID must be rejected")
	}
	if _, err := parseResponse(reply(q, 0, "1.2.3.4")[:20], q); err == nil {
		t.Fatal("truncated reply must be rejected")
	}
}

func TestParseTXT(t *testing.T) {
	q := buildQuery("AS13335.asn.cymru.com", typeTXT)
	m := reply(q, 0)
	binary.BigEndian.PutUint16(m[6:], 1)
	txt := "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"
	m = append(m, 0xc0, 12, 0, typeTXT, 0, 1, 0, 0, 0, 60, 0, byte(len(txt)+1), byte(len(txt)))
	m = append(m, txt...)
	a, err := parseResponse(m, q)
	if err != nil || len(a.txt) != 1 || cymruFields(a.txt[0])[4] != "CLOUDFLARENET - Cloudflare, Inc., US" {
		t.Fatalf("got %+v, %v", a, err)
	}
}

func TestParseTarget(t *testing.T) {
	cases := map[string]Target{
		"1.2.3.4":                        {IP: "1.2.3.4", Port: 443},
		"1.2.3.4:8443@www.microsoft.com": {IP: "1.2.3.4", Port: 8443, SNI: "www.microsoft.com"},
		"vpn.example.com@vk.com":         {IP: "vpn.example.com", Port: 443, SNI: "vk.com"},
	}
	for in, want := range cases {
		got, err := ParseTarget(in)
		if err != nil || got.IP != want.IP || got.Port != want.Port || got.SNI != want.SNI {
			t.Errorf("%q: got %+v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"1.2.3.4:0", "1.2.3.4:x", ":443"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestEmbeddedLists(t *testing.T) {
	targets, err := DefaultTargets()
	if err != nil || len(targets) < 50 {
		t.Fatalf("targets: %d, %v", len(targets), err)
	}
	for _, tg := range targets {
		if net.ParseIP(tg.IP) == nil || tg.Port == 0 {
			t.Errorf("bad target %+v", tg)
		}
	}
	for _, d := range DefaultDomains() {
		if net.ParseIP(d) != nil || d == "" || len(d) > 253 {
			t.Errorf("bad domain %q", d)
		}
		if d == "x.com/i/api/1.1/graphql/user_flow.json" {
			t.Error("path must be stripped")
		}
	}
	if len(WhitelistSNI()) < 100 {
		t.Error("whitelist too short")
	}
}

func TestSilenceWindow(t *testing.T) {
	p := New(8*time.Second, 1)
	if g := p.silenceWindow(10 * time.Millisecond); g != 400*time.Millisecond {
		t.Fatalf("floor: %s", g)
	}
	if g := p.silenceWindow(100 * time.Millisecond); g != 800*time.Millisecond {
		t.Fatalf("8*rtt: %s", g)
	}
	if g := p.silenceWindow(time.Second); g != 1500*time.Millisecond {
		t.Fatalf("cap: %s", g)
	}
	p.Timeout = 300 * time.Millisecond
	if g := p.silenceWindow(time.Second); g != 300*time.Millisecond {
		t.Fatalf("probe timeout: %s", g)
	}
}

func TestParseHTTPSExtractsECH(t *testing.T) {
	q := buildQuery("example.com", typeHTTPS)
	m := reply(q, 0)
	binary.BigEndian.PutUint16(m[6:], 1)
	ech := []byte{0x00, 0x04, 0x01, 0x02, 0x03, 0x04}
	rd := []byte{0x00, 0x01, 0x00}          // priority 1, root target
	rd = append(rd, 0x00, 0x01, 0x00, 0x00) // alpn, empty
	rd = append(rd, 0x00, svcParamECH)
	rd = binary.BigEndian.AppendUint16(rd, uint16(len(ech)))
	rd = append(rd, ech...)
	m = append(m, 0xc0, 12, 0, typeHTTPS, 0, 1, 0, 0, 0, 60)
	m = binary.BigEndian.AppendUint16(m, uint16(len(rd)))
	m = append(m, rd...)
	a, err := parseResponse(m, q)
	if err != nil || !bytes.Equal(a.ech, ech) {
		t.Fatalf("got %x, %v", a.ech, err)
	}
}

func TestSplitRecordKeepsSNIOut(t *testing.T) {
	flight, err := clientHelloFlight("blocked.example")
	if err != nil {
		t.Fatal(err)
	}
	first, second, err := splitRecordBefore(flight, []byte("blocked.example"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first, []byte("blocked.example")) {
		t.Fatal("SNI leaked into the first record")
	}
	if !bytes.Contains(second, []byte("blocked.example")) {
		t.Fatal("SNI missing from the second record")
	}
}

func TestKindOf(t *testing.T) {
	cases := []struct {
		err  error
		want failKind
	}{
		{os.ErrDeadlineExceeded, kTimeout},
		{&net.OpError{Op: "read", Err: syscall.Errno(wsaeConnReset)}, kReset},
		{&net.OpError{Op: "dial", Err: syscall.Errno(wsaeConnRefused)}, kRefused},
		{io.EOF, kEOF},
		{errors.New("remote error: tls: handshake failure"), kAlert},
	}
	for _, c := range cases {
		if got := kindOf(c.err); got != c.want {
			t.Errorf("%v: got %d, want %d", c.err, got, c.want)
		}
	}
	if statusFor(stageTLS, os.ErrDeadlineExceeded) != "TLS DROP" || statusFor(stageTCP, os.ErrDeadlineExceeded) != "SYN DROP" {
		t.Error("stage mapping")
	}
}
