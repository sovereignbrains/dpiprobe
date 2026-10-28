package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sovereignbrains/dpiprobe/probe"
)

func TestContainsAddrIgnoresVersion(t *testing.T) {
	if containsAddr("0.3.2") || containsAddr("dpiprobe/0.3.2") {
		t.Fatal("version matched")
	}
	if !containsAddr("192.0.2.10") || !containsAddr("dial 203.0.113.5:443") {
		t.Fatal("address missed")
	}
}

func TestConsentAnswers(t *testing.T) {
	yes := []string{"д", "Д", "y", "Y", "да", "Да", "yes", "YES", " yes \n"}
	for _, s := range yes {
		if !consentYes(s) {
			t.Errorf("want yes %q", s)
		}
	}
	no := []string{"", " ", "н", "Н", "нет", "no", "д/Н", "yes please"}
	for _, s := range no {
		if consentYes(s) {
			t.Errorf("want no %q", s)
		}
	}
}

func TestAskConsentTimeout(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	var buf bytes.Buffer
	start := time.Now()
	if askConsent(&buf, r, 40*time.Millisecond) {
		t.Fatal("accepted silence")
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout too slow")
	}
	if !strings.Contains(buf.String(), "(д/Н):") {
		t.Fatalf("prompt %q", buf.String())
	}
}

func TestAskConsentYes(t *testing.T) {
	var buf bytes.Buffer
	if !askConsent(&buf, strings.NewReader("да\n"), time.Second) {
		t.Fatal("да")
	}
	if askConsent(&buf, strings.NewReader("\n"), time.Second) {
		t.Fatal("empty line")
	}
}

func TestChooseSend(t *testing.T) {
	cases := []struct {
		send, nosend, term, vpn bool
		ask, goSend             bool
	}{
		{false, false, true, false, true, false},
		{false, false, false, false, false, false},
		{false, true, true, false, false, false},
		{true, true, true, false, false, false},
		{true, false, false, false, false, true},
		{false, false, true, true, false, false},
		{true, false, true, true, false, true},
	}
	for _, c := range cases {
		got := chooseSend(c.send, c.nosend, c.term, c.vpn)
		if got.ask != c.ask || got.send != c.goSend {
			t.Errorf("send=%v nosend=%v term=%v vpn=%v -> ask=%v send=%v", c.send, c.nosend, c.term, c.vpn, got.ask, got.send)
		}
	}
}

func boolPtr(v bool) *bool { return &v }

func TestSentPayloadStripsSecrets(t *testing.T) {
	const (
		ip     = "192.0.2.10"
		prefix = "192.0.2.0/24"
		mapped = "192.0.2.55"
		target = "203.0.113.50"
		domain = "secret.example"
		proc   = "zapret (winws)"
		iface  = "tun0"
		reply  = "198.51.100.8:3478"
	)
	rep := report{
		Net: &probe.NetInfo{
			IP:        ip,
			AS:        probe.ASInfo{ASN: 64496, Prefix: prefix, CC: "ZZ", Name: "Example Net"},
			Err:       "dial " + ip + ":443: i/o timeout",
			VPNIfaces: []string{iface},
			Bypass:    []string{proc},
		},
		TLS: []probe.TLSResult{
			{Domain: domain, IP: target, Status: "DROP", Detail: "saw " + ip, Verdict: "DPI"},
			{Domain: "www.example.com", IP: "198.51.100.20", Status: "OK", Detail: "via " + ip + " " + proc, Verdict: "open"},
		},
		QUIC: &probe.QUICReport{
			Sites:   []probe.QUICResult{{Domain: "www.example.com", IP: "198.51.100.20", Status: "OK"}},
			Targets: []probe.QUICResult{{Domain: target, IP: target, Status: "NO REPLY"}},
			STUN: []probe.STUNResult{{
				Name: "Example", Addr: "stun.example.com:3478", OK: true,
				ReplyAddr: reply, MappedAddr: mapped, Err: "from " + mapped,
			}},
		},
		TCP16: []probe.TCP16Result{
			{Target: probe.Target{ID: target, IP: target, Port: 443, SNI: domain, Provider: "свой сервер"}, Verdict: "DETECTED"},
			{Target: probe.Target{ID: "cdn", IP: "198.51.100.9", Port: 443, Provider: "Example CDN"}, Verdict: "OK", Up: probe.FatResult{Status: "OK"}},
		},
	}
	targets := []probe.Target{{IP: target, ID: target, SNI: domain, Port: 443}}
	domains := []string{domain}
	w := buildWire(rep, wireMeta{Version: "0.3.2", OS: "windows/amd64", Dur: 5 * time.Second, UserDomains: domains, UserTargets: targets})
	raw, gz, err := packWire(&w)
	if err != nil {
		t.Fatal(err)
	}
	if len(gz) > wireMax {
		t.Fatalf("gzip %d", len(gz))
	}
	text := string(raw)
	for _, s := range []string{ip, prefix, mapped, target, domain, proc, iface, "MappedAddr", "VPNIfaces", "Prefix"} {
		if strings.Contains(text, s) {
			t.Errorf("leaked %q", s)
		}
	}
	for _, s := range []string{reply, "www.example.com", "198.51.100.20", "198.51.100.9", "Example Net", "\"asn\":64496"} {
		if !strings.Contains(text, s) {
			t.Errorf("missing %q", s)
		}
	}
	if w.Schema != 1 || !w.VPN || !w.BypassOn || w.Targets != 1 || w.Domains != 1 {
		t.Fatalf("meta schema=%d vpn=%v bypass=%v targets=%d domains=%d", w.Schema, w.VPN, w.BypassOn, w.Targets, w.Domains)
	}
	if w.Net == nil || w.Net.Err != "" || w.Net.CC != "ZZ" {
		t.Fatalf("net %+v", w.Net)
	}
	if err := leakGuard(raw, secretStrings(rep, domains, targets)); err != nil {
		t.Fatal(err)
	}
}

func TestPackTrimsTo14KB(t *testing.T) {
	w := wireReport{Schema: 1, Version: "0.3.2", OS: "linux/amd64", DurSec: 3}
	long := strings.Repeat("white.example ", 30)
	for i := 0; i < 400; i++ {
		w.TCP16 = append(w.TCP16, wireTCP{
			ID: "h", IP: "198.51.100.9", Up: "DETECTED", Down: "OK", Verdict: "DETECTED",
			White: []string{long, long},
		})
		w.TLS = append(w.TLS, wireTLS{Domain: "www.example.com", IP: "198.51.100.20", Status: "DROP", Detail: long, Verdict: "DPI"})
	}
	raw, gz, err := packWire(&w)
	if err != nil {
		t.Fatal(err)
	}
	if len(gz) > wireWant {
		t.Fatalf("gzip %d", len(gz))
	}
	if gz[0] != 0x1f || gz[1] != 0x8b {
		t.Fatal("not gzip")
	}
	got, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, raw) {
		t.Fatal("gzip body is not the saved json")
	}
	var back wireReport
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatal(err)
	}
	if back.Schema != 1 || back.Version != "0.3.2" {
		t.Fatalf("schema %d %s", back.Schema, back.Version)
	}
}

func TestPostGzipShapeAndRetry(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("encoding %q", r.Header.Get("Content-Encoding"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("type %q", r.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if len(body) > wireMax {
			t.Errorf("body %d", len(body))
		}
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		plain, _ := io.ReadAll(zr)
		if !bytes.Contains(plain, []byte(`"schema":1`)) {
			t.Errorf("plain %s", plain)
		}
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	mode, err := postGzip(context.Background(), []namedClient{
		{"обычный", srv.Client()},
	}, srv.URL, mustGzip(t, []byte(`{"schema":1}`)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "обычный" || hits.Load() != 2 {
		t.Fatalf("mode %s hits %d", mode, hits.Load())
	}
}

func TestPost500Stops(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("store"))
	}))
	t.Cleanup(srv.Close)
	mode, err := postGzip(context.Background(), []namedClient{
		{"обычный", srv.Client()},
		{"record", srv.Client()},
	}, srv.URL, mustGzip(t, []byte(`{"schema":1}`)), time.Second)
	if err == nil || mode != "обычный" || hits.Load() != 1 {
		t.Fatalf("mode %s hits %d err %v", mode, hits.Load(), err)
	}
}

func TestPostFallsThroughToNextClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	fail := &http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	})}
	mode, err := postGzip(context.Background(), []namedClient{
		{"обычный", fail},
		{"record", srv.Client()},
	}, srv.URL, mustGzip(t, []byte(`{"schema":1}`)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "record" {
		t.Fatalf("mode %s", mode)
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mustGzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	b, err := gzipBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnreachableKeepsSentFile(t *testing.T) {
	dir := t.TempDir()
	sent := filepath.Join(dir, "dpiprobe-sent.json")
	logPath := filepath.Join(dir, "out.txt")
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	term := false
	offerReport(context.Background(), offerOpts{
		rep:        report{Net: &probe.NetInfo{AS: probe.ASInfo{ASN: 64496, CC: "ZZ", Name: "Example"}}},
		flagSend:   true,
		sentPath:   sent,
		reportFile: logf,
		clients:    []namedClient{{"обычный", &http.Client{Timeout: 200 * time.Millisecond}}},
		url:        "http://127.0.0.1:1/v1/report",
		perTry:     200 * time.Millisecond,
		stdinTerm:  &term,
	})
	_ = logf.Close()
	body, err := os.ReadFile(sent)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"schema":1`)) {
		t.Fatalf("file %s", body)
	}
	text, _ := os.ReadFile(logPath)
	if !bytes.Contains(text, []byte("не ушло")) || !bytes.Contains(text, []byte(sent)) || !bytes.Contains(text, []byte("вручную")) {
		t.Fatalf("note %s", text)
	}
}

func TestNoSendWithoutTerminalOrNosend(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	term := false
	noTerm := filepath.Join(dir, "a.json")
	offerReport(context.Background(), offerOpts{
		rep: report{}, sentPath: noTerm, clients: []namedClient{{"обычный", srv.Client()}},
		url: srv.URL, perTry: time.Second, stdinTerm: &term,
	})
	nosend := filepath.Join(dir, "b.json")
	yes := true
	offerReport(context.Background(), offerOpts{
		rep: report{}, flagNosend: true, sentPath: nosend,
		clients: []namedClient{{"обычный", srv.Client()}},
		url:     srv.URL, perTry: time.Second, stdinTerm: &yes,
	})
	if hits.Load() != 0 {
		t.Fatalf("hits %d", hits.Load())
	}
	if _, err := os.Stat(noTerm); !os.IsNotExist(err) {
		t.Fatal("not a terminal still wrote a file")
	}
	if _, err := os.Stat(nosend); !os.IsNotExist(err) {
		t.Fatal("-nosend still wrote a file")
	}
}

func TestRealReportFitsAndStrips(t *testing.T) {
	path := filepath.Join("..", "..", "dpiprobe-20261028-171748.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skip("no local report")
	}
	var rep report
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Net == nil || rep.Net.IP == "" {
		t.Fatal("report has no address to strip")
	}
	secrets := secretStrings(rep, nil, nil)
	w := buildWire(rep, wireMeta{Version: version, OS: "windows/amd64", Dur: 2 * time.Minute})
	full, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	fullGz, err := gzipBytes(full)
	if err != nil {
		t.Fatal(err)
	}
	raw, gz, err := packWire(&w)
	if err != nil {
		t.Fatal(err)
	}
	if err := leakGuard(raw, secrets); err != nil {
		t.Fatal(leakAt(raw, secrets))
	}
	t.Logf("full gzip=%d packed gzip=%d raw=%d", len(fullGz), len(gz), len(raw))
}

func leakAt(raw []byte, secrets []string) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err.Error()
	}
	return walkLeak(v, "$", secrets)
}

func walkLeak(v any, path string, secrets []string) string {
	switch x := v.(type) {
	case string:
		for _, s := range secrets {
			if len(s) >= 3 && strings.Contains(x, s) {
				return path
			}
		}
	case map[string]any:
		for k, child := range x {
			if p := walkLeak(child, path+"."+k, secrets); p != "" {
				return p
			}
		}
	case []any:
		for i, child := range x {
			if p := walkLeak(child, path+".[]", secrets); p != "" {
				_ = i
				return p
			}
		}
	}
	return ""
}
