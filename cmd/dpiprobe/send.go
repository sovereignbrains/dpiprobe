package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/sovereignbrains/dpiprobe/probe"
)

// reportURL is the public receiver. The binary has no token and no account id.
const reportURL = "https://dpiprobe-reports.qz7mtk4rwp.workers.dev/v1/report"

const consentPrompt = "Отправить обезличенный отчёт автору, чтобы улучшить проверку? Уходит: провайдер, AS, страна и результаты проб; ваш IP и свои серверы — нет. (д/Н): "

const (
	wireSchema  = 1
	wireWant    = 14 * 1024
	wireMax     = 64 * 1024
	sendTimeout = 20 * time.Second
	consentWait = 60 * time.Second
)

// An IPv4 here is four real octets. "0.3.2" does not match.
var ipv4re = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)`)
var ipv6re = regexp.MustCompile(`(?i)(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}`)

func containsAddr(s string) bool {
	return ipv4re.MatchString(s) || ipv6re.MatchString(s)
}

type offerOpts struct {
	rep        report
	dur        time.Duration
	domains    []string
	targets    []probe.Target
	flagSend   bool
	flagNosend bool
	sentPath   string
	reportFile *os.File
	clients    []namedClient
	url        string
	perTry     time.Duration
	stdinTerm  *bool
	in         io.Reader
	promptOut  io.Writer
}

type sendChoice struct {
	ask  bool
	send bool
}

func chooseSend(flagSend, flagNosend, terminal, vpn bool) sendChoice {
	if flagNosend {
		return sendChoice{}
	}
	if flagSend {
		return sendChoice{send: true}
	}
	if !terminal || vpn {
		return sendChoice{}
	}
	return sendChoice{ask: true}
}

func consentYes(line string) bool {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "д", "y", "да", "yes":
		return true
	default:
		return false
	}
}

func askConsent(w io.Writer, r io.Reader, timeout time.Duration) bool {
	fmt.Fprint(w, consentPrompt)
	type ans struct {
		line string
		err  error
	}
	ch := make(chan ans, 1)
	go func() {
		br := bufio.NewReader(r)
		line, err := br.ReadString('\n')
		ch <- ans{line, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case got := <-ch:
		if got.line == "" && got.err != nil {
			return false
		}
		return consentYes(got.line)
	case <-timer.C:
		fmt.Fprintln(w)
		return false
	}
}

func stdinTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func note(f *os.File, format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, line)
	if f != nil {
		fmt.Fprintln(f, line)
	}
}

// wireReport is the only JSON that leaves the machine. Fields are copied
// one by one: a new field on report is not sent until it is added here.
type wireReport struct {
	Schema    int         `json:"schema"`
	Version   string      `json:"v"`
	OS        string      `json:"os"`
	DurSec    int         `json:"dur_s"`
	VPN       bool        `json:"vpn"`
	BypassOn  bool        `json:"bypass_on"`
	Targets   int         `json:"targets"`
	Domains   int         `json:"domains"`
	Net       *wireNet    `json:"net,omitempty"`
	DNS       *wireDNS    `json:"dns,omitempty"`
	TLS       []wireTLS   `json:"tls,omitempty"`
	SNIBypass *wireBypass `json:"sni_bypass,omitempty"`
	QUIC      *wireQUIC   `json:"quic,omitempty"`
	TCP16     []wireTCP   `json:"tcp16,omitempty"`
	TG        *wireTG     `json:"tg,omitempty"`
}

type wireNet struct {
	ASN  int    `json:"asn,omitempty"`
	CC   string `json:"cc,omitempty"`
	Name string `json:"name,omitempty"`
	Err  string `json:"err,omitempty"`
}

type wireDNS struct {
	Truth   []wireTruth  `json:"truth,omitempty"`
	Servers []wireDNSSrv `json:"servers,omitempty"`
	Enc     []wireEnc    `json:"enc,omitempty"`
}

type wireTruth struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	RTT  int    `json:"rtt_ms,omitempty"`
	Err  string `json:"err,omitempty"`
}

type wireDNSSrv struct {
	Name     string       `json:"name"`
	Addr     string       `json:"addr,omitempty"`
	Alive    bool         `json:"alive"`
	RTT      int          `json:"rtt_ms,omitempty"`
	Hijacked bool         `json:"hijacked,omitempty"`
	Egress   string       `json:"egress,omitempty"`
	EgressAS int          `json:"egress_as,omitempty"`
	EgressCC string       `json:"egress_cc,omitempty"`
	Domains  []wireDNSDom `json:"domains,omitempty"`
}

type wireDNSDom struct {
	Domain  string   `json:"d"`
	Verdict string   `json:"v,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

type wireEnc struct {
	Name   string `json:"name"`
	Kind   string `json:"kind,omitempty"`
	Addr   string `json:"addr,omitempty"`
	Status string `json:"status,omitempty"`
	RTT    int    `json:"rtt_ms,omitempty"`
	Truth  string `json:"truth,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type wireTLS struct {
	Domain     string `json:"domain"`
	IP         string `json:"ip,omitempty"`
	SysIP      string `json:"sys_ip,omitempty"`
	Status     string `json:"status,omitempty"`
	Verdict    string `json:"verdict,omitempty"`
	PassesToRU bool   `json:"passes_ru,omitempty"`
	HTTP       string `json:"http,omitempty"`
	Detail     string `json:"detail,omitempty"`
	HTTPDetail string `json:"http_detail,omitempty"`
	RTT        int    `json:"rtt_ms,omitempty"`
}

type wireBypass struct {
	Domain string            `json:"domain"`
	IP     string            `json:"ip,omitempty"`
	Probes []wireBypassProbe `json:"probes,omitempty"`
}

type wireBypassProbe struct {
	Name   string `json:"name"`
	Status string `json:"status,omitempty"`
	Worked bool   `json:"worked,omitempty"`
}

type wireQUIC struct {
	Control     string         `json:"control,omitempty"`
	ControlRTT  int            `json:"control_rtt_ms,omitempty"`
	ControlName string         `json:"control_name,omitempty"`
	RU          bool           `json:"ru,omitempty"`
	Fat         string         `json:"fat,omitempty"`
	Sites       []wireQUICSite `json:"sites,omitempty"`
	STUN        []wireSTUN     `json:"stun,omitempty"`
}

type wireQUICSite struct {
	Domain      string `json:"domain"`
	IP          string `json:"ip,omitempty"`
	Status      string `json:"status,omitempty"`
	Verdict     string `json:"verdict,omitempty"`
	RTT         int    `json:"rtt_ms,omitempty"`
	PassesToRU  bool   `json:"passes_ru,omitempty"`
	ControlMiss bool   `json:"control_miss,omitempty"`
}

type wireSTUN struct {
	Name  string `json:"name"`
	Addr  string `json:"addr,omitempty"`
	OK    bool   `json:"ok"`
	RTT   int    `json:"rtt_ms,omitempty"`
	Err   string `json:"err,omitempty"`
	Reply string `json:"reply,omitempty"`
}

type wireTCP struct {
	ID      string   `json:"id,omitempty"`
	ASN     string   `json:"asn,omitempty"`
	Prov    string   `json:"prov,omitempty"`
	IP      string   `json:"ip,omitempty"`
	Port    int      `json:"port,omitempty"`
	Up      string   `json:"up,omitempty"`
	UpKB    float64  `json:"up_kb,omitempty"`
	Down    string   `json:"down,omitempty"`
	DownKB  float64  `json:"down_kb,omitempty"`
	Verdict string   `json:"verdict,omitempty"`
	White   []string `json:"white,omitempty"`
}

type wireTG struct {
	DCs        []wireDC `json:"dcs,omitempty"`
	MediaBytes int64    `json:"media_bytes,omitempty"`
	MediaKBps  float64  `json:"media_kbps,omitempty"`
	MediaErr   string   `json:"media_err,omitempty"`
}

type wireDC struct {
	Name   string `json:"name"`
	IP     string `json:"ip,omitempty"`
	Status string `json:"status,omitempty"`
	RTT    int    `json:"rtt_ms,omitempty"`
}

type wireMeta struct {
	Version     string
	OS          string
	Dur         time.Duration
	UserDomains []string
	UserTargets []probe.Target
}

type scrub struct {
	bad []string
}

func (s scrub) has(v string) bool {
	if len(v) < 3 {
		return false
	}
	for _, b := range s.bad {
		if len(b) >= 3 && strings.Contains(v, b) {
			return true
		}
	}
	return false
}

func (s scrub) ok(v string) string {
	if s.has(v) {
		return ""
	}
	return v
}

func (s scrub) errField(v string) string {
	v = s.ok(v)
	if v == "" || containsAddr(v) {
		return ""
	}
	return v
}

func (s scrub) list(in []string) []string {
	var out []string
	for _, v := range in {
		if v = s.ok(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func secretStrings(rep report, domains []string, targets []probe.Target) []string {
	var bad []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) >= 3 {
			bad = append(bad, s)
		}
	}
	if rep.Net != nil {
		add(rep.Net.IP)
		add(rep.Net.AS.Prefix)
		for _, name := range rep.Net.VPNIfaces {
			add(name)
		}
		for _, name := range rep.Net.Bypass {
			add(name)
		}
	}
	if rep.QUIC != nil {
		for _, st := range rep.QUIC.STUN {
			add(st.MappedAddr)
		}
	}
	for _, d := range domains {
		add(d)
	}
	for _, t := range targets {
		add(t.IP)
		add(t.ID)
		add(t.SNI)
	}
	return bad
}

func domainSet(list []string) map[string]bool {
	m := map[string]bool{}
	for _, d := range list {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			m[d] = true
		}
	}
	return m
}

func durMS(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(d / time.Millisecond)
}

func buildWire(rep report, meta wireMeta) wireReport {
	s := scrub{bad: secretStrings(rep, meta.UserDomains, meta.UserTargets)}
	ownD := domainSet(meta.UserDomains)
	w := wireReport{
		Schema:  wireSchema,
		Version: meta.Version,
		OS:      meta.OS,
		DurSec:  int(meta.Dur.Round(time.Second) / time.Second),
		Targets: len(meta.UserTargets),
		Domains: len(meta.UserDomains),
	}
	if rep.Net != nil {
		w.VPN = len(rep.Net.VPNIfaces) > 0
		w.BypassOn = len(rep.Net.Bypass) > 0
		w.Net = &wireNet{
			ASN:  rep.Net.AS.ASN,
			CC:   s.ok(rep.Net.AS.CC),
			Name: s.ok(rep.Net.AS.Name),
			Err:  s.errField(rep.Net.Err),
		}
	}
	if rep.DNS != nil {
		d := &wireDNS{}
		for _, t := range rep.DNS.Truth {
			if s.has(t.Name) {
				continue
			}
			d.Truth = append(d.Truth, wireTruth{Name: t.Name, OK: t.OK, RTT: durMS(t.RTT), Err: s.errField(t.Err)})
		}
		for _, srv := range rep.DNS.Servers {
			if s.has(srv.Name) || s.has(srv.Addr) {
				continue
			}
			row := wireDNSSrv{
				Name: srv.Name, Addr: s.ok(srv.Addr), Alive: srv.Alive, RTT: durMS(srv.RTT),
				Hijacked: srv.Hijacked, Egress: s.ok(srv.Egress),
				EgressAS: srv.EgressAS.ASN, EgressCC: s.ok(srv.EgressAS.CC),
			}
			for _, dom := range srv.Domains {
				if ownD[strings.ToLower(dom.Domain)] || s.has(dom.Domain) {
					continue
				}
				row.Domains = append(row.Domains, wireDNSDom{Domain: dom.Domain, Verdict: s.ok(dom.Verdict), IPs: s.list(dom.IPs)})
			}
			d.Servers = append(d.Servers, row)
		}
		for _, e := range rep.DNS.Encrypted {
			if s.has(e.Name) || s.has(e.Addr) {
				continue
			}
			d.Enc = append(d.Enc, wireEnc{
				Name: e.Name, Kind: s.ok(e.Kind), Addr: s.ok(e.Addr), Status: s.ok(e.Status),
				RTT: durMS(e.RTT), Truth: s.ok(e.Truth), Detail: s.ok(e.Detail),
			})
		}
		if d.Truth != nil || d.Servers != nil || d.Enc != nil {
			w.DNS = d
		}
	}
	for _, row := range rep.TLS {
		if ownD[strings.ToLower(row.Domain)] || s.has(row.Domain) || s.has(row.IP) {
			continue
		}
		w.TLS = append(w.TLS, wireTLS{
			Domain: row.Domain, IP: s.ok(row.IP), SysIP: s.ok(row.SysIP),
			Status: s.ok(row.Status), Verdict: s.ok(row.Verdict), PassesToRU: row.PassesToRU,
			HTTP: s.ok(row.HTTP), Detail: s.ok(row.Detail), HTTPDetail: s.ok(row.HTTPDetail),
			RTT: durMS(row.Elapsed),
		})
	}
	if rep.Bypass != nil && !ownD[strings.ToLower(rep.Bypass.Domain)] && !s.has(rep.Bypass.Domain) && !s.has(rep.Bypass.IP) {
		b := &wireBypass{Domain: rep.Bypass.Domain, IP: s.ok(rep.Bypass.IP)}
		for _, pr := range rep.Bypass.Probes {
			if s.has(pr.Name) {
				continue
			}
			b.Probes = append(b.Probes, wireBypassProbe{Name: pr.Name, Status: s.ok(pr.Status), Worked: pr.Worked})
		}
		w.SNIBypass = b
	}
	if rep.QUIC != nil {
		q := &wireQUIC{
			Control: s.ok(rep.QUIC.Control), ControlRTT: durMS(rep.QUIC.ControlRTT),
			ControlName: s.ok(rep.QUIC.ControlName), RU: rep.QUIC.RUControl, Fat: s.ok(rep.QUIC.FatStatus),
		}
		for _, row := range rep.QUIC.Sites {
			if ownD[strings.ToLower(row.Domain)] || s.has(row.Domain) || s.has(row.IP) {
				continue
			}
			q.Sites = append(q.Sites, wireQUICSite{
				Domain: row.Domain, IP: s.ok(row.IP), Status: s.ok(row.Status), Verdict: s.ok(row.Verdict),
				RTT: durMS(row.RTT), PassesToRU: row.PassesToRU, ControlMiss: row.ControlMiss,
			})
		}
		for _, st := range rep.QUIC.STUN {
			if s.has(st.Name) || s.has(st.Addr) {
				continue
			}
			q.STUN = append(q.STUN, wireSTUN{
				Name: st.Name, Addr: s.ok(st.Addr), OK: st.OK, RTT: durMS(st.RTT),
				Err: s.errField(st.Err), Reply: s.ok(st.ReplyAddr),
			})
		}
		w.QUIC = q
	}
	for _, row := range rep.TCP16 {
		t := row.Target
		if ownD[strings.ToLower(t.SNI)] || s.has(t.IP) || s.has(t.ID) || s.has(t.SNI) || s.has(t.Provider) {
			continue
		}
		w.TCP16 = append(w.TCP16, wireTCP{
			ID: s.ok(t.ID), ASN: s.ok(t.ASN), Prov: s.ok(t.Provider), IP: s.ok(t.IP), Port: t.Port,
			Up: s.ok(row.Up.Status), UpKB: row.Up.SentKB, Down: s.ok(row.Down.Status), DownKB: row.Down.RecvKB,
			Verdict: s.ok(row.Verdict), White: s.list(row.WhiteSNI),
		})
	}
	if rep.Telegram != nil {
		g := &wireTG{MediaBytes: rep.Telegram.MediaBytes, MediaKBps: rep.Telegram.MediaKBps, MediaErr: s.errField(rep.Telegram.MediaErr)}
		for _, dc := range rep.Telegram.DCs {
			if s.has(dc.Name) {
				continue
			}
			g.DCs = append(g.DCs, wireDC{Name: dc.Name, IP: s.ok(dc.IP), Status: s.ok(dc.Status), RTT: durMS(dc.RTT)})
		}
		w.TG = g
	}
	return w
}

func gzipBytes(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	z, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := z.Write(raw); err != nil {
		return nil, err
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func stripBulky(w *wireReport) {
	for i := range w.TLS {
		w.TLS[i].Detail = ""
		w.TLS[i].HTTPDetail = ""
		w.TLS[i].SysIP = ""
	}
	for i := range w.TCP16 {
		w.TCP16[i].White = nil
		w.TCP16[i].Prov = ""
	}
	if w.DNS != nil {
		for i := range w.DNS.Servers {
			w.DNS.Servers[i].Egress = ""
			for j := range w.DNS.Servers[i].Domains {
				w.DNS.Servers[i].Domains[j].IPs = nil
			}
		}
		for i := range w.DNS.Enc {
			w.DNS.Enc[i].Detail = ""
		}
	}
	if w.QUIC != nil {
		for i := range w.QUIC.STUN {
			w.QUIC.STUN[i].Err = ""
		}
	}
	if w.TG != nil {
		w.TG.MediaErr = ""
	}
}

func cutLongest(w *wireReport) bool {
	type slice struct {
		n    int
		trim func(int)
	}
	var lists []slice
	lists = append(lists, slice{len(w.TLS), func(n int) { w.TLS = w.TLS[:n] }})
	lists = append(lists, slice{len(w.TCP16), func(n int) { w.TCP16 = w.TCP16[:n] }})
	if w.QUIC != nil {
		lists = append(lists, slice{len(w.QUIC.Sites), func(n int) { w.QUIC.Sites = w.QUIC.Sites[:n] }})
		lists = append(lists, slice{len(w.QUIC.STUN), func(n int) { w.QUIC.STUN = w.QUIC.STUN[:n] }})
	}
	if w.DNS != nil {
		lists = append(lists, slice{len(w.DNS.Servers), func(n int) { w.DNS.Servers = w.DNS.Servers[:n] }})
		lists = append(lists, slice{len(w.DNS.Truth), func(n int) { w.DNS.Truth = w.DNS.Truth[:n] }})
		lists = append(lists, slice{len(w.DNS.Enc), func(n int) { w.DNS.Enc = w.DNS.Enc[:n] }})
		for i := range w.DNS.Servers {
			i := i
			lists = append(lists, slice{len(w.DNS.Servers[i].Domains), func(n int) {
				w.DNS.Servers[i].Domains = w.DNS.Servers[i].Domains[:n]
			}})
		}
	}
	if w.TG != nil {
		lists = append(lists, slice{len(w.TG.DCs), func(n int) { w.TG.DCs = w.TG.DCs[:n] }})
	}
	best := -1
	for i, sl := range lists {
		if sl.n > 0 && (best < 0 || sl.n > lists[best].n) {
			best = i
		}
	}
	if best < 0 {
		return false
	}
	n := lists[best].n / 2
	if n >= lists[best].n {
		n = lists[best].n - 1
	}
	lists[best].trim(n)
	return true
}

// packWire gzips the report. Above ~14 KB it drops detail and then shortens
// lists, and returns the JSON that was actually compressed. It does not
// return a cut-off body.
func packWire(w *wireReport) (raw, gz []byte, err error) {
	bulky := false
	for step := 0; step < 48; step++ {
		raw, err = json.Marshal(w)
		if err != nil {
			return nil, nil, err
		}
		gz, err = gzipBytes(raw)
		if err != nil {
			return nil, nil, err
		}
		if len(gz) <= wireWant {
			return raw, gz, nil
		}
		if !bulky {
			stripBulky(w)
			bulky = true
			continue
		}
		if !cutLongest(w) {
			break
		}
	}
	if len(gz) > wireMax {
		return nil, nil, fmt.Errorf("отчёт больше 64 КБ")
	}
	if len(gz) > wireWant {
		return nil, nil, fmt.Errorf("отчёт не умещается в 14 КБ")
	}
	return raw, gz, nil
}

func leakGuard(raw []byte, bad []string) error {
	s := string(raw)
	for _, b := range bad {
		if len(b) >= 3 && strings.Contains(s, b) {
			return fmt.Errorf("в отчёте осталась лишняя строка")
		}
	}
	return nil
}

type namedClient struct {
	name string
	c    *http.Client
}

type statusErr struct {
	code int
	body string
}

func (e *statusErr) Error() string {
	if e.body == "" {
		return fmt.Sprintf("приёмник %d", e.code)
	}
	return fmt.Sprintf("приёмник %d %s", e.code, e.body)
}

func retryable(err error) bool {
	if err == nil {
		return false
	}
	var se *statusErr
	if errors.As(err, &se) {
		return se.code == http.StatusBadGateway || se.code == http.StatusServiceUnavailable || se.code == http.StatusGatewayTimeout
	}
	return true
}

func sendReason(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "таймаут"
	}
	var se *statusErr
	if errors.As(err, &se) {
		return se.Error()
	}
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if msg == "" {
		return "нет связи"
	}
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return msg
}

func reportClients() []namedClient {
	res := probe.New(4*time.Second, 2)
	return []namedClient{
		{"обычный", githubClient("", res, 2500*time.Millisecond)},
		{"record", githubClient("record", res, 5*time.Second)},
		{"byte", githubClient("byte", res, 5*time.Second)},
	}
}

func postOnce(ctx context.Context, c *http.Client, url string, body []byte, perTry time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, perTry)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", "dpiprobe/"+version)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	text := strings.Join(strings.Fields(string(snippet)), " ")
	if len(text) > 80 {
		text = text[:80]
	}
	if resp.StatusCode != http.StatusOK {
		return &statusErr{code: resp.StatusCode, body: text}
	}
	if !strings.Contains(string(snippet), `"ok":true`) && !strings.Contains(string(snippet), `"ok": true`) {
		return &statusErr{code: resp.StatusCode, body: text}
	}
	return nil
}

func postGzip(ctx context.Context, clients []namedClient, url string, body []byte, perTry time.Duration) (string, error) {
	if len(body) > wireMax {
		return "", fmt.Errorf("отчёт больше 64 КБ")
	}
	if len(clients) == 0 {
		return "", fmt.Errorf("нет клиента")
	}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		for _, cl := range clients {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			err := postOnce(ctx, cl.c, url, body, perTry)
			if err == nil {
				return cl.name, nil
			}
			last = err
			if !retryable(err) {
				return cl.name, err
			}
		}
	}
	if last == nil {
		last = fmt.Errorf("нет связи")
	}
	return "", last
}

func offerReport(ctx context.Context, o offerOpts) {
	vpn := o.rep.Net != nil && len(o.rep.Net.VPNIfaces) > 0
	term := stdinTerminal()
	if o.stdinTerm != nil {
		term = *o.stdinTerm
	}
	choice := chooseSend(o.flagSend, o.flagNosend, term, vpn)
	if choice.ask {
		in := o.in
		if in == nil {
			in = os.Stdin
		}
		out := o.promptOut
		if out == nil {
			out = os.Stderr
		}
		if !askConsent(out, in, consentWait) {
			return
		}
	} else if !choice.send {
		return
	}
	if err := ctx.Err(); err != nil {
		return
	}
	w := buildWire(o.rep, wireMeta{
		Version: version, OS: runtime.GOOS + "/" + runtime.GOARCH, Dur: o.dur,
		UserDomains: o.domains, UserTargets: o.targets,
	})
	raw, gz, err := packWire(&w)
	if err != nil {
		note(o.reportFile, "не ушло (%s)", sendReason(err))
		return
	}
	bad := secretStrings(o.rep, o.domains, o.targets)
	if err := leakGuard(raw, bad); err != nil {
		note(o.reportFile, "не ушло (в отчёте остался лишний адрес)")
		return
	}
	if err := os.WriteFile(o.sentPath, raw, 0o644); err != nil {
		note(o.reportFile, "не ушло (не сохранилась копия)")
		return
	}
	clients := o.clients
	if clients == nil {
		clients = reportClients()
	}
	url := o.url
	if url == "" {
		url = reportURL
	}
	perTry := o.perTry
	if perTry <= 0 {
		perTry = sendTimeout
	}
	mode, err := postGzip(ctx, clients, url, gz, perTry)
	if err != nil {
		note(o.reportFile, "не ушло (%s), пришлите файл %s вручную", sendReason(err), o.sentPath)
		if mode != "" {
			note(o.reportFile, "путь: %s", mode)
		}
		return
	}
	note(o.reportFile, "отправлено, копия: %s", o.sentPath)
	note(o.reportFile, "путь: %s", mode)
}
