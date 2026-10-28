package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sovereignbrains/dpiprobe/probe"
)

// version is overwritten by -ldflags "-X main.version=…" on a tagged release.
// The default is the next version about to be published. A lower default
// makes an exe built by hand in this folder replace itself with the GitHub
// release.
var version = "0.3.2"

const updateRepo = "sovereignbrains/dpiprobe"

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

func verParts(s string) []int {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	var out []int
	for _, p := range strings.Split(s, ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

func verLess(a, b string) bool {
	pa, pb := verParts(a), verParts(b)
	n := max(len(pa), len(pb))
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func cleanupOldBinary() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	old := exe + ".old"
	for i := 0; i < 5; i++ {
		err := os.Remove(old)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = os.Remove(exe + ".new")
}

func canSelfUpdate() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	slash := filepath.ToSlash(strings.ToLower(exe))
	if strings.Contains(slash, "/go-build") {
		return false
	}
	base := strings.ToLower(filepath.Base(exe))
	return !strings.HasSuffix(base, ".test.exe") && !strings.HasSuffix(base, ".test")
}

func maybeUpdate(ctx context.Context, live *liveView) {
	if !canSelfUpdate() {
		live.note("Обновление", "—")
		return
	}
	live.note("Обновление", "проверяю")
	res := probe.New(4*time.Second, 2)
	clients := []*http.Client{
		githubClient("", res, 2500*time.Millisecond),
		githubClient("record", res, 5*time.Second),
		githubClient("byte", res, 5*time.Second),
	}
	rel, err := latestRelease(ctx, clients)
	if err != nil {
		live.note("Обновление", "нет связи")
		return
	}
	tag := strings.TrimPrefix(rel.TagName, "v")
	if !verLess(version, tag) {
		live.note("Обновление", "актуально")
		return
	}
	url, size := "", int64(0)
	for _, a := range rel.Assets {
		if strings.EqualFold(a.Name, "dpiprobe.exe") {
			url, size = a.URL, a.Size
			break
		}
	}
	if url == "" {
		live.note("Обновление", "в релизе нет exe")
		return
	}
	want := assetSHA(ctx, clients, rel, "dpiprobe.exe")
	if len(want) != 64 {
		live.note("Обновление", "нет подписи")
		return
	}
	live.note("Обновление", "качаю "+tag)
	exe, err := os.Executable()
	if err != nil {
		live.note("Обновление", "не нашёл себя")
		return
	}
	tmp := exe + ".new"
	sum, err := downloadExe(ctx, clients, url, tmp, size, live)
	if err != nil {
		_ = os.Remove(tmp)
		live.note("Обновление", "не скачалось")
		return
	}
	live.note("Обновление", "сверяю")
	if hex.EncodeToString(sum[:]) != want {
		_ = os.Remove(tmp)
		live.note("Обновление", "файл не сошёлся")
		return
	}
	live.note("Обновление", "перезапуск")
	if err := applyAndRestart(exe, tmp); err != nil {
		live.note("Обновление", "скачал, запустите ещё раз")
	}
}

func latestRelease(ctx context.Context, clients []*http.Client) (ghRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := ghDo(ctx, clients, "https://api.github.com/repos/"+updateRepo+"/releases/latest")
	if err != nil {
		return ghRelease{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ghRelease{}, fmt.Errorf("github %s", resp.Status)
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return ghRelease{}, err
	}
	if rel.TagName == "" {
		return ghRelease{}, fmt.Errorf("пустой тег")
	}
	return rel, nil
}

func assetSHA(ctx context.Context, clients []*http.Client, rel ghRelease, name string) string {
	for _, a := range rel.Assets {
		if strings.EqualFold(a.Name, name) {
			if h := normalizeSHA(a.Digest); len(h) == 64 {
				return h
			}
		}
	}
	var sumsURL string
	for _, a := range rel.Assets {
		if strings.EqualFold(a.Name, "SHA256SUMS.txt") {
			sumsURL = a.URL
			break
		}
	}
	if sumsURL == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := ghDo(ctx, clients, sumsURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}
	return parseSHA256SUMS(string(b))[name]
}

func normalizeSHA(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.ReplaceAll(s, " ", "")
	if len(s) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

func parseSHA256SUMS(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		h := normalizeSHA(fields[0])
		if h == "" {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		out[filepath.Base(name)] = h
	}
	return out
}

func downloadExe(ctx context.Context, clients []*http.Client, url, dest string, size int64, live *liveView) ([32]byte, error) {
	var zero [32]byte
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	resp, err := ghDo(ctx, clients, url)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("скачать: %s", resp.Status)
	}
	declared := size
	if size <= 0 {
		size = resp.ContentLength
	}
	var body io.Reader = resp.Body
	if declared > 0 {
		body = io.LimitReader(resp.Body, declared)
	}
	f, err := os.Create(dest)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	h := sha256.New()
	w := io.MultiWriter(f, h)
	var got int64
	buf := make([]byte, 32*1024)
	head := make([]byte, 0, 2)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if len(head) < 2 {
				need := min(2-len(head), n)
				head = append(head, buf[:need]...)
				if len(head) == 2 && (head[0] != 'M' || head[1] != 'Z') {
					return zero, fmt.Errorf("это не exe")
				}
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				return zero, werr
			}
			got += int64(n)
			if size > 0 && live != nil {
				live.note("Обновление", fmt.Sprintf("качаю %d%%", got*100/size))
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return zero, err
		}
	}
	if len(head) < 2 || head[0] != 'M' || head[1] != 'Z' {
		return zero, fmt.Errorf("это не exe")
	}
	if declared > 0 {
		var extra [1]byte
		n, err := resp.Body.Read(extra[:])
		if n > 0 {
			return zero, fmt.Errorf("размер не сошёлся")
		}
		if err != nil && err != io.EOF {
			return zero, err
		}
	}
	if err := f.Close(); err != nil {
		return zero, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func ghDo(ctx context.Context, clients []*http.Client, url string) (*http.Response, error) {
	var last error
	for _, c := range clients {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "dpiprobe/"+version)
		if strings.Contains(url, "api.github.com") {
			req.Header.Set("Accept", "application/vnd.github+json")
		}
		resp, err := c.Do(req)
		if err == nil {
			return resp, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("github: нет клиента")
	}
	return nil, last
}

func githubClient(mode string, res *probe.Prober, handshake time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   handshake,
			ResponseHeaderTimeout: 15 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialGitHub(ctx, addr, mode, handshake, res)
			},
		},
	}
}

func dialGitHub(ctx context.Context, addr, mode string, handshake time.Duration, res *probe.Prober) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := res.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) > 2 {
		ips = ips[:2]
	}
	d := net.Dialer{Timeout: handshake}
	var last error
	for _, ip := range ips {
		raw, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
		if err != nil {
			last = err
			continue
		}
		if tc, ok := raw.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		_ = raw.SetDeadline(time.Now().Add(handshake))
		var c net.Conn = raw
		switch mode {
		case "record":
			c = &splitHelloConn{Conn: raw, sni: host}
		case "byte":
			c = &oneByteHelloConn{Conn: raw}
		}
		tlsConn := tls.Client(c, &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			last = err
			continue
		}
		_ = tlsConn.SetDeadline(time.Time{})
		return tlsConn, nil
	}
	if last == nil {
		last = fmt.Errorf("github: нет адреса %s", host)
	}
	return nil, last
}

// splitHelloConn writes the first TLS record as two records, SNI in the second.
type splitHelloConn struct {
	net.Conn
	sni  string
	done bool
}

func (c *splitHelloConn) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	c.done = true
	first, second, err := probe.SplitTLSRecordBefore(b, []byte(c.sni))
	if err != nil {
		return c.Conn.Write(b)
	}
	if _, err := c.Conn.Write(first); err != nil {
		return 0, err
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := c.Conn.Write(second); err != nil {
		return 0, err
	}
	return len(b), nil
}

type oneByteHelloConn struct {
	net.Conn
	done bool
}

func (c *oneByteHelloConn) Write(b []byte) (int, error) {
	if c.done || len(b) <= 1 {
		return c.Conn.Write(b)
	}
	c.done = true
	if _, err := c.Conn.Write(b[:1]); err != nil {
		return 0, err
	}
	time.Sleep(15 * time.Millisecond)
	n, err := c.Conn.Write(b[1:])
	return n + 1, err
}
