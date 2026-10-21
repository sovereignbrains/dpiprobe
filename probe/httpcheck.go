package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpPort is a variable only so tests can point it at a local server.
var httpPort = "80"

// httpProbe sends a plain HTTP request to the real address: on port 80 the
// ISP can answer instead of the site — a 451, a redirect to its block page,
// or a reset.
func (p *Prober) httpProbe(ctx context.Context, ip, domain string) (status, detail string) {
	d := net.Dialer{Timeout: p.Timeout}
	c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, httpPort))
	if err != nil {
		return statusFor(stageTCP, err), shortErr(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(p.Timeout))
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", domain, userAgent); err != nil {
		return statusFor(stageData, err), shortErr(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodGet})
	if err != nil {
		return statusFor(stageData, err), shortErr(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnavailableForLegalReasons {
		return "BLOCKED", "HTTP 451"
	}
	if loc := resp.Header.Get("Location"); resp.StatusCode/100 == 3 && loc != "" {
		if u, err := url.Parse(loc); err == nil && u.Hostname() != "" && !sameSite(u.Hostname(), domain) {
			return "REDIRECT", "уводит на " + u.Hostname()
		}
	}
	return "OK", fmt.Sprintf("HTTP %d", resp.StatusCode)
}

// sameSite treats www., subdomains and parent domains as one site: sites
// routinely redirect example.com → www.example.com and back.
func sameSite(a, b string) bool {
	a = strings.TrimPrefix(strings.ToLower(a), "www.")
	b = strings.TrimPrefix(strings.ToLower(b), "www.")
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}
