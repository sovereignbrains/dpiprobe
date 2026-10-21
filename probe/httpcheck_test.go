package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSameSite(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"www.example.com", "example.com", true},
		{"example.com", "www.example.com", true},
		{"m.example.com", "example.com", true},
		{"Example.COM", "example.com", true},
		{"warning.rt.ru", "example.com", false},
		{"notexample.com", "example.com", false},
	} {
		if got := sameSite(c.a, c.b); got != c.want {
			t.Errorf("sameSite(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestHTTPProbe(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "blocked.test":
			w.WriteHeader(http.StatusUnavailableForLegalReasons)
		case "stub.test":
			http.Redirect(w, r, "http://warning.isp.example/blocked", http.StatusFound)
		case "site.test":
			http.Redirect(w, r, "https://www.site.test/", http.StatusMovedPermanently)
		}
	}))
	defer s.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(s.URL, "http://"))
	old := httpPort
	httpPort = port
	defer func() { httpPort = old }()

	p := New(2*time.Second, 1)
	for domain, want := range map[string]string{
		"blocked.test": "BLOCKED",
		"stub.test":    "REDIRECT",
		"site.test":    "OK",
	} {
		if got, detail := p.httpProbe(context.Background(), host, domain); got != want {
			t.Errorf("%s: got %s (%s), want %s", domain, got, detail, want)
		}
	}
}
