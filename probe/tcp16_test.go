package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// freezeListener imitates the ISP: once a connection has carried
// freezeAfter bytes in either direction, it goes silent.
type freezeListener struct {
	net.Listener
	freezeAfter int64
}

func (l freezeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &freezeConn{Conn: c, limit: l.freezeAfter}, nil
}

// freezeConn black-holes traffic past the limit the way the DPI does: bytes
// are swallowed, nothing is delivered, but a close by the peer still ends it.
type freezeConn struct {
	net.Conn
	limit int64
	seen  atomic.Int64
}

func (c *freezeConn) frozen() bool { return c.limit > 0 && c.seen.Load() >= c.limit }

func (c *freezeConn) Read(b []byte) (int, error) {
	for c.frozen() {
		if _, err := c.Conn.Read(b); err != nil {
			return 0, err
		}
	}
	n, err := c.Conn.Read(b)
	c.seen.Add(int64(n))
	return n, err
}

func (c *freezeConn) Write(b []byte) (int, error) {
	if c.frozen() {
		return len(b), nil
	}
	n, err := c.Conn.Write(b)
	c.seen.Add(int64(n))
	return n, err
}

func startServer(t *testing.T, freezeAfter int64, h http.HandlerFunc) (string, int) {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	s.Listener = freezeListener{Listener: s.Listener, freezeAfter: freezeAfter}
	s.Config.MaxHeaderBytes = 1 << 20
	s.StartTLS()
	t.Cleanup(s.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(s.URL, "https://"))
	n, _ := strconv.Atoi(port)
	return host, n
}

func bigBody(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write(make([]byte, 32<<10))
}

func TestFatDetectsFreeze(t *testing.T) {
	ip, port := startServer(t, 16<<10, bigBody)
	p := New(time.Second, 4)
	r := p.CheckTarget(context.Background(), Target{IP: ip, Port: port})
	if r.Verdict != "DETECTED" || r.Up.Status != "DETECTED" {
		t.Fatalf("freeze not detected: %+v", r)
	}
}

func TestFatCleanPath(t *testing.T) {
	ip, port := startServer(t, 0, bigBody)
	p := New(time.Second, 4)
	r := p.CheckTarget(context.Background(), Target{IP: ip, Port: port})
	if r.Verdict != "OK" || r.Up.Status != "OK" || r.Down.Status != "OK" {
		t.Fatalf("clean path: %+v", r)
	}
}

// A server that drops keep-alive must give "can't tell", not a false OK —
// a pooled client would reconnect silently and restart the byte count.
func TestFatServerClosesIsNotOK(t *testing.T) {
	ip, port := startServer(t, 0, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
	})
	p := New(time.Second, 4)
	if r := p.fatUp(context.Background(), ip, port, "example.com"); r.Status != "CLOSED" {
		t.Fatalf("got %+v", r)
	}
}

func TestFatFreezeOutsideWindowIsNotDetected(t *testing.T) {
	ip, port := startServer(t, 3<<10, bigBody) // dies right after the handshake
	p := New(time.Second, 4)
	if r := p.fatUp(context.Background(), ip, port, "example.com"); r.Status == "DETECTED" {
		t.Fatalf("a stall at %.0f KB is outside the 16–20 KB window: %+v", r.SentKB+r.RecvKB, r)
	}
}
