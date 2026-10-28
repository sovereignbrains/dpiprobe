package probe

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSplitRecordHidesSNI(t *testing.T) {
	flight, err := clientHelloFlight("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	first, second, err := splitRecordBefore(flight, []byte("api.github.com"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first, []byte("api.github.com")) {
		t.Fatal("SNI still in the first record")
	}
	if !bytes.Contains(second, []byte("api.github.com")) {
		t.Fatal("SNI missing from the second record")
	}
}

func TestFragmentReachesLocalTLS(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer s.Close()
	host, ps, _ := net.SplitHostPort(strings.TrimPrefix(s.URL, "https://"))
	port, _ := strconv.Atoi(ps)
	p := New(2*time.Second, 1)
	ctx := context.Background()
	if pr := p.probeSegment(ctx, host, port, "example.com"); !pr.Worked {
		t.Fatalf("segment: %+v", pr)
	}
	if pr := p.probeRecord(ctx, host, port, "example.com"); !pr.Worked {
		t.Fatalf("record: %+v", pr)
	}
}

func TestSTUNPlausible(t *testing.T) {
	if stunPlausible(500 * time.Microsecond) {
		t.Fatal("half a millisecond is not a path to the server")
	}
	if !stunPlausible(stunMinRTT) {
		t.Fatal("floor should count")
	}
}

func TestSTUNReply(t *testing.T) {
	txid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	b := make([]byte, 20)
	b[0], b[1] = 0x01, 0x01
	copy(b[4:8], stunMagic)
	copy(b[8:20], txid)
	if !stunReply(b, txid) {
		t.Fatal("binding success not recognised")
	}
	b[1] = 0x11
	if stunReply(b, txid) {
		t.Fatal("error response must not count")
	}
}
