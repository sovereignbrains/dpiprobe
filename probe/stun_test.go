package probe

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// XOR-MAPPED-ADDRESS for 203.0.113.10:40000, magic cookie 0x2112a442.
// Port 0x9C40 XOR 0x2112 = 0xBD52. Address bytes XOR the cookie.
func TestSTUNXORMappedAddress(t *testing.T) {
	txid := []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	soft := []byte{0x80, 0x22, 0x00, 0x01, 'a', 0, 0, 0}
	xor := []byte{0x00, 0x01, 0xBD, 0x52, 0xEA, 0x12, 0xD5, 0x48}
	attr := append([]byte{0x00, 0x20, 0x00, 0x08}, xor...)
	body := append(soft, attr...)
	msg := make([]byte, 20+len(body))
	msg[0], msg[1] = 0x01, 0x01
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:8], stunMagic)
	copy(msg[8:20], txid)
	copy(msg[20:], body)
	if got := stunMapped(msg); got != "203.0.113.10:40000" {
		t.Fatalf("got %q", got)
	}
	if got := stunMapped(msg[:20]); got != "" {
		t.Fatalf("header only: %q", got)
	}
}

func TestSTUNTooFastKeepsSourceAndMapped(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, addr, err := pc.ReadFromUDP(buf)
		if err != nil || n < 20 || addr == nil {
			return
		}
		_, _ = pc.WriteToUDP(stunSuccess(buf[8:20], net.ParseIP("198.51.100.20"), 54320), addr)
	}()
	p := New(time.Second, 1)
	port := pc.LocalAddr().(*net.UDPAddr).Port
	wantFrom := pc.LocalAddr().String()
	rtt, from, mapped, ok, err := p.stun(context.Background(), "127.0.0.1", port)
	pc.Close()
	<-done
	if ok || !errors.Is(err, errStunTooFast) {
		t.Fatalf("ok %v rtt %s err %v", ok, rtt, err)
	}
	if from != wantFrom {
		t.Fatalf("from %q want %q", from, wantFrom)
	}
	if mapped != "198.51.100.20:54320" {
		t.Fatalf("mapped %q", mapped)
	}
}

func stunSuccess(txid []byte, ip net.IP, port int) []byte {
	ip4 := ip.To4()
	xport := port ^ 0x2112
	val := []byte{0, 0x01, byte(xport >> 8), byte(xport), ip4[0] ^ stunMagic[0], ip4[1] ^ stunMagic[1], ip4[2] ^ stunMagic[2], ip4[3] ^ stunMagic[3]}
	body := append([]byte{0x00, 0x20, 0x00, 0x08}, val...)
	msg := make([]byte, 20+len(body))
	msg[0], msg[1] = 0x01, 0x01
	msg[3] = byte(len(body))
	copy(msg[4:8], stunMagic)
	copy(msg[8:20], txid)
	copy(msg[20:], body)
	return msg
}
