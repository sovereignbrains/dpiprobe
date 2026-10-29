package probe

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 9001, appendix A.1.
func TestClientInitialKeys(t *testing.T) {
	k := clientInitialKeys(unhex(t, "8394c8f03e515708"))
	for _, c := range []struct{ name, got, want string }{
		{"key", hex.EncodeToString(k.key), "1f369613dd76d5467730efcbe3b1a22d"},
		{"iv", hex.EncodeToString(k.iv), "fa044b2f42a3fd3b46fb255c"},
		{"hp", hex.EncodeToString(k.hp), "9f50449e04a0e810283a1e9933adedd2"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}
}

// RFC 9001, appendix A.2: the client's Initial with packet number 2.
func TestSealQUICInitialRFC(t *testing.T) {
	frame := unhex(t, "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"+
		"04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"+
		"616d706c652e636f6dff01000100000a00080006001d00170018001000070005"+
		"04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"+
		"baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"+
		"0d0010000e0403050306030203080408050806002d00020101001c0002400100"+
		"3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"+
		"75300901100f088394c8f03e51570806048000ffff")
	pkt := sealQUICInitial(unhex(t, "8394c8f03e515708"), nil, 2, frame[4:])
	if len(pkt) != quicMinDatagram {
		t.Fatalf("datagram %d bytes, want %d", len(pkt), quicMinDatagram)
	}
	want := "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"
	if got := hex.EncodeToString(pkt[:32]); got != want {
		t.Fatalf("packet starts\n%s\nwant\n%s", got, want)
	}
}

// openQUICInitial undoes sealQUICInitial for a packet with no token.
func openQUICInitial(t *testing.T, pkt []byte) (pn uint32, payload []byte) {
	t.Helper()
	dcid := pkt[6 : 6+int(pkt[5])]
	off := 6 + len(dcid)
	off += 1 + int(pkt[off]) // scid
	off++                    // token length 0
	off += 2                 // two-byte Length
	k := clientInitialKeys(dcid)
	hp, _ := aes.NewCipher(k.hp)
	mask := make([]byte, 16)
	hp.Encrypt(mask, pkt[off+4:off+20])
	hdr := bytes.Clone(pkt[:off+4])
	hdr[0] ^= mask[0] & 0x0f
	for i := range 4 {
		hdr[off+i] ^= mask[1+i]
	}
	pn = binary.BigEndian.Uint32(hdr[off:])
	block, _ := aes.NewCipher(k.key)
	aead, _ := cipher.NewGCM(block)
	nonce := bytes.Clone(k.iv)
	for i := range 4 {
		nonce[8+i] ^= byte(pn >> (24 - 8*i))
	}
	payload, err := aead.Open(nil, nonce, pkt[off+4:], hdr)
	if err != nil {
		t.Fatal("decrypt:", err)
	}
	return pn, payload
}

func TestBuildQUICInitialCarriesSNI(t *testing.T) {
	pkt, scid, err := buildQUICInitial(context.Background(), "blocked.example", []string{"h3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) < quicMinDatagram {
		t.Fatalf("datagram %d bytes, servers drop under %d", len(pkt), quicMinDatagram)
	}
	if !quicLongHeader(pkt) {
		t.Fatal("not a long-header packet")
	}
	if !bytes.Equal(pkt[6+int(pkt[5])+1:][:len(scid)], scid) {
		t.Fatal("scid returned is not the one in the packet")
	}
	if pn, payload := openQUICInitial(t, pkt); pn != 0 || payload[0] != 0x06 || !bytes.Contains(payload, []byte("blocked.example")) {
		t.Fatalf("pn %d, frame %#x, SNI inside: %v", pn, payload[0], bytes.Contains(payload, []byte("blocked.example")))
	}
}

func TestGreaseAndFatInitials(t *testing.T) {
	std, _, err := buildQUICInitialKind(context.Background(), "blocked.example", []string{"h3"}, quicPacketStd)
	if err != nil {
		t.Fatal(err)
	}
	grease, _, err := buildQUICInitialKind(context.Background(), "blocked.example", []string{"h3"}, quicPacketGrease)
	if err != nil {
		t.Fatal(err)
	}
	fat, _, err := buildQUICInitialKind(context.Background(), "blocked.example", []string{"h3"}, quicPacketFat)
	if err != nil {
		t.Fatal(err)
	}
	if len(std) < quicMinDatagram || len(grease) < quicMinDatagram {
		t.Fatalf("short datagrams %d %d", len(std), len(grease))
	}
	if len(fat) < quicFatDatagram {
		t.Fatalf("fat datagram %d, want at least %d", len(fat), quicFatDatagram)
	}
	for _, pkt := range [][]byte{grease, fat} {
		if _, payload := openQUICInitial(t, pkt); !bytes.Contains(payload, []byte("blocked.example")) {
			t.Fatal("SNI missing")
		}
	}
}

func scidOf(pkt []byte) []byte {
	if len(pkt) < 7 || pkt[0]&0x80 == 0 {
		return nil
	}
	off := 6 + int(pkt[5])
	if off >= len(pkt) {
		return nil
	}
	n := int(pkt[off])
	off++
	if n <= 0 || off+n > len(pkt) {
		return nil
	}
	return append([]byte(nil), pkt[off:off+n]...)
}

func TestQUICBurstMatchesReplies(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			id := scidOf(buf[:n])
			if id == nil {
				continue
			}
			reply := append([]byte{0xc0, 0, 0, 0, 1, byte(len(id))}, id...)
			_, _ = pc.WriteToUDP(reply, addr)
		}
	}()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	p := New(time.Second, 2)
	hits, _ := p.quicBurst(context.Background(), []quicShot{
		{ip: "127.0.0.1", port: port, sni: "a.example"},
		{ip: "127.0.0.1", port: port, sni: "b.example"},
	}, 20*time.Millisecond, false)
	pc.Close()
	<-done
	for i, h := range hits {
		if h.status != "OK" {
			t.Fatalf("shot %d: %+v", i, h)
		}
	}
}

func TestQUICBurstSilence(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	p := New(time.Second, 1)
	hits, _ := p.quicBurst(context.Background(), []quicShot{
		{ip: "127.0.0.1", port: pc.LocalAddr().(*net.UDPAddr).Port, sni: "a.example"},
	}, 10*time.Millisecond, false)
	if hits[0].status != "NO REPLY" {
		t.Fatalf("got %+v", hits[0])
	}
}

func TestQUICReplyNeedsOurConnectionID(t *testing.T) {
	scid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	other := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	packet := func(first byte, version uint32, dcid []byte) []byte {
		b := binary.BigEndian.AppendUint32([]byte{first}, version)
		b = append(b, byte(len(dcid)))
		b = append(b, dcid...)
		return append(b, 0, 0x40, 0x10) // empty scid, a little body
	}
	cases := []struct {
		name string
		b    []byte
		want bool
	}{
		{"server Initial", packet(0xc0, quicVersion1, scid), true},
		{"version negotiation", packet(0x80, 0, scid), true},
		{"someone else's id", packet(0xc0, quicVersion1, other), false},
		{"unknown version", packet(0xc0, 0x6b3343cf, scid), false},
		{"short header", packet(0x40, quicVersion1, scid), false},
		{"truncated", packet(0xc0, quicVersion1, scid)[:9], false},
	}
	for _, c := range cases {
		if got := quicReply(c.b, scid); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFillQUICVerdict(t *testing.T) {
	p := New(time.Second, 1)
	cases := []struct {
		name  string
		same  string
		tries []quicForeignTry
		want  string
		miss  bool
	}{
		{
			name: "control silent once, answers on retry",
			same: "OK",
			tries: []quicForeignTry{
				{Neutral: "OK", Name: "NO REPLY"},
				{Neutral: "OK", Name: "OK"},
			},
			want: "по отдельности адрес и имя проходят — блок только на их сочетание",
		},
		{
			name: "control silent once, answers on retry, address silent",
			same: "NO REPLY",
			tries: []quicForeignTry{
				{Neutral: "OK", Name: "NO REPLY"},
				{Neutral: "OK", Name: "OK"},
			},
			want: "адрес не отвечает по QUIC (QUIC у сайта нет или UDP к адресу закрыт)",
		},
		{
			name: "control silent on neutral too",
			same: "NO REPLY",
			tries: []quicForeignTry{
				{Neutral: "NO REPLY", Name: "NO REPLY"},
				{Neutral: "NO REPLY", Name: "NO REPLY"},
			},
			want: "нет ответа и с нейтральным SNI",
		},
		{
			name: "control silent on neutral, address answers",
			same: "OK",
			tries: []quicForeignTry{
				{Neutral: "NO REPLY", Name: "NO REPLY"},
			},
			want: "похоже на DPI по SNI (нет зарубежного QUIC-сервера для сверки)",
		},
		{
			name: "two silences but the address itself is silent",
			same: "NO REPLY",
			tries: []quicForeignTry{
				{Neutral: "OK", Name: "NO REPLY"},
				{Neutral: "OK", Name: "NO REPLY"},
			},
			want: "адрес по QUIC не отвечает",
			miss: true,
		},
		{
			name: "two silences and the address answers a neutral name",
			same: "OK",
			tries: []quicForeignTry{
				{Neutral: "OK", Name: "NO REPLY"},
				{Neutral: "OK", Name: "NO REPLY"},
			},
			want: "DPI по SNI: имя режется и на чистом адресе",
			miss: true,
		},
		{
			name: "one silence is not a cut",
			same: "OK",
			tries: []quicForeignTry{
				{Neutral: "OK", Name: "NO REPLY"},
			},
			want: "сверочный сервер на это имя промолчал один раз — за рез по имени не считаем",
			miss: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &QUICResult{Status: "NO REPLY", Domain: "blocked.example"}
			p.fillQUIC(r, c.same, c.tries)
			if r.Verdict != c.want || r.ControlMiss != c.miss {
				t.Fatalf("verdict %q miss %v, want %q miss %v", r.Verdict, r.ControlMiss, c.want, c.miss)
			}
			if c.miss && (stringsHasCut(r.Verdict) && c.same != "OK" || (c.same != "OK" && stringsHasCut(r.Verdict))) {
				t.Fatalf("address-silent verdict claims a cut: %q", r.Verdict)
			}
		})
	}
}

func stringsHasCut(v string) bool {
	return len(v) >= len("имя режется") && (bytes.HasPrefix([]byte(v), []byte("имя режется")) || bytes.HasPrefix([]byte(v), []byte("DPI по SNI")))
}

func TestRefineSilenceClearsControlMiss(t *testing.T) {
	p := New(time.Second, 1)
	r := &QUICResult{Domain: "youtube.com", Status: "NO REPLY", Verdict: "адрес по QUIC не отвечает", ControlMiss: true}
	p.refineSilence(r, "", true, false)
	if r.ControlMiss {
		t.Fatal("googleSTUN left ControlMiss")
	}
	if r.Verdict != "UDP до Google проходит (STUN), QUIC молчит — режут QUIC, не весь UDP" {
		t.Fatalf("googleSTUN verdict %q", r.Verdict)
	}
	r = &QUICResult{Domain: "google.com", Status: "NO REPLY", Verdict: "адрес по QUIC не отвечает", ControlMiss: true}
	p.refineSilence(r, "", false, true)
	if r.ControlMiss {
		t.Fatal("googleSilent left ControlMiss")
	}
	if r.Verdict != "UDP до Google молчит и по STUN, и по QUIC" {
		t.Fatalf("googleSilent verdict %q", r.Verdict)
	}
}

func TestQUICControlRetriesSilentName(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		seen := map[string]int{}
		known := map[string]bool{}
		_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			id := scidOf(pkt)
			payload, err := initialPayload(pkt)
			if id == nil || err != nil {
				continue
			}
			sni := ""
			switch {
			case bytes.Contains(payload, []byte(tlsRUControl)):
				sni = tlsRUControl
			case bytes.Contains(payload, []byte("blocked.example")):
				sni = "blocked.example"
			default:
				continue
			}
			key := sni + "/" + string(id)
			if !known[key] {
				known[key] = true
				seen[sni]++
			}
			if sni != tlsRUControl && seen["blocked.example"] < 2 {
				continue
			}
			reply := append([]byte{0xc0, 0, 0, 0, 1, byte(len(id))}, id...)
			_, _ = pc.WriteToUDP(reply, addr)
		}
	}()
	p := New(2*time.Second, 1)
	port := pc.LocalAddr().(*net.UDPAddr).Port
	got := p.quicControlNames(context.Background(), "127.0.0.1", port, []string{"blocked.example"}, 20*time.Millisecond)
	pc.Close()
	<-done
	tries := got["blocked.example"]
	if len(tries) < 2 {
		t.Fatalf("tries %+v", tries)
	}
	if tries[0].Neutral != "OK" || tries[0].Name == "OK" {
		t.Fatalf("first try %+v", tries[0])
	}
	if tries[1].Neutral != "OK" || tries[1].Name != "OK" {
		t.Fatalf("retry %+v", tries)
	}
	r := &QUICResult{Status: "NO REPLY"}
	p.fillQUIC(r, "NO REPLY", tries)
	if r.Verdict != "адрес не отвечает по QUIC (QUIC у сайта нет или UDP к адресу закрыт)" || r.ControlMiss {
		t.Fatalf("verdict %q miss %v", r.Verdict, r.ControlMiss)
	}
}

func initialPayload(pkt []byte) ([]byte, error) {
	if len(pkt) < 7 || pkt[0]&0x80 == 0 {
		return nil, errors.New("not a long header")
	}
	dcid := pkt[6 : 6+int(pkt[5])]
	off := 6 + len(dcid)
	if off >= len(pkt) {
		return nil, errors.New("truncated")
	}
	off += 1 + int(pkt[off])
	if off >= len(pkt) {
		return nil, errors.New("token")
	}
	off++
	off += 2
	if off+20 > len(pkt) {
		return nil, errors.New("short")
	}
	k := clientInitialKeys(dcid)
	hp, err := aes.NewCipher(k.hp)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	hp.Encrypt(mask, pkt[off+4:off+20])
	hdr := bytes.Clone(pkt[:off+4])
	hdr[0] ^= mask[0] & 0x0f
	for i := range 4 {
		hdr[off+i] ^= mask[1+i]
	}
	pn := binary.BigEndian.Uint32(hdr[off:])
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := bytes.Clone(k.iv)
	for i := range 4 {
		nonce[8+i] ^= byte(pn >> (24 - 8*i))
	}
	return aead.Open(nil, nonce, pkt[off+4:], hdr)
}
