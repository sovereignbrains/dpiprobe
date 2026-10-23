package probe

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"testing"
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
