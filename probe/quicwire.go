package probe

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
)

// A QUIC Initial packet (RFC 9000, RFC 9001) carrying a real TLS ClientHello:
// DPI reads the SNI out of it exactly as it would from a browser. The probe
// never decrypts the reply: a long-header datagram addressed to our source
// connection ID is proof that the server got the packet.

var quicV1Salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

const (
	quicVersion1    = 0x00000001
	quicMinDatagram = 1200
	quicFatDatagram = 1400
	quicPNLen       = 4
)

const (
	quicPacketStd = iota
	quicPacketGrease
	quicPacketFat
)

type quicKeys struct{ key, iv, hp []byte }

func hkdfExpandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // empty context
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		panic(err) // n is a constant well under the HKDF limit
	}
	return out
}

// clientInitialKeys derives the keys a client protects its Initial packets
// with: they depend only on the destination connection ID.
func clientInitialKeys(dcid []byte) quicKeys {
	initial, err := hkdf.Extract(sha256.New, dcid, quicV1Salt)
	if err != nil {
		panic(err)
	}
	client := hkdfExpandLabel(initial, "client in", sha256.Size)
	return quicKeys{
		key: hkdfExpandLabel(client, "quic key", 16),
		iv:  hkdfExpandLabel(client, "quic iv", 12),
		hp:  hkdfExpandLabel(client, "quic hp", 16),
	}
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	}
	return binary.BigEndian.AppendUint64(b, v|0xc0<<56)
}

// quicTransportParams: the minimum a server accepts before it answers.
// grease adds max_ack_delay and a grease parameter, which is what a browser
// sends and what a picky server may require.
func quicTransportParams(scid []byte, grease bool) []byte {
	var b []byte
	param := func(id uint64, val []byte) {
		b = appendVarint(b, id)
		b = appendVarint(b, uint64(len(val)))
		b = append(b, val...)
	}
	num := func(id, v uint64) { param(id, appendVarint(nil, v)) }
	num(0x01, 30000)  // max_idle_timeout, ms
	num(0x03, 1452)   // max_udp_payload_size
	num(0x04, 1<<20)  // initial_max_data
	num(0x05, 1<<18)  // initial_max_stream_data_bidi_local
	num(0x06, 1<<18)  // initial_max_stream_data_bidi_remote
	num(0x07, 1<<18)  // initial_max_stream_data_uni
	num(0x08, 100)    // initial_max_streams_bidi
	num(0x09, 100)    // initial_max_streams_uni
	param(0x0f, scid) // initial_source_connection_id
	if grease {
		num(0x0b, 25)             // max_ack_delay, ms
		param(27+31*2, []byte{0}) // grease, RFC 9000
	}
	return b
}

// quicClientHello asks crypto/tls for the ClientHello a QUIC client sends.
func quicClientHello(ctx context.Context, sni string, alpn []string, scid []byte, grease bool) ([]byte, error) {
	q := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		ServerName:         sni,
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // the handshake is never finished
	}})
	defer q.Close()
	q.SetTransportParameters(quicTransportParams(scid, grease))
	if err := q.Start(ctx); err != nil {
		return nil, err
	}
	var hello []byte
	for {
		ev := q.NextEvent()
		switch ev.Kind {
		case tls.QUICNoEvent:
			if len(hello) == 0 {
				return nil, errors.New("crypto/tls не выдал ClientHello")
			}
			return hello, nil
		case tls.QUICWriteData:
			if ev.Level == tls.QUICEncryptionLevelInitial {
				hello = append(hello, ev.Data...)
			}
		}
	}
}

// buildQUICInitial returns one Initial datagram, padded to 1200 bytes as
// RFC 9000 requires of a client — servers drop shorter ones.
// The source connection ID comes back too: every server reply carries it.
func buildQUICInitial(ctx context.Context, sni string, alpn []string) (pkt, scid []byte, err error) {
	return buildQUICInitialKind(ctx, sni, alpn, quicPacketStd)
}

// buildQUICInitialKind: std is the usual 1200-byte Initial, grease adds the
// transport parameters a browser sends, fat pads to 1400 bytes.
func buildQUICInitialKind(ctx context.Context, sni string, alpn []string, kind int) (pkt, scid []byte, err error) {
	dcid := make([]byte, 8)
	scid = make([]byte, 8)
	_, _ = rand.Read(dcid)
	_, _ = rand.Read(scid)
	hello, err := quicClientHello(ctx, sni, alpn, scid, kind == quicPacketGrease)
	if err != nil {
		return nil, nil, err
	}
	size := quicMinDatagram
	if kind == quicPacketFat {
		size = quicFatDatagram
	}
	return sealQUICInitialN(dcid, scid, 0, hello, size), scid, nil
}

func sealQUICInitial(dcid, scid []byte, pn uint32, crypto []byte) []byte {
	return sealQUICInitialN(dcid, scid, pn, crypto, quicMinDatagram)
}

func sealQUICInitialN(dcid, scid []byte, pn uint32, crypto []byte, size int) []byte {
	if size < quicMinDatagram {
		size = quicMinDatagram
	}
	frames := []byte{0x06} // CRYPTO
	frames = appendVarint(frames, 0)
	frames = appendVarint(frames, uint64(len(crypto)))
	frames = append(frames, crypto...)

	hdr := []byte{0xc0 | (quicPNLen - 1)} // long header, Initial
	hdr = binary.BigEndian.AppendUint32(hdr, quicVersion1)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, 0) // token length

	// Length is a two-byte varint: header size stays fixed while padding
	// is worked out.
	const tag = 16
	if room := size - (len(hdr) + 2 + quicPNLen + len(frames) + tag); room > 0 {
		frames = append(frames, make([]byte, room)...) // PADDING frames are zeros
	}
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(quicPNLen+len(frames)+tag)|0x4000)
	pnOff := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)

	k := clientInitialKeys(dcid)
	block, _ := aes.NewCipher(k.key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	copy(nonce, k.iv)
	for i := range 4 {
		nonce[8+i] ^= byte(pn >> (24 - 8*i))
	}
	pkt := aead.Seal(hdr, nonce, frames, hdr)

	// Header protection: the sample starts 4 bytes after the packet number's start.
	hp, _ := aes.NewCipher(k.hp)
	mask := make([]byte, 16)
	hp.Encrypt(mask, pkt[pnOff+4:pnOff+4+16])
	pkt[0] ^= mask[0] & 0x0f
	for i := range quicPNLen {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

// quicLongHeader: a datagram that looks like QUIC from the outside.
func quicLongHeader(b []byte) bool {
	return len(b) >= 7 && b[0]&0x80 != 0
}

// quicReply: the server answered us — a long-header packet (Initial,
// Handshake, Retry or Version Negotiation) of version 1 or 0 whose
// destination connection ID is our scid. A middlebox that never parsed our
// packet can't produce that; one that fakes "QUIC" with any long header can.
func quicReply(b, scid []byte) bool {
	if !quicLongHeader(b) || len(b) < 6+len(scid) {
		return false
	}
	if v := binary.BigEndian.Uint32(b[1:5]); v != quicVersion1 && v != 0 {
		return false
	}
	return int(b[5]) == len(scid) && bytes.Equal(b[6:6+len(scid)], scid)
}
