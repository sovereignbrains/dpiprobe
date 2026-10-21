package probe

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

const (
	typeA   = 1
	typeTXT = 16

	rcodeNXDomain = 3
)

var errDNSFormat = errors.New("битый DNS-ответ")

type dnsAnswer struct {
	rcode int
	ips   []net.IP
	txt   []string
}

func buildQuery(name string, qtype uint16) []byte {
	b := make([]byte, 12, 12+len(name)+6)
	_, _ = rand.Read(b[:2])
	b[2] = 0x01 // RD
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
}

// parseResponse accepts only a reply to query: same ID and the QR bit set.
func parseResponse(msg, query []byte) (dnsAnswer, error) {
	var a dnsAnswer
	if len(msg) < 12 || msg[0] != query[0] || msg[1] != query[1] || msg[2]&0x80 == 0 {
		return a, errDNSFormat
	}
	a.rcode = int(msg[3] & 0x0f)
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	var err error
	for range qd {
		if off, err = skipName(msg, off); err != nil {
			return a, err
		}
		off += 4
	}
	for range an {
		if off, err = skipName(msg, off); err != nil {
			return a, err
		}
		if off+10 > len(msg) {
			return a, errDNSFormat
		}
		typ := binary.BigEndian.Uint16(msg[off:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return a, errDNSFormat
		}
		rd := msg[off : off+rdlen]
		switch {
		case typ == typeA && rdlen == 4:
			a.ips = append(a.ips, net.IP(append([]byte(nil), rd...)))
		case typ == typeTXT:
			var sb strings.Builder
			for j := 0; j < len(rd); {
				n := int(rd[j])
				if j+1+n > len(rd) {
					break
				}
				sb.Write(rd[j+1 : j+1+n])
				j += 1 + n
			}
			a.txt = append(a.txt, sb.String())
		}
		off += rdlen
	}
	return a, nil
}

func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errDNSFormat
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			return off + 2, nil
		default:
			off += 1 + l
		}
	}
}
