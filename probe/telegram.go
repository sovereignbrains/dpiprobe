package probe

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"time"
)

var telegramDCs = []struct{ Name, IP string }{
	{"DC1", "149.154.175.53"},
	{"DC2", "149.154.167.51"},
	{"DC3", "149.154.175.100"},
	{"DC4", "149.154.167.91"},
	{"DC5", "91.108.56.130"},
}

const (
	telegramMediaURL = "https://telegram.org/img/Telegram200million.png"
	tgDownloadLimit  = 8 << 20
	tgDownloadTime   = 12 * time.Second

	mtprotoReqPQMulti = 0xbe7e8ef1
	mtprotoResPQ      = 0x05162463
	obfsIntermediate  = 0xeeeeeeee
)

type DCResult struct {
	Name, IP string
	Status   string // OK = the DC answered a real MTProto request
	RTT      time.Duration
}

type TelegramReport struct {
	DCs        []DCResult
	MediaBytes int64
	MediaKBps  float64
	MediaErr   string
}

func (p *Prober) CheckTelegram(ctx context.Context) TelegramReport {
	var rep TelegramReport
	rep.DCs = make([]DCResult, len(telegramDCs))
	p.forEach(len(telegramDCs), func(i int) {
		dc := telegramDCs[i]
		rtt, st := p.mtprotoPing(ctx, dc.IP)
		rep.DCs[i] = DCResult{Name: dc.Name, IP: dc.IP, Status: st, RTT: rtt}
	})
	rep.MediaBytes, rep.MediaKBps, rep.MediaErr = p.download(ctx, telegramMediaURL)
	return rep
}

// mtprotoPing sends req_pq_multi over obfuscated2 — what a Telegram client
// sends first. A bare TCP connect proves little: DPI may let the SYN through
// and kill the protocol afterwards.
func (p *Prober) mtprotoPing(ctx context.Context, ip string) (time.Duration, string) {
	d := net.Dialer{Timeout: p.Timeout}
	c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, "443"))
	if err != nil {
		return 0, statusFor(stageTCP, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(p.Timeout))
	t0 := time.Now()

	init := obfsInit()
	encBlock, _ := aes.NewCipher(init[8:40])
	enc := cipher.NewCTR(encBlock, init[40:56])
	rev := make([]byte, 48)
	for i := range rev {
		rev[i] = init[55-i]
	}
	decBlock, _ := aes.NewCipher(rev[:32])
	dec := cipher.NewCTR(decBlock, rev[32:48])
	wire := make([]byte, 64)
	enc.XORKeyStream(wire, init)
	copy(wire[:56], init[:56])

	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	msg := make([]byte, 8, 40) // auth_key_id = 0: unencrypted message
	msg = binary.LittleEndian.AppendUint64(msg, uint64(time.Now().Unix())<<32)
	msg = binary.LittleEndian.AppendUint32(msg, 20)
	msg = binary.LittleEndian.AppendUint32(msg, mtprotoReqPQMulti)
	msg = append(msg, nonce...)
	pkt := binary.LittleEndian.AppendUint32(nil, uint32(len(msg)))
	pkt = append(pkt, msg...)
	enc.XORKeyStream(pkt, pkt)
	if _, err := c.Write(append(wire, pkt...)); err != nil {
		return 0, statusFor(stageData, err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return 0, statusFor(stageData, err)
	}
	dec.XORKeyStream(hdr, hdr)
	n := binary.LittleEndian.Uint32(hdr)
	if n < 40 || n > 4096 {
		return 0, "BAD REPLY"
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		return 0, statusFor(stageData, err)
	}
	dec.XORKeyStream(body, body)
	if binary.LittleEndian.Uint32(body[20:24]) != mtprotoResPQ || !bytes.Equal(body[24:40], nonce) {
		return 0, "BAD REPLY"
	}
	return time.Since(t0), "OK"
}

// obfsInit builds the 64-byte obfuscated2 header; the first bytes must not
// look like another protocol the server would sniff.
func obfsInit() []byte {
	init := make([]byte, 64)
	for {
		_, _ = rand.Read(init)
		first := binary.LittleEndian.Uint32(init)
		switch {
		case init[0] == 0xef,
			first == 0x44414548, first == 0x54534f50, first == 0x20544547, first == 0x4954504f, // HEAD POST GET OPTI
			first == 0xeeeeeeee, first == 0xdddddddd, first == 0x02010316,
			binary.LittleEndian.Uint32(init[4:]) == 0:
			continue
		}
		binary.LittleEndian.PutUint32(init[56:], obfsIntermediate)
		return init
	}
}

func (p *Prober) download(ctx context.Context, url string) (int64, float64, string) {
	ctx, cancel := context.WithTimeout(ctx, tgDownloadTime)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, shortErr(err)
	}
	req.Header.Set("User-Agent", userAgent)
	t0 := time.Now()
	resp, err := p.http.Do(req)
	if err != nil {
		return 0, 0, statusFor(stageTLS, err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, tgDownloadLimit))
	speed := float64(n) / 1024 / time.Since(t0).Seconds()
	if err != nil {
		return n, speed, statusFor(stageData, err)
	}
	return n, speed, ""
}
