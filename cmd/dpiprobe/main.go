// Command dpiprobe checks how the ISP interferes with traffic and prints
// a report; -json saves the raw results.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/sovereignbrains/dpiprobe/probe"
)

type report struct {
	Net      *probe.NetInfo        `json:"net,omitempty"`
	DNS      *probe.DNSReport      `json:"dns,omitempty"`
	TLS      []probe.TLSResult     `json:"tls,omitempty"`
	QUIC     *probe.QUICReport     `json:"quic,omitempty"`
	TCP16    []probe.TCP16Result   `json:"tcp16,omitempty"`
	Telegram *probe.TelegramReport `json:"telegram,omitempty"`
}

func main() {
	only := flag.String("only", "net,dns,tls,quic,tcp16,tg", "какие проверки: net,dns,tls,quic,tcp16,tg")
	targets := flag.String("target", "", "свои серверы через запятую: host[:port][@sni] — только они проверяются на обрыв 16 КБ и ответ по UDP (QUIC)")
	domains := flag.String("domains", "", "свои домены для TLS-проверки через запятую")
	jsonOut := flag.String("json", "", "сохранить результаты в JSON-файл")
	parallel := flag.Int("parallel", 8, "сколько проверок одновременно")
	timeout := flag.Duration("timeout", 8*time.Second, "таймаут одной пробы")
	sniSearch := flag.Bool("sni", true, "искать белые SNI для сетей с обрывом")
	flag.Parse()

	onlySet := false
	flag.Visit(func(f *flag.Flag) { onlySet = onlySet || f.Name == "only" })
	sections := strings.Split(*only, ",")
	if *targets != "" && !onlySet {
		sections = []string{"net", "quic", "tcp16"}
	}
	has := func(s string) bool { return slices.Contains(sections, s) }
	var own []probe.Target
	for _, s := range splitList(*targets) {
		t, err := probe.ParseTarget(s)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		own = append(own, t)
	}
	sites := probe.DefaultDomains()
	if *domains != "" {
		sites = splitList(*domains)
	}

	// A double-clicked console closes on exit, so the report always goes to
	// files next to the exe as well.
	base := reportBase()
	if f, err := os.Create(base + ".txt"); err == nil {
		defer f.Close()
		out = io.MultiWriter(os.Stdout, f)
	} else {
		fmt.Fprintln(os.Stderr, "Не удалось создать файл отчёта:", err)
	}
	if *jsonOut == "" {
		*jsonOut = base + ".json"
	}
	defer waitIfOwnConsole()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	p := probe.New(*timeout, *parallel)
	var progressMu sync.Mutex
	p.Progress = func(done, total int) {
		progressMu.Lock()
		defer progressMu.Unlock()
		fmt.Fprintf(os.Stderr, "\r   %d/%d", done, total)
		if done == total {
			fmt.Fprintln(os.Stderr)
		}
	}
	var rep report
	start := time.Now()
	progress("Проверка займёт 3–6 минут. Окно не закрывайте — отчёт сохранится сам.")

	if has("net") {
		ni := p.NetInfo(ctx)
		rep.Net = &ni
		printNet(ni)
	}
	if has("dns") {
		progress("DNS: эталон через DoH и опрос резолверов…")
		d := p.CheckDNS(ctx)
		rep.DNS = &d
		printDNS(d)
	}
	if has("tls") {
		progress(fmt.Sprintf("TLS: %d доменов…", len(sites)))
		rep.TLS = p.CheckTLS(ctx, sites)
		printTLS(rep.TLS)
	}
	if has("quic") {
		// With own servers given, they alone are probed, as for tcp16.
		list := sites
		if len(own) > 0 {
			list = nil
		}
		progress(fmt.Sprintf("QUIC (UDP 443): %d доменов, %d своих серверов…", len(list), len(own)))
		q := p.CheckQUIC(ctx, list, own)
		rep.QUIC = &q
		printQUIC(q)
	}
	if has("tcp16") {
		list := own
		if len(list) == 0 {
			var err error
			if list, err = probe.DefaultTargets(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		var white []string
		if *sniSearch {
			white = probe.WhitelistSNI()
		}
		progress(fmt.Sprintf("Обрыв 16–20 КБ: %d целей, вверх и вниз…", len(list)))
		rep.TCP16 = p.CheckTCP16(ctx, list, white)
		printTCP16(rep.TCP16)
	}
	if has("tg") {
		progress("Telegram: MTProto к дата-центрам и загрузка с telegram.org…")
		tg := p.CheckTelegram(ctx)
		rep.Telegram = &tg
		printTelegram(tg)
	}
	printSummary(rep)
	fmt.Fprintf(out, "\nГотово за %s.\n", time.Since(start).Round(time.Second))

	b, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "JSON:", err)
		return
	}
	fmt.Fprintf(out, "Отчёт сохранён: %s.txt и %s\n", base, *jsonOut)
}

var out io.Writer = os.Stdout

func reportBase() string {
	dir := "."
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	return filepath.Join(dir, "dpiprobe-"+time.Now().Format("20060102-150405"))
}

func waitIfOwnConsole() {
	if !ownConsole() {
		return
	}
	fmt.Fprint(os.Stderr, "\nНажмите Enter, чтобы закрыть окно…")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func progress(s string) { fmt.Fprintln(os.Stderr, "→ "+s) }

func header(s string) { fmt.Fprintf(out, "\n== %s ==\n", s) }

func table() *tabwriter.Writer { return tabwriter.NewWriter(out, 0, 0, 2, ' ', 0) }

func ms(d time.Duration) string {
	if d == 0 {
		return "—"
	}
	return fmt.Sprintf("%d мс", d.Milliseconds())
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func printNet(ni probe.NetInfo) {
	header("Сеть")
	if ni.Err != "" {
		fmt.Fprintln(out, "  Внешний IP узнать не удалось:", ni.Err)
	} else {
		fmt.Fprintf(out, "  Внешний IP: %s  %s\n", ni.IP, ni.AS)
	}
	if len(ni.VPNIfaces) > 0 {
		fmt.Fprintf(out, "  ВНИМАНИЕ: поднят VPN-интерфейс (%s) — проверяется путь через VPN, а не провайдер.\n", strings.Join(ni.VPNIfaces, ", "))
		fmt.Fprintln(out, "  Для проверки провайдера выключите VPN.")
	}
	if len(ni.Bypass) > 0 {
		fmt.Fprintf(out, "  ВНИМАНИЕ: запущен обход DPI — %s. Он переделывает пакеты самой проверки:\n", strings.Join(ni.Bypass, ", "))
		fmt.Fprintln(out, "  сайты откроются, а провайдер окажется «чистым». Для проверки провайдера закройте его.")
	}
}

var shortVerdict = map[string]string{
	probe.VerdictOK:       "ok",
	probe.VerdictSpoofed:  "ПОДМЕНА",
	probe.VerdictInjected: "ВБРОС",
	probe.VerdictSilent:   "молчит",
	probe.VerdictNoReply:  "—",
	probe.VerdictNoTruth:  "?",
}

func printDNS(d probe.DNSReport) {
	header("DNS")
	var truth []string
	for _, t := range d.Truth {
		if t.OK {
			truth = append(truth, fmt.Sprintf("%s %s", t.Name, ms(t.RTT)))
		} else {
			truth = append(truth, fmt.Sprintf("%s — %s", t.Name, clip(t.Err, 40)))
		}
	}
	fmt.Fprintln(out, "  Эталон (DoH без фильтров):", strings.Join(truth, "; "))

	w := table()
	head := "  Резолвер\tАдрес\tПинг\tКто ответил на самом деле"
	if len(d.Servers) > 0 {
		for _, dr := range firstDomains(d) {
			head += "\t" + dr
		}
	}
	fmt.Fprintln(w, head)
	cols := len(firstDomains(d))
	var details []string
	for _, s := range d.Servers {
		egress := "—"
		if s.Egress != "" {
			egress = s.Egress + " " + clip(s.EgressAS.String(), 30)
			if s.Hijacked {
				egress = "ПЕРЕХВАТ → " + egress
			}
		}
		if !s.Alive && s.Egress == "" {
			egress = "недоступен"
		}
		row := fmt.Sprintf("  %s\t%s\t%s\t%s", s.Name, s.Addr, ms(s.RTT), egress)
		// Every row gets every cell: tabwriter restarts column alignment
		// after a line with fewer cells.
		var bad []string
		for i := range cols {
			cell := ""
			if i < len(s.Domains) {
				dr := s.Domains[i]
				cell = shortVerdict[dr.Verdict]
				if dr.Verdict == probe.VerdictSpoofed || dr.Verdict == probe.VerdictInjected {
					bad = append(bad, dr.Detail)
				}
			}
			row += "\t" + cell
		}
		if len(bad) > 0 {
			details = append(details, fmt.Sprintf("  %s: %s", s.Name, summarize(bad)))
		}
		fmt.Fprintln(w, row)
	}
	w.Flush()
	if len(details) > 0 {
		fmt.Fprintln(out, "  Что подсунули:")
		for _, l := range details {
			fmt.Fprintln(out, "  "+l)
		}
	}

	if len(d.Encrypted) == 0 {
		return
	}
	fmt.Fprintln(out, "\n  Зашифрованный DNS (что можно поставить вместо обычного):")
	w = table()
	fmt.Fprintln(w, "  Сервер\tТип\tСтатус\tВремя\tОтвечает")
	for _, e := range d.Encrypted {
		truth := e.Truth
		if e.Truth == probe.EncFiltered {
			truth += " (" + clip(e.Detail, 40) + ")"
		}
		if e.Status != "OK" {
			truth = clip(e.Detail, 40)
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n", e.Name, e.Kind, e.Status, ms(e.RTT), truth)
	}
	w.Flush()
}

// oneEgress: every resolver was answered from the same network — what a VPN
// client looks like when it captures all DNS (sing-box hijack-dns and the like).
func oneEgress(d *probe.DNSReport) bool {
	asn := 0
	for _, s := range d.Servers {
		if s.Egress == "" {
			continue
		}
		if asn == 0 {
			asn = s.EgressAS.ASN
		}
		if s.EgressAS.ASN == 0 || s.EgressAS.ASN != asn {
			return false
		}
	}
	return asn != 0
}

// summarize folds repeated details: "NXDOMAIN ×5" instead of five lines.
func summarize(items []string) string {
	var order []string
	count := map[string]int{}
	for _, s := range items {
		if count[s] == 0 {
			order = append(order, s)
		}
		count[s]++
	}
	parts := make([]string, len(order))
	for i, s := range order {
		parts[i] = s
		if count[s] > 1 {
			parts[i] += fmt.Sprintf(" ×%d", count[s])
		}
	}
	return strings.Join(parts, "; ")
}

func firstDomains(d probe.DNSReport) []string {
	for _, s := range d.Servers {
		if len(s.Domains) > 0 {
			var out []string
			for _, dr := range s.Domains {
				out = append(out, dr.Domain)
			}
			return out
		}
	}
	return nil
}

func printTLS(rs []probe.TLSResult) {
	header("Сайты (TLS)")
	w := table()
	fmt.Fprintln(w, "  Домен\tIP\tHTTP\tHTTPS\tВывод")
	for _, r := range rs {
		verdict := r.Verdict
		if r.Status == "OK" {
			verdict = ms(r.Elapsed)
		}
		if r.HTTP == "BLOCKED" || r.HTTP == "REDIRECT" {
			verdict += " [HTTP: " + r.HTTPDetail + "]"
		}
		if r.SysIP != "" {
			verdict += " [системный DNS даёт " + r.SysIP + "]"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n", clip(r.Domain, 28), r.IP, r.HTTP, r.Status, verdict)
	}
	w.Flush()
}

func printQUIC(q probe.QUICReport) {
	header("QUIC (UDP)")
	if len(q.Sites) == 0 {
		// Own servers only: no controls were probed.
	} else if q.ControlName != "" {
		fmt.Fprintf(out, "  Google, YouTube и Cloudflare по QUIC молчат; для сверки взят %s (%s).\n", q.ControlName, q.Control)
	} else if q.Control != "" {
		fmt.Fprintf(out, "  Зарубежный QUIC-сервер для сверки: %s, ответил за %s.\n", q.Control, ms(q.ControlRTT))
	} else {
		fmt.Fprintln(out, "  Нет зарубежного QUIC-сервера, который отвечает на любое имя: причину молчания сайтов не уточнить.")
	}
	if len(q.Sites) > 0 {
		w := table()
		fmt.Fprintln(w, "  Домен\tIP\tQUIC\tВывод")
		for _, r := range q.Sites {
			verdict := r.Verdict
			if r.Status == "OK" && verdict == "" {
				verdict = ms(r.RTT)
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", clip(r.Domain, 28), r.IP, r.Status, verdict)
		}
		w.Flush()
	}
	if len(q.Targets) > 0 {
		fmt.Fprintln(out, "  Свои серверы по UDP:")
		w := table()
		for _, r := range q.Targets {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", r.Domain, r.IP, r.Status, r.Verdict)
		}
		w.Flush()
	}
}

func printQUICSummary(q probe.QUICReport, tls []probe.TLSResult, vpnOn bool) {
	if vpnOn && len(q.Sites) > 0 && (q.Control == "" || q.ControlName != "") {
		fmt.Fprintln(out, "  • QUIC: VPN-клиенты часто сами отклоняют QUIC, чтобы браузер ушёл на TCP, — молчание ниже может быть их правилом.")
	}
	answered := slices.ContainsFunc(q.Sites, func(s probe.QUICResult) bool { return s.Status == "OK" })
	if len(q.Sites) > 0 && q.Control == "" && !answered {
		fmt.Fprintln(out, "  • QUIC за рубеж не проходит вообще: Hysteria2, TUIC и HTTP/3 работать не будут, нужен VPN поверх TCP (например, VLESS Reality).")
	} else if len(q.Sites) > 0 {
		tlsDown := map[string]bool{}
		for _, t := range tls {
			tlsDown[t.Domain] = t.Status != "OK" && t.Status != "DNS FAIL"
		}
		ok, sni, toRU, fake := 0, 0, 0, 0
		var onlyQUIC []string
		for _, s := range q.Sites {
			switch {
			case s.Status == "OK":
				ok++
				if tlsDown[s.Domain] {
					onlyQUIC = append(onlyQUIC, s.Domain)
				}
			case s.Status == "FAKE":
				fake++
			case strings.HasPrefix(s.Verdict, "DPI по SNI"), strings.HasPrefix(s.Verdict, "имя режется"):
				sni++
				if s.PassesToRU {
					toRU++
				}
			}
		}
		fmt.Fprintf(out, "  • QUIC: отвечают %d из %d сайтов, режут по SNI: %d.", ok, len(q.Sites), sni)
		if sni > 0 {
			fmt.Fprint(out, " Часть имён режут и в QUIC: для Hysteria2 и TUIC берите нейтральный SNI.")
		} else if ok > 0 {
			fmt.Fprint(out, " UDP за рубеж проходит хотя бы к части адресов; свой сервер проверьте: -target адрес:порт.")
		}
		fmt.Fprintln(out)
		if len(onlyQUIC) > 0 {
			fmt.Fprintf(out, "  • По TLS закрыты, а по QUIC отвечают: %d (%s) — имя в QUIC здесь не проверяют.\n",
				len(onlyQUIC), clip(strings.Join(onlyQUIC, ", "), 80))
		}
		if fake > 0 {
			fmt.Fprintf(out, "  • QUIC подменяют: у %d сайтов ответил не сервер, а кто-то по пути.\n", fake)
		}
		if toRU > 0 {
			fmt.Fprintf(out, "  • По QUIC к российскому адресу запрещённые имена проходят (%d из %d).\n", toRU, sni)
		}
	}
	for _, t := range q.Targets {
		fmt.Fprintf(out, "  • %s по UDP: %s.\n", t.Domain, t.Verdict)
	}
}

func printTCP16(rs []probe.TCP16Result) {
	header("Обрыв после 16–20 КБ")
	w := table()
	fmt.Fprintln(w, "  ID\tСеть\tВверх\tВниз\tИтог\tБелые SNI")
	for _, r := range rs {
		asn := r.Target.ASN
		if asn != "" {
			asn = "AS" + asn
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			r.Target.ID, clip(strings.TrimSpace(r.Target.Provider+" "+asn), 28),
			fatCell(r.Up), fatCell(r.Down), r.Verdict, strings.Join(r.WhiteSNI, ", "))
	}
	w.Flush()
}

func fatCell(f probe.FatResult) string {
	switch f.Status {
	case "":
		return "—"
	case "OK":
		return fmt.Sprintf("OK %.0f КБ", max(f.SentKB, f.RecvKB))
	case "DETECTED", "FLAKY":
		return f.Status + " " + clip(f.Detail, 24)
	case "STALL", "RST", "CLOSED", "ERR":
		return fmt.Sprintf("%s на %.0f КБ", f.Status, f.SentKB+f.RecvKB)
	}
	return f.Status
}

func printTelegram(t probe.TelegramReport) {
	header("Telegram")
	w := table()
	for _, dc := range t.DCs {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", dc.Name, dc.IP, dc.Status, ms(dc.RTT))
	}
	w.Flush()
	if t.MediaErr != "" {
		fmt.Fprintf(out, "  telegram.org: %s (скачано %.0f КБ)\n", t.MediaErr, float64(t.MediaBytes)/1024)
	} else {
		fmt.Fprintf(out, "  telegram.org: %.0f КБ, %.0f КБ/с\n", float64(t.MediaBytes)/1024, t.MediaKBps)
	}
}

func printSummary(r report) {
	header("Итог")
	if r.Net != nil && len(r.Net.VPNIfaces) > 0 {
		fmt.Fprintln(out, "  • Включён VPN — выводы ниже про путь через VPN, а не про провайдера.")
	}
	if r.Net != nil && len(r.Net.Bypass) > 0 {
		fmt.Fprintln(out, "  • Работает обход DPI — выводы ниже про провайдера вместе с ним, а не про провайдера.")
	}
	if r.DNS != nil {
		var hijacked, spoofed []string
		for _, s := range r.DNS.Servers {
			if s.Hijacked {
				hijacked = append(hijacked, s.Name)
			}
			for _, d := range s.Domains {
				if d.Verdict == probe.VerdictSpoofed || d.Verdict == probe.VerdictInjected || d.Verdict == probe.VerdictSilent {
					spoofed = append(spoofed, s.Name)
					break
				}
			}
		}
		vpnOn := r.Net != nil && len(r.Net.VPNIfaces) > 0
		switch {
		case len(hijacked) > 0 && vpnOn && oneEgress(r.DNS):
			fmt.Fprintln(out, "  • DNS-запросы забирает VPN-клиент и отвечает сам — так и задумано, провайдер их не видит.")
		case len(hijacked) > 0:
			fmt.Fprintf(out, "  • DNS перехватывается: запросы к %s отвечает чужой резолвер. Нужен DoH/DoT.\n", strings.Join(hijacked, ", "))
		case len(spoofed) > 0:
			fmt.Fprintf(out, "  • DNS подменяется у: %s. Нужен DoH/DoT.\n", strings.Join(spoofed, ", "))
		default:
			fmt.Fprintln(out, "  • DNS: подмены не видно.")
		}
		var good []string
		for _, e := range r.DNS.Encrypted {
			if e.Status == "OK" && e.Truth == probe.EncHonest {
				good = append(good, e.Name+" "+e.Kind)
			}
		}
		if len(good) > 0 {
			fmt.Fprintf(out, "  • Работает и не фильтрует: %s.\n", clip(strings.Join(good, ", "), 140))
		}
	}
	if r.TLS != nil {
		count := map[string]int{}
		blocked := 0
		for _, t := range r.TLS {
			if t.Status != "OK" {
				blocked++
				if t.PassesToRU {
					count["toRU"]++
				}
				switch {
				case strings.HasPrefix(t.Verdict, "DPI по SNI"):
					count["sni"]++
				case strings.HasPrefix(t.Verdict, "блок по IP"):
					count["ip"]++
				case strings.HasPrefix(t.Verdict, "режут и"):
					count["both"]++
				}
			}
		}
		fmt.Fprintf(out, "  • Сайты: недоступно %d из %d — по SNI: %d, по IP: %d, и так и так: %d.\n",
			blocked, len(r.TLS), count["sni"], count["ip"], count["both"])
		httpHits := 0
		for _, t := range r.TLS {
			if t.HTTP == "BLOCKED" || t.HTTP == "REDIRECT" {
				httpHits++
			}
		}
		if httpHits > 0 {
			fmt.Fprintf(out, "  • По HTTP провайдер подменяет ответ у %d сайтов (заглушка или увод на чужой адрес).\n", httpHits)
		}
		if count["toRU"] > 0 {
			fmt.Fprintf(out, "  • К российскому адресу (ya.ru) запрещённые имена проходят (%d из %d): похоже, SNI проверяют только в трафике за рубеж.\n",
				count["toRU"], blocked)
		}
	}
	if r.QUIC != nil {
		printQUICSummary(*r.QUIC, r.TLS, r.Net != nil && len(r.Net.VPNIfaces) > 0)
	}
	if r.TCP16 != nil {
		hit, ok := 0, 0
		var clean []string
		for _, t := range r.TCP16 {
			switch t.Verdict {
			case "DETECTED":
				hit++
			case "OK":
				ok++
				if !slices.Contains(clean, t.Target.Provider) {
					clean = append(clean, t.Target.Provider)
				}
			}
		}
		fmt.Fprintf(out, "  • Обрыв 16–20 КБ: подтверждён у %d из %d, чисто у %d.", hit, len(r.TCP16), ok)
		if len(clean) > 0 && hit > 0 {
			fmt.Fprintf(out, " Без обрыва: %s.", clip(strings.Join(clean, ", "), 120))
		}
		fmt.Fprintln(out)
	}
	if r.Telegram != nil {
		up := 0
		for _, dc := range r.Telegram.DCs {
			if dc.Status == "OK" {
				up++
			}
		}
		fmt.Fprintf(out, "  • Telegram: MTProto отвечает у %d из %d дата-центров.\n", up, len(r.Telegram.DCs))
	}
}
