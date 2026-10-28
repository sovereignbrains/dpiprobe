package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// phaseText is one line of the live window: "ждёт", "12 из 36" or "готово".
// done < 0 means the stage never ran.
func phaseText(done, total int) string {
	switch {
	case done < 0:
		return "—"
	case total <= 0:
		return "ждёт"
	case done >= total:
		return "готово"
	default:
		return fmt.Sprintf("%d из %d", done, total)
	}
}

func padRunes(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		return string(r[:n])
	}
	return s + strings.Repeat(" ", n-len(r))
}

var phaseTitle = map[string]string{
	"DNS":        "DNS",
	"Сайты":      "Сайты",
	"Обход":      "Обход SNI",
	"QUIC":       "QUIC",
	"16 КБ":      "Обрыв 16 КБ",
	"SNI":        "Белые SNI",
	"TG":         "Telegram",
	"Обновление": "Обновление",
}

func phaseLabel(k string) string {
	if s, ok := phaseTitle[k]; ok {
		return s
	}
	return k
}

// liveView is the status block in the console. With VT it redraws in place,
// one stage per line. Without VT it keeps a single updating line.
type liveView struct {
	mu    sync.Mutex
	order []string
	state map[string][2]int
	notes map[string]string
	lines int
	vt    bool
	w     io.Writer
}

func newLive(w io.Writer, vt bool, order []string) *liveView {
	st := map[string][2]int{}
	for _, k := range order {
		st[k] = [2]int{0, 0}
	}
	return &liveView{
		order: append([]string(nil), order...),
		state: st,
		notes: map[string]string{},
		vt:    vt,
		w:     w,
	}
}

func (l *liveView) lineText(k string, v [2]int) string {
	if n := l.notes[k]; n != "" {
		return n
	}
	return phaseText(v[0], v[1])
}

func (l *liveView) show() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.draw()
}

func (l *liveView) note(label, text string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.state[label]; !ok {
		l.order = append([]string{label}, l.order...)
		l.state[label] = [2]int{0, 0}
	}
	l.notes[label] = text
	l.draw()
}

func (l *liveView) set(label string, done, total int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.state[label]; !ok {
		l.order = append(l.order, label)
	}
	l.state[label] = [2]int{done, total}
	l.draw()
}

// settle marks stages that never started, so the last frame does not say
// they are still waiting.
func (l *liveView) settle() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range l.state {
		if k == "Обновление" {
			continue
		}
		if v[1] == 0 {
			l.state[k] = [2]int{-1, 0}
		}
	}
	l.draw()
}

func (l *liveView) draw() {
	if !l.vt {
		var parts []string
		for _, k := range l.order {
			v := l.state[k]
			parts = append(parts, phaseLabel(k)+" "+l.lineText(k, v))
		}
		fmt.Fprintf(l.w, "\r%s", strings.Join(parts, "   "))
		return
	}
	var b strings.Builder
	if l.lines > 0 {
		fmt.Fprintf(&b, "\x1b[%dA", l.lines)
	}
	for _, k := range l.order {
		v := l.state[k]
		fmt.Fprintf(&b, "  %s  %s\x1b[K\n", padRunes(phaseLabel(k), 12), l.lineText(k, v))
	}
	fmt.Fprint(l.w, b.String())
	l.lines = len(l.order)
}
