package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sovereignbrains/dpiprobe/probe"
)

func capture(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := out
	out = &buf
	t.Cleanup(func() { out = prev })
	fn()
	return buf.String()
}

func TestQUICSummaryWhenTLSClosedAnswers(t *testing.T) {
	q := probe.QUICReport{
		Control: "203.0.113.10",
		Sites: []probe.QUICResult{
			{Domain: "x.com", Status: "OK"},
			{Domain: "a.example", Status: "NO REPLY", Verdict: "адрес по QUIC не отвечает", ControlMiss: true},
			{Domain: "b.example", Status: "NO REPLY", Verdict: "адрес по QUIC не отвечает", ControlMiss: true},
		},
	}
	tls := []probe.TLSResult{
		{Domain: "x.com", Status: "TLS DROP"},
		{Domain: "a.example", Status: "TLS DROP"},
	}
	got := capture(t, func() { printQUICSummary(q, tls, false) })
	if strings.Contains(got, "режут по SNI") {
		t.Fatalf("false SNI cut:\n%s", got)
	}
	if !strings.Contains(got, "По TLS закрыты, а по QUIC отвечают") {
		t.Fatalf("missing quic-open line:\n%s", got)
	}
	if !strings.Contains(got, "Сверочный сервер не ответил на 2 имени — вероятно, потери") {
		t.Fatalf("soft line:\n%s", got)
	}
}

func TestQUICSummaryKeepsRealSNICut(t *testing.T) {
	q := probe.QUICReport{
		Control: "203.0.113.10",
		Sites: []probe.QUICResult{
			{Domain: "a.example", Status: "NO REPLY", Verdict: "DPI по SNI: имя режется и на чистом адресе", ControlMiss: true},
		},
	}
	tls := []probe.TLSResult{{Domain: "a.example", Status: "OK"}}
	got := capture(t, func() { printQUICSummary(q, tls, false) })
	if !strings.Contains(got, "режут по SNI: 1") {
		t.Fatalf("got:\n%s", got)
	}
	if strings.Contains(got, "вероятно, потери") {
		t.Fatalf("soft line without quic-open names:\n%s", got)
	}
}

func TestQUICSummaryVPNDoesNotAskForVPN(t *testing.T) {
	q := probe.QUICReport{Sites: []probe.QUICResult{{Domain: "a.example", Status: "NO REPLY"}}}
	got := capture(t, func() { printQUICSummary(q, nil, true) })
	if strings.Contains(got, "нужен VPN поверх TCP") {
		t.Fatalf("asked for a VPN while one is up:\n%s", got)
	}
	if !strings.Contains(got, "правилом") {
		t.Fatalf("missing client-rule line:\n%s", got)
	}
	off := capture(t, func() { printQUICSummary(q, nil, false) })
	if !strings.Contains(off, "нужен VPN поверх TCP") {
		t.Fatalf("no-vpn:\n%s", off)
	}
}

func TestTCP16SummaryCountsHandshakeDrops(t *testing.T) {
	var rs []probe.TCP16Result
	for range 56 {
		rs = append(rs, probe.TCP16Result{Verdict: "DETECTED"})
	}
	for range 20 {
		rs = append(rs, probe.TCP16Result{Verdict: "TLS DROP"})
	}
	for range 19 {
		rs = append(rs, probe.TCP16Result{Verdict: "OK", Target: probe.Target{Provider: "Hetzner"}})
	}
	for len(rs) < 110 {
		rs = append(rs, probe.TCP16Result{Verdict: "SYN DROP"})
	}
	line := tcp16SummaryLine(rs)
	want := "подтверждён у 56 из 110, ещё 20 рвутся на рукопожатии (TLS DROP), чисто у 19."
	if !strings.Contains(line, want) {
		t.Fatalf("got %q", line)
	}
}
