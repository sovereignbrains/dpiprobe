package main

import "testing"

func TestPhaseText(t *testing.T) {
	if g := phaseText(0, 0); g != "ждёт" {
		t.Fatalf("waiting: %q", g)
	}
	if g := phaseText(12, 36); g != "12 из 36" {
		t.Fatalf("running: %q", g)
	}
	if g := phaseText(36, 36); g != "готово" {
		t.Fatalf("done: %q", g)
	}
	if g := phaseText(-1, 0); g != "—" {
		t.Fatalf("skipped: %q", g)
	}
}

func TestPadRunesCountsLetters(t *testing.T) {
	if g := padRunes("16 КБ", 8); len([]rune(g)) != 8 {
		t.Fatalf("%q", g)
	}
}
