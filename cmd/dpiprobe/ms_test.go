package main

import (
	"testing"
	"time"
)

func TestMSKeepsSubMillisecond(t *testing.T) {
	if g := ms(500 * time.Microsecond); g != "0,5 мс" {
		t.Fatalf("got %q", g)
	}
	if g := ms(32 * time.Millisecond); g != "32 мс" {
		t.Fatalf("got %q", g)
	}
	if g := ms(0); g != "—" {
		t.Fatalf("got %q", g)
	}
}
