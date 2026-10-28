package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/sovereignbrains/dpiprobe/probe"
)

func TestVerLess(t *testing.T) {
	cases := []struct {
		a, b string
		less bool
	}{
		{"0.2.1", "0.3.0", true},
		{"0.3.0", "0.2.1", false},
		{"0.3.0", "0.3.0", false},
		{"v0.3.0", "0.3.1", true},
		{"0.2.9", "0.2.10", true},
		{"0.3.0-dev", "0.3.1", true},
		{"0.3.1", "0.3.0", false},
	}
	for _, c := range cases {
		if g := verLess(c.a, c.b); g != c.less {
			t.Errorf("verLess(%q,%q)=%v", c.a, c.b, g)
		}
	}
}

func TestNormalizeSHA(t *testing.T) {
	want := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if g := normalizeSHA("SHA256:" + want); g != want {
		t.Fatalf("%q", g)
	}
	if g := normalizeSHA(want[:63]); g != "" {
		t.Fatalf("short: %q", g)
	}
	if g := normalizeSHA(want[:63] + "g"); g != "" {
		t.Fatalf("not hex: %q", g)
	}
}

func TestParseSHA256SUMS(t *testing.T) {
	text := "" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  dpiprobe.exe\n" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb *dpiprobe-linux-amd64\n" +
		"# comment\n"
	m := parseSHA256SUMS(text)
	if m["dpiprobe.exe"] == "" || m["dpiprobe-linux-amd64"] == "" {
		t.Fatalf("%v", m)
	}
	if m["dpiprobe.exe"][0] != 'a' || m["dpiprobe-linux-amd64"][0] != 'b' {
		t.Fatalf("%v", m)
	}
}

func TestGitHubLatestReachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res := probe.New(4*time.Second, 2)
	clients := []*http.Client{
		githubClient("", res, 2500*time.Millisecond),
		githubClient("record", res, 5*time.Second),
		githubClient("byte", res, 5*time.Second),
	}
	rel, err := latestRelease(ctx, clients)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tag %s assets %d", rel.TagName, len(rel.Assets))
	if h := assetSHA(ctx, clients, rel, "dpiprobe.exe"); len(h) != 64 {
		t.Fatalf("no sha for exe, assets=%v", rel.Assets)
	}
}
