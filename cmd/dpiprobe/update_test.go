package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sovereignbrains/dpiprobe/probe"
)

func TestDefaultVersionIsNextRelease(t *testing.T) {
	if version != "0.3.2" {
		t.Fatalf("default version %s", version)
	}
}

func TestDownloadExeRejectsLongerBody(t *testing.T) {
	const declared int64 = 32
	exact := append([]byte("MZ"), bytes.Repeat([]byte{'x'}, int(declared)-2)...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := exact
		if r.URL.Query().Get("more") == "1" {
			body = append(append([]byte{}, exact...), 'Z')
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	dest := filepath.Join(t.TempDir(), "exact.exe")
	if _, err := downloadExe(context.Background(), []*http.Client{client}, srv.URL, dest, declared, nil); err != nil {
		t.Fatal(err)
	}
	dest2 := filepath.Join(t.TempDir(), "long.exe")
	_, err := downloadExe(context.Background(), []*http.Client{client}, srv.URL+"?more=1", dest2, declared, nil)
	if err == nil || !strings.Contains(err.Error(), "размер не сошёлся") {
		t.Fatalf("got %v", err)
	}
}

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
