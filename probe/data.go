package probe

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Target lists come from dpi-detector (MIT), see NOTICE.
var (
	//go:embed data/tcp16.json
	tcp16JSON []byte
	//go:embed data/whitelist_sni.txt
	whitelistTxt string
	//go:embed data/domains.txt
	domainsTxt string
)

func DefaultTargets() ([]Target, error) {
	var t []Target
	if err := json.Unmarshal(tcp16JSON, &t); err != nil {
		return nil, fmt.Errorf("tcp16.json: %w", err)
	}
	return t, nil
}

func WhitelistSNI() []string { return lines(whitelistTxt) }

// DefaultDomains returns hostnames only: some entries carry a URL path.
func DefaultDomains() []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range lines(domainsTxt) {
		host, _, _ := strings.Cut(l, "/")
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out
}

// ParseTarget reads "host[:port][@sni]"; host may be a name.
func ParseTarget(s string) (Target, error) {
	addr, sni, _ := strings.Cut(strings.TrimSpace(s), "@")
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host, portStr = addr, "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 || host == "" {
		return Target{}, fmt.Errorf("цель %q: нужен формат host[:port][@sni]", s)
	}
	return Target{ID: host, Provider: "свой сервер", IP: host, Port: port, SNI: sni}, nil
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}
