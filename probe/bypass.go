package probe

import (
	"slices"
	"strings"
)

// DPI bypass tools rewrite the probe's own packets (fake ClientHello,
// split segments, TTL tricks): with one running, the report shows the tool,
// not the ISP.
var bypassTools = map[string]string{
	"winws":        "zapret",
	"nfqws":        "zapret",
	"tpws":         "zapret",
	"goodbyedpi":   "GoodbyeDPI",
	"ciadpi":       "ByeDPI",
	"byedpi":       "ByeDPI",
	"byedpi-win":   "ByeDPI",
	"spoofdpi":     "SpoofDPI",
	"spoof-dpi":    "SpoofDPI",
	"dpitunnel":    "DPITunnel",
	"dpi-tunnel":   "DPITunnel",
	"powertunnel":  "PowerTunnel",
	"green-tunnel": "GreenTunnel",
	"gdpi":         "GoodbyeDPI",
}

// bypassName maps a process name to the tool it belongs to, "" if none.
func bypassName(process string) string {
	p := strings.ToLower(process)
	p = strings.TrimSuffix(p, ".exe")
	return bypassTools[p]
}

// RunningBypass lists the DPI bypass tools found among running processes.
func RunningBypass() []string {
	var out []string
	for _, p := range processNames() {
		if tool := bypassName(p); tool != "" {
			label := tool + " (" + p + ")"
			if !slices.Contains(out, label) {
				out = append(out, label)
			}
		}
	}
	return out
}
