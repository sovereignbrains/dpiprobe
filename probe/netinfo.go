package probe

import (
	"context"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
)

type NetInfo struct {
	IP        string
	AS        ASInfo
	Err       string
	VPNIfaces []string
}

// Anchored: Windows has "Teredo Tunneling Pseudo-Interface", which is not a VPN.
var vpnIfaceRe = regexp.MustCompile(`(?i)^(tun\d*|wintun.*|wg\d*|wireguard.*|sing.*|warp.*|amnezia.*|outline.*|zerotier.*|tailscale.*|.*vpn.*)$`)

func (p *Prober) NetInfo(ctx context.Context) NetInfo {
	var ni NetInfo
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			if ifc.Flags&net.FlagUp != 0 && vpnIfaceRe.MatchString(ifc.Name) {
				ni.VPNIfaces = append(ni.VPNIfaces, ifc.Name)
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		ni.Err = shortErr(err)
		return ni
	}
	resp, err := p.http.Do(req)
	if err != nil {
		ni.Err = shortErr(err)
		return ni
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ni.IP = strings.TrimSpace(string(b))
	if ip := net.ParseIP(ni.IP); ip != nil {
		ni.AS = p.ASOf(ctx, ip)
	}
	return ni
}
