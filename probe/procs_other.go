//go:build !windows

package probe

import (
	"os"
	"path/filepath"
	"strings"
)

// processNames reads /proc where there is one (Linux); elsewhere it finds nothing.
func processNames() []string {
	comms, _ := filepath.Glob("/proc/[0-9]*/comm")
	var out []string
	for _, f := range comms {
		if b, err := os.ReadFile(f); err == nil {
			out = append(out, strings.TrimSpace(string(b)))
		}
	}
	return out
}
