package probe

import "testing"

func TestBypassName(t *testing.T) {
	for process, want := range map[string]string{
		"winws.exe":      "zapret",
		"GoodbyeDPI.exe": "GoodbyeDPI",
		"ciadpi":         "ByeDPI",
		"nfqws":          "zapret",
		"chrome.exe":     "",
		"winwsx.exe":     "",
	} {
		if got := bypassName(process); got != want {
			t.Errorf("bypassName(%q) = %q, want %q", process, got, want)
		}
	}
}

func TestRunningBypassListsProcesses(t *testing.T) {
	if len(processNames()) == 0 {
		t.Skip("no process list on this OS")
	}
	_ = RunningBypass() // must not fail on a real snapshot
}
