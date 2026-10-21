package main

import (
	"syscall"
	"unsafe"
)

// ownConsole reports a console that belongs to this process alone — the
// exe was double-clicked and its window will vanish on exit.
func ownConsole() bool {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	if proc.Find() != nil {
		return false
	}
	var ids [4]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	return n == 1
}
