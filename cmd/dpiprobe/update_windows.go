//go:build windows

package main

import (
	"os"
	"path/filepath"
)

// applyAndRestart renames the running exe (Windows allows that), puts the
// new file in its place and starts it with the same console handles.
func applyAndRestart(exe, tmp string) error {
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Rename(old, exe)
		return err
	}
	argv := append([]string{exe}, os.Args[1:]...)
	p, err := os.StartProcess(exe, argv, &os.ProcAttr{
		Dir:   filepath.Dir(exe),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		return err
	}
	_ = p.Release()
	os.Exit(0)
	return nil
}
