//go:build !windows

package main

import "fmt"

func applyAndRestart(_, _ string) error {
	return fmt.Errorf("замените файл вручную")
}
