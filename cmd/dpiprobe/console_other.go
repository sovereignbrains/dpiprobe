//go:build !windows

package main

func ownConsole() bool { return false }

func enableVT() bool { return false }

func setTitle(string) {}
