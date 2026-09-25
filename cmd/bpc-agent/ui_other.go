//go:build !windows

package main

import "errors"

func installWindowsUI(string, string) error { return errors.New("BPC Agent UI requires Windows") }
func startWindowsUI() error                 { return errors.New("BPC Agent UI requires Windows") }
func removeWindowsUI() error                { return nil }
func launchWindowsUI() error                { return errors.New("BPC Agent UI requires Windows") }
