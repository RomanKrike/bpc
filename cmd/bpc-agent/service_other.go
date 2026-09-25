//go:build !windows

package main

import "errors"

const serviceName = "BPCAgent"

func runWindowsService() error {
	return errors.New("Windows service support is unavailable on this platform")
}

func installWindowsService(string) error {
	return errors.New("Windows service support is unavailable on this platform")
}

func setWindowsServiceAutomatic(bool) error {
	return errors.New("Windows service support is unavailable on this platform")
}

func startWindowsService() error {
	return errors.New("Windows service support is unavailable on this platform")
}

func stopWindowsService() error {
	return nil
}

func removeWindowsService() error {
	return nil
}

func windowsServiceStatus() string {
	return "unsupported"
}
