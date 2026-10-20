//go:build !windows

package main

import "errors"

func startP2PService() error { return startWindowsService() }
func stopP2PService() error  { return stopWindowsService() }

func secureP2PDirectory(string) error { return errors.New("P2P Agent pilot requires Windows") }
