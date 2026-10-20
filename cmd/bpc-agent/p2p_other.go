//go:build !windows

package main

import "errors"

func secureP2PDirectory(string) error { return errors.New("P2P Agent pilot requires Windows") }
