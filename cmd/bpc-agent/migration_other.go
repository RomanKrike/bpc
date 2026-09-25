//go:build !windows

package main

import (
	"errors"

	"github.com/RomanKrike/bpc/internal/agentctl"
)

func captureLegacyWireGuardProfile(string) (agentctl.WireGuardProfile, error) {
	return agentctl.WireGuardProfile{}, errors.New("legacy WireGuard migration is available on Windows only")
}
