//go:build windows

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/RomanKrike/bpc/internal/agentctl"
)

func captureLegacyWireGuardProfile(tunnel string) (agentctl.WireGuardProfile, error) {
	tunnel = strings.TrimSpace(tunnel)
	if tunnel == "" {
		return agentctl.WireGuardProfile{}, fmt.Errorf("legacy tunnel name is empty")
	}
	wgPath, err := findWireGuardTool()
	if err != nil {
		return agentctl.WireGuardProfile{}, err
	}
	showConf, err := runCommand(wgPath, "showconf", tunnel)
	if err != nil {
		return agentctl.WireGuardProfile{}, fmt.Errorf(
			"read WireGuard tunnel %q configuration: %w: %s",
			tunnel,
			err,
			strings.TrimSpace(showConf),
		)
	}

	escaped := psQuote(tunnel)
	addressScript := fmt.Sprintf(
		"$x=Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv4 -ErrorAction Stop | "+
			"Where-Object {$_.IPAddress -notlike '169.254*'} | Select-Object -First 1; "+
			"if(-not $x){exit 3}; Write-Output ($x.IPAddress + '/' + $x.PrefixLength)",
		escaped,
	)
	address, err := runCommand(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		addressScript,
	)
	if err != nil {
		return agentctl.WireGuardProfile{}, fmt.Errorf(
			"read WireGuard tunnel %q address: %w: %s",
			tunnel,
			err,
			strings.TrimSpace(address),
		)
	}

	mtuScript := fmt.Sprintf(
		"$x=Get-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -ErrorAction Stop | "+
			"Select-Object -First 1 -ExpandProperty NlMtuBytes; "+
			"if(-not $x){exit 3}; Write-Output $x",
		escaped,
	)
	mtuText, err := runCommand(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		mtuScript,
	)
	if err != nil {
		return agentctl.WireGuardProfile{}, fmt.Errorf(
			"read WireGuard tunnel %q MTU: %w: %s",
			tunnel,
			err,
			strings.TrimSpace(mtuText),
		)
	}
	mtu, err := strconv.Atoi(strings.TrimSpace(mtuText))
	if err != nil {
		return agentctl.WireGuardProfile{}, fmt.Errorf("parse legacy WireGuard MTU: %w", err)
	}

	profile, err := agentctl.ParseWireGuardShowConf(showConf, strings.TrimSpace(address), mtu)
	if err != nil {
		return agentctl.WireGuardProfile{}, fmt.Errorf(
			"parse legacy WireGuard tunnel %q: %w",
			tunnel,
			err,
		)
	}
	return profile, nil
}
