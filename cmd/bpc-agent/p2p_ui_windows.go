//go:build windows

package main

import (
	"encoding/base64"
	"os/exec"
	"strings"
	"unicode/utf16"
)

func launchP2PUI() error {
	if !isAdministrator() {
		return elevate("p2p-ui")
	}
	_, exePath, _, err := installPaths()
	if err != nil {
		return err
	}
	body := strings.ReplaceAll(p2pUIScript, "__BPC_AGENT_PATH__", psQuote(exePath))
	chars := utf16.Encode([]rune(body))
	raw := make([]byte, len(chars)*2)
	for i, c := range chars {
		raw[2*i], raw[2*i+1] = byte(c), byte(c>>8)
	}
	// Elevated UI executes an embedded script, never a user-writable cached file.
	cmd := exec.Command("powershell.exe", "-NoProfile", "-STA", "-WindowStyle", "Hidden", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	return cmd.Run()
}
