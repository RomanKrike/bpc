//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestP2PPreparationRequiresOwnedServiceBinaryAndArguments(t *testing.T) {
	expected := `C:\ProgramData\BPC\bpc-agent.exe`
	if !p2pServiceOwned(syscall.EscapeArg(expected)+" run-service", expected) {
		t.Fatal("installed service refused")
	}
	for _, command := range []string{
		`C:\Other\bpc-agent.exe run-service`,
		syscall.EscapeArg(expected) + " install",
		syscall.EscapeArg(expected) + " run-service --foreign",
	} {
		if p2pServiceOwned(command, expected) {
			t.Fatalf("foreign service accepted: %s", command)
		}
	}
}

func TestEmbeddedP2PWindowParsesWithoutExecutingUI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pilot.ps1")
	if err := os.WriteFile(path, append([]byte{0xef, 0xbb, 0xbf}, []byte(p2pUIScript)...), 0600); err != nil {
		t.Fatal(err)
	}
	script := "$tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile('" + psQuote(path) + "',[ref]$tokens,[ref]$errors) | Out-Null; if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }"
	output, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		t.Fatalf("P2P window syntax: %v: %s", err, output)
	}
}
