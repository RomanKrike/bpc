package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	wintunPayloadStart = "\nBPC_AGENT_WINTUN_V1\n"
	wintunPayloadEnd   = "\nBPC_AGENT_WINTUN_END\n"
)

func installWintunPayload(executablePath, installDir string) error {
	data, err := os.ReadFile(executablePath)
	if err != nil {
		return fmt.Errorf("read prepared agent payload: %w", err)
	}
	dll, err := extractPayload(data, wintunPayloadStart, wintunPayloadEnd)
	if err != nil {
		// Updates do not carry the payload. Reuse the installed DLL if present.
		existing := filepath.Join(installDir, "wintun.dll")
		if info, statErr := os.Stat(existing); statErr == nil && info.Size() > 0 {
			return nil
		}
		return fmt.Errorf("Wintun payload: %w", err)
	}
	if len(dll) < 64*1024 || len(dll) > 4*1024*1024 {
		return fmt.Errorf("Wintun payload has unexpected size: %d", len(dll))
	}

	if err := os.MkdirAll(installDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(installDir, "wintun.dll")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, dll, 0o600); err != nil {
		return err
	}
	_ = os.Remove(path)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	lockDownPath(path)
	return nil
}

func extractPayload(data []byte, startMarker, endMarker string) ([]byte, error) {
	start := bytes.LastIndex(data, []byte(startMarker))
	if start < 0 {
		return nil, errors.New("payload start marker is missing")
	}
	start += len(startMarker)
	endRelative := bytes.Index(data[start:], []byte(endMarker))
	if endRelative < 0 {
		return nil, errors.New("payload end marker is missing")
	}
	encoded := strings.TrimSpace(string(data[start : start+endRelative]))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	return decoded, nil
}
