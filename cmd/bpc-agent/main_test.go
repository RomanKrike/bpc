package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseBootstrapBytes(t *testing.T) {
	cfg := bootstrap{
		Version:    1,
		Device:     "pc004",
		Tunnel:     "blinpi.home",
		Server:     "176.32.38.65:24444",
		Listen:     "127.0.0.1:24081",
		Target:     "176.32.35.91:24081",
		PaddingMin: 0,
		PaddingMax: 31,
		PSK:        base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	data := []byte("MZfake-pe-data" + bootstrapStart + encoded + bootstrapEnd)

	got, err := parseBootstrapBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Device != cfg.Device || got.Tunnel != cfg.Tunnel || got.Server != cfg.Server || got.Target != cfg.Target {
		t.Fatalf("unexpected bootstrap: %#v", got)
	}
	if err := validateBootstrap(got); err != nil {
		t.Fatalf("valid bootstrap rejected: %v", err)
	}
}

func TestParseBootstrapUsesLastOverlay(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	makeOverlay := func(device string) string {
		raw, err := json.Marshal(bootstrap{
			Version: 1, Device: device, Tunnel: "wg", Server: "1.1.1.1:1",
			Listen: "127.0.0.1:2", Target: "2.2.2.2:3", PSK: key,
		})
		if err != nil {
			t.Fatal(err)
		}
		return bootstrapStart + base64.StdEncoding.EncodeToString(raw) + bootstrapEnd
	}
	got, err := parseBootstrapBytes([]byte("MZ" + makeOverlay("old") + makeOverlay("new")))
	if err != nil {
		t.Fatal(err)
	}
	if got.Device != "new" {
		t.Fatalf("expected last overlay, got %q", got.Device)
	}
}

func TestParseEndpoints(t *testing.T) {
	entries := parseEndpoints("peer-a\t176.32.35.91:24081\r\npeer-b\t127.0.0.1:24081\r\n")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Peer != "peer-a" || entries[1].Endpoint != "127.0.0.1:24081" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestGenericBinaryRejected(t *testing.T) {
	_, err := parseBootstrapBytes([]byte("MZ-no-overlay"))
	if err == nil || !strings.Contains(err.Error(), "generic BPC Agent") {
		t.Fatalf("expected generic binary error, got %v", err)
	}
}
