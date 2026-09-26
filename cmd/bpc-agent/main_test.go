package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/RomanKrike/bpc/internal/agentctl"
)

func testBootstrap(t *testing.T, device string) agentctl.Bootstrap {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return agentctl.Bootstrap{
		Version:         agentctl.BootstrapVersion,
		Device:          device,
		ControlURL:      "https://control.example.invalid:8444",
		EnrollToken:     strings.Repeat("a", 64),
		UpdatePublicKey: base64.StdEncoding.EncodeToString(publicPEM),
	}
}

func TestParseBootstrapBytes(t *testing.T) {
	cfg := testBootstrap(t, "pc004")
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
	if got.Device != cfg.Device || got.ControlURL != cfg.ControlURL || got.EnrollToken != cfg.EnrollToken {
		t.Fatalf("unexpected bootstrap: %#v", got)
	}
	if err := agentctl.ValidateBootstrap(*got); err != nil {
		t.Fatalf("valid bootstrap rejected: %v", err)
	}
}

func TestParseBootstrapUsesLastOverlay(t *testing.T) {
	makeOverlay := func(device string) string {
		cfg := testBootstrap(t, device)
		raw, err := json.Marshal(cfg)
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


func TestPreparedBootstrapV3NeedsNoEnrollmentSecret(t *testing.T) {
	cfg := testBootstrap(t, "pc004")
	cfg.EnrollToken = ""
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
	if got.Version != agentctl.BootstrapVersion {
		t.Fatalf("unexpected bootstrap version %d", got.Version)
	}
	if got.EnrollToken != "" {
		t.Fatal("Stage 3 prepared bootstrap unexpectedly contains enrollment secret")
	}
	if err := agentctl.ValidateBootstrap(*got); err != nil {
		t.Fatalf("valid Stage 3 bootstrap rejected: %v", err)
	}
}

func TestLegacyBootstrapV2StillParses(t *testing.T) {
	cfg := testBootstrap(t, "legacy-pc")
	cfg.Version = agentctl.LegacyBootstrapVersion
	cfg.EnrollToken = strings.Repeat("b", 64)
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	data := []byte("MZfake-pe-data" + legacyBootstrapStart + encoded + bootstrapEnd)

	got, err := parseBootstrapBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != agentctl.LegacyBootstrapVersion || got.EnrollToken != cfg.EnrollToken {
		t.Fatalf("unexpected legacy bootstrap: %#v", got)
	}
	if err := agentctl.ValidateBootstrap(*got); err != nil {
		t.Fatalf("legacy bootstrap rejected: %v", err)
	}
}
