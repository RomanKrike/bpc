package agentctl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateIdentity(t *testing.T) {
	publicKey, privateKey, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("invalid public key: len=%d err=%v", len(pub), err)
	}
	priv, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("invalid private key: len=%d err=%v", len(priv), err)
	}
}

func TestVerifySignedUpdateManifest(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	encodedPublic := base64.StdEncoding.EncodeToString(publicPEM)

	manifest := UpdateManifest{
		Version: "0.10.0",
		URL:     "https://control.example.invalid/v1/update/agent.exe",
		SHA256:  hex.EncodeToString(make([]byte, 32)),
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(privateKey, UpdateSigningBytes(manifest)),
	)
	if err := VerifyUpdateManifest(manifest, encodedPublic); err != nil {
		t.Fatal(err)
	}

	manifest.URL = "https://evil.example.invalid/agent.exe"
	if err := VerifyUpdateManifest(manifest, encodedPublic); err == nil {
		t.Fatal("tampered manifest was accepted")
	}
}

func TestStableVersionOrdering(t *testing.T) {
	cases := []struct {
		candidate string
		current   string
		want      bool
	}{
		{"0.10.0", "0.9.0", true},
		{"0.9.1", "0.9.0", true},
		{"1.0.0", "0.99.99", true},
		{"0.10.0", "0.10.0", false},
		{"0.9.9", "0.10.0", false},
		{"0.10.0-beta", "0.9.0", false},
	}
	for _, tc := range cases {
		if got := IsNewerVersion(tc.candidate, tc.current); got != tc.want {
			t.Fatalf("IsNewerVersion(%q, %q)=%v want %v", tc.candidate, tc.current, got, tc.want)
		}
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := State{
		Version:     StateVersion,
		DeviceID:    "dev-1",
		DeviceName:  "pc004",
		DeviceToken: "token",
		ControlURL:  "https://control.example.invalid",
		Config: RuntimeConfig{
			ConfigVersion: 1,
			WGShimServer:  "127.0.0.1:24444",
			WGShimListen:  "127.0.0.1:24081",
			WGShimTarget:  "127.0.0.1:24082",
			WGShimPSK:     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
	}
	if err := SaveState(path, state); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != state.DeviceID || got.DeviceName != state.DeviceName {
		t.Fatalf("unexpected state: %#v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		t.Fatal("state path is a directory")
	}
}

func TestValidateRuntimeConfigAdaptiveEndpointPool(t *testing.T) {
	base := RuntimeConfig{
		ConfigVersion: 4,
		WGShimServer:  "127.0.0.1:24445",
		WGShimListen:  "127.0.0.1:24081",
		WGShimTarget:  "127.0.0.1:51821",
		WGShimPSK:     base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	if err := ValidateRuntimeConfig(base); err != nil {
		t.Fatalf("legacy single endpoint config must remain valid: %v", err)
	}

	base.WGShimServers = []string{
		"127.0.0.1:24445",
		"127.0.0.1:31001",
		"127.0.0.1:47002",
	}
	if err := ValidateRuntimeConfig(base); err != nil {
		t.Fatalf("valid endpoint pool rejected: %v", err)
	}

	base.WGShimServers = []string{"127.0.0.1:31001"}
	if err := ValidateRuntimeConfig(base); err == nil {
		t.Fatal("pool without backward-compatible primary endpoint was accepted")
	}

	base.WGShimServers = make([]string, 17)
	for i := range base.WGShimServers {
		base.WGShimServers[i] = fmt.Sprintf("127.0.0.1:%d", 30000+i)
	}
	base.WGShimServer = base.WGShimServers[0]
	if err := ValidateRuntimeConfig(base); err == nil {
		t.Fatal("oversized endpoint pool was accepted")
	}
}

func TestDeviceProofSigningBytes(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateB64 := base64.StdEncoding.EncodeToString(privateKey)
	signing := RegistrationSigningBytes("access-token", "public-key", "wg-public-key")
	signatureB64, err := SignDeviceProof(privateB64, signing)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, signing, signature) {
		t.Fatal("registration proof did not verify")
	}

	refresh := RefreshSigningBytes("refresh-token")
	refreshSignatureB64, err := SignDeviceProof(privateB64, refresh)
	if err != nil {
		t.Fatal(err)
	}
	refreshSignature, err := base64.StdEncoding.DecodeString(refreshSignatureB64)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, refresh, refreshSignature) {
		t.Fatal("refresh proof did not verify")
	}
}

func TestStateCredentialSelectionAndRefreshWindow(t *testing.T) {
	now := time.Unix(1_000, 0)
	state := State{
		Version:         StateVersion,
		AccessToken:     "access",
		AccessExpiresAt: 1_200,
		RefreshToken:    "refresh",
	}
	if got := state.ControlCredential(); got != "access" {
		t.Fatalf("ControlCredential()=%q want access", got)
	}
	if state.NeedsRefresh(now) {
		t.Fatal("fresh access token requested an early refresh")
	}
	state.AccessExpiresAt = 1_050
	if !state.NeedsRefresh(now) {
		t.Fatal("access token inside refresh window was not refreshed")
	}

	legacy := State{
		Version:     LegacyStateVersion,
		DeviceToken: "legacy-static-token",
	}
	if got := legacy.ControlCredential(); got != "legacy-static-token" {
		t.Fatalf("legacy ControlCredential()=%q", got)
	}
	if legacy.NeedsRefresh(now) {
		t.Fatal("legacy state without refresh token must not refresh")
	}
}
