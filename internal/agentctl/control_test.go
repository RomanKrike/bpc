package agentctl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
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
