package wgshim

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func testPSK(t *testing.T) []byte {
	t.Helper()
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	return psk
}

func TestCodecRoundTrip(t *testing.T) {
	psk := testPSK(t)
	key, err := DeriveKey(psk, ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := NewCodec(key, 0, 31)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("wireguard-packet")
	outer, err := codec.Seal(payload)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := codec.Open(outer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inner, payload) {
		t.Fatalf("round-trip mismatch: %q != %q", inner, payload)
	}
}

func TestCodecRejectsTampering(t *testing.T) {
	psk := testPSK(t)
	key, _ := DeriveKey(psk, ClientToServer)
	codec, _ := NewCodec(key, 0, 0)
	outer, err := codec.Seal([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	outer[len(outer)-1] ^= 0x80
	if _, err := codec.Open(outer); err == nil {
		t.Fatal("tampered packet was accepted")
	}
}

func TestDirectionKeysDiffer(t *testing.T) {
	psk := testPSK(t)
	c2s, _ := DeriveKey(psk, ClientToServer)
	s2c, _ := DeriveKey(psk, ServerToClient)
	if bytes.Equal(c2s, s2c) {
		t.Fatal("direction keys must differ")
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	psk := testPSK(t)
	key, _ := DeriveKey(psk, ClientToServer)
	codec, _ := NewCodec(key, 0, 0)
	a, _ := codec.Seal([]byte("same"))
	b, _ := codec.Seal([]byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("same plaintext produced identical outer datagrams")
	}
}

func TestLoadPSK(t *testing.T) {
	psk := testPSK(t)
	path := filepath.Join(t.TempDir(), "psk")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(psk)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPSK(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, psk) {
		t.Fatal("loaded PSK mismatch")
	}
}
