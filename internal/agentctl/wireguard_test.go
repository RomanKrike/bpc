package agentctl

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateWireGuardKeypair(t *testing.T) {
	privateKey, publicKey, err := GenerateWireGuardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseWGKey(privateKey, false); err != nil {
		t.Fatalf("private key invalid: %v", err)
	}
	if _, err := ParseWGKey(publicKey, false); err != nil {
		t.Fatalf("public key invalid: %v", err)
	}
	if privateKey == publicKey {
		t.Fatal("private and public key unexpectedly match")
	}
}

func TestParseWireGuardShowConf(t *testing.T) {
	keyA := base64.StdEncoding.EncodeToString(bytesOf(1))
	keyB := base64.StdEncoding.EncodeToString(bytesOf(2))
	keyC := base64.StdEncoding.EncodeToString(bytesOf(3))
	conf := `[Interface]
PrivateKey = ` + keyA + `

[Peer]
PublicKey = ` + keyB + `
PresharedKey = ` + keyC + `
AllowedIPs = 192.168.88.0/24, 10.10.4.0/24
Endpoint = 127.0.0.1:24081
PersistentKeepalive = 25
`

	profile, err := ParseWireGuardShowConf(conf, "10.10.4.10/32", 1360)
	if err != nil {
		t.Fatal(err)
	}
	if profile.PrivateKey != keyA || profile.PeerPublicKey != keyB || profile.PresharedKey != keyC {
		t.Fatalf("unexpected keys: %#v", profile)
	}
	if profile.Address != "10.10.4.10/32" || profile.MTU != 1360 || profile.PersistentKeepalive != 25 {
		t.Fatalf("unexpected interface config: %#v", profile)
	}
	if strings.Join(profile.AllowedIPs, ",") != "192.168.88.0/24,10.10.4.0/24" {
		t.Fatalf("unexpected allowed IPs: %#v", profile.AllowedIPs)
	}
}

func TestParseWireGuardShowConfRejectsMultiplePeers(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytesOf(1))
	conf := `[Interface]
PrivateKey = ` + key + `
[Peer]
PublicKey = ` + key + `
AllowedIPs = 10.0.0.0/8
[Peer]
PublicKey = ` + key + `
AllowedIPs = 192.168.0.0/16
`
	if _, err := ParseWireGuardShowConf(conf, "10.0.0.2/32", 1360); err == nil {
		t.Fatal("multiple peers were accepted")
	}
}

func TestWGKeyHex(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytesOf(0xab))
	value, err := WGKeyHex(key, false)
	if err != nil {
		t.Fatal(err)
	}
	if value != strings.Repeat("ab", 32) {
		t.Fatalf("unexpected key hex: %s", value)
	}
}

func bytesOf(value byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = value
	}
	return out
}


func TestValidateWireGuardServerProfileAllowsMissingPrivateKey(t *testing.T) {
	publicKey := base64.StdEncoding.EncodeToString(bytesOf(7))
	profile := WireGuardProfile{
		Address:             "10.253.0.2/32",
		MTU:                 1360,
		PeerPublicKey:       publicKey,
		AllowedIPs:          []string{"10.253.0.0/24"},
		PersistentKeepalive: 25,
	}
	if err := ValidateWireGuardServerProfile(profile); err != nil {
		t.Fatalf("server profile rejected: %v", err)
	}
	if err := ValidateWireGuardProfile(profile); err == nil {
		t.Fatal("client profile without private key was accepted")
	}
}
