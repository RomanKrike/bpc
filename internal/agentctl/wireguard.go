package agentctl

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

type WireGuardProfile struct {
	PrivateKey          string   `json:"private_key"`
	Address             string   `json:"address"`
	MTU                 int      `json:"mtu"`
	PeerPublicKey       string   `json:"peer_public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
}

func (p WireGuardProfile) Complete() bool {
	return ValidateWireGuardProfile(p) == nil
}

func ValidateWireGuardProfile(p WireGuardProfile) error {
	return validateWireGuardProfile(p, true)
}

func ValidateWireGuardServerProfile(p WireGuardProfile) error {
	return validateWireGuardProfile(p, false)
}

func validateWireGuardProfile(p WireGuardProfile, requirePrivate bool) error {
	if requirePrivate {
		if _, err := ParseWGKey(p.PrivateKey, false); err != nil {
			return fmt.Errorf("private key: %w", err)
		}
	}
	if _, err := ParseWGKey(p.PeerPublicKey, false); err != nil {
		return fmt.Errorf("peer public key: %w", err)
	}
	if strings.TrimSpace(p.PresharedKey) != "" {
		if _, err := ParseWGKey(p.PresharedKey, true); err != nil {
			return fmt.Errorf("preshared key: %w", err)
		}
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(p.Address))
	if err != nil || !prefix.Addr().Is4() {
		return errors.New("address must be an IPv4 CIDR")
	}
	if p.MTU < 576 || p.MTU > 9000 {
		return errors.New("MTU must be between 576 and 9000")
	}
	if len(p.AllowedIPs) == 0 {
		return errors.New("allowed IP list is empty")
	}
	for _, value := range p.AllowedIPs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("invalid allowed IP %q", value)
		}
		if !prefix.Addr().Is4() && !prefix.Addr().Is6() {
			return fmt.Errorf("unsupported allowed IP %q", value)
		}
	}
	if p.PersistentKeepalive < 0 || p.PersistentKeepalive > 65535 {
		return errors.New("persistent keepalive is out of range")
	}
	return nil
}

func ParseWGKey(encoded string, allowZero bool) ([32]byte, error) {
	var key [32]byte
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return key, err
	}
	if len(raw) != len(key) {
		return key, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	copy(key[:], raw)
	if !allowZero {
		var nonzero byte
		for _, value := range key {
			nonzero |= value
		}
		if nonzero == 0 {
			return key, errors.New("zero key is not valid")
		}
	}
	return key, nil
}

func WGKeyHex(encoded string, allowZero bool) (string, error) {
	key, err := ParseWGKey(encoded, allowZero)
	if err != nil {
		return "", err
	}
	const digits = "0123456789abcdef"
	out := make([]byte, len(key)*2)
	for i, value := range key {
		out[i*2] = digits[value>>4]
		out[i*2+1] = digits[value&0x0f]
	}
	return string(out), nil
}

func GenerateWireGuardKeypair() (privateB64, publicB64 string, err error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return "", "", err
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	var public [32]byte
	curve25519.ScalarBaseMult(&public, &private)
	return base64.StdEncoding.EncodeToString(private[:]),
		base64.StdEncoding.EncodeToString(public[:]), nil
}

func ParseWireGuardShowConf(text, address string, mtu int) (WireGuardProfile, error) {
	profile := WireGuardProfile{
		Address: strings.TrimSpace(address),
		MTU:     mtu,
	}
	section := ""
	peerCount := 0

	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				peerCount++
				if peerCount > 1 {
					return WireGuardProfile{}, errors.New("legacy migration supports exactly one WireGuard peer")
				}
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			if key == "privatekey" {
				profile.PrivateKey = value
			}
		case "peer":
			switch key {
			case "publickey":
				profile.PeerPublicKey = value
			case "presharedkey":
				profile.PresharedKey = value
			case "allowedips":
				for _, cidr := range strings.Split(value, ",") {
					cidr = strings.TrimSpace(cidr)
					if cidr != "" {
						profile.AllowedIPs = append(profile.AllowedIPs, cidr)
					}
				}
			case "persistentkeepalive":
				keepalive, err := strconv.Atoi(value)
				if err != nil {
					return WireGuardProfile{}, fmt.Errorf("parse PersistentKeepalive: %w", err)
				}
				profile.PersistentKeepalive = keepalive
			}
		}
	}

	if peerCount != 1 {
		return WireGuardProfile{}, fmt.Errorf("legacy migration expected one WireGuard peer, found %d", peerCount)
	}
	if err := ValidateWireGuardProfile(profile); err != nil {
		return WireGuardProfile{}, err
	}
	return profile, nil
}
