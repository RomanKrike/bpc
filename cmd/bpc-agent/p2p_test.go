package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RomanKrike/bpc/internal/agentctl"
	"github.com/RomanKrike/bpc/internal/p2p"
)

func TestP2PBootstrapCannotResetMissingOrMismatchedStore(t *testing.T) {
	dir := t.TempDir()
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	trust := p2p.Trust{ClusterID: "cluster", DeviceID: strings.Repeat("a", 32), Issuer: public}
	if err := initializeP2PTrust(dir, trust); err != nil {
		t.Fatal(err)
	}
	if _, err := loadP2PTrust(dir, "another-device"); err == nil {
		t.Fatal("foreign Device accepted trust")
	}
	if err := initializeP2PTrust(dir, trust); err == nil {
		t.Fatal("trust overwritten")
	}
	if err := os.Remove(filepath.Join(dir, "policy.db")); err != nil {
		t.Fatal(err)
	}
	if err := initializeP2PTrust(dir, trust); err == nil {
		t.Fatal("missing store silently reset")
	}
	if _, err := os.Stat(filepath.Join(dir, "policy.db")); !os.IsNotExist(err) {
		t.Fatal("failed bootstrap recreated revision floor")
	}
}

func TestP2PBootDefaultAndPartialState(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	store, _, enabled, err := openP2PAuthority(statePath)
	if err != nil || enabled || store != nil {
		t.Fatal("default Agent unexpectedly enabled P2P")
	}
	if err = os.Mkdir(filepath.Join(root, "p2p"), 0700); err != nil {
		t.Fatal(err)
	}
	_, _, enabled, err = openP2PAuthority(statePath)
	if err == nil || !enabled {
		t.Fatal("partial P2P state silently fell back")
	}
	state := agentctl.State{Version: agentctl.StateVersion, DeviceID: strings.Repeat("b", 32)}
	if err = agentctl.SaveState(statePath, state); err != nil {
		t.Fatal(err)
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	trust := p2p.Trust{ClusterID: "cluster", DeviceID: state.DeviceID, Issuer: public}
	if err = initializeP2PTrust(filepath.Join(root, "p2p"), trust); err != nil {
		t.Fatal(err)
	}
	store, _, enabled, err = openP2PAuthority(statePath)
	if err != nil || !enabled || store == nil {
		t.Fatal("explicit trust did not enable pilot", err)
	}
	_ = store.Close()
}

func TestP2PRequestFileValidationAndAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.json")
	first := p2pRequest{Version: 1, ID: strings.Repeat("a", 32), Stop: true}
	if err := writeP2PJSON(path, first, false); err != nil {
		t.Fatal(err)
	}
	second := p2pRequest{Version: 1, ID: strings.Repeat("b", 32), Stop: true}
	if err := writeP2PJSON(path, second, false); err != nil {
		t.Fatal(err)
	}
	var got p2pRequest
	if _, err := readP2PJSON(path, &got, 16384); err != nil || got.ID != second.ID {
		t.Fatal("request replacement failed", err)
	}
	for _, raw := range []string{`{"version":1,"private_key":"forbidden"}`, `{} {}`, strings.Repeat("x", 16385)} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readP2PJSON(path, new(p2pRequest), 16384); err == nil {
			t.Fatal("invalid/unbounded request accepted")
		}
	}
}

func TestP2PRoutePlanRequiresInstanceIdentityAndPreservesExternalObjects(t *testing.T) {
	peer := netip.MustParseAddr("10.253.0.3")
	guid := "00112233-4455-6677-8899-aabbccddeeff"
	script, err := p2pRouteScript(23, guid, peer, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "Remove-") || strings.Contains(script, "InterfaceAlias") || strings.Contains(script, "0.0.0.0/0") {
		t.Fatal("route plan mutates unrelated objects")
	}
	if !strings.Contains(script, "InterfaceGuid") || !strings.Contains(script, "Conflicting P2P route") || !strings.Contains(script, "-DestinationPrefix '10.253.0.3/32'") {
		t.Fatal("route ownership guard missing")
	}
	for _, bad := range []struct {
		index uint32
		guid  string
		peer  netip.Addr
	}{{0, guid, peer}, {23, "'; injection", peer}, {23, guid, netip.MustParseAddr("8.8.8.8")}, {23, guid, netip.IPv6Loopback()}} {
		if _, err = p2pRouteScript(bad.index, bad.guid, bad.peer, false); err == nil {
			t.Fatal("untrusted route identity accepted")
		}
	}
}
