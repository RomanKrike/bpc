package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RomanKrike/bpc/internal/agentctl"
	"github.com/RomanKrike/bpc/internal/p2p"
)

func TestPrepareP2PPreservesTrustAndRefusesRepair(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.json")
	state := agentctl.State{Version: agentctl.StateVersion, DeviceID: strings.Repeat("a", 32)}
	if err := agentctl.SaveState(path, state); err != nil {
		t.Fatal(err)
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	trust := p2p.Trust{ClusterID: "cluster", DeviceID: state.DeviceID, Issuer: public}
	dir := filepath.Join(root, "p2p")
	initializations, stops, starts := 0, 0, 0
	init := func() error {
		initializations++
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
		return initializeP2PTrust(dir, trust)
	}
	stop := func() error { stops++; return nil }
	start := func() error { starts++; return nil }
	for i := 0; i < 2; i++ {
		if err := prepareP2P(path, init, stop, start); err != nil {
			t.Fatal(err)
		}
	}
	if initializations != 1 || starts != 2 {
		t.Fatal("repeat preparation reset trust")
	}
	if err := os.Remove(filepath.Join(dir, "policy.db")); err != nil {
		t.Fatal(err)
	}
	if err := prepareP2P(path, init, stop, start); err == nil {
		t.Fatal("missing floor repaired")
	}
	if initializations != 1 || starts != 2 || stops != 3 {
		t.Fatal("unsafe restart")
	}
	if _, err := os.Stat(filepath.Join(dir, "policy.db")); !os.IsNotExist(err) {
		t.Fatal("store recreated")
	}
}

func TestPrepareP2PInitializationFailureDoesNotStopGateway(t *testing.T) {
	err := prepareP2P(filepath.Join(t.TempDir(), "state.json"),
		func() error { return errors.New("Controller unavailable") },
		func() error { t.Fatal("gateway stopped before initialization"); return nil },
		func() error { t.Fatal("service started after failed initialization"); return nil })
	if err == nil {
		t.Fatal("failure ignored")
	}
}
