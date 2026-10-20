package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/RomanKrike/bpc/internal/agentctl"
)

// Only fresh, successful account enrollment calls this. Restart/reinstall must
// never reverse a user's later consent withdrawal.
func initializeAccountP2P(state *agentctl.State) error {
	client, err := agentctl.NewMultiClient(state.ControlEndpoints(), state.ControlCredential())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	info, err := client.FetchP2PInfo(ctx)
	if err != nil {
		// P2P is optional: old/disabled/unreachable Controllers preserve install.
		return nil
	}
	if !info.AccountMode {
		return nil
	}
	if err = p2pCommand([]string{"init"}); err != nil {
		return err
	}
	return p2pCommand([]string{"consent", "--enabled=true"})
}

// prepareP2P reuses enrollment and preserves existing trust/revision floors.
// Restart is explicit because initialization changes the shared TUN lifecycle.
func prepareP2P(statePath string, initialize, stop, start func() error) error {
	dir := filepath.Join(filepath.Dir(statePath), "p2p")
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		if err = initialize(); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := stop(); err != nil {
		return fmt.Errorf("stop Agent for P2P preparation: %w", err)
	}
	store, _, enabled, err := openP2PAuthority(statePath)
	if err != nil {
		return fmt.Errorf("P2P state invalid; Agent remains stopped, preserve trust and policy files: %w", err)
	}
	if !enabled || store == nil {
		return errors.New("P2P initialization incomplete; Agent remains stopped")
	}
	if err = store.Close(); err != nil {
		return err
	}
	return start()
}
