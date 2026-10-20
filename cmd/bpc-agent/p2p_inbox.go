package main

import (
	"context"
	"path/filepath"
	"time"

	"github.com/RomanKrike/bpc/internal/agentctl"
	"github.com/RomanKrike/bpc/internal/p2p"
)

func runP2PInbox(ctx context.Context, statePath, dir string, trust p2p.Trust) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var last string
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		state, err := agentctl.LoadState(statePath)
		if err != nil || state.DeviceID != trust.DeviceID {
			continue
		}
		client, err := agentctl.NewMultiClient(state.ControlEndpoints(), state.ControlCredential())
		if err != nil {
			continue
		}
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		offer, err := client.P2PInbox(call)
		cancel()
		if err != nil || offer == nil {
			continue
		}
		request, err := verifiedP2POffer(state, trust, *offer)
		if err != nil || request.ID == last {
			continue
		}
		if err = writeP2PJSON(filepath.Join(dir, "request.json"), request, false); err == nil {
			last = request.ID
		}
	}
}

func verifiedP2POffer(state *agentctl.State, trust p2p.Trust, offer agentctl.P2POffer) (p2pRequest, error) {
	session, err := p2p.VerifyGrant(offer.Ticket, trust.Issuer, trust.ClusterID, 0, time.Now())
	if err != nil {
		return p2pRequest{}, err
	}
	request := p2pRequest{Version: 1, ID: session.Grant().SessionID, Ticket: offer.Ticket, Relay: offer.Relay}
	cfg, err := localP2PConfig(state, state.WireGuard, request)
	if err != nil {
		return p2pRequest{}, err
	}
	if _, err = p2p.BindEndpoint(session, cfg); err != nil {
		return p2pRequest{}, err
	}
	return request, nil
}
