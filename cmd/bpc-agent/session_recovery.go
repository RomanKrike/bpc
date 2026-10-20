package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/RomanKrike/bpc/internal/agentctl"
	"golang.org/x/crypto/curve25519"
)

// This is an explicit interactive installer action, never a background service
// login. Keep the stored Controller trust, Device and local cryptographic keys.
func recoverDeviceSession(ctx context.Context, previous *agentctl.State, path string,
	credentials func() (string, string, error), beforeSave func() error) (*agentctl.State, error) {
	client, err := agentctl.NewMultiClient(previous.ControlEndpoints(), "")
	if err != nil {
		return nil, err
	}
	username, password, err := credentials()
	if err != nil {
		return nil, err
	}
	login, err := client.Login(ctx, username, password)
	password = ""
	if err != nil {
		return nil, fmt.Errorf("sign in again: %w", err)
	}
	private, err := base64.StdEncoding.DecodeString(previous.WireGuard.PrivateKey)
	if err != nil {
		return nil, err
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	wgPublic := base64.StdEncoding.EncodeToString(public)
	proof, err := agentctl.SignDeviceProof(previous.PrivateKey,
		agentctl.RegistrationSigningBytes(login.AccessToken, previous.PublicKey, wgPublic))
	if err != nil {
		return nil, err
	}
	response, err := client.ReauthenticateDevice(ctx, login.AccessToken, agentctl.DeviceRegistrationRequest{
		DeviceID: previous.DeviceID, Name: previous.DeviceName, PublicKey: previous.PublicKey,
		WireGuardPublicKey: wgPublic, Version: version, Proof: proof,
	})
	if err != nil {
		return nil, fmt.Errorf("restore existing device session (updated Controller required): %w", err)
	}
	if response.DeviceID != previous.DeviceID || response.WireGuard.Address != previous.WireGuard.Address {
		return nil, errors.New("sign-in recovery returned a different Device or overlay address")
	}
	next := *previous
	next.Version = agentctl.StateVersion
	next.AccessToken, next.AccessExpiresAt = response.AccessToken, response.AccessExpiresAt
	next.RefreshToken, next.RefreshExpiresAt = response.RefreshToken, response.RefreshExpiresAt
	next.DeviceToken = ""
	next.Config = response.Config
	next.WireGuard = response.WireGuard
	next.WireGuard.PrivateKey = previous.WireGuard.PrivateKey
	if next.WireGuard.PresharedKey == "" {
		next.WireGuard.PresharedKey = previous.WireGuard.PresharedKey
	}
	if err := agentctl.ValidateWireGuardProfile(next.WireGuard); err != nil {
		return nil, err
	}
	if err := next.ValidateRuntimeConfig(); err != nil {
		return nil, err
	}
	// Stop any old service before replacing credentials so it cannot overwrite
	// the new session with a concurrent refresh. SaveState replaces atomically.
	if err := beforeSave(); err != nil {
		return nil, err
	}
	if err := agentctl.SaveState(path, next); err != nil {
		return nil, err
	}
	return &next, nil
}
