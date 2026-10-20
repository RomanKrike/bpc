package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/RomanKrike/bpc/internal/agentctl"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestSessionRecoveryKeepsIdentityAndFailsWithoutSaving(t *testing.T) {
	for _, mode := range []string{"ok", "wrong-device", "wrong-address", "revoked", "old-controller", "stop-failed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			pub, private, _ := agentctl.GenerateIdentity()
			wgPrivate, wgPublic, _ := agentctl.GenerateWireGuardKeypair()
			_, peer, _ := agentctl.GenerateWireGuardKeypair()
			old := agentctl.State{Version: agentctl.StateVersion, DeviceID: "existing-device", DeviceName: "pc004",
				PublicKey: pub, PrivateKey: private, UpdatePubKey: "stored-pin", RefreshToken: "expired",
				WireGuard: agentctl.WireGuardProfile{PrivateKey: wgPrivate, Address: "10.253.0.2/32", PeerPublicKey: peer,
					MTU: 1280, AllowedIPs: []string{"0.0.0.0/0"}}}
			old.Config = agentctl.RuntimeConfig{WGShimServer: "127.0.0.1:24444", WGShimListen: "127.0.0.1:24081",
				WGShimTarget: "127.0.0.1:24082", WGShimPSK: base64.StdEncoding.EncodeToString(make([]byte, 32))}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/auth/login":
					json.NewEncoder(w).Encode(map[string]any{"access_token": "login", "access_expires_at": time.Now().Add(time.Minute).Unix(), "user": map[string]string{"id": "owner"}})
				case "/v1/devices/reauthenticate":
					var req agentctl.DeviceRegistrationRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
					}
					public, _ := base64.StdEncoding.DecodeString(pub)
					signature, _ := base64.StdEncoding.DecodeString(req.Proof)
					if req.DeviceID != old.DeviceID || req.PublicKey != pub || req.WireGuardPublicKey != wgPublic ||
						!ed25519.Verify(public, agentctl.RegistrationSigningBytes("login", pub, wgPublic), signature) {
						t.Error("identity proof not preserved")
					}
					if mode == "old-controller" {
						w.WriteHeader(404)
						return
					}
					if mode == "revoked" {
						w.WriteHeader(403)
						return
					}
					response := agentctl.DeviceRegistrationResponse{DeviceID: old.DeviceID, AccessToken: "new-access", RefreshToken: "new-refresh", Config: old.Config, WireGuard: old.WireGuard}
					response.WireGuard.PrivateKey = ""
					if mode == "wrong-device" {
						response.DeviceID = "another"
					}
					if mode == "wrong-address" {
						response.WireGuard.Address = "10.253.0.99/32"
					}
					json.NewEncoder(w).Encode(response)
				default:
					t.Errorf("unexpected endpoint %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			old.ControlURL = server.URL
			path := filepath.Join(t.TempDir(), "state.json")
			if err := agentctl.SaveState(path, old); err != nil {
				t.Fatal(err)
			}
			original, _ := os.ReadFile(path)
			// Supply the real client's TLS test trust without weakening normal HTTPS.
			previous := http.DefaultTransport
			http.DefaultTransport = server.Client().Transport
			defer func() { http.DefaultTransport = previous }()
			stopped := false
			credentials := func() (string, string, error) {
				if mode == "cancelled" {
					return "", "", errors.New("cancelled")
				}
				return "owner", "password", nil
			}
			next, err := recoverDeviceSession(context.Background(), &old, path, credentials, func() error {
				stopped = true
				if mode == "stop-failed" {
					return errors.New("stop failed")
				}
				return nil
			})
			if mode != "ok" {
				if err == nil {
					t.Fatal("failure accepted")
				}
				actual, _ := os.ReadFile(path)
				if string(actual) != string(original) {
					t.Fatal("failed recovery changed saved identity")
				}
				if stopped && mode != "stop-failed" {
					t.Fatal("service stopped before validation")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !stopped || next.DeviceID != old.DeviceID || next.PrivateKey != private || next.PublicKey != pub ||
				next.WireGuard.PrivateKey != wgPrivate || next.UpdatePubKey != old.UpdatePubKey || next.RefreshToken != "new-refresh" {
				t.Fatal("identity/trust lost")
			}
			saved, e := agentctl.LoadState(path)
			if e != nil || !reflect.DeepEqual(*next, *saved) {
				t.Fatal("session not persisted")
			}
		})
	}
}
