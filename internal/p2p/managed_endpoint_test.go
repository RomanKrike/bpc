package p2p

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RomanKrike/bpc/internal/agentctl"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestManagedEndpointBindsKeysBeforeSyncOrRoute(t *testing.T) {
	for _, kind := range []string{"device", "identity", "wireguard", "address"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			store, err := CreatePolicyStore(filepath.Join(t.TempDir(), "policy.db"), fixtureTrust(f))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			raw := newPipeTUN()
			mux, _ := NewMuxTUN(raw)
			defer mux.Close()
			_, _, tlsConfig := startRelay(t, f)
			cfg := EndpointConfig{Ticket: f.ticket, DeviceID: f.grant.Participants[1].DeviceID, Identity: f.identities[1], WireGuardPrivate: f.wgPrivate[1], Address: f.grant.Participants[1].Address, RelayAddress: "localhost:1", TLS: tlsConfig}
			switch kind {
			case "device":
				cfg.DeviceID = "wrong"
			case "identity":
				cfg.Identity = f.identities[0]
			case "wireguard":
				cfg.WireGuardPrivate = f.wgPrivate[0]
			case "address":
				cfg.Address = f.grant.Participants[0].Address
			}
			cfg.AddRoute = func(context.Context, netip.Addr) error { t.Error("unbound local profile changed routes"); return nil }
			err = RunManagedEndpoint(context.Background(), store, mux, cfg, func(context.Context, [][]byte) ([]byte, error) {
				t.Error("unbound profile contacted Controller")
				return nil, errors.New("unexpected")
			})
			if err == nil || len(mux.peers) != 0 {
				t.Fatal("mismatched local keys authorized")
			}
		})
	}
}

func TestManagedEndpointControllerPolicyOverRealWireGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("real TLS/Controller/WireGuard acceptance")
	}
	for _, failure := range []string{"denial", "controller-error", "idle-expiry", "blocked-sync"} {
		t.Run(failure, func(t *testing.T) {
			f := newFixture(t)
			relayServer, relay, tlsConfig := startRelay(t, f)
			var revoked atomic.Bool
			var revision atomic.Uint64
			revision.Store(7)
			release := make(chan struct{})
			controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/p2p/sync" {
					http.NotFound(w, r)
					return
				}
				id := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				if id != f.grant.Participants[0].DeviceID && id != f.grant.Participants[1].DeviceID {
					w.WriteHeader(401)
					return
				}
				if revoked.Load() && failure == "controller-error" {
					w.WriteHeader(503)
					return
				}
				var request struct {
					Tickets [][]byte `json:"tickets"`
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.Tickets) != 1 {
					w.WriteHeader(400)
					return
				}
				if revoked.Load() && failure == "blocked-sync" {
					select {
					case <-r.Context().Done():
					case <-release:
					}
					return
				}
				life := int64(25)
				if failure == "idle-expiry" {
					life = 2
				}
				if failure == "blocked-sync" {
					life = 7
				}
				policy := checkpoint{Version: 1, ClusterID: f.grant.ClusterID, DeviceID: id, Revision: revision.Add(1), IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + life, Allowed: []policyEntry{}}
				if !revoked.Load() {
					hash := sha256.Sum256(f.ticket)
					policy.Allowed = []policyEntry{{SessionID: f.grant.SessionID, TicketSHA256: hex.EncodeToString(hash[:])}}
				}
				_ = json.NewEncoder(w).Encode(map[string][]byte{"checkpoint": signPolicyValue(t, f.issuer, policy)})
			}))
			defer controller.Close()
			defer close(release)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			var stacks [2]*netstack.Net
			done := make(chan error, 2)
			for i := 0; i < 2; i++ {
				raw, stack, err := netstack.CreateNetTUN([]netip.Addr{f.grant.Participants[i].Address}, nil, 1280)
				if err != nil {
					t.Fatal(err)
				}
				stacks[i] = stack
				mux, err := NewMuxTUN(raw)
				if err != nil {
					t.Fatal(err)
				}
				defer mux.Close()
				trust := Trust{ClusterID: f.grant.ClusterID, DeviceID: f.grant.Participants[i].DeviceID, Issuer: f.issuer.Public().(ed25519.PublicKey)}
				store, err := CreatePolicyStore(filepath.Join(t.TempDir(), "policy.db"), trust)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				client, err := agentctl.NewClient(controller.URL, trust.DeviceID)
				if err != nil {
					t.Fatal(err)
				}
				client.HTTP = controller.Client()
				cfg := EndpointConfig{Ticket: f.ticket, DeviceID: trust.DeviceID, Identity: f.identities[i], WireGuardPrivate: f.wgPrivate[i], Address: f.grant.Participants[i].Address, RelayAddress: relay, TLS: tlsConfig}
				go func() { done <- RunManagedEndpoint(ctx, store, mux, cfg, client.SyncP2PPolicy) }()
			}
			defer func() {
				cancel()
				for i := 0; i < 2; i++ {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("managed endpoint leaked")
					}
				}
			}()
			joinedUntil := time.Now().Add(time.Second)
			for {
				relayServer.mu.Lock()
				room := relayServer.sessions[f.grant.SessionID]
				joined := room != nil && room.peers[0] != nil && room.peers[1] != nil
				relayServer.mu.Unlock()
				if joined {
					break
				}
				select {
				case err := <-done:
					done <- err
					t.Fatalf("endpoint setup failed: %v", err)
				default:
				}
				if time.Now().After(joinedUntil) {
					t.Fatal("both endpoints did not join")
				}
				time.Sleep(time.Millisecond)
			}
			host := f.grant.Participants[1].Address
			udp, err := stacks[1].ListenUDPAddrPort(netip.AddrPortFrom(host, 47998))
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			go func() {
				b := make([]byte, 2000)
				for {
					n, from, err := udp.ReadFrom(b)
					if err != nil {
						return
					}
					_, _ = udp.WriteTo(b[:n], from)
				}
			}()
			client, err := stacks[0].DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(host, 47998))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			// The first packet may precede attaching the verified peers. Retry only
			// within this test's setup window, never as a runtime fallback.
			deadline := time.Now().Add(time.Second)
			var b [64]byte
			for {
				_ = client.SetDeadline(time.Now().Add(100 * time.Millisecond))
				_, _ = client.Write([]byte("managed-udp"))
				n, err := client.Read(b[:])
				if err == nil && string(b[:n]) == "managed-udp" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("managed WG UDP did not become active")
				}
			}
			listener, err := stacks[1].ListenTCPAddrPort(netip.AddrPortFrom(host, 47989))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
			tcp, err := stacks[0].DialContext(ctx, "tcp", netip.AddrPortFrom(host, 47989).String())
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			_ = tcp.SetDeadline(time.Now().Add(time.Second))
			_, _ = tcp.Write([]byte("tcp"))
			if _, err = io.ReadFull(tcp, b[:3]); err != nil {
				t.Fatal(err)
			}
			if failure != "idle-expiry" {
				revoked.Store(true)
			}
			terminationWindow := 8 * time.Second
			if failure == "blocked-sync" {
				terminationWindow = 7500 * time.Millisecond
			}
			select {
			case err := <-done:
				if err == nil {
					t.Error("terminal policy condition succeeded")
				}
				done <- err
			case <-time.After(terminationWindow):
				t.Fatal("policy failure did not close idle transport")
			}
			_ = client.SetDeadline(time.Now().Add(150 * time.Millisecond))
			_, _ = client.Write([]byte("revoked"))
			if _, err = client.Read(b[:]); err == nil {
				t.Fatal("revoked UDP reached OS")
			}
			_ = tcp.SetDeadline(time.Now().Add(150 * time.Millisecond))
			_, _ = tcp.Write([]byte("bad"))
			if _, err = io.ReadFull(tcp, b[:3]); err == nil {
				t.Fatal("established TCP survived revoke")
			}
		})
	}
}
