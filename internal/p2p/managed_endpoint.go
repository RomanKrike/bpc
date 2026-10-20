package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RomanKrike/bpc/internal/agentctl"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

type EndpointConfig struct {
	Ticket           []byte
	DeviceID         string
	Identity         ed25519.PrivateKey
	WireGuardPrivate string
	Address          netip.Addr
	RelayAddress     string
	TLS              *tls.Config
	// AddRoute may only add a /32 on the currently owned BPC adapter, and
	// must reject conflicting/unowned routes. The mux is reserved first.
	AddRoute func(context.Context, netip.Addr) error
}

// BindEndpoint validates all local identity material before any socket or route.
func BindEndpoint(s *Session, c EndpointConfig) (Side, error) {
	if s == nil || len(c.Identity) != ed25519.PrivateKeySize {
		return 0, errors.New("P2P local identity required")
	}
	key, err := agentctl.ParseWGKey(c.WireGuardPrivate, false)
	if err != nil {
		return 0, errors.New("P2P local WireGuard key required")
	}
	public, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		return 0, err
	}
	for i, peer := range s.grant.Participants {
		if peer.DeviceID != c.DeviceID {
			continue
		}
		identity, _ := base64.StdEncoding.DecodeString(peer.IdentityKey)
		if !bytes.Equal(identity, c.Identity.Public().(ed25519.PublicKey)) || peer.WireGuardKey != base64.StdEncoding.EncodeToString(public) || peer.Address != c.Address {
			return 0, errors.New("P2P grant does not match enrolled local keys/address")
		}
		return Side(i), nil
	}
	return 0, errors.New("P2P grant belongs to another Device")
}

type PolicySync func(context.Context, [][]byte) ([]byte, error)

// RunManagedEndpoint is an explicit, bounded pilot session, not a grant-renewal
// protocol. It never renews a grant offline or silently falls back to gateway.
// Sync errors terminate this transport; a new request/ticket is required.
func RunManagedEndpoint(ctx context.Context, store *PolicyStore, mux *MuxTUN, c EndpointConfig, syncPolicy PolicySync) (result error) {
	if store == nil || mux == nil || syncPolicy == nil || c.TLS == nil || c.TLS.InsecureSkipVerify || c.TLS.ServerName == "" {
		return errors.New("P2P Controller, mux and relay trust required")
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	defer store.FailClosed()
	s, err := store.Track(c.Ticket)
	if err != nil {
		return err
	}
	defer func() {
		if err := store.Stop(s.grant.SessionID); err != nil {
			result = errors.Join(result, errors.New("P2P terminal denial could not be persisted"))
		}
	}()
	side, err := BindEndpoint(s, c)
	if err != nil {
		return err
	}
	peer := s.grant.Participants[1-side]
	if err = mux.Reserve(peer.Address); err != nil {
		return err
	}
	reconcile := func() error {
		deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		checkpoint, err := syncPolicy(deadline, [][]byte{c.Ticket})
		if err != nil {
			store.FailClosed()
			return errors.New("P2P Controller policy unavailable")
		}
		if _, err = store.Apply(checkpoint); err != nil {
			return err
		}
		if !s.active(time.Now()) {
			return errors.New("P2P policy denied or expired")
		}
		return nil
	}
	if err = reconcile(); err != nil {
		return err
	}
	policy, err := NewPolicy(s, side)
	if err != nil {
		return err
	}
	defer policy.Revoke()
	if c.AddRoute != nil {
		if err = c.AddRoute(ctx, peer.Address); err != nil {
			return err
		}
	}
	input, err := mux.Attach(peer.Address, policy)
	if err != nil {
		return err
	}
	// Close this virtual peer only; the OS adapter/gateway stay alive.
	defer input.Close()
	bridge, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer bridge.Close()
	wg := device.NewDevice(input, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer wg.Close()
	private, _ := agentctl.WGKeyHex(c.WireGuardPrivate, false)
	remote, _ := agentctl.WGKeyHex(peer.WireGuardKey, false)
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nendpoint=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=0\n", private, remote, bridge.LocalAddr(), peer.Address)
	if err = wg.IpcSet(uapi); err != nil {
		return errors.New("configure P2P WireGuard failed")
	}
	if err = wg.Up(); err != nil {
		return err
	}
	raw, err := wg.IpcGet()
	if err != nil {
		return err
	}
	var port int
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port, _ = strconv.Atoi(strings.TrimPrefix(line, "listen_port="))
		}
	}
	if port <= 0 {
		return errors.New("P2P WireGuard socket unavailable")
	}
	relay, err := DialRelay(ctx, c.RelayAddress, c.TLS, s, side, c.Identity)
	if err != nil {
		return errors.New("P2P relay authentication failed")
	}
	defer relay.Close()
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	var syncWorkers sync.WaitGroup
	updates := make(chan error, 1)
	pending := false
	go func() {
		done <- RunEndpoint(child, bridge, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, relay)
	}()
	defer func() {
		policy.Revoke()
		stop()
		cancel()
		_ = bridge.Close()
		_ = relay.Close()
		<-done
		syncWorkers.Wait()
		store.FailClosed()
	}()
	poll := time.NewTicker(5 * time.Second)
	defer poll.Stop()
	expiry := time.NewTicker(100 * time.Millisecond)
	defer expiry.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-mux.done:
			return errors.New("owned BPC adapter stopped")
		case err := <-done:
			// Keep one completion for the cleanup join.
			done <- err
			return errors.New("P2P relay stopped")
		case <-poll.C:
			if !pending {
				pending = true
				syncWorkers.Add(1)
				go func() { defer syncWorkers.Done(); updates <- reconcile() }()
			}
		case err := <-updates:
			pending = false
			if err != nil {
				return err
			}
		case <-expiry.C:
			if !s.active(time.Now()) {
				return errors.New("P2P lease expired")
			}
		}
	}
}
