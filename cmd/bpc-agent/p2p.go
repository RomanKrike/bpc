package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/RomanKrike/bpc/internal/agentctl"
	"github.com/RomanKrike/bpc/internal/p2p"
)

type p2pTrustFile struct {
	Version int       `json:"version"`
	Trust   p2p.Trust `json:"trust"`
}
type p2pRequest struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Stop    bool   `json:"stop,omitempty"`
	Ticket  []byte `json:"ticket,omitempty"`
	Relay   string `json:"relay,omitempty"`
}

func readP2PJSON(path string, out any, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("P2P file too large")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return nil, errors.New("invalid P2P file")
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid P2P trailing data")
	}
	return raw, nil
}

func loadP2PTrust(dir, device string) (p2p.Trust, error) {
	var file p2pTrustFile
	_, err := readP2PJSON(filepath.Join(dir, "trust.json"), &file, 4096)
	if err != nil {
		return p2p.Trust{}, err
	}
	if file.Version != 1 || file.Trust.DeviceID != device || file.Trust.ClusterID == "" || len(file.Trust.Issuer) != 32 {
		return p2p.Trust{}, errors.New("P2P trust subject mismatch")
	}
	return file.Trust, nil
}

func initializeP2PTrust(dir string, trust p2p.Trust) error {
	if _, err := os.Lstat(filepath.Join(dir, "trust.json")); !os.IsNotExist(err) {
		return errors.New("P2P trust already exists or cannot be checked; refusing bootstrap")
	}
	store, err := p2p.CreatePolicyStore(filepath.Join(dir, "policy.db"), trust)
	if err != nil {
		return err
	}
	if err = store.Close(); err != nil {
		return err
	}
	return writeP2PJSON(filepath.Join(dir, "trust.json"), p2pTrustFile{1, trust}, true)
}

func openP2PAuthority(statePath string) (*p2p.PolicyStore, p2p.Trust, bool, error) {
	dir := filepath.Join(filepath.Dir(statePath), "p2p")
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil, p2p.Trust{}, false, nil
	}
	if err != nil {
		return nil, p2p.Trust{}, true, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, p2p.Trust{}, true, errors.New("invalid P2P state directory")
	}
	state, err := agentctl.LoadState(statePath)
	if err != nil {
		return nil, p2p.Trust{}, true, err
	}
	trust, err := loadP2PTrust(dir, state.DeviceID)
	if err != nil {
		return nil, p2p.Trust{}, true, err
	}
	store, err := p2p.OpenPolicyStore(filepath.Join(dir, "policy.db"), trust)
	return store, trust, true, err
}

func writeP2PJSON(path string, value any, exclusive bool) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if exclusive {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(raw)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".p2p-request-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// A Windows reader can briefly hold the old file without share-delete.
	// Keep replacement atomic and bound retries; never unlink the live request.
	for attempt := 0; attempt < 5; attempt++ {
		err = os.Rename(name, path)
		if err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return err
}

func relayHost(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	p, parseErr := strconv.Atoi(port)
	if err != nil || host == "" || parseErr != nil || p < 1 || p > 65535 {
		return "", errors.New("relay must be host:port")
	}
	return host, nil
}

func localP2PConfig(state *agentctl.State, profile agentctl.WireGuardProfile, request p2pRequest) (p2p.EndpointConfig, error) {
	key, err := base64.StdEncoding.DecodeString(state.PrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return p2p.EndpointConfig{}, errors.New("invalid enrolled Device identity")
	}
	address, err := netip.ParsePrefix(profile.Address)
	if err != nil {
		return p2p.EndpointConfig{}, err
	}
	host, err := relayHost(request.Relay)
	if err != nil {
		return p2p.EndpointConfig{}, err
	}
	return p2p.EndpointConfig{Ticket: request.Ticket, DeviceID: state.DeviceID, Identity: ed25519.PrivateKey(key), WireGuardPrivate: profile.PrivateKey, Address: address.Addr(), RelayAddress: request.Relay, TLS: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS13}}, nil
}

func p2pCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("P2P pilot: init | consent --enabled=true|false | request --host DEVICE --out FILE | start --ticket FILE --relay HOST:PORT | stop")
	}
	if !isAdministrator() {
		return errors.New("P2P pilot requires an Administrator terminal")
	}
	root, _, statePath, err := installPaths()
	if err != nil {
		return err
	}
	state, err := agentctl.LoadState(statePath)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "p2p")
	if args[0] != "init" {
		if _, err = os.Lstat(dir); err != nil {
			return errors.New("initialize the P2P pilot first")
		}
		if err = secureP2PDirectory(dir); err != nil {
			return err
		}
	}
	flags := flag.NewFlagSet("p2p "+args[0], flag.ContinueOnError)
	enabled := flags.Bool("enabled", false, "explicit Device consent")
	host := flags.String("host", "", "same-owner host Device ID")
	out := flags.String("out", "", "new public ticket file")
	ticketPath := flags.String("ticket", "", "public ticket file")
	relay := flags.String("relay", "", "TLS relay host:port")
	if err = flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected P2P arguments")
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	request := p2pRequest{Version: 1, ID: hex.EncodeToString(nonce), Stop: true}
	if args[0] == "stop" || (args[0] == "consent" && !*enabled) {
		if err = writeP2PJSON(filepath.Join(dir, "request.json"), request, false); err != nil {
			return err
		}
		if args[0] == "stop" {
			fmt.Println("P2P stop requested; gateway remains active.")
			return nil
		}
	}
	control, err := agentctl.NewMultiClient(state.ControlEndpoints(), state.ControlCredential())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if args[0] == "init" {
		info, err := control.FetchP2PInfo(ctx)
		if err != nil {
			return err
		}
		if info.DeviceID != state.DeviceID {
			return errors.New("P2P Controller returned another Device")
		}
		key, _ := base64.StdEncoding.DecodeString(info.IssuerPublicKey)
		trust := p2p.Trust{ClusterID: info.ClusterID, DeviceID: info.DeviceID, Issuer: ed25519.PublicKey(key)}
		if err = secureP2PDirectory(dir); err != nil {
			return err
		}
		if err = initializeP2PTrust(dir, trust); err != nil {
			return err
		}
		fmt.Println("P2P Controller trust initialized; restart the Agent to activate the pilot. Consent remains unchanged.")
		return nil
	}
	trust, err := loadP2PTrust(dir, state.DeviceID)
	if err != nil {
		return err
	}
	switch args[0] {
	case "consent":
		info, err := control.FetchP2PInfo(ctx)
		if err != nil {
			return err
		}
		if info.DeviceID != trust.DeviceID || info.ClusterID != trust.ClusterID || info.IssuerPublicKey != base64.StdEncoding.EncodeToString(trust.Issuer) {
			return errors.New("P2P Controller trust changed")
		}
		if err = control.SetP2PConsent(ctx, *info, *enabled, state.PrivateKey); err != nil {
			return err
		}
		fmt.Printf("P2P Device consent: %t\n", *enabled)
		return nil
	case "request":
		if *out == "" {
			return errors.New("new ticket output path required")
		}
		ticket, err := control.IssueP2PGrant(ctx, *host)
		if err != nil {
			return err
		}
		session, err := p2p.VerifyGrant(ticket, trust.Issuer, trust.ClusterID, 0, time.Now())
		if err != nil {
			return err
		}
		// Verify local bindings before exporting a ticket to the other Device.
		cfg, err := localP2PConfig(state, state.WireGuard, p2pRequest{Ticket: ticket, Relay: "localhost:1"})
		if err != nil {
			return err
		}
		if _, err = p2p.BindEndpoint(session, cfg); err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(ticket)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Println("Public P2P ticket written; maximum lease is 60 seconds.")
		return nil
	case "start":
		if *ticketPath == "" {
			return errors.New("public ticket file required")
		}
		var envelope json.RawMessage
		ticket, err := readP2PJSON(*ticketPath, &envelope, 8192)
		if err != nil {
			return err
		}
		request.Stop = false
		request.Ticket = ticket
		request.Relay = *relay
		cfg, err := localP2PConfig(state, state.WireGuard, request)
		if err != nil {
			return err
		}
		session, err := p2p.VerifyGrant(ticket, trust.Issuer, trust.ClusterID, 0, time.Now())
		if err != nil {
			return err
		}
		if _, err = p2p.BindEndpoint(session, cfg); err != nil {
			return err
		}
		if err = writeP2PJSON(filepath.Join(dir, "request.json"), request, false); err != nil {
			return err
		}
		fmt.Println("P2P pilot requested; the running Agent enforces policy and lease expiry.")
		return nil
	default:
		return errors.New("unknown P2P pilot command")
	}
}

func p2pRouteScript(index uint32, guid string, peer netip.Addr, alreadyOwned bool) (string, error) {
	if index == 0 || !peer.Is4() || !peer.IsPrivate() {
		return "", errors.New("invalid owned P2P route")
	}
	// GUID comes from the live TUN handle, never an alias/config/request.
	guid = strings.Trim(guid, "{}")
	if len(guid) != 36 {
		return "", errors.New("invalid TUN GUID")
	}
	for i, c := range guid {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return "", errors.New("invalid TUN GUID")
			}
		} else if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return "", errors.New("invalid TUN GUID")
		}
	}
	owned := "$false"
	if alreadyOwned {
		owned = "$true"
	}
	return fmt.Sprintf("$ErrorActionPreference='Stop'; "+
		"$adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {$_.ifIndex -eq %d}); "+
		"if ($adapters.Count -ne 1 -or $adapters[0].InterfaceGuid.ToString() -ne '%s') {throw 'BPC TUN ownership changed'}; "+
		"$routes=@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {$_.DestinationPrefix -eq '%s/32'}); "+
		"if ($routes.Count -ne 0) { "+
		"if (%s -and $routes.Count -eq 1 -and $routes[0].InterfaceIndex -eq %d -and $routes[0].NextHop -eq '0.0.0.0' -and $routes[0].RouteMetric -eq 5) {exit 0}; "+
		"throw 'Conflicting P2P route; external routes are preserved'}; "+
		"New-NetRoute -InterfaceIndex %d -DestinationPrefix '%s/32' -NextHop 0.0.0.0 -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null",
		index, guid, peer, owned, index, index, peer), nil
}

// Runs with the existing overlay lifetime. It never recreates the gateway,
// refreshes credentials independently or reads private keys from request files.
func runP2PLoop(ctx context.Context, mux *p2p.MuxTUN, store *p2p.PolicyStore, trust p2p.Trust, profile agentctl.WireGuardProfile, logger *log.Logger, route func(context.Context, netip.Addr) error) {
	root, _, statePath, err := installPaths()
	if err != nil {
		return
	}
	dir := filepath.Join(root, "p2p")
	var worker runtimeWorker
	defer func() {
		_ = worker.stop()
	}()
	var last [32]byte
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		var request p2pRequest
		raw, err := readP2PJSON(filepath.Join(dir, "request.json"), &request, 16384)
		if err != nil {
			if store != nil {
				store.FailClosed()
			}
			_ = worker.stop()
			continue
		}
		hash := sha256.Sum256(raw)
		if hash == last {
			continue
		}
		if store != nil {
			store.FailClosed()
		}
		if err = worker.stop(); err != nil {
			logger.Printf("P2P worker shutdown failed")
			continue
		}
		last = hash
		id, idErr := hex.DecodeString(request.ID)
		if request.Version != 1 || idErr != nil || len(id) != 16 || hex.EncodeToString(id) != request.ID {
			logger.Printf("P2P request rejected")
			continue
		}
		if request.Stop {
			continue
		}
		state, err := agentctl.LoadState(statePath)
		if err != nil {
			continue
		}
		if state.DeviceID != trust.DeviceID {
			logger.Printf("P2P Device changed")
			continue
		}
		cfg, err := localP2PConfig(state, profile, request)
		if err != nil {
			logger.Printf("P2P local binding unavailable")
			continue
		}
		cfg.AddRoute = route
		sync := func(call context.Context, tickets [][]byte) ([]byte, error) {
			latest, err := agentctl.LoadState(statePath)
			if err != nil {
				return nil, err
			}
			if latest.DeviceID != trust.DeviceID {
				return nil, errors.New("P2P Device changed")
			}
			client, err := agentctl.NewMultiClient(latest.ControlEndpoints(), latest.ControlCredential())
			if err != nil {
				return nil, err
			}
			return client.SyncP2PPolicy(call, tickets)
		}
		if err = worker.replace(ctx, request.ID, func(child context.Context) {
			if err := p2p.RunManagedEndpoint(child, store, mux, cfg, sync); err != nil && err != context.Canceled {
				logger.Printf("P2P session stopped: %v", err)
			}
		}); err != nil {
			logger.Printf("P2P worker start failed")
		}
	}
}
