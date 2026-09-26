package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/RomanKrike/bpc/internal/agentctl"
	"github.com/RomanKrike/bpc/internal/wgshim"
)

const (
	version              = "0.16.0"
	legacyTaskName       = "BPC Agent"
	bootstrapStart       = "\nBPC_AGENT_BOOTSTRAP_V3\n"
	legacyBootstrapStart = "\nBPC_AGENT_BOOTSTRAP_V2\n"
	bootstrapEnd         = "\nBPC_AGENT_BOOTSTRAP_END\n"
	defaultLogEvery      = 30 * time.Second
)

type tunnelTelemetry struct {
	UpdatedAt   int64  `json:"updated_at"`
	HandshakeAt int64  `json:"handshake_at"`
	RXBytes     uint64 `json:"rx_bytes"`
	TXBytes     uint64 `json:"tx_bytes"`
}

type transportTelemetry struct {
	UpdatedAt int64  `json:"updated_at"`
	Endpoint  string `json:"endpoint"`
	RTTMS     int64  `json:"rtt_ms"`
	Reachable int    `json:"reachable"`
	Total     int    `json:"total"`
}

type runtimeSupervisor struct {
	mu          sync.Mutex
	fingerprint string
	cancel      context.CancelFunc
}

func main() {
	cmd := "install"
	if len(os.Args) > 1 {
		cmd = strings.ToLower(os.Args[1])
	}

	if cmd == "version" || cmd == "--version" || cmd == "-version" {
		fmt.Printf("bpc-agent %s\n", version)
		return
	}
	if runtime.GOOS != "windows" {
		fatalf("BPC Agent currently supports Windows only")
	}

	var err error
	switch cmd {
	case "install":
		err = installAgent()
	case "run":
		err = runAgent()
	case "run-service":
		err = runWindowsService()
	case "status":
		err = printStatus()
	case "status-json":
		err = printStatusJSON()
	case "connect":
		err = connectAgent()
	case "disconnect":
		err = disconnectAgent()
	case "ui":
		err = launchWindowsUI()
	case "install-ui":
		if !isAdministrator() {
			err = elevate("install-ui")
		} else {
			dir, exePath, _, pathErr := installPaths()
			if pathErr != nil {
				err = pathErr
			} else if installErr := installWindowsUI(exePath, dir); installErr != nil {
				err = installErr
			} else {
				_, _, statePath, _ := installPaths()
				if state, loadErr := agentctl.LoadState(statePath); loadErr == nil {
					_ = writeUIStatus(state)
				}
				allowUsersReadPath(dir)
				allowUsersReadPath(exePath)
				if statusPath, statusErr := uiStatusPath(); statusErr == nil {
					allowUsersReadPath(statusPath)
				}
				err = startWindowsUI()
			}
		}
	case "update":
		err = updateNow()
	case "uninstall":
		err = uninstallAgent()
	case "help", "--help", "-h":
		usage()
		return
	default:
		usage()
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func installAgent() error {
	bootstrap, err := loadBootstrap()
	if err != nil {
		return err
	}
	if err := agentctl.ValidateBootstrap(*bootstrap); err != nil {
		return err
	}
	if !isAdministrator() {
		return elevate("install")
	}

	dir, exePath, statePath, err := installPaths()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create install directory: %w", err)
	}

	state, err := enrollOrLoadState(context.Background(), *bootstrap, statePath)
	if err != nil {
		return fmt.Errorf("device enrollment: %w", err)
	}
	if err := agentctl.ValidateRuntimeConfig(state.Config); err != nil {
		return fmt.Errorf("runtime config: %w", err)
	}

	current, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	current, _ = filepath.Abs(current)
	exePath, _ = filepath.Abs(exePath)

	if err := installWintunPayload(current, dir); err != nil {
		return fmt.Errorf("install Wintun runtime: %w", err)
	}

	// Remove the 0.9.x startup task before switching to the native service.
	_, _ = runCommand("schtasks.exe", "/End", "/TN", legacyTaskName)
	_, _ = runCommand("schtasks.exe", "/Delete", "/TN", legacyTaskName, "/F")
	_ = removeWindowsUI()
	if err := stopWindowsService(); err != nil {
		return fmt.Errorf("stop existing BPC Agent service: %w", err)
	}
	if !samePath(current, exePath) {
		if err := copyFile(current, exePath); err != nil {
			return fmt.Errorf("install agent binary: %w", err)
		}
	}
	lockDownPath(dir)
	lockDownPath(exePath)
	lockDownPath(statePath)
	if err := installWindowsUI(exePath, dir); err != nil {
		return fmt.Errorf("install BPC Agent UI: %w", err)
	}
	if err := writeUIStatus(state); err != nil {
		return fmt.Errorf("write UI status: %w", err)
	}
	allowUsersReadPath(dir)
	allowUsersReadPath(exePath)
	allowUsersReadPath(filepath.Join(dir, "bpc-ui.ps1"))
	if statusPath, statusErr := uiStatusPath(); statusErr == nil {
		allowUsersReadPath(statusPath)
	}

	if err := installWindowsService(exePath); err != nil {
		return fmt.Errorf("install BPC Agent service: %w", err)
	}
	if err := startWindowsService(); err != nil {
		return fmt.Errorf("start BPC Agent service: %w", err)
	}
	_ = startWindowsUI()

	fmt.Printf("BPC Agent %s installed.\n", version)
	fmt.Printf("Device: %s\nDevice ID: %s\n", state.DeviceName, state.DeviceID)
	fmt.Printf("Control: %s\n", state.ControlURL)
	fmt.Printf("Installed path: %s\n", exePath)
	fmt.Println("The agent will start automatically with Windows.")
	return nil
}

func enrollOrLoadState(
	ctx context.Context,
	bootstrap agentctl.Bootstrap,
	statePath string,
) (*agentctl.State, error) {
	if state, err := agentctl.LoadState(statePath); err == nil {
		return state, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	var legacyProfile agentctl.WireGuardProfile
	if bootstrap.LegacyTunnel != "" {
		profile, err := captureLegacyWireGuardProfile(bootstrap.LegacyTunnel)
		if err != nil {
			return nil, fmt.Errorf("capture legacy WireGuard profile: %w", err)
		}
		legacyProfile = profile
	}

	publicKey, privateKey, err := agentctl.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate device identity: %w", err)
	}
	wireGuardPrivate, wireGuardPublic, err := agentctl.GenerateWireGuardKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate WireGuard identity: %w", err)
	}
	client, err := agentctl.NewClient(bootstrap.ControlURL, "")
	if err != nil {
		return nil, err
	}

	if bootstrap.Version == agentctl.LegacyBootstrapVersion {
		response, err := client.Enroll(ctx, agentctl.EnrollmentRequest{
			Token:              bootstrap.EnrollToken,
			Device:             bootstrap.Device,
			PublicKey:          publicKey,
			WireGuardPublicKey: wireGuardPublic,
			Version:            version,
		})
		if err != nil {
			return nil, err
		}
		if err := agentctl.ValidateRuntimeConfig(response.Config); err != nil {
			return nil, err
		}

		wireGuardProfile := response.WireGuard
		wireGuardProfile.PrivateKey = wireGuardPrivate
		if err := agentctl.ValidateWireGuardProfile(wireGuardProfile); err != nil {
			if legacyProfile.Complete() {
				wireGuardProfile = legacyProfile
			} else {
				return nil, fmt.Errorf("provisioned WireGuard profile: %w", err)
			}
		}

		state := &agentctl.State{
			Version:      agentctl.StateVersion,
			DeviceID:     response.DeviceID,
			DeviceName:   bootstrap.Device,
			DeviceToken:  response.DeviceToken,
			PublicKey:    publicKey,
			PrivateKey:   privateKey,
			ControlURL:   bootstrap.ControlURL,
			UpdatePubKey: bootstrap.UpdatePublicKey,
			Config:       response.Config,
			WireGuard:    wireGuardProfile,
		}
		if err := agentctl.SaveState(statePath, *state); err != nil {
			return nil, err
		}
		return state, nil
	}

	username, password, err := readLoginCredentials()
	if err != nil {
		return nil, err
	}
	login, err := client.Login(ctx, username, password)
	password = ""
	if err != nil {
		return nil, fmt.Errorf("user login: %w", err)
	}

	proof, err := agentctl.SignDeviceProof(
		privateKey,
		agentctl.RegistrationSigningBytes(
			login.AccessToken,
			publicKey,
			wireGuardPublic,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("sign device registration: %w", err)
	}
	response, err := client.RegisterDevice(
		ctx,
		login.AccessToken,
		agentctl.DeviceRegistrationRequest{
			Name:               bootstrap.Device,
			PublicKey:          publicKey,
			WireGuardPublicKey: wireGuardPublic,
			Version:            version,
			Proof:              proof,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}
	if err := agentctl.ValidateRuntimeConfig(response.Config); err != nil {
		return nil, err
	}

	wireGuardProfile := response.WireGuard
	wireGuardProfile.PrivateKey = wireGuardPrivate
	if err := agentctl.ValidateWireGuardProfile(wireGuardProfile); err != nil {
		if legacyProfile.Complete() {
			wireGuardProfile = legacyProfile
		} else {
			return nil, fmt.Errorf("provisioned WireGuard profile: %w", err)
		}
	}

	state := &agentctl.State{
		Version:          agentctl.StateVersion,
		DeviceID:         response.DeviceID,
		DeviceName:       bootstrap.Device,
		AccessToken:      response.AccessToken,
		AccessExpiresAt:  response.AccessExpiresAt,
		RefreshToken:     response.RefreshToken,
		RefreshExpiresAt: response.RefreshExpiresAt,
		PublicKey:        publicKey,
		PrivateKey:       privateKey,
		ControlURL:       bootstrap.ControlURL,
		UpdatePubKey:     bootstrap.UpdatePublicKey,
		Config:           response.Config,
		WireGuard:        wireGuardProfile,
	}
	if err := agentctl.SaveState(statePath, *state); err != nil {
		return nil, err
	}
	return state, nil
}

func runAgent() error {
	return runAgentContext(context.Background())
}

func runAgentContext(parent context.Context) error {
	_, _, statePath, err := installPaths()
	if err != nil {
		return err
	}
	state, err := agentctl.LoadState(statePath)
	if err != nil {
		return fmt.Errorf("load agent state: %w", err)
	}
	if err := agentctl.ValidateRuntimeConfig(state.Config); err != nil {
		return err
	}
	_ = writeUIStatus(state)
	_ = clearUIRuntimeStatus()
	_ = clearUITransportStatus()
	defer clearUIRuntimeStatus()
	defer clearUITransportStatus()

	logger, closer, err := newFileLogger()
	if err != nil {
		return err
	}
	defer closer.Close()
	logger.Printf(
		"starting BPC Agent version=%s device=%s id=%s control=%s",
		version,
		state.DeviceName,
		state.DeviceID,
		state.ControlURL,
	)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	control, err := agentctl.NewClient(state.ControlURL, state.ControlCredential())
	if err != nil {
		return err
	}
	if err := ensureControlCredential(ctx, control, state, statePath); err != nil {
		return fmt.Errorf("refresh access credential: %w", err)
	}
	if err := syncRuntimeState(ctx, control, state, statePath); err != nil {
		logger.Printf("initial config sync failed: %v", err)
	}

	var supervisor runtimeSupervisor
	if err := supervisor.apply(ctx, state.Config, state.WireGuard, logger); err != nil {
		logger.Printf("initial transport start failed: %v", err)
	}

	configTicker := time.NewTicker(30 * time.Second)
	heartbeatTicker := time.NewTicker(60 * time.Second)
	updateTicker := time.NewTicker(6 * time.Hour)
	updateDelay := time.NewTimer(45 * time.Second)
	defer configTicker.Stop()
	defer heartbeatTicker.Stop()
	defer updateTicker.Stop()
	defer updateDelay.Stop()

	for {
		select {
		case <-configTicker.C:
			if err := syncRuntimeState(ctx, control, state, statePath); err != nil {
				logger.Printf("config sync failed: %v", err)
			} else if err := supervisor.apply(ctx, state.Config, state.WireGuard, logger); err != nil {
				logger.Printf("apply synced config failed: %v", err)
			}
		case <-heartbeatTicker.C:
			status := "control-online-data-plane-pending"
			transport := "wgshim"
			if state.WireGuard.Complete() {
				status = "connected-embedded-wireguard"
			} else if state.Config.LegacyTunnel != "" {
				status = "connected-legacy-wireguard"
			}
			if err := ensureControlCredential(ctx, control, state, statePath); err != nil {
				logger.Printf("credential refresh failed: %v", err)
			} else if err := control.Heartbeat(ctx, agentctl.HeartbeatRequest{
				Version:   version,
				Transport: transport,
				Status:    status,
			}); err != nil {
				logger.Printf("heartbeat failed: %v", err)
			}
		case <-updateDelay.C:
			if err := ensureControlCredential(ctx, control, state, statePath); err != nil {
				logger.Printf("credential refresh failed: %v", err)
				continue
			}
			if err := ensureControlCredential(ctx, control, state, statePath); err != nil {
				logger.Printf("credential refresh failed: %v", err)
				continue
			}
			updated, err := checkAndStageUpdate(ctx, control, state, logger, false)
			if err != nil {
				logger.Printf("update check failed: %v", err)
			}
			if updated {
				supervisor.stop()
				return nil
			}
		case <-updateTicker.C:
			updated, err := checkAndStageUpdate(ctx, control, state, logger, false)
			if err != nil {
				logger.Printf("update check failed: %v", err)
			}
			if updated {
				supervisor.stop()
				return nil
			}
		case <-ctx.Done():
			supervisor.stop()
			return nil
		}
	}
}

func ensureControlCredential(
	ctx context.Context,
	control *agentctl.Client,
	state *agentctl.State,
	statePath string,
) error {
	if strings.TrimSpace(state.RefreshToken) == "" {
		control.Token = state.ControlCredential()
		return nil
	}
	if !state.NeedsRefresh(time.Now()) {
		control.Token = state.AccessToken
		return nil
	}

	proof, err := agentctl.SignDeviceProof(
		state.PrivateKey,
		agentctl.RefreshSigningBytes(state.RefreshToken),
	)
	if err != nil {
		return err
	}
	response, err := control.Refresh(ctx, state.RefreshToken, proof)
	if err != nil {
		return err
	}
	if response.DeviceID != "" && response.DeviceID != state.DeviceID {
		return errors.New("controller returned refresh credentials for another device")
	}
	state.Version = agentctl.StateVersion
	state.AccessToken = response.AccessToken
	state.AccessExpiresAt = response.AccessExpiresAt
	state.RefreshToken = response.RefreshToken
	state.RefreshExpiresAt = response.RefreshExpiresAt
	state.DeviceToken = ""
	control.Token = response.AccessToken
	return agentctl.SaveState(statePath, *state)
}

func syncRuntimeState(
	ctx context.Context,
	control *agentctl.Client,
	state *agentctl.State,
	statePath string,
) error {
	if err := ensureControlCredential(ctx, control, state, statePath); err != nil {
		return err
	}
	cfg, err := control.FetchConfig(ctx)
	if err != nil {
		return err
	}
	if err := agentctl.ValidateRuntimeConfig(*cfg); err != nil {
		return err
	}
	if cfg.WireGuard != nil {
		profile := *cfg.WireGuard
		profile.PrivateKey = state.WireGuard.PrivateKey
		if strings.TrimSpace(profile.PresharedKey) == "" {
			profile.PresharedKey = state.WireGuard.PresharedKey
		}
		if err := agentctl.ValidateWireGuardProfile(profile); err != nil {
			return fmt.Errorf("synced WireGuard profile: %w", err)
		}
		state.WireGuard = profile
		cfg.WireGuard = nil
	}
	state.Config = *cfg
	if err := agentctl.SaveState(statePath, *state); err != nil {
		return err
	}
	return writeUIStatus(state)
}

func (s *runtimeSupervisor) apply(
	parent context.Context,
	cfg agentctl.RuntimeConfig,
	profile agentctl.WireGuardProfile,
	logger *log.Logger,
) error {
	raw, err := json.Marshal(struct {
		Config  agentctl.RuntimeConfig
		Profile agentctl.WireGuardProfile
	}{cfg, profile})
	if err != nil {
		return err
	}
	fingerprint := string(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	if fingerprint == s.fingerprint && s.cancel != nil {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}

	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.fingerprint = fingerprint

	go runWGShimLoop(ctx, cfg, logger)
	if profile.Complete() {
		go func() {
			telemetry := func(stats tunnelTelemetry) {
				if err := writeUIRuntimeStatus(stats); err != nil && ctx.Err() == nil {
					logger.Printf("write UI tunnel telemetry: %v", err)
				}
			}
			if err := runEmbeddedWireGuard(ctx, cfg, profile, logger, telemetry); err != nil && ctx.Err() == nil {
				logger.Printf("embedded WireGuard stopped: %v", err)
			}
		}()
	} else if cfg.LegacyTunnel != "" {
		go runLegacyWireGuardLoop(ctx, cfg, logger)
	} else {
		logger.Printf("no provisioned WireGuard profile; control plane remains online")
	}
	return nil
}

func (s *runtimeSupervisor) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
}

func runWGShimLoop(ctx context.Context, cfg agentctl.RuntimeConfig, logger *log.Logger) {
	for ctx.Err() == nil {
		psk, err := base64.StdEncoding.DecodeString(cfg.WGShimPSK)
		if err != nil || len(psk) != 32 {
			logger.Printf("invalid runtime WGShim key")
			return
		}
		txKey, err := wgshim.DeriveKey(psk, wgshim.ClientToServer)
		if err != nil {
			logger.Printf("derive TX key: %v", err)
			return
		}
		rxKey, err := wgshim.DeriveKey(psk, wgshim.ServerToClient)
		if err != nil {
			logger.Printf("derive RX key: %v", err)
			return
		}
		tx, err := wgshim.NewCodec(txKey, cfg.PaddingMin, cfg.PaddingMax)
		if err != nil {
			logger.Printf("create TX codec: %v", err)
			return
		}
		rx, err := wgshim.NewCodec(rxKey, cfg.PaddingMin, cfg.PaddingMax)
		if err != nil {
			logger.Printf("create RX codec: %v", err)
			return
		}
		servers := append([]string(nil), cfg.WGShimServers...)
		if len(servers) == 0 {
			servers = []string{cfg.WGShimServer}
		}
		if len(servers) > 1 {
			err = wgshim.RunAdaptiveClient(ctx, wgshim.AdaptiveClientConfig{
				LocalListen:     cfg.WGShimListen,
				Servers:         servers,
				TX:              tx,
				RX:              rx,
				Logger:          logger,
				StatsInterval:   defaultLogEvery,
				ProbeTimeout:    900 * time.Millisecond,
				SwitchThreshold: 10 * time.Millisecond,
				OnEndpointReport: func(report wgshim.EndpointReport) {
					rttMS := int64(0)
					if report.RTT > 0 {
						rttMS = report.RTT.Milliseconds()
						if rttMS == 0 {
							rttMS = 1
						}
					}
					if writeErr := writeUITransportStatus(transportTelemetry{
						UpdatedAt: time.Now().Unix(),
						Endpoint:  report.Selected,
						RTTMS:     rttMS,
						Reachable: report.Reachable,
						Total:     report.Total,
					}); writeErr != nil && ctx.Err() == nil {
						logger.Printf("write UI transport telemetry: %v", writeErr)
					}
				},
			})
		} else {
			_ = writeUITransportStatus(transportTelemetry{
				UpdatedAt: time.Now().Unix(),
				Endpoint:  cfg.WGShimServer,
				Reachable: 1,
				Total:     1,
			})
			err = wgshim.RunClient(ctx, wgshim.ClientConfig{
				LocalListen:   cfg.WGShimListen,
				Server:        cfg.WGShimServer,
				TX:            tx,
				RX:            rx,
				Logger:        logger,
				StatsInterval: defaultLogEvery,
			})
		}
		if ctx.Err() != nil {
			return
		}
		logger.Printf("WGShim stopped: %v; retrying in 1s", err)
		time.Sleep(time.Second)
	}
}

func runLegacyWireGuardLoop(ctx context.Context, cfg agentctl.RuntimeConfig, logger *log.Logger) {
	for ctx.Err() == nil {
		wgPath, err := findWireGuardTool()
		if err != nil {
			logger.Printf("legacy WireGuard backend unavailable: %v", err)
		} else if err := ensureTunnelEndpoint(wgPath, cfg, logger); err != nil {
			logger.Printf("legacy tunnel reconciliation failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func ensureTunnelEndpoint(wgPath string, cfg agentctl.RuntimeConfig, logger *log.Logger) error {
	tunnel := cfg.LegacyTunnel
	if tunnel == "" {
		return nil
	}
	if _, err := runCommand("sc.exe", "query", "WireGuardTunnel$"+tunnel); err != nil {
		return fmt.Errorf("WireGuard tunnel service %q is not installed", tunnel)
	}
	_, _ = runCommand("sc.exe", "start", "WireGuardTunnel$"+tunnel)

	out, err := runCommand(wgPath, "show", tunnel, "endpoints")
	if err != nil {
		return fmt.Errorf("read WireGuard endpoints: %w: %s", err, strings.TrimSpace(out))
	}
	entries := parseEndpoints(out)
	if len(entries) == 0 {
		return errors.New("WireGuard tunnel has no peers")
	}
	for _, entry := range entries {
		if equalEndpoint(entry.Endpoint, cfg.WGShimListen) {
			return nil
		}
	}

	peer := ""
	for _, entry := range entries {
		if equalEndpoint(entry.Endpoint, cfg.WGShimTarget) {
			peer = entry.Peer
			break
		}
	}
	if peer == "" && len(entries) == 1 {
		peer = entries[0].Peer
	}
	if peer == "" {
		return fmt.Errorf("cannot choose WireGuard peer: expected target %s and found %d peers", cfg.WGShimTarget, len(entries))
	}

	out, err = runCommand(wgPath, "set", tunnel, "peer", peer, "endpoint", cfg.WGShimListen)
	if err != nil {
		return fmt.Errorf("set WireGuard endpoint: %w: %s", err, strings.TrimSpace(out))
	}
	logger.Printf("legacy WireGuard peer endpoint switched to %s", cfg.WGShimListen)
	return nil
}

func checkAndStageUpdate(
	ctx context.Context,
	control *agentctl.Client,
	state *agentctl.State,
	logger *log.Logger,
	installUI bool,
) (bool, error) {
	manifest, err := control.FetchUpdateManifest(ctx)
	if err != nil {
		return false, err
	}
	if err := agentctl.VerifyUpdateManifest(*manifest, state.UpdatePubKey); err != nil {
		return false, err
	}
	if !agentctl.IsNewerVersion(manifest.Version, version) {
		return false, nil
	}

	dir, exePath, _, err := installPaths()
	if err != nil {
		return false, err
	}
	nextPath := filepath.Join(dir, "bpc-agent.next.exe")
	if err := control.Download(ctx, manifest.URL, nextPath); err != nil {
		return false, err
	}
	if err := agentctl.VerifyFileSHA256(nextPath, manifest.SHA256); err != nil {
		_ = os.Remove(nextPath)
		return false, err
	}
	lockDownPath(nextPath)
	logger.Printf("verified BPC Agent update %s; scheduling replacement", manifest.Version)
	if err := scheduleReplacement(exePath, nextPath, installUI); err != nil {
		return false, err
	}
	return true, nil
}

func scheduleReplacement(exePath, nextPath string, installUI bool) error {
	uiStep := ""
	if installUI {
		uiStep = fmt.Sprintf("& '%s' install-ui; ", psQuote(exePath))
	}
	script := fmt.Sprintf(
		"Start-Sleep -Seconds 3; Move-Item -LiteralPath '%s' -Destination '%s' -Force; %ssc.exe start '%s' | Out-Null",
		psQuote(nextPath),
		psQuote(exePath),
		uiStep,
		psQuote(serviceName),
	)
	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-WindowStyle",
		"Hidden",
		"-Command",
		script,
	)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start update helper: %w", err)
	}
	return nil
}

func updateNow() error {
	if !isAdministrator() {
		return elevate("update")
	}
	_, _, statePath, err := installPaths()
	if err != nil {
		return err
	}
	state, err := agentctl.LoadState(statePath)
	if err != nil {
		return err
	}
	control, err := agentctl.NewClient(state.ControlURL, state.ControlCredential())
	if err != nil {
		return err
	}
	if err := ensureControlCredential(context.Background(), control, state, statePath); err != nil {
		return fmt.Errorf("refresh access credential: %w", err)
	}
	logger := log.New(os.Stderr, "bpc-agent ", log.LstdFlags)
	updated, err := checkAndStageUpdate(context.Background(), control, state, logger, true)
	if err != nil {
		return err
	}
	if !updated {
		fmt.Println("BPC Agent is already up to date.")
		return nil
	}
	fmt.Println("Update verified and staged. BPC Agent will restart with the new version.")
	return nil
}

func uninstallAgent() error {
	if !isAdministrator() {
		return elevate("uninstall")
	}
	_, _ = runCommand("schtasks.exe", "/End", "/TN", legacyTaskName)
	_, _ = runCommand("schtasks.exe", "/Delete", "/TN", legacyTaskName, "/F")
	if err := stopWindowsService(); err != nil {
		return err
	}
	if err := removeWindowsService(); err != nil {
		return err
	}
	fmt.Println("BPC Agent Windows service removed.")
	fmt.Println("Device revocation remains server-side; use bpc-agent revoke NAME on the VPS.")
	return nil
}

func connectAgent() error {
	if !isAdministrator() {
		return elevate("connect")
	}
	if err := setWindowsServiceAutomatic(true); err != nil {
		return err
	}
	return startWindowsService()
}

func disconnectAgent() error {
	if !isAdministrator() {
		return elevate("disconnect")
	}
	if err := stopWindowsService(); err != nil {
		return err
	}
	return setWindowsServiceAutomatic(false)
}

type uiStatus struct {
	Version       string   `json:"version"`
	Device        string   `json:"device"`
	DeviceID      string   `json:"device_id"`
	Service       string   `json:"service"`
	Control       string   `json:"control"`
	Relay         string   `json:"relay"`
	RelayPool     []string `json:"relay_pool,omitempty"`
	TunnelAddress string   `json:"tunnel_address"`
	Routes        []string `json:"routes"`
	UpdatedAt     int64    `json:"updated_at,omitempty"`
	HandshakeAt   int64    `json:"handshake_at,omitempty"`
	RXBytes       uint64   `json:"rx_bytes,omitempty"`
	TXBytes       uint64   `json:"tx_bytes,omitempty"`
}

func uiStatusPath() (string, error) {
	dir, _, _, err := installPaths()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ui-status.json"), nil
}

func uiRuntimeStatusPath() (string, error) {
	dir, _, _, err := installPaths()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ui-runtime.json"), nil
}

func writeUIRuntimeStatus(stats tunnelTelemetry) error {
	path, err := uiRuntimeStatusPath()
	if err != nil {
		return err
	}
	_, statErr := os.Stat(path)
	encoded, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return err
	}
	if errors.Is(statErr, os.ErrNotExist) {
		allowUsersReadPath(path)
	}
	return nil
}

func clearUIRuntimeStatus() error {
	path, err := uiRuntimeStatusPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func uiTransportStatusPath() (string, error) {
	dir, _, _, err := installPaths()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ui-transport.json"), nil
}

func writeUITransportStatus(stats transportTelemetry) error {
	path, err := uiTransportStatusPath()
	if err != nil {
		return err
	}
	_, statErr := os.Stat(path)
	encoded, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return err
	}
	if errors.Is(statErr, os.ErrNotExist) {
		allowUsersReadPath(path)
	}
	return nil
}

func clearUITransportStatus() error {
	path, err := uiTransportStatusPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func writeUIStatus(state *agentctl.State) error {
	path, err := uiStatusPath()
	if err != nil {
		return err
	}
	payload := uiStatus{
		Version:       version,
		Device:        state.DeviceName,
		DeviceID:      state.DeviceID,
		Control:       state.ControlURL,
		Relay:         state.Config.WGShimServer,
		RelayPool:     append([]string(nil), state.Config.WGShimServers...),
		TunnelAddress: state.WireGuard.Address,
		Routes:        append([]string(nil), state.WireGuard.AllowedIPs...),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return err
	}
	allowUsersReadPath(path)
	return nil
}

func printStatusJSON() error {
	path, err := uiStatusPath()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var payload uiStatus
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	payload.Service = windowsServiceStatus()
	if runtimePath, runtimeErr := uiRuntimeStatusPath(); runtimeErr == nil {
		if runtimeRaw, readErr := os.ReadFile(runtimePath); readErr == nil {
			var runtimeStatus tunnelTelemetry
			if json.Unmarshal(runtimeRaw, &runtimeStatus) == nil {
				payload.UpdatedAt = runtimeStatus.UpdatedAt
				payload.HandshakeAt = runtimeStatus.HandshakeAt
				payload.RXBytes = runtimeStatus.RXBytes
				payload.TXBytes = runtimeStatus.TXBytes
			}
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func printStatus() error {
	_, _, statePath, err := installPaths()
	if err != nil {
		return err
	}
	state, err := agentctl.LoadState(statePath)
	if err != nil {
		return err
	}

	fmt.Printf("BPC Agent: %s\n", version)
	fmt.Printf("Device: %s\n", state.DeviceName)
	fmt.Printf("Device ID: %s\n", state.DeviceID)
	fmt.Printf("Control: %s\n", state.ControlURL)
	fmt.Printf("Windows service: %s\n", windowsServiceStatus())
	fmt.Printf("WGShim server: %s\n", state.Config.WGShimServer)
	fmt.Printf("WGShim target: %s\n", state.Config.WGShimTarget)
	if state.WireGuard.Complete() {
		fmt.Printf(
			"Tunnel backend: embedded WireGuard (%s; MTU %d)\n",
			state.WireGuard.Address,
			state.WireGuard.MTU,
		)
		fmt.Printf("Tunnel routes: %s\n", strings.Join(state.WireGuard.AllowedIPs, ","))
	} else if state.Config.LegacyTunnel != "" {
		fmt.Printf("Tunnel backend: legacy WireGuard (%s)\n", state.Config.LegacyTunnel)
	} else {
		fmt.Println("Tunnel backend: not provisioned")
	}
	return nil
}

type endpointEntry struct {
	Peer     string
	Endpoint string
}

func parseEndpoints(output string) []endpointEntry {
	var entries []endpointEntry
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		entries = append(entries, endpointEntry{Peer: fields[0], Endpoint: fields[1]})
	}
	return entries
}

func equalEndpoint(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func findWireGuardTool() (string, error) {
	if path, err := exec.LookPath("wg.exe"); err == nil {
		return path, nil
	}
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "WireGuard", "wg.exe"),
		"C:\\Program Files\\WireGuard\\wg.exe",
	}
	for _, path := range candidates {
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}
	return "", errors.New("WireGuard for Windows is not installed or wg.exe was not found")
}

func loadBootstrap() (*agentctl.Bootstrap, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable: %w", err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return nil, fmt.Errorf("read executable bootstrap: %w", err)
	}
	return parseBootstrapBytes(data)
}

func parseBootstrapBytes(data []byte) (*agentctl.Bootstrap, error) {
	marker := bootstrapStart
	start := bytes.LastIndex(data, []byte(marker))
	legacyStart := bytes.LastIndex(data, []byte(legacyBootstrapStart))
	if legacyStart > start {
		start = legacyStart
		marker = legacyBootstrapStart
	}
	if start < 0 {
		return nil, errors.New("this is a generic BPC Agent binary; create a prepared client with bpc-agent create on the VPS")
	}
	start += len(marker)
	endRel := bytes.Index(data[start:], []byte(bootstrapEnd))
	if endRel < 0 {
		return nil, errors.New("embedded bootstrap footer is missing")
	}
	encoded := strings.TrimSpace(string(data[start : start+endRel]))
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode embedded bootstrap: %w", err)
	}
	var cfg agentctl.Bootstrap
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse embedded bootstrap: %w", err)
	}
	return &cfg, nil
}

func installPaths() (string, string, string, error) {
	base := os.Getenv("ProgramData")
	if strings.TrimSpace(base) == "" {
		base = "C:\\ProgramData"
	}
	dir := filepath.Join(base, "BPC")
	return dir, filepath.Join(dir, "bpc-agent.exe"), filepath.Join(dir, "state.json"), nil
}

func newFileLogger() (*log.Logger, io.Closer, error) {
	dir, _, _, err := installPaths()
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open agent log: %w", err)
	}
	return log.New(file, "bpc-agent ", log.LstdFlags|log.LUTC), file, nil
}

func isAdministrator() bool {
	command := "$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }"
	return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command).Run() == nil
}

func elevate(command string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ps := fmt.Sprintf(
		"$p=Start-Process -FilePath '%s' -ArgumentList '%s' -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
		psQuote(exe),
		psQuote(command),
	)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", ps)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("administrator elevation failed: %w", err)
	}
	return nil
}

func psQuote(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	_ = os.Remove(dst)
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func lockDownPath(path string) {
	_, _ = runCommand(
		"icacls.exe",
		path,
		"/inheritance:r",
		"/grant:r",
		"*S-1-5-18:F",
		"*S-1-5-32-544:F",
	)
}

func allowUsersReadPath(path string) {
	_, _ = runCommand(
		"icacls.exe",
		path,
		"/grant",
		"*S-1-5-32-545:RX",
	)
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func usage() {
	fmt.Println("BPC Agent for Windows\n\n" +
		"Usage:\n" +
		"  bpc-agent.exe                 Enroll and install a prepared agent package\n" +
		"  bpc-agent.exe install         Enroll/reinstall and start at boot\n" +
		"  bpc-agent.exe run             Run the foreground agent loop (diagnostics)\n" +
		"  bpc-agent.exe status          Show local agent state\n" +
		"  bpc-agent.exe connect         Enable the tunnel service\n" +
		"  bpc-agent.exe disconnect      Disable the tunnel service\n" +
		"  bpc-agent.exe ui              Open the tray UI\n" +
		"  bpc-agent.exe install-ui      Install tray UI autostart\n" +
		"  bpc-agent.exe update          Check, verify and stage a signed update\n" +
		"  bpc-agent.exe uninstall       Remove the agent and tray UI\n" +
		"  bpc-agent.exe version\n\n" +
		"Prepared binaries are generated on the BPC VPS with:\n" +
		"  bpc-agent create NAME")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "BPC Agent: "+format+"\n", args...)
	os.Exit(1)
}
