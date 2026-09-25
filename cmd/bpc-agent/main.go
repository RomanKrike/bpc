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
	version         = "0.10.0"
	bootstrapStart  = "\nBPC_AGENT_BOOTSTRAP_V2\n"
	bootstrapEnd    = "\nBPC_AGENT_BOOTSTRAP_END\n"
	defaultLogEvery = 30 * time.Second
)

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

	if err := installWindowsService(exePath); err != nil {
		return fmt.Errorf("install BPC Agent service: %w", err)
	}
	if err := startWindowsService(); err != nil {
		return fmt.Errorf("start BPC Agent service: %w", err)
	}

	fmt.Printf("BPC Agent %s installed.\n", version)
	fmt.Printf("Device: %s\nDevice ID: %s\n", state.DeviceName, state.DeviceID)
	fmt.Printf("Control: %s\n", state.ControlURL)
	fmt.Printf("Installed path: %s\n", exePath)
	fmt.Println("The agent will start automatically with Windows.")
	return nil
}

func enrollOrLoadState(ctx context.Context, bootstrap agentctl.Bootstrap, statePath string) (*agentctl.State, error) {
	if state, err := agentctl.LoadState(statePath); err == nil {
		return state, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	publicKey, privateKey, err := agentctl.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate device identity: %w", err)
	}
	client, err := agentctl.NewClient(bootstrap.ControlURL, "")
	if err != nil {
		return nil, err
	}
	response, err := client.Enroll(ctx, agentctl.EnrollmentRequest{
		Token:     bootstrap.EnrollToken,
		Device:    bootstrap.Device,
		PublicKey: publicKey,
		Version:   version,
	})
	if err != nil {
		return nil, err
	}
	if err := agentctl.ValidateRuntimeConfig(response.Config); err != nil {
		return nil, err
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

	var supervisor runtimeSupervisor
	if err := supervisor.apply(ctx, state.Config, logger); err != nil {
		logger.Printf("initial transport start failed: %v", err)
	}

	control, err := agentctl.NewClient(state.ControlURL, state.DeviceToken)
	if err != nil {
		return err
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
			if cfg, err := control.FetchConfig(ctx); err != nil {
				logger.Printf("config sync failed: %v", err)
			} else if err := agentctl.ValidateRuntimeConfig(*cfg); err != nil {
				logger.Printf("config sync rejected: %v", err)
			} else {
				state.Config = *cfg
				if err := agentctl.SaveState(statePath, *state); err != nil {
					logger.Printf("save synced config failed: %v", err)
				}
				if err := supervisor.apply(ctx, *cfg, logger); err != nil {
					logger.Printf("apply synced config failed: %v", err)
				}
			}
		case <-heartbeatTicker.C:
			status := "control-online"
			transport := "wgshim"
			if state.Config.LegacyTunnel == "" {
				status = "control-online-data-plane-pending"
			}
			if err := control.Heartbeat(ctx, agentctl.HeartbeatRequest{
				Version:   version,
				Transport: transport,
				Status:    status,
			}); err != nil {
				logger.Printf("heartbeat failed: %v", err)
			}
		case <-updateDelay.C:
			updated, err := checkAndStageUpdate(ctx, control, state, logger)
			if err != nil {
				logger.Printf("update check failed: %v", err)
			}
			if updated {
				supervisor.stop()
				return nil
			}
		case <-updateTicker.C:
			updated, err := checkAndStageUpdate(ctx, control, state, logger)
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

func (s *runtimeSupervisor) apply(parent context.Context, cfg agentctl.RuntimeConfig, logger *log.Logger) error {
	raw, err := json.Marshal(cfg)
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
	if cfg.LegacyTunnel != "" {
		go runLegacyWireGuardLoop(ctx, cfg, logger)
	} else {
		logger.Printf("self-contained tunnel backend is not enabled yet; control plane and updater are active")
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
		err = wgshim.RunClient(ctx, wgshim.ClientConfig{
			LocalListen:   cfg.WGShimListen,
			Server:        cfg.WGShimServer,
			TX:            tx,
			RX:            rx,
			Logger:        logger,
			StatsInterval: defaultLogEvery,
		})
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
	if err := scheduleReplacement(exePath, nextPath); err != nil {
		return false, err
	}
	return true, nil
}

func scheduleReplacement(exePath, nextPath string) error {
	script := fmt.Sprintf(
		"Start-Sleep -Seconds 3; Move-Item -LiteralPath '%s' -Destination '%s' -Force; sc.exe start '%s' | Out-Null",
		psQuote(nextPath),
		psQuote(exePath),
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
	control, err := agentctl.NewClient(state.ControlURL, state.DeviceToken)
	if err != nil {
		return err
	}
	logger := log.New(os.Stderr, "bpc-agent ", log.LstdFlags)
	updated, err := checkAndStageUpdate(context.Background(), control, state, logger)
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
	if state.Config.LegacyTunnel == "" {
		fmt.Println("Tunnel backend: embedded backend pending")
	} else {
		fmt.Printf("Tunnel backend: legacy WireGuard (%s)\n", state.Config.LegacyTunnel)
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
	start := bytes.LastIndex(data, []byte(bootstrapStart))
	if start < 0 {
		return nil, errors.New("this is a generic BPC Agent binary; create a prepared client with bpc-agent create on the VPS")
	}
	start += len(bootstrapStart)
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
		"  bpc-agent.exe update          Check, verify and stage a signed update\n" +
		"  bpc-agent.exe uninstall       Remove the startup task\n" +
		"  bpc-agent.exe version\n\n" +
		"Prepared binaries are generated on the BPC VPS with:\n" +
		"  bpc-agent create NAME")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "BPC Agent: "+format+"\n", args...)
	os.Exit(1)
}
