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
	"strconv"
	"strings"
	"time"

	"github.com/RomanKrike/bpc/internal/wgshim"
)

const (
	version         = "0.9.0"
	taskName        = "BPC Agent"
	bootstrapStart  = "\nBPC_AGENT_BOOTSTRAP_V1\n"
	bootstrapEnd    = "\nBPC_AGENT_BOOTSTRAP_END\n"
	defaultLogEvery = 30 * time.Second
)

type bootstrap struct {
	Version    int    `json:"version"`
	Device     string `json:"device"`
	Tunnel     string `json:"tunnel"`
	Server     string `json:"server"`
	Listen     string `json:"listen"`
	Target     string `json:"target"`
	PaddingMin int    `json:"padding_min"`
	PaddingMax int    `json:"padding_max"`
	PSK        string `json:"psk"`
}

type endpointEntry struct {
	Peer     string
	Endpoint string
}

func main() {
	cmd := "install"
	args := os.Args[1:]
	if len(args) > 0 {
		cmd = strings.ToLower(args[0])
		args = args[1:]
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
	case "status":
		err = printStatus()
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
	cfg, err := loadBootstrap()
	if err != nil {
		return err
	}
	if err := validateBootstrap(cfg); err != nil {
		return err
	}

	if !isAdministrator() {
		return elevate("install")
	}

	dir, exePath, err := installPaths()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create install directory: %w", err)
	}

	current, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	current, _ = filepath.Abs(current)
	exePath, _ = filepath.Abs(exePath)

	_, _ = runCommand("schtasks.exe", "/End", "/TN", taskName)
	if !samePath(current, exePath) {
		if err := copyFile(current, exePath); err != nil {
			return fmt.Errorf("install agent binary: %w", err)
		}
	}
	lockDownPath(dir)
	lockDownPath(exePath)

	action := fmt.Sprintf("\"%s\" run", exePath)
	if out, err := runCommand(
		"schtasks.exe", "/Create",
		"/TN", taskName,
		"/TR", action,
		"/SC", "ONSTART",
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
		"/F",
	); err != nil {
		return fmt.Errorf("create startup task: %w: %s", err, strings.TrimSpace(out))
	}
	if out, err := runCommand("schtasks.exe", "/Run", "/TN", taskName); err != nil {
		return fmt.Errorf("start agent task: %w: %s", err, strings.TrimSpace(out))
	}

	fmt.Printf("BPC Agent %s installed.\n", version)
	fmt.Printf("Device: %s\nTunnel: %s\nServer: %s\n", cfg.Device, cfg.Tunnel, cfg.Server)
	fmt.Printf("Installed path: %s\n", exePath)
	fmt.Println("The agent will start automatically with Windows.")
	return nil
}

func uninstallAgent() error {
	cfg, _ := loadBootstrap()
	if !isAdministrator() {
		return elevate("uninstall")
	}
	_, _ = runCommand("schtasks.exe", "/End", "/TN", taskName)
	_, _ = runCommand("schtasks.exe", "/Delete", "/TN", taskName, "/F")
	if cfg != nil {
		if wgPath, err := findWireGuardTool(); err == nil {
			_ = restoreEndpoint(wgPath, cfg)
		}
	}
	fmt.Println("BPC Agent startup task removed.")
	fmt.Println("The installed binary is left in ProgramData so this command can finish safely.")
	return nil
}

func runAgent() error {
	cfg, err := loadBootstrap()
	if err != nil {
		return err
	}
	if err := validateBootstrap(cfg); err != nil {
		return err
	}

	logger, closer, err := newFileLogger()
	if err != nil {
		return err
	}
	defer closer.Close()
	logger.Printf("starting BPC Agent version=%s device=%s tunnel=%s server=%s", version, cfg.Device, cfg.Tunnel, cfg.Server)

	wgPath, err := waitForWireGuard(logger, 5*time.Minute)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runWGShimLoop(ctx, cfg, logger)

	// Give the local UDP listener a short head start before repointing WireGuard.
	time.Sleep(300 * time.Millisecond)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		if err := ensureTunnelEndpoint(wgPath, cfg, logger); err != nil {
			logger.Printf("tunnel reconciliation failed: %v", err)
		}
		<-ticker.C
	}
}

func runWGShimLoop(ctx context.Context, cfg *bootstrap, logger *log.Logger) {
	for ctx.Err() == nil {
		psk, err := base64.StdEncoding.DecodeString(cfg.PSK)
		if err != nil || len(psk) != 32 {
			logger.Printf("invalid embedded WGShim key")
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
			LocalListen:   cfg.Listen,
			Server:        cfg.Server,
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

func ensureTunnelEndpoint(wgPath string, cfg *bootstrap, logger *log.Logger) error {
	if _, err := runCommand("sc.exe", "query", "WireGuardTunnel$"+cfg.Tunnel); err != nil {
		return fmt.Errorf("WireGuard tunnel service %q is not installed", cfg.Tunnel)
	}
	_, _ = runCommand("sc.exe", "start", "WireGuardTunnel$"+cfg.Tunnel)

	out, err := runCommand(wgPath, "show", cfg.Tunnel, "endpoints")
	if err != nil {
		return fmt.Errorf("read WireGuard endpoints: %w: %s", err, strings.TrimSpace(out))
	}
	entries := parseEndpoints(out)
	if len(entries) == 0 {
		return errors.New("WireGuard tunnel has no peers")
	}

	local := cfg.Listen
	for _, entry := range entries {
		if equalEndpoint(entry.Endpoint, local) {
			return nil
		}
	}

	peer := ""
	for _, entry := range entries {
		if equalEndpoint(entry.Endpoint, cfg.Target) {
			peer = entry.Peer
			break
		}
	}
	if peer == "" && len(entries) == 1 {
		peer = entries[0].Peer
	}
	if peer == "" {
		return fmt.Errorf("cannot choose WireGuard peer: expected target %s and found %d peers", cfg.Target, len(entries))
	}

	out, err = runCommand(wgPath, "set", cfg.Tunnel, "peer", peer, "endpoint", local)
	if err != nil {
		return fmt.Errorf("set WireGuard endpoint: %w: %s", err, strings.TrimSpace(out))
	}
	logger.Printf("WireGuard peer endpoint switched to %s (target behind WGShim: %s)", local, cfg.Target)
	return nil
}

func restoreEndpoint(wgPath string, cfg *bootstrap) error {
	out, err := runCommand(wgPath, "show", cfg.Tunnel, "endpoints")
	if err != nil {
		return err
	}
	entries := parseEndpoints(out)
	for _, entry := range entries {
		if equalEndpoint(entry.Endpoint, cfg.Listen) {
			_, err = runCommand(wgPath, "set", cfg.Tunnel, "peer", entry.Peer, "endpoint", cfg.Target)
			return err
		}
	}
	return nil
}

func printStatus() error {
	cfg, err := loadBootstrap()
	if err != nil {
		return err
	}
	fmt.Printf("BPC Agent: %s\n", version)
	fmt.Printf("Device: %s\nTunnel: %s\nServer: %s\nTarget: %s\n", cfg.Device, cfg.Tunnel, cfg.Server, cfg.Target)

	wgPath, err := findWireGuardTool()
	if err != nil {
		fmt.Println("WireGuard: not found")
		return nil
	}
	out, err := runCommand(wgPath, "show", cfg.Tunnel, "endpoints")
	if err != nil {
		fmt.Printf("WireGuard tunnel: unavailable (%v)\n", err)
		return nil
	}
	entries := parseEndpoints(out)
	for _, entry := range entries {
		fmt.Printf("Peer endpoint: %s\n", entry.Endpoint)
	}

	handshake, err := runCommand(wgPath, "show", cfg.Tunnel, "latest-handshakes")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(handshake), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			unixTime, parseErr := strconv.ParseInt(fields[1], 10, 64)
			if parseErr != nil || unixTime <= 0 {
				continue
			}
			fmt.Printf("Latest handshake: %s ago\n", time.Since(time.Unix(unixTime, 0)).Round(time.Second))
			break
		}
	}
	return nil
}

func waitForWireGuard(logger *log.Logger, max time.Duration) (string, error) {
	deadline := time.Now().Add(max)
	for {
		path, err := findWireGuardTool()
		if err == nil {
			return path, nil
		}
		if time.Now().After(deadline) {
			return "", err
		}
		logger.Printf("WireGuard for Windows not found yet; retrying")
		time.Sleep(5 * time.Second)
	}
}

func findWireGuardTool() (string, error) {
	if path, err := exec.LookPath("wg.exe"); err == nil {
		return path, nil
	}
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "WireGuard", "wg.exe"),
		`C:\Program Files\WireGuard\wg.exe`,
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

func loadBootstrap() (*bootstrap, error) {
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

func parseBootstrapBytes(data []byte) (*bootstrap, error) {
	start := bytes.LastIndex(data, []byte(bootstrapStart))
	if start < 0 {
		return nil, errors.New("this is a generic BPC Agent binary; create a prepared client with `bpc-agent create` on the VPS")
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
	var cfg bootstrap
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse embedded bootstrap: %w", err)
	}
	return &cfg, nil
}

func validateBootstrap(cfg *bootstrap) error {
	if cfg.Version != 1 {
		return fmt.Errorf("unsupported bootstrap version %d", cfg.Version)
	}
	for field, value := range map[string]string{
		"device": cfg.Device,
		"tunnel": cfg.Tunnel,
		"server": cfg.Server,
		"listen": cfg.Listen,
		"target": cfg.Target,
		"psk":    cfg.PSK,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("bootstrap field %s is empty", field)
		}
	}
	key, err := base64.StdEncoding.DecodeString(cfg.PSK)
	if err != nil || len(key) != 32 {
		return errors.New("bootstrap WGShim key is invalid")
	}
	if cfg.PaddingMin < 0 || cfg.PaddingMax < cfg.PaddingMin || cfg.PaddingMax > 255 {
		return errors.New("invalid bootstrap padding range")
	}
	return nil
}

func installPaths() (string, string, error) {
	base := os.Getenv("ProgramData")
	if strings.TrimSpace(base) == "" {
		base = `C:\ProgramData`
	}
	dir := filepath.Join(base, "BPC")
	return dir, filepath.Join(dir, "bpc-agent.exe"), nil
}

func newFileLogger() (*log.Logger, io.Closer, error) {
	dir, _, err := installPaths()
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
	cmd := `$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }`
	return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd).Run() == nil
}

func elevate(command string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ps := fmt.Sprintf("$p=Start-Process -FilePath '%s' -ArgumentList '%s' -Verb RunAs -Wait -PassThru; exit $p.ExitCode", psQuote(exe), psQuote(command))
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
	_, _ = runCommand("icacls.exe", path, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F")
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func usage() {
	fmt.Println(`BPC Agent for Windows

Usage:
  bpc-agent.exe                 Install a prepared agent package
  bpc-agent.exe install         Install/reinstall and start at boot
  bpc-agent.exe run             Run the background agent loop
  bpc-agent.exe status          Show tunnel and handshake state
  bpc-agent.exe uninstall       Remove startup task and restore direct endpoint
  bpc-agent.exe version

Prepared binaries are generated on the BPC VPS with:
  bpc-agent create NAME --tunnel TUNNEL`)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "BPC Agent: "+format+"\n", args...)
	os.Exit(1)
}
