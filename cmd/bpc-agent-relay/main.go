package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/RomanKrike/bpc/internal/wgshim"
)

const version = "0.10.0"

func main() {
	listen := flag.String("listen", "0.0.0.0:24444", "public WGShim UDP listen address")
	target := flag.String("target", "127.0.0.1:51821", "local WireGuard UDP target")
	keyDir := flag.String("key-dir", "", "directory containing one base64 PSK per device")
	paddingMin := flag.Int("padding-min", 0, "minimum random padding bytes per packet")
	paddingMax := flag.Int("padding-max", 31, "maximum random padding bytes per packet")
	reloadInterval := flag.Duration("reload-interval", time.Second, "device key reload interval")
	statsInterval := flag.Duration("stats-interval", 30*time.Second, "stats log interval; 0 disables")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("bpc-agent-relay %s\n", version)
		return
	}
	if strings.TrimSpace(*keyDir) == "" {
		flag.Usage()
		os.Exit(2)
	}

	logger := log.New(os.Stdout, "bpc-agent-relay ", log.LstdFlags|log.LUTC)
	ctx, stop := signalContext()
	defer stop()

	err := wgshim.RunMultiServer(ctx, wgshim.MultiServerConfig{
		Listen: *listen,
		Target: *target,
		LoadPeers: func() (map[string]wgshim.MultiServerPeer, error) {
			return loadPeers(*keyDir, *paddingMin, *paddingMax)
		},
		ReloadInterval: *reloadInterval,
		Logger:         logger,
		StatsInterval:  *statsInterval,
	})
	if err != nil {
		logger.Fatal(err)
	}
}

func loadPeers(dir string, paddingMin, paddingMax int) (map[string]wgshim.MultiServerPeer, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read key directory: %w", err)
	}
	peers := make(map[string]wgshim.MultiServerPeer)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".key")
		if id == "" {
			continue
		}
		psk, err := wgshim.LoadPSK(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("load peer %s: %w", id, err)
		}
		rxKey, err := wgshim.DeriveKey(psk, wgshim.ClientToServer)
		if err != nil {
			return nil, err
		}
		txKey, err := wgshim.DeriveKey(psk, wgshim.ServerToClient)
		if err != nil {
			return nil, err
		}
		rx, err := wgshim.NewCodec(rxKey, paddingMin, paddingMax)
		if err != nil {
			return nil, err
		}
		tx, err := wgshim.NewCodec(txKey, paddingMin, paddingMax)
		if err != nil {
			return nil, err
		}
		peers[id] = wgshim.MultiServerPeer{
			Fingerprint: string(psk),
			RX:          rx,
			TX:          tx,
		}
	}
	return peers, nil
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-signals:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
