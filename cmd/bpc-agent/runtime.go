package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/RomanKrike/bpc/internal/agentctl"
)

type pathSwitchEvent struct {
	FromNode string
	ToNode   string
}

// Cross-node switches are edge-triggered for the transport but level-triggered
// for the overlay: only the newest selected Public Node matters. Keep a
// one-element mailbox and replace a stale notification instead of dropping the
// newest rehandshake request during a rapid failover/recovery burst.
func publishLatestPathSwitch(ch chan pathSwitchEvent, event pathSwitchEvent) bool {
	if ch == nil {
		return false
	}
	select {
	case ch <- event:
		return false
	default:
	}
	select {
	case <-ch:
	default:
	}
	ch <- event
	return true
}

type runtimeWorker struct {
	fingerprint string
	cancel      context.CancelFunc
	done        chan struct{}
}

func (w *runtimeWorker) stop() error {
	if w.cancel == nil {
		return nil
	}
	w.cancel()
	select {
	case <-w.done:
		w.cancel = nil
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("runtime did not stop within 5 seconds")
	}
}
func (w *runtimeWorker) replace(parent context.Context, fingerprint string, run func(context.Context)) error {
	if w.cancel != nil && w.fingerprint == fingerprint {
		select {
		case <-w.done:
		default:
			return nil
		}
	}
	if err := w.stop(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	w.fingerprint = fingerprint
	w.done = make(chan struct{})
	done := w.done
	go func() { defer close(done); run(ctx) }()
	return nil
}

// Overlay lifetime depends only on its profile and the stable local transport
// socket. Controller metadata and public endpoint selection cannot recreate it.
type runtimeSupervisor struct {
	mu           sync.Mutex
	overlay      runtimeWorker
	transport    runtimeWorker
	pathSwitches chan pathSwitchEvent
	runTransport func(context.Context, agentctl.RuntimeConfig, *log.Logger)
	runOverlay   func(context.Context, agentctl.RuntimeConfig, agentctl.WireGuardProfile, *log.Logger)
}

func (s *runtimeSupervisor) apply(parent context.Context, cfg agentctl.RuntimeConfig, profile agentctl.WireGuardProfile, logger *log.Logger) error {
	transportRaw, err := json.Marshal(struct {
		Paths                  []agentctl.TransportPath
		Listen, PSK            string
		PaddingMin, PaddingMax int
	}{cfg.TransportPaths(), cfg.WGShimListen, cfg.WGShimPSK, cfg.PaddingMin, cfg.PaddingMax})
	if err != nil {
		return err
	}
	overlayRaw, err := json.Marshal(struct {
		Profile              agentctl.WireGuardProfile
		Listen, LegacyTunnel string
	}{profile, cfg.WGShimListen, cfg.LegacyTunnel})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pathSwitches == nil {
		s.pathSwitches = make(chan pathSwitchEvent, 1)
	}
	switches := s.pathSwitches
	transport := s.runTransport
	if transport == nil {
		transport = func(ctx context.Context, cfg agentctl.RuntimeConfig, logger *log.Logger) {
			runWGShimLoopWithSwitch(ctx, cfg, logger, switches)
		}
	}
	overlay := s.runOverlay
	if overlay == nil {
		overlay = func(
			ctx context.Context,
			cfg agentctl.RuntimeConfig,
			profile agentctl.WireGuardProfile,
			logger *log.Logger,
		) {
			runOverlayLoopWithSwitch(ctx, cfg, profile, logger, switches)
		}
	}
	if err := s.transport.replace(parent, string(transportRaw), func(ctx context.Context) { transport(ctx, cfg, logger) }); err != nil {
		return err
	}
	return s.overlay.replace(parent, string(overlayRaw), func(ctx context.Context) { overlay(ctx, cfg, profile, logger) })
}
func (s *runtimeSupervisor) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.transport.stop()
	_ = s.overlay.stop()
}
func runOverlayLoop(
	ctx context.Context,
	cfg agentctl.RuntimeConfig,
	profile agentctl.WireGuardProfile,
	logger *log.Logger,
) {
	runOverlayLoopWithSwitch(ctx, cfg, profile, logger, nil)
}

func runOverlayLoopWithSwitch(
	ctx context.Context,
	cfg agentctl.RuntimeConfig,
	profile agentctl.WireGuardProfile,
	logger *log.Logger,
	pathSwitches <-chan pathSwitchEvent,
) {
	if profile.Complete() {
		telemetry := func(stats tunnelTelemetry) {
			if err := writeUIRuntimeStatus(stats); err != nil && ctx.Err() == nil {
				logger.Printf("write UI tunnel telemetry: %v", err)
			}
		}
		if err := runEmbeddedWireGuard(
			ctx,
			cfg,
			profile,
			logger,
			telemetry,
			pathSwitches,
		); err != nil && ctx.Err() == nil {
			logger.Printf("embedded WireGuard stopped: %v", err)
		}
	} else if cfg.LegacyTunnel != "" {
		runLegacyWireGuardLoop(ctx, cfg, logger)
	} else {
		logger.Printf("no provisioned WireGuard profile; control plane remains online")
	}
}
