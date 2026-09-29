package main

import (
	"context"
	"io"
	"log"
	"testing"
	"time"

	"github.com/RomanKrike/bpc/internal/agentctl"
)

func TestRuntimeSeparatesOverlayFromTransportAndControl(t *testing.T) {
	transports := make(chan context.Context, 8)
	overlays := make(chan context.Context, 8)
	s := runtimeSupervisor{
		runTransport: func(ctx context.Context, _ agentctl.RuntimeConfig, _ *log.Logger) { transports <- ctx; <-ctx.Done() },
		runOverlay: func(ctx context.Context, _ agentctl.RuntimeConfig, _ agentctl.WireGuardProfile, _ *log.Logger) {
			overlays <- ctx
			<-ctx.Done()
		},
	}
	defer s.stop()
	logger := log.New(io.Discard, "", 0)
	cfg := agentctl.RuntimeConfig{WGShimServer: "ru-01:24444", WGShimListen: "127.0.0.1:24081"}
	profile := agentctl.WireGuardProfile{Address: "10.253.0.2/32", AllowedIPs: []string{"192.168.88.0/24"}}
	apply := func() {
		t.Helper()
		if err := s.apply(context.Background(), cfg, profile, logger); err != nil {
			t.Fatal(err)
		}
	}
	receive := func(ch chan context.Context) context.Context {
		t.Helper()
		select {
		case ctx := <-ch:
			return ctx
		case <-time.After(time.Second):
			t.Fatal("runtime not started")
			return nil
		}
	}
	apply()
	transport := receive(transports)
	overlay := receive(overlays)
	cfg.ConfigVersion++
	cfg.Controllers = []string{"https://ru-02:8444"}
	cfg.UpdateChannel = "stable"
	apply()
	if transport.Err() != nil || overlay.Err() != nil {
		t.Fatal("control metadata restarted dataplane")
	}
	cfg.Paths = []agentctl.TransportPath{{Node: "ru-01", Endpoint: "ru-01:24444"}, {Node: "ru-02", Endpoint: "ru-02:24444"}}
	apply()
	newTransport := receive(transports)
	if transport.Err() == nil {
		t.Fatal("old local listener not stopped before replacement")
	}
	if overlay.Err() != nil {
		t.Fatal("path pool change recreated overlay")
	}
	profile.AllowedIPs = append(profile.AllowedIPs, "10.1.0.0/16")
	apply()
	receive(overlays)
	if overlay.Err() == nil {
		t.Fatal("overlay policy change was ignored")
	}
	if newTransport.Err() != nil {
		t.Fatal("Access change restarted transport")
	}
	s.stop()
	if newTransport.Err() == nil {
		t.Fatal("shutdown left transport running")
	}
}
