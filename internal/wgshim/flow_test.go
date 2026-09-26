package wgshim

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestAdaptiveFlowClientSelectsFastSourceFlow(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	c2s, s2c := testPeerCodecs(t)

	var sourceMu sync.Mutex
	sources := map[string]struct{}{}
	slowSource := ""

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, readErr := server.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			remote := cloneUDPAddr(addr)
			packetType, inner, openErr := c2s.OpenTyped(packet)
			if openErr != nil {
				continue
			}

			sourceMu.Lock()
			sources[remote.String()] = struct{}{}
			if slowSource == "" {
				slowSource = remote.String()
			}
			isSlow := remote.String() == slowSource
			sourceMu.Unlock()

			go func(packetType byte, inner []byte, peer *net.UDPAddr, slow bool) {
				if slow {
					time.Sleep(45 * time.Millisecond)
				} else {
					time.Sleep(2 * time.Millisecond)
				}
				var outer []byte
				var sealErr error
				switch {
				case IsProbe(packetType):
					outer, sealErr = s2c.SealProbeReply(inner)
				case IsData(packetType):
					outer, sealErr = s2c.Seal(inner)
				default:
					return
				}
				if sealErr == nil {
					_, _ = server.WriteToUDP(outer, peer)
				}
			}(packetType, inner, remote, isSlow)
		}
	}()

	clientAddr := reserveUDPAddr(t)
	reports := make(chan FlowReport, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientErr := make(chan error, 1)
	go func() {
		clientErr <- RunAdaptiveFlowTransportClient(ctx, AdaptiveFlowTransportClientConfig{
			LocalListen:     clientAddr,
			UDPServer:       server.LocalAddr().String(),
			UDPFlows:        3,
			TX:              c2s,
			RX:              s2c,
			ProbeInterval:   100 * time.Millisecond,
			ProbeTimeout:    200 * time.Millisecond,
			SwitchThreshold: 5 * time.Millisecond,
			OnFlowReport: func(report FlowReport) {
				reports <- report
			},
		})
	}()

	var selected FlowReport
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case report := <-reports:
			if report.Replies == report.Samples && report.RTT > 0 && report.RTT < 20*time.Millisecond {
				selected = report
				goto selectedFast
			}
		case <-deadline.C:
			t.Fatal("adaptive flow client did not select a fast source flow")
		}
	}

selectedFast:
	sourceMu.Lock()
	uniqueSources := len(sources)
	slow := slowSource
	sourceMu.Unlock()
	if uniqueSources < 3 {
		t.Fatalf("expected at least 3 distinct UDP source flows, got %d", uniqueSources)
	}
	if selected.Transport != TransportUDP {
		t.Fatalf("expected UDP flow, got %q", selected.Transport)
	}
	if selected.Local == slow {
		t.Fatalf("selected slow source flow %s", slow)
	}

	clientUDP, err := net.ResolveUDPAddr("udp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	wgConn, err := net.DialUDP("udp", nil, clientUDP)
	if err != nil {
		t.Fatal(err)
	}
	defer wgConn.Close()
	if err := wgConn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	payload := []byte("adaptive-flow-data")
	start := time.Now()
	if _, err := wgConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := wgConn.Read(buf)
	if err != nil {
		t.Fatalf("adaptive flow data round-trip failed: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("unexpected adaptive flow reply: got %q want %q", buf[:n], payload)
	}
	if elapsed := time.Since(start); elapsed >= 30*time.Millisecond {
		t.Fatalf("selected data path remained slow: %s", elapsed)
	}

	cancel()
	select {
	case err := <-clientErr:
		if err != nil {
			t.Fatalf("adaptive flow client exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("adaptive flow client did not stop")
	}
}
