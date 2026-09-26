package wgshim

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	TransportUDP = "udp"
	TransportTCP = "tcp"
)

type TransportReport struct {
	Selected   string
	UDPRTT     time.Duration
	TCPRTT     time.Duration
	UDPReplies int
	TCPReplies int
	Samples    int
	Switched   bool
}

type AdaptiveTransportClientConfig struct {
	LocalListen       string
	UDPServer         string
	TCPServer         string
	TX                *Codec
	RX                *Codec
	Logger            *log.Logger
	StatsInterval     time.Duration
	ProbeInterval     time.Duration
	ProbeTimeout      time.Duration
	SwitchThreshold   time.Duration
	OnTransportReport func(TransportReport)
}

type transportProbePending struct {
	transport string
	sent      time.Time
}

type transportProbeMeasurement struct {
	transport string
	rtt       time.Duration
}

func RunAdaptiveTransportClient(ctx context.Context, cfg AdaptiveTransportClientConfig) error {
	if cfg.UDPServer == "" || cfg.TCPServer == "" {
		return fmt.Errorf("adaptive transport client requires both UDP and TCP servers")
	}
	if cfg.ProbeInterval <= 0 {
		cfg.ProbeInterval = 15 * time.Second
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 750 * time.Millisecond
	}
	if cfg.SwitchThreshold <= 0 {
		cfg.SwitchThreshold = 5 * time.Millisecond
	}

	localAddr, err := net.ResolveUDPAddr("udp", cfg.LocalListen)
	if err != nil {
		return fmt.Errorf("resolve local listen address: %w", err)
	}
	udpServerAddr, err := net.ResolveUDPAddr("udp", cfg.UDPServer)
	if err != nil {
		return fmt.Errorf("resolve UDP server: %w", err)
	}

	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("listen for WireGuard: %w", err)
	}
	defer localConn.Close()
	udpConn, err := net.DialUDP("udp", nil, udpServerAddr)
	if err != nil {
		return fmt.Errorf("connect UDP outer transport: %w", err)
	}
	defer udpConn.Close()

	tcpLink := newTCPClientLink(cfg.TCPServer, cfg.Logger)
	go tcpLink.run(ctx)
	defer tcpLink.close()

	stats := &Stats{}
	stopStats := make(chan struct{})
	defer close(stopStats)
	if cfg.StatsInterval > 0 {
		go logStats(stopStats, cfg.Logger, "adaptive-transport-client", stats, cfg.StatsInterval)
	}

	var wgPeerMu sync.RWMutex
	var wgPeer *net.UDPAddr

	var selectedMu sync.RWMutex
	selected := TransportUDP
	getSelected := func() string {
		selectedMu.RLock()
		defer selectedMu.RUnlock()
		return selected
	}
	setSelected := func(next string) bool {
		selectedMu.Lock()
		defer selectedMu.Unlock()
		switched := selected != next
		selected = next
		return switched
	}

	pending := map[string]transportProbePending{}
	var pendingMu sync.Mutex
	probeResults := make(chan transportProbeMeasurement, 64)

	recordProbeReply := func(transport string, payload []byte) {
		token := hex.EncodeToString(payload)
		pendingMu.Lock()
		probe, ok := pending[token]
		if ok {
			delete(pending, token)
		}
		pendingMu.Unlock()
		if !ok || probe.transport != transport {
			return
		}
		select {
		case probeResults <- transportProbeMeasurement{
			transport: transport,
			rtt:       time.Since(probe.sent),
		}:
		default:
		}
	}

	deliverOuter := func(transport string, packet []byte) error {
		stats.OuterRX.Add(uint64(len(packet)))
		packetType, inner, openErr := cfg.RX.OpenTyped(packet)
		if openErr != nil {
			stats.AuthDrops.Add(1)
			return nil
		}
		if IsProbeReply(packetType) {
			recordProbeReply(transport, inner)
			return nil
		}
		if !IsData(packetType) {
			return nil
		}
		wgPeerMu.RLock()
		peer := cloneUDPAddr(wgPeer)
		wgPeerMu.RUnlock()
		if peer == nil {
			stats.NoPeerDrop.Add(1)
			return nil
		}
		if _, writeErr := localConn.WriteToUDP(inner, peer); writeErr != nil {
			return fmt.Errorf("deliver %s packet to WireGuard: %w", transport, writeErr)
		}
		stats.InnerRX.Add(uint64(len(inner)))
		return nil
	}

	go func() {
		<-ctx.Done()
		_ = localConn.Close()
		_ = udpConn.Close()
		tcpLink.close()
	}()

	errCh := make(chan error, 4)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, readErr := udpConn.Read(buf)
			if readErr != nil {
				errCh <- normalizeNetErr(ctx, readErr)
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			if deliverErr := deliverOuter(TransportUDP, packet); deliverErr != nil {
				errCh <- normalizeNetErr(ctx, deliverErr)
				return
			}
		}
	}()

	go func() {
		for packet := range tcpLink.recv {
			if deliverErr := deliverOuter(TransportTCP, packet); deliverErr != nil {
				errCh <- normalizeNetErr(ctx, deliverErr)
				return
			}
		}
		if ctx.Err() == nil {
			errCh <- errorsNewTCPReceiveStopped()
		}
	}()

	sendOuter := func(transport string, packet []byte) error {
		switch transport {
		case TransportTCP:
			if sendErr := tcpLink.send(packet); sendErr != nil {
				return sendErr
			}
		case TransportUDP:
			if _, sendErr := udpConn.Write(packet); sendErr != nil {
				return sendErr
			}
		default:
			return fmt.Errorf("unknown transport %q", transport)
		}
		stats.OuterTX.Add(uint64(len(packet)))
		return nil
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, readErr := localConn.ReadFromUDP(buf)
			if readErr != nil {
				errCh <- normalizeNetErr(ctx, readErr)
				return
			}
			wgPeerMu.Lock()
			wgPeer = cloneUDPAddr(addr)
			wgPeerMu.Unlock()

			stats.InnerTX.Add(uint64(n))
			outer, sealErr := cfg.TX.Seal(buf[:n])
			if sealErr != nil {
				errCh <- fmt.Errorf("seal WireGuard packet: %w", sealErr)
				return
			}

			active := getSelected()
			if sendErr := sendOuter(active, outer); sendErr == nil {
				continue
			}
			// Fast-path fallback keeps WireGuard alive while the next probe cycle
			// decides whether the failed transport should remain selected.
			if active == TransportTCP {
				_ = sendOuter(TransportUDP, outer)
			} else if tcpLink.connected() {
				_ = sendOuter(TransportTCP, outer)
			}
		}
	}()

	sendProbe := func(transport string) bool {
		token := make([]byte, 16)
		if _, randErr := crand.Read(token); randErr != nil {
			return false
		}
		packet, sealErr := cfg.TX.SealProbe(token)
		if sealErr != nil {
			return false
		}
		key := hex.EncodeToString(token)
		pendingMu.Lock()
		pending[key] = transportProbePending{
			transport: transport,
			sent:      time.Now(),
		}
		pendingMu.Unlock()

		if sendErr := sendOuter(transport, packet); sendErr != nil {
			pendingMu.Lock()
			delete(pending, key)
			pendingMu.Unlock()
			return false
		}
		return true
	}

	go func() {
		if !sleepContext(ctx, 150*time.Millisecond) {
			return
		}
		const samples = 3
		for ctx.Err() == nil {
			expected := 0
			for sample := 0; sample < samples; sample++ {
				if sendProbe(TransportUDP) {
					expected++
				}
				if sendProbe(TransportTCP) {
					expected++
				}
				if sample+1 < samples && !sleepContext(ctx, 15*time.Millisecond) {
					return
				}
			}

			values := map[string][]time.Duration{
				TransportUDP: {},
				TransportTCP: {},
			}
			timer := time.NewTimer(cfg.ProbeTimeout)
			received := 0
		collect:
			for received < expected {
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case result := <-probeResults:
					values[result.transport] = append(values[result.transport], result.rtt)
					received++
				case <-timer.C:
					break collect
				}
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}

			pendingMu.Lock()
			now := time.Now()
			for token, probe := range pending {
				if now.Sub(probe.sent) >= cfg.ProbeTimeout {
					delete(pending, token)
				}
			}
			pendingMu.Unlock()

			median := func(items []time.Duration) time.Duration {
				if len(items) == 0 {
					return 0
				}
				sort.Slice(items, func(i, j int) bool { return items[i] < items[j] })
				return items[len(items)/2]
			}
			udpRTT := median(values[TransportUDP])
			tcpRTT := median(values[TransportTCP])
			current := getSelected()
			next := current

			switch {
			case udpRTT == 0 && tcpRTT > 0:
				next = TransportTCP
			case tcpRTT == 0 && udpRTT > 0:
				next = TransportUDP
			case udpRTT > 0 && tcpRTT > 0:
				if current == TransportUDP && tcpRTT+cfg.SwitchThreshold < udpRTT {
					next = TransportTCP
				} else if current == TransportTCP && udpRTT+cfg.SwitchThreshold < tcpRTT {
					next = TransportUDP
				}
			}

			switched := setSelected(next)
			report := TransportReport{
				Selected:   next,
				UDPRTT:     udpRTT,
				TCPRTT:     tcpRTT,
				UDPReplies: len(values[TransportUDP]),
				TCPReplies: len(values[TransportTCP]),
				Samples:    samples,
				Switched:   switched,
			}
			if cfg.OnTransportReport != nil {
				cfg.OnTransportReport(report)
			}
			if cfg.Logger != nil {
				cfg.Logger.Printf(
					"transport selected=%s udp_rtt=%s udp_replies=%d/%d tcp_rtt=%s tcp_replies=%d/%d switched=%t",
					report.Selected,
					report.UDPRTT,
					report.UDPReplies,
					report.Samples,
					report.TCPRTT,
					report.TCPReplies,
					report.Samples,
					report.Switched,
				)
			}

			if !sleepContext(ctx, cfg.ProbeInterval) {
				return
			}
		}
	}()

	err = <-errCh
	return err
}

func errorsNewTCPReceiveStopped() error {
	return fmt.Errorf("TCP transport receive loop stopped")
}
