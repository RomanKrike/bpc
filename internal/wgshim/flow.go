package wgshim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

// FlowReport describes the currently selected outer transport flow.
// A flow is a concrete socket/connection, not just a protocol+destination,
// so multiple flows to the same relay endpoint can exercise different
// source ports and therefore different ECMP paths.
type FlowReport struct {
	Selected  string
	Transport string
	Endpoint  string
	Local     string
	RTT       time.Duration
	Replies   int
	Samples   int
	Reachable int
	Total     int
	Switched  bool
}

type AdaptiveFlowTransportClientConfig struct {
	LocalListen       string
	UDPServer         string
	UDPFlows          int
	TCPServer         string
	TCPFlows          int
	TX                *Codec
	RX                *Codec
	Logger            *log.Logger
	StatsInterval     time.Duration
	ProbeInterval     time.Duration
	ProbeTimeout      time.Duration
	SwitchThreshold   time.Duration
	OnFlowReport      func(FlowReport)
}

type transportFlow struct {
	id        string
	transport string
	endpoint  string
	local     string
	udp       *net.UDPConn
	tcp       *tcpClientLink
}

type flowProbePending struct {
	flow int
	sent time.Time
}

type flowProbeMeasurement struct {
	flow int
	rtt  time.Duration
}

type flowScore struct {
	index   int
	rtt     time.Duration
	replies int
}

// RunAdaptiveFlowTransportClient keeps several independent UDP sockets and TCP
// connections alive at the same time and sends WireGuard through the healthiest
// concrete flow. Separate sockets intentionally produce separate source ports;
// this lets BPC avoid a persistently slow ECMP path without restarting WireGuard.
func RunAdaptiveFlowTransportClient(ctx context.Context, cfg AdaptiveFlowTransportClientConfig) error {
	if cfg.TX == nil || cfg.RX == nil {
		return errors.New("adaptive flow client requires TX and RX codecs")
	}
	if cfg.UDPServer == "" && cfg.TCPServer == "" {
		return errors.New("adaptive flow client requires at least one relay endpoint")
	}
	if cfg.UDPServer != "" && cfg.UDPFlows <= 0 {
		cfg.UDPFlows = 4
	}
	if cfg.TCPServer != "" && cfg.TCPFlows <= 0 {
		cfg.TCPFlows = 1
	}
	if cfg.UDPFlows < 0 || cfg.UDPFlows > 16 {
		return fmt.Errorf("UDP flow count must be between 0 and 16")
	}
	if cfg.TCPFlows < 0 || cfg.TCPFlows > 8 {
		return fmt.Errorf("TCP flow count must be between 0 and 8")
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
	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("listen for WireGuard: %w", err)
	}
	defer localConn.Close()

	flows := make([]*transportFlow, 0, cfg.UDPFlows+cfg.TCPFlows)
	if cfg.UDPServer != "" {
		serverAddr, resolveErr := net.ResolveUDPAddr("udp", cfg.UDPServer)
		if resolveErr != nil {
			return fmt.Errorf("resolve UDP server: %w", resolveErr)
		}
		for i := 0; i < cfg.UDPFlows; i++ {
			conn, dialErr := net.DialUDP("udp", nil, serverAddr)
			if dialErr != nil {
				for _, flow := range flows {
					if flow.udp != nil {
						_ = flow.udp.Close()
					}
				}
				return fmt.Errorf("open UDP flow %d: %w", i+1, dialErr)
			}
			flows = append(flows, &transportFlow{
				id:        fmt.Sprintf("udp-%d", i+1),
				transport: TransportUDP,
				endpoint:  serverAddr.String(),
				local:     conn.LocalAddr().String(),
				udp:       conn,
			})
		}
	}

	if cfg.TCPServer != "" {
		for i := 0; i < cfg.TCPFlows; i++ {
			link := newTCPClientLink(cfg.TCPServer, cfg.Logger)
			flows = append(flows, &transportFlow{
				id:        fmt.Sprintf("tcp-%d", i+1),
				transport: TransportTCP,
				endpoint:  cfg.TCPServer,
				local:     "pending",
				tcp:       link,
			})
		}
	}

	if len(flows) == 0 {
		return errors.New("adaptive flow client has no transport flows")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		for _, flow := range flows {
			if flow.udp != nil {
				_ = flow.udp.Close()
			}
			if flow.tcp != nil {
				flow.tcp.close()
			}
		}
	}()

	for _, flow := range flows {
		if flow.tcp != nil {
			go flow.tcp.run(runCtx)
		}
	}

	stats := &Stats{}
	stopStats := make(chan struct{})
	defer close(stopStats)
	if cfg.StatsInterval > 0 {
		go logStats(stopStats, cfg.Logger, "adaptive-flow-client", stats, cfg.StatsInterval)
	}

	var wgPeerMu sync.RWMutex
	var wgPeer *net.UDPAddr

	var selectedMu sync.RWMutex
	selected := 0
	getSelected := func() int {
		selectedMu.RLock()
		defer selectedMu.RUnlock()
		return selected
	}
	setSelected := func(next int) bool {
		selectedMu.Lock()
		defer selectedMu.Unlock()
		switched := selected != next
		selected = next
		return switched
	}

	pending := map[string]flowProbePending{}
	var pendingMu sync.Mutex
	probeResults := make(chan flowProbeMeasurement, 256)

	var codecMu sync.Mutex
	sealData := func(payload []byte) ([]byte, error) {
		codecMu.Lock()
		defer codecMu.Unlock()
		return cfg.TX.Seal(payload)
	}
	sealProbe := func(payload []byte) ([]byte, error) {
		codecMu.Lock()
		defer codecMu.Unlock()
		return cfg.TX.SealProbe(payload)
	}
	openPacket := func(packet []byte) (byte, []byte, error) {
		codecMu.Lock()
		defer codecMu.Unlock()
		return cfg.RX.OpenTyped(packet)
	}

	recordProbeReply := func(flowIndex int, payload []byte) {
		token := hex.EncodeToString(payload)
		pendingMu.Lock()
		probe, ok := pending[token]
		if ok {
			delete(pending, token)
		}
		pendingMu.Unlock()
		if !ok || probe.flow != flowIndex {
			return
		}
		select {
		case probeResults <- flowProbeMeasurement{
			flow: flowIndex,
			rtt:  time.Since(probe.sent),
		}:
		default:
		}
	}

	errCh := make(chan error, 8)
	deliverOuter := func(flowIndex int, packet []byte) error {
		stats.OuterRX.Add(uint64(len(packet)))
		packetType, inner, openErr := openPacket(packet)
		if openErr != nil {
			stats.AuthDrops.Add(1)
			return nil
		}
		if IsProbeReply(packetType) {
			recordProbeReply(flowIndex, inner)
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
			return fmt.Errorf("deliver flow packet to WireGuard: %w", writeErr)
		}
		stats.InnerRX.Add(uint64(len(inner)))
		return nil
	}

	for i, flow := range flows {
		flowIndex := i
		flow := flow
		if flow.udp != nil {
			go func() {
				buf := make([]byte, 65535)
				for {
					n, readErr := flow.udp.Read(buf)
					if readErr != nil {
						if runCtx.Err() == nil && cfg.Logger != nil {
							cfg.Logger.Printf("flow=%s UDP receive stopped: %v", flow.id, readErr)
						}
						return
					}
					packet := append([]byte(nil), buf[:n]...)
					if deliverErr := deliverOuter(flowIndex, packet); deliverErr != nil {
						select {
						case errCh <- deliverErr:
						case <-runCtx.Done():
						}
						return
					}
				}
			}()
		}
		if flow.tcp != nil {
			go func() {
				for packet := range flow.tcp.recv {
					if deliverErr := deliverOuter(flowIndex, packet); deliverErr != nil {
						select {
						case errCh <- deliverErr:
						case <-runCtx.Done():
						}
						return
					}
				}
			}()
		}
	}

	go func() {
		<-runCtx.Done()
		_ = localConn.Close()
		for _, flow := range flows {
			if flow.udp != nil {
				_ = flow.udp.Close()
			}
			if flow.tcp != nil {
				flow.tcp.close()
			}
		}
	}()

	sendOuter := func(flowIndex int, packet []byte) error {
		if flowIndex < 0 || flowIndex >= len(flows) {
			return errors.New("invalid adaptive flow index")
		}
		flow := flows[flowIndex]
		switch flow.transport {
		case TransportUDP:
			if _, sendErr := flow.udp.Write(packet); sendErr != nil {
				return sendErr
			}
		case TransportTCP:
			if sendErr := flow.tcp.send(packet); sendErr != nil {
				return sendErr
			}
		default:
			return fmt.Errorf("unknown flow transport %q", flow.transport)
		}
		stats.OuterTX.Add(uint64(len(packet)))
		return nil
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, readErr := localConn.ReadFromUDP(buf)
			if readErr != nil {
				select {
				case errCh <- normalizeNetErr(runCtx, readErr):
				case <-runCtx.Done():
				}
				return
			}
			wgPeerMu.Lock()
			wgPeer = cloneUDPAddr(addr)
			wgPeerMu.Unlock()

			stats.InnerTX.Add(uint64(n))
			outer, sealErr := sealData(buf[:n])
			if sealErr != nil {
				select {
				case errCh <- fmt.Errorf("seal WireGuard packet: %w", sealErr):
				case <-runCtx.Done():
				}
				return
			}

			active := getSelected()
			if sendErr := sendOuter(active, outer); sendErr == nil {
				continue
			}
			// Keep WireGuard alive when the selected flow dies between probe cycles.
			for offset := 1; offset < len(flows); offset++ {
				candidate := (active + offset) % len(flows)
				if sendErr := sendOuter(candidate, outer); sendErr == nil {
					break
				}
			}
		}
	}()

	sendProbe := func(flowIndex int) bool {
		token := make([]byte, 16)
		if _, randErr := rand.Read(token); randErr != nil {
			return false
		}
		packet, sealErr := sealProbe(token)
		if sealErr != nil {
			return false
		}
		key := hex.EncodeToString(token)
		pendingMu.Lock()
		pending[key] = flowProbePending{
			flow: flowIndex,
			sent: time.Now(),
		}
		pendingMu.Unlock()

		if sendErr := sendOuter(flowIndex, packet); sendErr != nil {
			pendingMu.Lock()
			delete(pending, key)
			pendingMu.Unlock()
			return false
		}
		return true
	}

	go func() {
		if !sleepContext(runCtx, 150*time.Millisecond) {
			return
		}
		const samples = 3
		for runCtx.Err() == nil {
			expected := 0
			for sample := 0; sample < samples; sample++ {
				for flowIndex := range flows {
					if sendProbe(flowIndex) {
						expected++
					}
					if !sleepContext(runCtx, 2*time.Millisecond) {
						return
					}
				}
			}

			values := make([][]time.Duration, len(flows))
			timer := time.NewTimer(cfg.ProbeTimeout)
			received := 0
		collect:
			for received < expected {
				select {
				case <-runCtx.Done():
					timer.Stop()
					return
				case result := <-probeResults:
					if result.flow >= 0 && result.flow < len(values) {
						values[result.flow] = append(values[result.flow], result.rtt)
					}
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

			scores := make([]flowScore, 0, len(flows))
			for i, items := range values {
				if len(items) == 0 {
					continue
				}
				sort.Slice(items, func(a, b int) bool { return items[a] < items[b] })
				scores = append(scores, flowScore{
					index:   i,
					rtt:     items[len(items)/2],
					replies: len(items),
				})
			}
			sort.Slice(scores, func(i, j int) bool {
				if scores[i].replies != scores[j].replies {
					return scores[i].replies > scores[j].replies
				}
				return scores[i].rtt < scores[j].rtt
			})

			current := getSelected()
			currentRTT := time.Duration(0)
			currentReplies := 0
			currentReachable := false
			for _, score := range scores {
				if score.index == current {
					currentRTT = score.rtt
					currentReplies = score.replies
					currentReachable = true
					break
				}
			}

			next := current
			nextRTT := currentRTT
			nextReplies := currentReplies
			if len(scores) > 0 {
				best := scores[0]
				if !currentReachable ||
					best.replies > currentReplies ||
					(best.index != current &&
						best.replies == currentReplies &&
						best.rtt+cfg.SwitchThreshold < currentRTT) {
					next = best.index
					nextRTT = best.rtt
					nextReplies = best.replies
				}
			}
			switched := setSelected(next)

			flow := flows[next]
			local := flow.local
			if flow.tcp != nil {
				if conn := flow.tcp.current(); conn != nil {
					local = conn.LocalAddr().String()
				}
			}
			report := FlowReport{
				Selected:  flow.id,
				Transport: flow.transport,
				Endpoint:  flow.endpoint,
				Local:     local,
				RTT:       nextRTT,
				Replies:   nextReplies,
				Samples:   samples,
				Reachable: len(scores),
				Total:     len(flows),
				Switched:  switched,
			}
			if cfg.OnFlowReport != nil {
				cfg.OnFlowReport(report)
			}
			if cfg.Logger != nil {
				cfg.Logger.Printf(
					"flow selected=%s transport=%s endpoint=%s local=%s rtt=%s replies=%d/%d reachable=%d/%d switched=%t",
					report.Selected,
					report.Transport,
					report.Endpoint,
					report.Local,
					report.RTT,
					report.Replies,
					report.Samples,
					report.Reachable,
					report.Total,
					report.Switched,
				)
			}

			if !sleepContext(runCtx, cfg.ProbeInterval) {
				return
			}
		}
	}()

	err = <-errCh
	return normalizeNetErr(runCtx, err)
}
