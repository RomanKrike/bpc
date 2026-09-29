package wgshim

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	InnerTX    atomic.Uint64
	InnerRX    atomic.Uint64
	OuterTX    atomic.Uint64
	OuterRX    atomic.Uint64
	AuthDrops  atomic.Uint64
	NoPeerDrop atomic.Uint64
}

type ClientConfig struct {
	LocalListen   string
	Server        string
	TX            *Codec
	RX            *Codec
	Logger        *log.Logger
	StatsInterval time.Duration
}

type ServerConfig struct {
	Listen        string
	Target        string
	RX            *Codec
	TX            *Codec
	Logger        *log.Logger
	StatsInterval time.Duration
}

type EndpointReport struct {
	Selected  string
	RTT       time.Duration
	Reachable int
	Total     int
	Switched  bool
	Paths     []PathHealth `json:"paths"`
}

type AdaptiveClientConfig struct {
	LocalListen          string
	Servers              []string
	TX                   *Codec
	RX                   *Codec
	Logger               *log.Logger
	StatsInterval        time.Duration
	ProbeTimeout         time.Duration
	SwitchThreshold      time.Duration
	ProbeInterval        time.Duration
	ResolveRetryInterval time.Duration
	Policy               PathPolicy
	OnEndpointReport     func(EndpointReport)
}

type probePending struct {
	endpoint string
	sent     time.Time
}

type probeMeasurement struct {
	endpoint string
	rtt      time.Duration
}

type adaptiveUDPResolver func(network, address string) (*net.UDPAddr, error)

func resolveAdaptiveServers(
	servers []string,
	resolver adaptiveUDPResolver,
	logger *log.Logger,
) ([]*net.UDPAddr, []string, map[string]string, []string, error) {
	serverAddrs := make([]*net.UDPAddr, 0, len(servers))
	serverNames := make([]string, 0, len(servers))
	serverSources := make(map[string]string, len(servers))
	unresolved := make([]string, 0, len(servers))
	seen := map[string]struct{}{}
	for _, raw := range servers {
		addr, err := resolver("udp", raw)
		if err != nil {
			unresolved = append(unresolved, raw)
			if logger != nil {
				logger.Printf("adaptive endpoint unavailable endpoint=%s error=%v", raw, err)
			}
			continue
		}
		key := addr.String()
		if _, ok := seen[key]; ok {
			if logger != nil {
				logger.Printf("adaptive endpoint duplicate endpoint=%s resolved=%s", raw, key)
			}
			continue
		}
		seen[key] = struct{}{}
		serverAddrs = append(serverAddrs, addr)
		serverNames = append(serverNames, raw)
		serverSources[key] = raw
	}
	if len(serverAddrs) == 0 {
		return nil, nil, nil, unresolved, fmt.Errorf(
			"adaptive client has no resolvable servers (%d configured)",
			len(servers),
		)
	}
	return serverAddrs, serverNames, serverSources, unresolved, nil
}

func waitForAdaptiveServerRecovery(
	ctx context.Context,
	unresolved []string,
	interval time.Duration,
	resolver adaptiveUDPResolver,
) bool {
	if len(unresolved) == 0 {
		return false
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			for _, raw := range unresolved {
				if _, err := resolver("udp", raw); err == nil {
					return true
				}
			}
		}
	}
}

func RunClient(ctx context.Context, cfg ClientConfig) error {
	localAddr, err := net.ResolveUDPAddr("udp", cfg.LocalListen)
	if err != nil {
		return fmt.Errorf("resolve local listen address: %w", err)
	}
	serverAddr, err := net.ResolveUDPAddr("udp", cfg.Server)
	if err != nil {
		return fmt.Errorf("resolve server address: %w", err)
	}

	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("listen for WireGuard: %w", err)
	}
	defer localConn.Close()
	outerConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return fmt.Errorf("connect outer UDP: %w", err)
	}
	defer outerConn.Close()

	var wgPeerMu sync.RWMutex
	var wgPeer *net.UDPAddr
	stats := &Stats{}
	stop := make(chan struct{})
	defer close(stop)
	if cfg.StatsInterval > 0 {
		go logStats(stop, cfg.Logger, "client", stats, cfg.StatsInterval)
	}
	go func() {
		<-ctx.Done()
		_ = localConn.Close()
		_ = outerConn.Close()
	}()

	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := localConn.ReadFromUDP(buf)
			if err != nil {
				errCh <- normalizeNetErr(ctx, err)
				return
			}
			wgPeerMu.Lock()
			wgPeer = cloneUDPAddr(addr)
			wgPeerMu.Unlock()
			stats.InnerTX.Add(uint64(n))
			outer, err := cfg.TX.Seal(buf[:n])
			if err != nil {
				errCh <- fmt.Errorf("seal WireGuard packet: %w", err)
				return
			}
			if _, err := outerConn.Write(outer); err != nil {
				errCh <- normalizeNetErr(ctx, fmt.Errorf("send outer UDP: %w", err))
				return
			}
			stats.OuterTX.Add(uint64(len(outer)))
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := outerConn.Read(buf)
			if err != nil {
				errCh <- normalizeNetErr(ctx, err)
				return
			}
			stats.OuterRX.Add(uint64(n))
			inner, err := cfg.RX.Open(buf[:n])
			if err != nil {
				stats.AuthDrops.Add(1)
				continue
			}
			wgPeerMu.RLock()
			peer := cloneUDPAddr(wgPeer)
			wgPeerMu.RUnlock()
			if peer == nil {
				stats.NoPeerDrop.Add(1)
				continue
			}
			if _, err := localConn.WriteToUDP(inner, peer); err != nil {
				errCh <- normalizeNetErr(ctx, fmt.Errorf("deliver packet to WireGuard: %w", err))
				return
			}
			stats.InnerRX.Add(uint64(len(inner)))
		}
	}()

	return <-errCh
}

type adaptiveEndpointPoolChangedError struct {
	preferred string
}

func (e *adaptiveEndpointPoolChangedError) Error() string {
	return "adaptive endpoint pool changed"
}

func preferAdaptiveServer(servers []string, preferred string) []string {
	if preferred == "" || len(servers) < 2 || servers[0] == preferred {
		return append([]string(nil), servers...)
	}
	result := make([]string, 0, len(servers))
	for _, server := range servers {
		if server == preferred {
			result = append(result, server)
			break
		}
	}
	for _, server := range servers {
		if server != preferred {
			result = append(result, server)
		}
	}
	if len(result) != len(servers) {
		return append([]string(nil), servers...)
	}
	return result
}

func RunAdaptiveClient(ctx context.Context, cfg AdaptiveClientConfig) error {
	for {
		err := runAdaptiveClientOnce(ctx, cfg)
		var changed *adaptiveEndpointPoolChangedError
		if ctx.Err() != nil || !errors.As(err, &changed) {
			return err
		}
		cfg.Servers = preferAdaptiveServer(cfg.Servers, changed.preferred)
		if cfg.Logger != nil {
			cfg.Logger.Printf(
				"adaptive endpoint DNS recovered; rebuilding path pool preferred=%s",
				changed.preferred,
			)
		}
	}
}

func runAdaptiveClientOnce(ctx context.Context, cfg AdaptiveClientConfig) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if len(cfg.Servers) == 0 {
		return errors.New("adaptive client requires at least one server")
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 400 * time.Millisecond
	}
	if cfg.SwitchThreshold <= 0 {
		cfg.SwitchThreshold = 10 * time.Millisecond
	}

	if cfg.ProbeInterval <= 0 {
		cfg.ProbeInterval = 250 * time.Millisecond
	}
	if cfg.ResolveRetryInterval <= 0 {
		cfg.ResolveRetryInterval = 5 * time.Second
	}
	if cfg.Policy.MinimumImprovement <= 0 {
		cfg.Policy.MinimumImprovement = cfg.SwitchThreshold
	}
	localAddr, err := net.ResolveUDPAddr("udp", cfg.LocalListen)
	if err != nil {
		return fmt.Errorf("resolve local listen address: %w", err)
	}
	serverAddrs, serverNames, serverSources, unresolved, err := resolveAdaptiveServers(
		cfg.Servers,
		net.ResolveUDPAddr,
		cfg.Logger,
	)
	if err != nil {
		return err
	}

	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("listen for WireGuard: %w", err)
	}
	defer localConn.Close()
	outerConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fmt.Errorf("listen outer UDP: %w", err)
	}
	defer outerConn.Close()

	var wgPeerMu sync.RWMutex
	var wgPeer *net.UDPAddr
	var selectedMu sync.RWMutex
	selected := 0

	stats := &Stats{}
	stopStats := make(chan struct{})
	defer close(stopStats)
	if cfg.StatsInterval > 0 {
		go logStats(stopStats, cfg.Logger, "adaptive-client", stats, cfg.StatsInterval)
	}

	pending := map[string]probePending{}
	var pendingMu sync.Mutex
	probeResults := make(chan probeMeasurement, 128)

	manager := NewPathManager(serverNames, cfg.Policy)
	setSelected := func(next int, rtt time.Duration, reachable int, switched bool) {
		selectedMu.Lock()
		selected = next
		selectedMu.Unlock()
		paths := manager.Snapshot()
		for _, endpoint := range unresolved {
			paths = append(paths, PathHealth{Endpoint: endpoint, State: "FAILED"})
		}
		report := EndpointReport{
			Selected:  serverNames[next],
			RTT:       rtt,
			Reachable: reachable,
			Total:     len(serverNames) + len(unresolved),
			Switched:  switched,
			Paths:     paths,
		}
		if cfg.OnEndpointReport != nil {
			cfg.OnEndpointReport(report)
		}
		if cfg.Logger != nil && switched {
			cfg.Logger.Printf(
				"adaptive endpoint switched endpoint=%s rtt=%s reachable=%d/%d",
				report.Selected,
				report.RTT,
				report.Reachable,
				report.Total,
			)
		}
	}
	getSelected := func() (int, *net.UDPAddr) {
		selectedMu.RLock()
		defer selectedMu.RUnlock()
		return selected, cloneUDPAddr(serverAddrs[selected])
	}
	setSelected(0, 0, 0, false)

	go func() {
		<-runCtx.Done()
		_ = localConn.Close()
		_ = outerConn.Close()
	}()

	errCh := make(chan error, 4)
	if len(unresolved) > 0 {
		go func() {
			if !waitForAdaptiveServerRecovery(
				runCtx,
				unresolved,
				cfg.ResolveRetryInterval,
				net.ResolveUDPAddr,
			) {
				return
			}
			index, _ := getSelected()
			preferred := ""
			if index >= 0 && index < len(serverNames) {
				preferred = serverNames[index]
			}
			select {
			case errCh <- &adaptiveEndpointPoolChangedError{preferred: preferred}:
			case <-runCtx.Done():
			}
		}()
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := localConn.ReadFromUDP(buf)
			if err != nil {
				errCh <- normalizeNetErr(runCtx, err)
				return
			}
			wgPeerMu.Lock()
			wgPeer = cloneUDPAddr(addr)
			wgPeerMu.Unlock()

			stats.InnerTX.Add(uint64(n))
			outer, err := cfg.TX.Seal(buf[:n])
			if err != nil {
				errCh <- fmt.Errorf("seal WireGuard packet: %w", err)
				return
			}
			index, endpoint := getSelected()
			manager.MarkSent(index, time.Now())
			if _, err := outerConn.WriteToUDP(outer, endpoint); err != nil {
				errCh <- normalizeNetErr(runCtx, fmt.Errorf("send adaptive outer UDP: %w", err))
				return
			}
			stats.OuterTX.Add(uint64(len(outer)))
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, source, err := outerConn.ReadFromUDP(buf)
			if err != nil {
				errCh <- normalizeNetErr(runCtx, err)
				return
			}
			if _, known := serverSources[source.String()]; !known {
				continue
			}
			stats.OuterRX.Add(uint64(n))
			packetType, inner, err := cfg.RX.OpenTyped(buf[:n])
			if err != nil {
				stats.AuthDrops.Add(1)
				continue
			}
			if IsProbeReply(packetType) {
				token := hex.EncodeToString(inner)
				pendingMu.Lock()
				probe, ok := pending[token]
				if ok {
					delete(pending, token)
				}
				pendingMu.Unlock()
				if ok && source.String() == probe.endpoint {
					select {
					case probeResults <- probeMeasurement{
						endpoint: serverSources[probe.endpoint],
						rtt:      time.Since(probe.sent),
					}:
					default:
					}
				}
				continue
			}
			if !IsData(packetType) {
				continue
			}
			manager.ConfirmTraffic(serverSources[source.String()], time.Now())

			wgPeerMu.RLock()
			peer := cloneUDPAddr(wgPeer)
			wgPeerMu.RUnlock()
			if peer == nil {
				stats.NoPeerDrop.Add(1)
				continue
			}
			if _, err := localConn.WriteToUDP(inner, peer); err != nil {
				errCh <- normalizeNetErr(runCtx, fmt.Errorf("deliver adaptive packet to WireGuard: %w", err))
				return
			}
			stats.InnerRX.Add(uint64(len(inner)))
		}
	}()

	go func() {
		for runCtx.Err() == nil {
			measurements := make(map[string][]time.Duration, len(serverNames))
			expected := 0
			samplesPerEndpoint := 3
			order := make([]int, len(serverAddrs))
			for i := range order {
				order[i] = i
			}
			for i := len(order) - 1; i > 0; i-- {
				j := randomIndex(i + 1)
				order[i], order[j] = order[j], order[i]
			}
			for _, i := range order {
				endpoint := serverAddrs[i]
				for sample := 0; sample < samplesPerEndpoint; sample++ {
					token := make([]byte, 8+randomIndex(25))
					if _, err := crand.Read(token); err != nil {
						errCh <- fmt.Errorf("generate adaptive probe token: %w", err)
						return
					}
					tokenKey := hex.EncodeToString(token)
					pendingMu.Lock()
					pending[tokenKey] = probePending{
						endpoint: endpoint.String(),
						sent:     time.Now(),
					}
					pendingMu.Unlock()
					packet, err := cfg.TX.SealProbe(token)
					if err != nil {
						errCh <- fmt.Errorf("seal adaptive probe: %w", err)
						return
					}
					if _, err := outerConn.WriteToUDP(packet, endpoint); err == nil {
						stats.OuterTX.Add(uint64(len(packet)))
						expected++
					} else {
						pendingMu.Lock()
						delete(pending, tokenKey)
						pendingMu.Unlock()
					}

				}
			}

			timer := time.NewTimer(cfg.ProbeTimeout)
			received := 0
		collect:
			for received < expected {
				select {
				case <-runCtx.Done():
					timer.Stop()
					return
				case result := <-probeResults:
					measurements[result.endpoint] = append(measurements[result.endpoint], result.rtt)
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

			for i, name := range serverNames {
				manager.Observe(i, samplesPerEndpoint, measurements[name], now)
			}
			next, switched := manager.Select(now)
			health := manager.Snapshot()
			reachable := 0
			for _, path := range health {
				if path.Reachable {
					reachable++
				}
			}
			setSelected(next, time.Duration(health[next].RTTMS*float64(time.Millisecond)), reachable, switched)
			wait := cfg.ProbeInterval
			select {
			case <-runCtx.Done():
				return
			case <-time.After(wait):
			}
		}
	}()

	return <-errCh
}

func randomDuration(minimum, maximum time.Duration) time.Duration {
	if maximum <= minimum {
		return minimum
	}
	span := uint64(maximum - minimum)
	var raw [8]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return minimum
	}
	value := uint64(raw[0]) |
		uint64(raw[1])<<8 |
		uint64(raw[2])<<16 |
		uint64(raw[3])<<24 |
		uint64(raw[4])<<32 |
		uint64(raw[5])<<40 |
		uint64(raw[6])<<48 |
		uint64(raw[7])<<56
	return minimum + time.Duration(value%(span+1))
}

func randomIndex(count int) int {
	if count <= 1 {
		return 0
	}
	var raw [2]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return 0
	}
	return int((uint16(raw[0]) | uint16(raw[1])<<8) % uint16(count))
}

func RunServer(ctx context.Context, cfg ServerConfig) error {
	listenAddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("resolve listen address: %w", err)
	}
	targetAddr, err := net.ResolveUDPAddr("udp", cfg.Target)
	if err != nil {
		return fmt.Errorf("resolve WireGuard target: %w", err)
	}

	outerConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen outer UDP: %w", err)
	}
	defer outerConn.Close()
	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return fmt.Errorf("connect WireGuard target: %w", err)
	}
	defer targetConn.Close()

	var clientMu sync.RWMutex
	var clientPeer *net.UDPAddr
	stats := &Stats{}
	stop := make(chan struct{})
	defer close(stop)
	if cfg.StatsInterval > 0 {
		go logStats(stop, cfg.Logger, "server", stats, cfg.StatsInterval)
	}
	go func() {
		<-ctx.Done()
		_ = outerConn.Close()
		_ = targetConn.Close()
	}()

	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := outerConn.ReadFromUDP(buf)
			if err != nil {
				errCh <- normalizeNetErr(ctx, err)
				return
			}
			stats.OuterRX.Add(uint64(n))
			inner, err := cfg.RX.Open(buf[:n])
			if err != nil {
				stats.AuthDrops.Add(1)
				continue
			}
			clientMu.Lock()
			clientPeer = cloneUDPAddr(addr)
			clientMu.Unlock()
			if _, err := targetConn.Write(inner); err != nil {
				errCh <- normalizeNetErr(ctx, fmt.Errorf("forward to WireGuard target: %w", err))
				return
			}
			stats.InnerTX.Add(uint64(len(inner)))
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				errCh <- normalizeNetErr(ctx, err)
				return
			}
			stats.InnerRX.Add(uint64(n))
			clientMu.RLock()
			peer := cloneUDPAddr(clientPeer)
			clientMu.RUnlock()
			if peer == nil {
				stats.NoPeerDrop.Add(1)
				continue
			}
			outer, err := cfg.TX.Seal(buf[:n])
			if err != nil {
				errCh <- fmt.Errorf("seal return packet: %w", err)
				return
			}
			if _, err := outerConn.WriteToUDP(outer, peer); err != nil {
				errCh <- normalizeNetErr(ctx, fmt.Errorf("send return outer UDP: %w", err))
				return
			}
			stats.OuterTX.Add(uint64(len(outer)))
		}
	}()

	return <-errCh
}

func logStats(stop <-chan struct{}, logger *log.Logger, mode string, stats *Stats, interval time.Duration) {
	if logger == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			logger.Printf("mode=%s inner_tx=%d inner_rx=%d outer_tx=%d outer_rx=%d auth_drops=%d no_peer_drops=%d",
				mode,
				stats.InnerTX.Load(),
				stats.InnerRX.Load(),
				stats.OuterTX.Load(),
				stats.OuterRX.Load(),
				stats.AuthDrops.Load(),
				stats.NoPeerDrop.Load(),
			)
		}
	}
}

func normalizeNetErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	out := *addr
	if addr.IP != nil {
		out.IP = append(net.IP(nil), addr.IP...)
	}
	return &out
}
