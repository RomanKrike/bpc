package routed

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RomanKrike/bpc/internal/wgshim"
)

const (
	probeInterval = 250 * time.Millisecond
	probeTimeout  = 400 * time.Millisecond
	linkFailAfter = time.Second
)

type LinkStatus struct {
	ID          string  `json:"id"`
	From        string  `json:"from"`
	To          string  `json:"to"`
	PeerName    string  `json:"peer_name"`
	Health      string  `json:"health"`
	RTTMS       float64 `json:"rtt_ms"`
	LossPercent float64 `json:"loss_percent"`
	Cost        float64 `json:"cost"`
	LastSeen    int64   `json:"last_seen"`
	Endpoint    string  `json:"endpoint,omitempty"`
}

type meshPeer struct {
	configMu    sync.RWMutex
	config      LinkConfig
	fingerprint [32]byte
	tx          *wgshim.Codec
	rx          *wgshim.Codec

	addrMu       sync.RWMutex
	addr         *net.UDPAddr
	addressSince time.Time

	metricMu  sync.Mutex
	lastAuth  time.Time
	lastReply time.Time
	lastRTT   time.Duration
	samples   []bool

	sendSeq     atomic.Uint64
	recvMu      sync.Mutex
	recvHigh    uint64
	recvMask    uint64
	localEpoch  [16]byte
	remoteEpoch [16]byte
}

func (p *meshPeer) setAddress(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	copyAddr := *addr
	copyAddr.IP = append(net.IP(nil), addr.IP...)
	now := time.Now()

	p.addrMu.Lock()
	changed := p.addr == nil || !p.addr.IP.Equal(copyAddr.IP) || p.addr.Port != copyAddr.Port
	p.addr = &copyAddr
	if changed {
		p.addressSince = now
	}
	p.addrMu.Unlock()

	if changed {
		p.metricMu.Lock()
		p.lastReply = time.Time{}
		p.samples = nil
		p.metricMu.Unlock()
	}
}

func (p *meshPeer) address() *net.UDPAddr {
	p.addrMu.RLock()
	defer p.addrMu.RUnlock()
	if p.addr == nil {
		return nil
	}
	copyAddr := *p.addr
	copyAddr.IP = append(net.IP(nil), p.addr.IP...)
	return &copyAddr
}

func (p *meshPeer) markAuth(now time.Time) {
	p.metricMu.Lock()
	p.lastAuth = now
	p.metricMu.Unlock()
}

func (p *meshPeer) recordProbe(ok bool, rtt time.Duration, now time.Time) {
	p.metricMu.Lock()
	if ok {
		p.lastAuth = now
		p.lastReply = now
		p.lastRTT = rtt
	}
	p.samples = append(p.samples, ok)
	if len(p.samples) > 20 {
		p.samples = append([]bool(nil), p.samples[len(p.samples)-20:]...)
	}
	p.metricMu.Unlock()
}

func (p *meshPeer) status(localNodeID string, now time.Time) LinkStatus {
	p.metricMu.Lock()
	lastAuth := p.lastAuth
	lastReply := p.lastReply
	lastRTT := p.lastRTT
	samples := append([]bool(nil), p.samples...)
	p.metricMu.Unlock()

	p.addrMu.RLock()
	hasAddress := p.addr != nil
	addressSince := p.addressSince
	endpoint := ""
	if p.addr != nil {
		endpoint = p.addr.String()
	}
	p.addrMu.RUnlock()

	health := "unknown"
	if hasAddress {
		switch {
		case !lastReply.IsZero() && now.Sub(lastReply) <= linkFailAfter:
			health = "healthy"
		case !addressSince.IsZero() && now.Sub(addressSince) <= linkFailAfter:
			health = "degraded"
		default:
			health = "failed"
		}
	}
	loss := 0.0
	if len(samples) > 0 {
		failed := 0
		for _, sample := range samples {
			if !sample {
				failed++
			}
		}
		loss = float64(failed) * 100 / float64(len(samples))
	}
	lastSeen := int64(0)
	if !lastReply.IsZero() {
		lastSeen = lastReply.Unix()
	} else if !lastAuth.IsZero() {
		lastSeen = lastAuth.Unix()
	}
	return LinkStatus{
		ID:          p.configuration().ID,
		From:        localNodeID,
		To:          p.configuration().PeerNodeID,
		PeerName:    p.configuration().PeerName,
		Health:      health,
		RTTMS:       float64(lastRTT.Microseconds()) / 1000,
		LossPercent: loss,
		Cost:        p.configuration().Cost,
		LastSeen:    lastSeen,
		Endpoint:    endpoint,
	}
}
func (p *meshPeer) nextSequence() uint64 {
	return p.sendSeq.Add(1)
}

func (p *meshPeer) acceptSequence(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	p.recvMu.Lock()
	defer p.recvMu.Unlock()
	return p.acceptSequenceLocked(sequence)
}

func (p *meshPeer) acceptSequenceLocked(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	if p.recvHigh == 0 {
		p.recvHigh = sequence
		p.recvMask = 1
		return true
	}
	if sequence > p.recvHigh {
		shift := sequence - p.recvHigh
		if shift >= 64 {
			p.recvMask = 1
		} else {
			p.recvMask = (p.recvMask << shift) | 1
		}
		p.recvHigh = sequence
		return true
	}
	delta := p.recvHigh - sequence
	if delta >= 64 {
		return false
	}
	bit := uint64(1) << delta
	if p.recvMask&bit != 0 {
		return false
	}
	p.recvMask |= bit
	return true
}

type pendingProbe struct {
	peerID   string
	sent     time.Time
	endpoint string
}

type Mesh struct {
	resolve     func(string, string) (*net.UDPAddr, error)
	localNodeID string
	conn        *net.UDPConn
	logger      *log.Logger

	peersMu sync.RWMutex
	peers   map[string]*meshPeer

	pendingMu sync.Mutex
	pending   map[string]pendingProbe

	onDataMu sync.RWMutex
	onData   func(peerID string, payload []byte)
}

func NewMesh(localNodeID string, listenPort int, logger *log.Logger) (*Mesh, error) {
	if localNodeID == "" {
		return nil, fmt.Errorf("local Node id is required")
	}
	if listenPort == 0 {
		listenPort = DefaultMeshPort
	}
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", listenPort))
	if err != nil {
		return nil, fmt.Errorf("resolve mesh listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen routed mesh UDP: %w", err)
	}
	return &Mesh{
		resolve:     net.ResolveUDPAddr,
		localNodeID: localNodeID,
		conn:        conn,
		logger:      logger,
		peers:       make(map[string]*meshPeer),
		pending:     make(map[string]pendingProbe),
	}, nil
}

func (m *Mesh) Close() error {
	return m.conn.Close()
}

func (m *Mesh) SetDataHandler(handler func(peerID string, payload []byte)) {
	m.onDataMu.Lock()
	m.onData = handler
	m.onDataMu.Unlock()
}

func makePeer(localNodeID string, config LinkConfig, resolve func(string, string) (*net.UDPAddr, error)) (*meshPeer, error) {
	psk, err := config.PSKBytes()
	if err != nil {
		return nil, err
	}
	txDirection := wgshim.ClientToServer
	rxDirection := wgshim.ServerToClient
	if localNodeID > config.PeerNodeID {
		txDirection = wgshim.ServerToClient
		rxDirection = wgshim.ClientToServer
	}
	txKey, err := wgshim.DeriveKey(psk, txDirection)
	if err != nil {
		return nil, err
	}
	rxKey, err := wgshim.DeriveKey(psk, rxDirection)
	if err != nil {
		return nil, err
	}
	tx, err := wgshim.NewCodec(txKey, 0, 31)
	if err != nil {
		return nil, err
	}
	rx, err := wgshim.NewCodec(rxKey, 0, 31)
	if err != nil {
		return nil, err
	}
	peer := &meshPeer{
		config:      config,
		fingerprint: sha256.Sum256(psk),
		tx:          tx,
		rx:          rx,
	}
	if _, err := rand.Read(peer.localEpoch[:]); err != nil {
		return nil, fmt.Errorf("create routed session epoch: %w", err)
	}
	if config.PeerEndpoint != "" {
		if resolve == nil {
			resolve = net.ResolveUDPAddr
		}
		// A transient DNS failure is a path failure, not a failure of the pool.
		if addr, err := resolve("udp", config.PeerEndpoint); err == nil {
			peer.setAddress(addr)
		}
	}
	return peer, nil
}

func (m *Mesh) Reconcile(links []LinkConfig) error {
	next := make(map[string]*meshPeer, len(links))
	m.peersMu.RLock()
	current := make(map[string]*meshPeer, len(m.peers))
	for id, peer := range m.peers {
		current[id] = peer
	}
	m.peersMu.RUnlock()

	for _, config := range links {
		if err := config.Validate(m.localNodeID); err != nil {
			return err
		}
		candidate, err := makePeer(m.localNodeID, config, m.resolve)
		if err != nil {
			return err
		}
		if config.PeerEndpoint != "" && candidate.address() == nil && m.logger != nil {
			m.logger.Printf("routed endpoint unresolved peer=%s endpoint=%s; retaining other uplinks", config.PeerNodeID, config.PeerEndpoint)
		}
		if previous := current[config.PeerNodeID]; previous != nil &&
			previous.configuration().ID == config.ID &&
			previous.fingerprint == candidate.fingerprint {
			previous.configMu.Lock()
			previous.config = config
			previous.configMu.Unlock()
			// Keep a working learned endpoint when DNS is temporarily down.
			// Config reconciliation retries resolution without replacing session
			// epochs, keys or the replay window.
			if addr := candidate.address(); addr != nil {
				previous.setAddress(addr)
			}

			next[config.PeerNodeID] = previous
			continue
		}
		next[config.PeerNodeID] = candidate
	}

	m.peersMu.Lock()
	m.peers = next
	m.peersMu.Unlock()
	return nil
}

func (m *Mesh) peer(peerID string) *meshPeer {
	m.peersMu.RLock()
	defer m.peersMu.RUnlock()
	return m.peers[peerID]
}

func (m *Mesh) peerSnapshot() []*meshPeer {
	m.peersMu.RLock()
	defer m.peersMu.RUnlock()
	result := make([]*meshPeer, 0, len(m.peers))
	for _, peer := range m.peers {
		result = append(result, peer)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].configuration().PeerNodeID < result[j].configuration().PeerNodeID
	})
	return result
}

func (m *Mesh) Send(peerID string, payload []byte) error {
	peer := m.peer(peerID)
	if peer == nil {
		return fmt.Errorf("routed peer %s is not configured", peerID)
	}
	addr := peer.address()
	if addr == nil {
		return fmt.Errorf("routed peer %s has no learned endpoint", peerID)
	}
	plaintext, err := peer.dataEnvelope(payload)
	if err != nil {
		return err
	}

	packet, err := peer.tx.Seal(plaintext)
	if err != nil {
		return fmt.Errorf("seal routed packet: %w", err)
	}
	if _, err := m.conn.WriteToUDP(packet, addr); err != nil {
		return fmt.Errorf("send routed packet to %s: %w", peerID, err)
	}
	return nil
}

func (m *Mesh) CanSend(peerID string) bool {
	peer := m.peer(peerID)
	if peer == nil || peer.address() == nil {
		return false
	}
	return peer.sessionReady() && peer.status(m.localNodeID, time.Now()).Health != "failed"
}

func (m *Mesh) Status() []LinkStatus {
	now := time.Now()
	peers := m.peerSnapshot()
	result := make([]LinkStatus, 0, len(peers))
	for _, peer := range peers {
		result = append(result, peer.status(m.localNodeID, now))
	}
	return result
}

func (m *Mesh) LinkStatus(peerID string) (LinkStatus, bool) {
	peer := m.peer(peerID)
	if peer == nil {
		return LinkStatus{}, false
	}
	return peer.status(m.localNodeID, time.Now()), true
}

func (m *Mesh) runReceive(ctx context.Context) error {
	buf := make([]byte, 65535)
	for {
		n, addr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read routed mesh UDP: %w", err)
		}
		packet := append([]byte(nil), buf[:n]...)
		var (
			matched    *meshPeer
			packetType byte
			plaintext  []byte
		)
		for _, peer := range m.peerSnapshot() {
			kind, opened, openErr := peer.rx.OpenTyped(packet)
			if openErr != nil {
				continue
			}
			matched = peer
			packetType = kind
			plaintext = opened
			break
		}
		if matched == nil {
			continue
		}
		now := time.Now()
		switch {
		case wgshim.IsProbe(packetType):
			if len(plaintext) != 32 {
				continue
			}
			response := append(append([]byte(nil), plaintext...), matched.localEpoch[:]...)
			reply, err := matched.tx.SealProbeReply(response)
			if err != nil {
				continue
			}
			_, _ = m.conn.WriteToUDP(reply, addr)
			// An authenticated but replayable request cannot change endpoint or
			// replay state. Challenge the sender before learning a new session.
			if !matched.matchesRemoteEpoch(plaintext[:16]) || !sameUDPAddress(matched.address(), addr) {
				m.sendProbeTo(matched, addr, now)
			}
		case wgshim.IsProbeReply(packetType):
			if len(plaintext) != 48 {
				continue
			}
			token := hex.EncodeToString(plaintext[:32])
			m.pendingMu.Lock()
			pending, ok := m.pending[token]
			if ok && pending.peerID == matched.configuration().PeerNodeID && pending.endpoint == addr.String() {
				delete(m.pending, token)
			} else {
				ok = false
			}
			m.pendingMu.Unlock()
			if ok {
				matched.confirmRemoteEpoch(plaintext[32:])
				matched.setAddress(addr)
				matched.recordProbe(true, now.Sub(pending.sent), now)
			}
		case wgshim.IsData(packetType):
			payload, ok := matched.acceptDataEnvelope(plaintext)
			if !ok {
				continue
			}
			matched.setAddress(addr)
			matched.markAuth(now)
			m.onDataMu.RLock()
			handler := m.onData
			m.onDataMu.RUnlock()
			if handler != nil {
				handler(matched.configuration().PeerNodeID, payload)
			}
		}
	}
}

func (m *Mesh) expireProbes(now time.Time) {
	var expired []pendingProbe
	m.pendingMu.Lock()
	for token, pending := range m.pending {
		if now.Sub(pending.sent) >= probeTimeout {
			delete(m.pending, token)
			expired = append(expired, pending)
		}
	}
	m.pendingMu.Unlock()
	for _, pending := range expired {
		if peer := m.peer(pending.peerID); peer != nil {
			peer.recordProbe(false, 0, now)
		}
	}
}

func (m *Mesh) sendProbe(peer *meshPeer, now time.Time) {
	m.sendProbeTo(peer, peer.address(), now)
}

func (m *Mesh) sendProbeTo(peer *meshPeer, addr *net.UDPAddr, now time.Time) {
	if addr == nil {
		return
	}
	peerID := peer.configuration().PeerNodeID
	tokenRaw := make([]byte, 32)
	copy(tokenRaw, peer.localEpoch[:])
	if _, err := rand.Read(tokenRaw[16:]); err != nil {
		return
	}
	packet, err := peer.tx.SealProbe(tokenRaw)
	if err != nil {
		return
	}
	token := hex.EncodeToString(tokenRaw)
	m.pendingMu.Lock()
	// Bound challenges even if captured probe requests are replayed in a flood.
	for _, pending := range m.pending {
		if pending.peerID == peerID {
			m.pendingMu.Unlock()
			return
		}
	}
	m.pending[token] = pendingProbe{peerID: peerID, sent: now, endpoint: addr.String()}
	m.pendingMu.Unlock()
	if _, err := m.conn.WriteToUDP(packet, addr); err != nil {
		m.pendingMu.Lock()
		delete(m.pending, token)
		m.pendingMu.Unlock()
		peer.recordProbe(false, 0, now)
	}
}

func sameUDPAddress(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.String() == b.String()
}

func (m *Mesh) runProbes(ctx context.Context) {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.expireProbes(now)
			for _, peer := range m.peerSnapshot() {
				m.sendProbe(peer, now)
			}
		}
	}
}

func (m *Mesh) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = m.conn.Close()
	}()
	go m.runProbes(ctx)
	err := m.runReceive(ctx)
	if err != nil && m.logger != nil {
		m.logger.Printf("routed mesh stopped: %v", err)
	}
	return err
}
