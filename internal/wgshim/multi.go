package wgshim

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type MultiServerPeer struct {
	Fingerprint string
	RX          *Codec
	TX          *Codec
}

type MultiServerConfig struct {
	Listen         string
	Target         string
	LoadPeers      func() (map[string]MultiServerPeer, error)
	ReloadInterval time.Duration
	Logger         *log.Logger
	StatsInterval  time.Duration
}

type multiServerSession struct {
	id          string
	fingerprint string
	conn        *net.UDPConn
	tx          *Codec

	peerMu sync.RWMutex
	peer   *net.UDPAddr
}

func (s *multiServerSession) setPeer(peer *net.UDPAddr) {
	s.peerMu.Lock()
	s.peer = cloneUDPAddr(peer)
	s.peerMu.Unlock()
}

func (s *multiServerSession) getPeer() *net.UDPAddr {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return cloneUDPAddr(s.peer)
}

func RunMultiServer(ctx context.Context, cfg MultiServerConfig) error {
	if cfg.LoadPeers == nil {
		return fmt.Errorf("multi-server peer loader is required")
	}
	if cfg.ReloadInterval <= 0 {
		cfg.ReloadInterval = time.Second
	}

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

	var peersMu sync.RWMutex
	peers := map[string]MultiServerPeer{}
	var sessionsMu sync.Mutex
	sessions := map[string]*multiServerSession{}

	closeSession := func(id string, expected *multiServerSession) {
		sessionsMu.Lock()
		session, ok := sessions[id]
		if ok && (expected == nil || session == expected) {
			delete(sessions, id)
			_ = session.conn.Close()
		}
		sessionsMu.Unlock()
	}

	reloadPeers := func() error {
		next, err := cfg.LoadPeers()
		if err != nil {
			return err
		}
		for id, peer := range next {
			if id == "" || peer.RX == nil || peer.TX == nil || peer.Fingerprint == "" {
				return fmt.Errorf("invalid multi-server peer %q", id)
			}
		}

		peersMu.Lock()
		peers = next
		peersMu.Unlock()

		sessionsMu.Lock()
		for id, session := range sessions {
			peer, ok := next[id]
			if !ok || peer.Fingerprint != session.fingerprint {
				delete(sessions, id)
				_ = session.conn.Close()
			}
		}
		sessionsMu.Unlock()
		return nil
	}
	if err := reloadPeers(); err != nil {
		return fmt.Errorf("load multi-server peers: %w", err)
	}

	stats := &Stats{}
	stopStats := make(chan struct{})
	defer close(stopStats)
	if cfg.StatsInterval > 0 {
		go logStats(stopStats, cfg.Logger, "multi-server", stats, cfg.StatsInterval)
	}

	go func() {
		<-ctx.Done()
		_ = outerConn.Close()
		sessionsMu.Lock()
		for id, session := range sessions {
			delete(sessions, id)
			_ = session.conn.Close()
		}
		sessionsMu.Unlock()
	}()

	reloadDone := make(chan struct{})
	defer close(reloadDone)
	go func() {
		ticker := time.NewTicker(cfg.ReloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-reloadDone:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := reloadPeers(); err != nil && cfg.Logger != nil {
					cfg.Logger.Printf("peer reload failed: %v", err)
				}
			}
		}
	}()

	startSession := func(id string, peer MultiServerPeer) (*multiServerSession, error) {
		sessionsMu.Lock()
		if existing := sessions[id]; existing != nil {
			sessionsMu.Unlock()
			return existing, nil
		}
		targetConn, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			sessionsMu.Unlock()
			return nil, fmt.Errorf("connect WireGuard target for peer %s: %w", id, err)
		}
		session := &multiServerSession{
			id:          id,
			fingerprint: peer.Fingerprint,
			conn:        targetConn,
			tx:          peer.TX,
		}
		sessions[id] = session
		sessionsMu.Unlock()

		go func() {
			defer closeSession(id, session)
			buf := make([]byte, 65535)
			for {
				n, err := targetConn.Read(buf)
				if err != nil {
					if ctx.Err() == nil && cfg.Logger != nil {
						cfg.Logger.Printf("peer=%s target read stopped: %v", id, err)
					}
					return
				}
				stats.InnerRX.Add(uint64(n))
				outerPeer := session.getPeer()
				if outerPeer == nil {
					stats.NoPeerDrop.Add(1)
					continue
				}
				outer, err := session.tx.Seal(buf[:n])
				if err != nil {
					if cfg.Logger != nil {
						cfg.Logger.Printf("peer=%s seal return packet failed: %v", id, err)
					}
					continue
				}
				if _, err := outerConn.WriteToUDP(outer, outerPeer); err != nil {
					if ctx.Err() == nil && cfg.Logger != nil {
						cfg.Logger.Printf("peer=%s send return outer UDP failed: %v", id, err)
					}
					continue
				}
				stats.OuterTX.Add(uint64(len(outer)))
			}
		}()
		return session, nil
	}

	buf := make([]byte, 65535)
	for {
		n, addr, err := outerConn.ReadFromUDP(buf)
		if err != nil {
			return normalizeNetErr(ctx, err)
		}
		stats.OuterRX.Add(uint64(n))

		peersMu.RLock()
		snapshot := make(map[string]MultiServerPeer, len(peers))
		for id, peer := range peers {
			snapshot[id] = peer
		}
		peersMu.RUnlock()

		var (
			matchedID   string
			matchedPeer MultiServerPeer
			packetType  byte
			inner       []byte
		)
		for id, peer := range snapshot {
			decodedType, decoded, openErr := peer.RX.OpenTyped(buf[:n])
			if openErr != nil {
				continue
			}
			matchedID = id
			matchedPeer = peer
			packetType = decodedType
			inner = decoded
			break
		}
		if matchedID == "" {
			stats.AuthDrops.Add(1)
			continue
		}

		if IsProbe(packetType) {
			reply, sealErr := matchedPeer.TX.SealProbeReply(inner)
			if sealErr != nil {
				if cfg.Logger != nil {
					cfg.Logger.Printf("peer=%s seal probe reply failed: %v", matchedID, sealErr)
				}
				continue
			}
			if _, writeErr := outerConn.WriteToUDP(reply, addr); writeErr != nil {
				if ctx.Err() == nil && cfg.Logger != nil {
					cfg.Logger.Printf("peer=%s send probe reply failed: %v", matchedID, writeErr)
				}
				continue
			}
			stats.OuterTX.Add(uint64(len(reply)))
			continue
		}
		if !IsData(packetType) {
			continue
		}

		session, err := startSession(matchedID, matchedPeer)
		if err != nil {
			if cfg.Logger != nil {
				cfg.Logger.Printf("peer=%s session start failed: %v", matchedID, err)
			}
			continue
		}
		session.setPeer(addr)
		if _, err := session.conn.Write(inner); err != nil {
			if cfg.Logger != nil {
				cfg.Logger.Printf("peer=%s forward to WireGuard target failed: %v", matchedID, err)
			}
			closeSession(matchedID, session)
			continue
		}
		stats.InnerTX.Add(uint64(len(inner)))
	}
}
