package wgshim

import (
	"context"
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
