package wgshim

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	tcpFrameHeaderSize = 4
	maxTCPFrameSize    = 65535
)

type TCPClientConfig struct {
	LocalListen   string
	Server        string
	TX            *Codec
	RX            *Codec
	Logger        *log.Logger
	StatsInterval time.Duration
}

type TCPMultiServerConfig struct {
	Listen         string
	Target         string
	LoadPeers      func() (map[string]MultiServerPeer, error)
	ReloadInterval time.Duration
	Logger         *log.Logger
	StatsInterval  time.Duration
}

func writeTCPFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxTCPFrameSize {
		return fmt.Errorf("invalid TCP frame size %d", len(payload))
	}
	var header [tcpFrameHeaderSize]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[n:]
	}
	return nil
}

func readTCPFrame(r io.Reader) ([]byte, error) {
	var header [tcpFrameHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint32(header[:]))
	if size <= 0 || size > maxTCPFrameSize {
		return nil, fmt.Errorf("invalid TCP frame size %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

type tcpClientLink struct {
	server string
	logger *log.Logger

	mu      sync.RWMutex
	conn    *net.TCPConn
	writeMu sync.Mutex
	recv    chan []byte
}

func newTCPClientLink(server string, logger *log.Logger) *tcpClientLink {
	return &tcpClientLink{
		server: server,
		logger: logger,
		recv:   make(chan []byte, 256),
	}
}

func (l *tcpClientLink) current() *net.TCPConn {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.conn
}

func (l *tcpClientLink) connected() bool {
	return l.current() != nil
}

func (l *tcpClientLink) set(conn *net.TCPConn) {
	l.mu.Lock()
	l.conn = conn
	l.mu.Unlock()
}

func (l *tcpClientLink) clear(expected *net.TCPConn) {
	l.mu.Lock()
	if l.conn == expected {
		l.conn = nil
	}
	l.mu.Unlock()
}

func (l *tcpClientLink) close() {
	conn := l.current()
	if conn != nil {
		_ = conn.Close()
	}
}

func (l *tcpClientLink) send(payload []byte) error {
	conn := l.current()
	if conn == nil {
		return errors.New("TCP transport is disconnected")
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	err := writeTCPFrame(conn, payload)
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		l.clear(conn)
		_ = conn.Close()
		return err
	}
	return nil
}

func (l *tcpClientLink) run(ctx context.Context) {
	defer close(l.recv)
	for ctx.Err() == nil {
		dialer := net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		raw, err := dialer.DialContext(ctx, "tcp", l.server)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if l.logger != nil {
				l.logger.Printf("TCP transport connect failed server=%s err=%v", l.server, err)
			}
			if !sleepContext(ctx, time.Second) {
				return
			}
			continue
		}
		conn, ok := raw.(*net.TCPConn)
		if !ok {
			_ = raw.Close()
			if !sleepContext(ctx, time.Second) {
				return
			}
			continue
		}
		_ = conn.SetNoDelay(true)
		_ = conn.SetKeepAlive(true)
		_ = conn.SetKeepAlivePeriod(30 * time.Second)
		l.set(conn)
		if l.logger != nil {
			l.logger.Printf("TCP transport connected server=%s", l.server)
		}

		for ctx.Err() == nil {
			frame, readErr := readTCPFrame(conn)
			if readErr != nil {
				break
			}
			select {
			case l.recv <- frame:
			case <-ctx.Done():
				l.clear(conn)
				_ = conn.Close()
				return
			}
		}
		l.clear(conn)
		_ = conn.Close()
		if ctx.Err() == nil {
			if l.logger != nil {
				l.logger.Printf("TCP transport disconnected server=%s; reconnecting", l.server)
			}
			if !sleepContext(ctx, 500*time.Millisecond) {
				return
			}
		}
	}
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func RunTCPClient(ctx context.Context, cfg TCPClientConfig) error {
	localAddr, err := net.ResolveUDPAddr("udp", cfg.LocalListen)
	if err != nil {
		return fmt.Errorf("resolve local listen address: %w", err)
	}
	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("listen for WireGuard: %w", err)
	}
	defer localConn.Close()

	link := newTCPClientLink(cfg.Server, cfg.Logger)
	go link.run(ctx)
	defer link.close()

	stats := &Stats{}
	stopStats := make(chan struct{})
	defer close(stopStats)
	if cfg.StatsInterval > 0 {
		go logStats(stopStats, cfg.Logger, "tcp-client", stats, cfg.StatsInterval)
	}

	var wgPeerMu sync.RWMutex
	var wgPeer *net.UDPAddr

	go func() {
		<-ctx.Done()
		_ = localConn.Close()
		link.close()
	}()

	errCh := make(chan error, 2)
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
			if sendErr := link.send(outer); sendErr != nil {
				continue
			}
			stats.OuterTX.Add(uint64(len(outer)))
		}
	}()

	go func() {
		for frame := range link.recv {
			stats.OuterRX.Add(uint64(len(frame)))
			packetType, inner, openErr := cfg.RX.OpenTyped(frame)
			if openErr != nil {
				stats.AuthDrops.Add(1)
				continue
			}
			if !IsData(packetType) {
				continue
			}
			wgPeerMu.RLock()
			peer := cloneUDPAddr(wgPeer)
			wgPeerMu.RUnlock()
			if peer == nil {
				stats.NoPeerDrop.Add(1)
				continue
			}
			if _, writeErr := localConn.WriteToUDP(inner, peer); writeErr != nil {
				errCh <- normalizeNetErr(ctx, fmt.Errorf("deliver TCP packet to WireGuard: %w", writeErr))
				return
			}
			stats.InnerRX.Add(uint64(len(inner)))
		}
		errCh <- normalizeNetErr(ctx, errors.New("TCP receive loop stopped"))
	}()

	return <-errCh
}

func RunTCPMultiServer(ctx context.Context, cfg TCPMultiServerConfig) error {
	if cfg.LoadPeers == nil {
		return errors.New("TCP multi-server peer loader is required")
	}
	if cfg.ReloadInterval <= 0 {
		cfg.ReloadInterval = time.Second
	}

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen TCP outer transport: %w", err)
	}
	defer listener.Close()

	targetAddr, err := net.ResolveUDPAddr("udp", cfg.Target)
	if err != nil {
		return fmt.Errorf("resolve WireGuard target: %w", err)
	}

	var peersMu sync.RWMutex
	peers := map[string]MultiServerPeer{}
	reloadPeers := func() error {
		next, loadErr := cfg.LoadPeers()
		if loadErr != nil {
			return loadErr
		}
		for id, peer := range next {
			if id == "" || peer.RX == nil || peer.TX == nil || peer.Fingerprint == "" {
				return fmt.Errorf("invalid TCP multi-server peer %q", id)
			}
		}
		peersMu.Lock()
		peers = next
		peersMu.Unlock()
		return nil
	}
	if err := reloadPeers(); err != nil {
		return fmt.Errorf("load TCP multi-server peers: %w", err)
	}

	getPeer := func(id string) (MultiServerPeer, bool) {
		peersMu.RLock()
		defer peersMu.RUnlock()
		peer, ok := peers[id]
		return peer, ok
	}
	matchPeer := func(frame []byte) (string, MultiServerPeer, byte, []byte, bool) {
		peersMu.RLock()
		defer peersMu.RUnlock()
		for id, peer := range peers {
			packetType, inner, openErr := peer.RX.OpenTyped(frame)
			if openErr != nil {
				continue
			}
			return id, peer, packetType, inner, true
		}
		return "", MultiServerPeer{}, 0, nil, false
	}

	stats := &Stats{}
	stopStats := make(chan struct{})
	defer close(stopStats)
	if cfg.StatsInterval > 0 {
		go logStats(stopStats, cfg.Logger, "tcp-multi-server", stats, cfg.StatsInterval)
	}

	go func() {
		ticker := time.NewTicker(cfg.ReloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if reloadErr := reloadPeers(); reloadErr != nil && cfg.Logger != nil {
					cfg.Logger.Printf("TCP peer reload failed: %v", reloadErr)
				}
			}
		}
	}()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		rawConn, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(acceptErr, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept TCP outer transport: %w", acceptErr)
		}

		tcpConn, ok := rawConn.(*net.TCPConn)
		if !ok {
			_ = rawConn.Close()
			continue
		}
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)

		wg.Add(1)
		go func(conn *net.TCPConn) {
			defer wg.Done()
			defer conn.Close()

			stopClose := make(chan struct{})
			defer close(stopClose)
			go func() {
				select {
				case <-ctx.Done():
					_ = conn.Close()
				case <-stopClose:
				}
			}()

			var (
				peerID          string
				peerFingerprint string
				targetConn      *net.UDPConn
				targetOnce      sync.Once
				writeMu         sync.Mutex
			)
			defer func() {
				if targetConn != nil {
					_ = targetConn.Close()
				}
			}()

			startTargetReader := func() error {
				var startErr error
				targetOnce.Do(func() {
					targetConn, startErr = net.DialUDP("udp", nil, targetAddr)
					if startErr != nil {
						return
					}
					go func() {
						buf := make([]byte, 65535)
						for {
							n, readErr := targetConn.Read(buf)
							if readErr != nil {
								return
							}
							current, exists := getPeer(peerID)
							if !exists || current.Fingerprint != peerFingerprint {
								return
							}
							outer, sealErr := current.TX.Seal(buf[:n])
							if sealErr != nil {
								if cfg.Logger != nil {
									cfg.Logger.Printf("TCP peer=%s seal return packet failed: %v", peerID, sealErr)
								}
								continue
							}
							writeMu.Lock()
							writeErr := writeTCPFrame(conn, outer)
							writeMu.Unlock()
							if writeErr != nil {
								_ = conn.Close()
								return
							}
							stats.InnerRX.Add(uint64(n))
							stats.OuterTX.Add(uint64(len(outer)))
						}
					}()
				})
				return startErr
			}

			for ctx.Err() == nil {
				frame, readErr := readTCPFrame(conn)
				if readErr != nil {
					return
				}
				stats.OuterRX.Add(uint64(len(frame)))

				var (
					peer       MultiServerPeer
					packetType byte
					inner      []byte
					openErr    error
				)
				if peerID == "" {
					var matched bool
					peerID, peer, packetType, inner, matched = matchPeer(frame)
					if !matched {
						stats.AuthDrops.Add(1)
						return
					}
					peerFingerprint = peer.Fingerprint
				} else {
					var exists bool
					peer, exists = getPeer(peerID)
					if !exists || peer.Fingerprint != peerFingerprint {
						return
					}
					packetType, inner, openErr = peer.RX.OpenTyped(frame)
					if openErr != nil {
						stats.AuthDrops.Add(1)
						return
					}
				}

				if IsProbe(packetType) {
					reply, sealErr := peer.TX.SealProbeReply(inner)
					if sealErr != nil {
						continue
					}
					writeMu.Lock()
					writeErr := writeTCPFrame(conn, reply)
					writeMu.Unlock()
					if writeErr != nil {
						return
					}
					stats.OuterTX.Add(uint64(len(reply)))
					continue
				}
				if !IsData(packetType) {
					continue
				}
				if startErr := startTargetReader(); startErr != nil {
					if cfg.Logger != nil {
						cfg.Logger.Printf("TCP peer=%s target connection failed: %v", peerID, startErr)
					}
					return
				}
				if _, writeErr := targetConn.Write(inner); writeErr != nil {
					return
				}
				stats.InnerTX.Add(uint64(len(inner)))
			}
		}(tcpConn)
	}
}
