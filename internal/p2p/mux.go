package p2p

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// MuxTUN shares one BPC-owned OS adapter with the unchanged gateway peer and
// per-session WireGuard devices. Reserved peer /32s NEVER fall back to gateway,
// even when a session fails, expires or stops. Reservations last until Close.
type MuxTUN struct {
	tun.Device
	mu        sync.RWMutex
	peers     map[netip.Addr]*peerTUN
	gateway   chan []byte
	done      chan struct{}
	readDone  chan struct{}
	once      sync.Once
	closeOnce sync.Once
	closeErr  error
	writeMu   sync.Mutex
}

func NewMuxTUN(base tun.Device) (*MuxTUN, error) {
	if base == nil {
		return nil, errors.New("owned BPC TUN required")
	}
	m := &MuxTUN{Device: base, peers: make(map[netip.Addr]*peerTUN), gateway: make(chan []byte, 128), done: make(chan struct{}), readDone: make(chan struct{})}
	go m.dispatch()
	return m, nil
}

// Reserve is called only after verifying the signed grant and local keys.
func (m *MuxTUN) Reserve(peer netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return io.ErrClosedPipe
	default:
	}
	if !peer.Is4() || !peer.IsPrivate() {
		return errors.New("private peer /32 required")
	}
	if _, ok := m.peers[peer]; !ok {
		if len(m.peers) >= MaxManagedSessions {
			return errors.New("P2P reservation limit reached")
		}
		m.peers[peer] = nil
	}
	return nil
}

func (m *MuxTUN) Attach(peer netip.Addr, policy *Policy) (tun.Device, error) {
	if policy == nil {
		return nil, errors.New("P2P endpoint policy required")
	}
	if err := m.Reserve(peer); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return nil, io.ErrClosedPipe
	default:
	}
	if m.peers[peer] != nil {
		return nil, errors.New("P2P peer already attached")
	}
	// Binding is checked here as well as by the packet filter.
	if policy.session.grant.Participants[1-policy.side].Address != peer {
		return nil, errors.New("P2P mux peer mismatch")
	}
	p := &peerTUN{owner: m, peer: peer, queue: make(chan []byte, 128), done: make(chan struct{}), events: make(chan tun.Event, 1)}
	p.events <- tun.EventUp
	m.peers[peer] = p
	return NewFilterTUN(p, policy)
}

func packetAddresses(p []byte) (netip.Addr, netip.Addr, bool) {
	// Route even malformed/fragmented IPv4 to the peer filter, never gateway.
	if len(p) < 20 || p[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20])), true
}

func (m *MuxTUN) dispatch() {
	defer close(m.readDone)
	defer m.signalClose()
	n := m.Device.BatchSize()
	if n < 1 {
		n = 1
	}
	bufs := make([][]byte, n)
	sizes := make([]int, n)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	for {
		count, err := m.Device.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := 0; i < count; i++ {
			if sizes[i] < 0 || sizes[i] > len(bufs[i]) {
				continue
			}
			packet := bufs[i][:sizes[i]]
			_, dst, ipv4 := packetAddresses(packet)
			m.mu.RLock()
			peer, reserved := m.peers[dst]
			if ipv4 && reserved {
				if peer != nil {
					select {
					case peer.queue <- append([]byte(nil), packet...):
					default:
					}
				}
			} else {
				select {
				case m.gateway <- append([]byte(nil), packet...):
				default:
				}
			}
			m.mu.RUnlock()
		}
	}
}

func readPacket(queue <-chan []byte, done <-chan struct{}, bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 {
		return 0, io.ErrShortBuffer
	}
	select {
	case <-done:
		return 0, io.EOF
	default:
	}
	select {
	case <-done:
		return 0, io.EOF
	case p := <-queue:
		if offset > len(bufs[0]) || len(p) > len(bufs[0])-offset {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], p)
		sizes[0] = len(p)
		return 1, nil
	}
}

func (m *MuxTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		n, err := readPacket(m.gateway, m.done, bufs, sizes, offset)
		if err != nil {
			return n, err
		}
		_, dst, ipv4 := packetAddresses(bufs[0][offset : offset+sizes[0]])
		m.mu.RLock()
		_, reserved := m.peers[dst]
		m.mu.RUnlock()
		if !ipv4 || !reserved {
			return n, nil
		}
		// It may have queued before Reserve. Never hand a stale peer packet
		// to the gateway after the reservation acknowledgement.
	}
}
func (m *MuxTUN) BatchSize() int { return 1 }

// Gateway ingress must not bypass the receiving P2P policy for reserved peers.
func (m *MuxTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		if offset < 0 || offset > len(b) {
			return 0, io.ErrShortBuffer
		}
		src, _, ipv4 := packetAddresses(b[offset:])
		m.mu.RLock()
		_, reserved := m.peers[src]
		m.mu.RUnlock()
		if ipv4 && reserved {
			continue
		}
		m.writeMu.Lock()
		_, err := m.Device.Write([][]byte{b}, offset)
		m.writeMu.Unlock()
		if err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

func (m *MuxTUN) signalClose() {
	m.once.Do(func() {
		close(m.done)
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, p := range m.peers {
			if p != nil {
				p.stop()
			}
		}
	})
}
func (m *MuxTUN) Close() error {
	m.closeOnce.Do(func() { m.signalClose(); m.closeErr = m.Device.Close(); <-m.readDone })
	return m.closeErr
}

type peerTUN struct {
	owner  *MuxTUN
	peer   netip.Addr
	queue  chan []byte
	done   chan struct{}
	events chan tun.Event
	once   sync.Once
}

func (p *peerTUN) File() *os.File        { return nil }
func (p *peerTUN) Name() (string, error) { return "BPC P2P", nil }
func (p *peerTUN) MTU() (int, error) {
	mtu, err := p.owner.Device.MTU()
	if mtu > 1280 {
		mtu = 1280
	}
	return mtu, err
}
func (p *peerTUN) BatchSize() int           { return 1 }
func (p *peerTUN) Events() <-chan tun.Event { return p.events }
func (p *peerTUN) Read(b [][]byte, s []int, o int) (int, error) {
	return readPacket(p.queue, p.done, b, s, o)
}
func (p *peerTUN) Write(b [][]byte, o int) (int, error) {
	select {
	case <-p.done:
		return 0, io.ErrClosedPipe
	default:
	}
	p.owner.writeMu.Lock()
	defer p.owner.writeMu.Unlock()
	return p.owner.Device.Write(b, o)
}
func (p *peerTUN) stop() { p.once.Do(func() { close(p.done); close(p.events) }) }
func (p *peerTUN) Close() error {
	p.owner.mu.Lock()
	defer p.owner.mu.Unlock()
	p.stop()
	if p.owner.peers[p.peer] == p {
		p.owner.peers[p.peer] = nil
	}
	return nil
}
