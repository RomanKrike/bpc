package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const maxDatagram = 4096

type relayAuth struct {
	Ticket []byte `json:"ticket"`
	Side   Side   `json:"side"`
	Proof  []byte `json:"proof"`
}

type relayPeer struct {
	conn net.Conn
	mu   sync.Mutex
}

type relaySession struct {
	session *Session
	hash    [32]byte
	peers   [2]*relayPeer
	joined  [2]bool
	revoked bool
}

// Relay never receives either Device's WireGuard private key. TLS terminates
// here, but its payload remains a Device-to-Device WireGuard datagram.
// This separate protocol/listener does not modify WGShim packet formats.
type Relay struct {
	issuer    ed25519.PublicKey
	cluster   string
	revision  uint64
	mu        sync.Mutex
	sessions  map[string]*relaySession
	denied    map[string]time.Time
	denyUntil time.Time
	forwarded atomic.Uint64
}

func NewRelay(issuer ed25519.PublicKey, cluster string, minRevision uint64) (*Relay, error) {
	if len(issuer) != ed25519.PublicKeySize || cluster == "" {
		return nil, errors.New("P2P relay trust required")
	}
	return &Relay{issuer: bytes.Clone(issuer), cluster: cluster, revision: minRevision, sessions: make(map[string]*relaySession), denied: make(map[string]time.Time)}, nil
}

func (r *Relay) ForwardedBytes() uint64 { return r.forwarded.Load() }

// Revoke is a synchronous local enforcement acknowledgement, not a claim that
// the Controller has delivered the revocation to every relay/endpoint.
func (r *Relay) Revoke(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for key, until := range r.denied {
		if !now.Before(until) {
			delete(r.denied, key)
		}
	}
	// Remember revocation even if it arrives before the first connection. Bound
	// tombstones; exhaustion fails closed instead of forgetting a revocation.
	if len(r.denied) < 4096 {
		r.denied[id] = now.Add(MaxLease)
	} else {
		r.denyUntil = now.Add(MaxLease)
	}
	if s := r.sessions[id]; s != nil {
		s.revoked = true
		for _, p := range s.peers {
			if p != nil {
				_ = p.conn.Close()
			}
		}
	}
}

// Serve takes ownership of the listener for its lifetime. TLS 1.3 plus a fresh
// signed Device challenge authenticate each side; no bearer-only enrollment.
// Unauthenticated connections and admitted sessions have fixed bounds.
func (r *Relay) Serve(ctx context.Context, listener net.Listener, config *tls.Config) error {
	if listener == nil || config == nil || len(config.Certificates) == 0 {
		return errors.New("P2P relay listener and TLS certificate required")
	}
	cfg := config.Clone()
	cfg.MinVersion = tls.VersionTLS13
	if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
		return errors.New("P2P requires TLS 1.3")
	}
	secure := tls.NewListener(listener, cfg)
	defer secure.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = secure.Close()
		case <-done:
		}
	}()
	var workers sync.WaitGroup
	defer workers.Wait()
	// Close connections before waiting for handlers, including on listener error.
	connections := make(map[net.Conn]struct{})
	var connectionsMu sync.Mutex
	defer func() {
		connectionsMu.Lock()
		defer connectionsMu.Unlock()
		for c := range connections {
			_ = c.Close()
		}
	}()
	slots := make(chan struct{}, 128)
	for {
		c, err := secure.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		connectionsMu.Lock()
		connections[c] = struct{}{}
		connectionsMu.Unlock()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots; connectionsMu.Lock(); delete(connections, c); connectionsMu.Unlock(); _ = c.Close() }()
			r.handle(c)
		}()
	}
}

func (r *Relay) handle(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	binding, err := tlsBinding(c)
	if err != nil {
		return
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return
	}
	if err := writeFrame(c, challenge); err != nil {
		return
	}
	raw, err := readFrame(c, maxTicket*2)
	if err != nil {
		return
	}
	var auth relayAuth
	if decodeStrict(raw, &auth) != nil || !auth.Side.valid() {
		return
	}
	session, err := VerifyGrant(auth.Ticket, r.issuer, r.cluster, r.revision, time.Now())
	if err != nil {
		return
	}
	identity, _ := base64.StdEncoding.DecodeString(session.grant.Participants[auth.Side].IdentityKey)
	if !ed25519.Verify(identity, proofMessage(challenge, auth.Ticket, auth.Side, binding), auth.Proof) {
		return
	}
	peer := &relayPeer{conn: c}
	// Serialize the acknowledgement before any forwarded data to this peer.
	peer.mu.Lock()
	room := r.attach(session, auth.Side, peer)
	if room == nil {
		peer.mu.Unlock()
		return
	}
	defer r.Revoke(session.grant.SessionID)
	err = writeFrame(c, []byte("BPC-P2P-READY-v1"))
	peer.mu.Unlock()
	if err != nil {
		return
	}
	_ = c.SetDeadline(session.deadline)
	for {
		packet, err := readFrame(c, maxDatagram)
		if err != nil {
			return
		}
		r.mu.Lock()
		valid := !room.revoked && room.session.active(time.Now())
		target := room.peers[1-auth.Side]
		r.mu.Unlock()
		if !valid {
			return
		}
		if !wireGuardPacket(packet) {
			continue
		}
		if target == nil {
			continue
		}
		target.mu.Lock()
		_ = target.conn.SetWriteDeadline(earlier(session.deadline, time.Now().Add(2*time.Second)))
		err = writeFrame(target.conn, packet)
		target.mu.Unlock()
		if err != nil {
			return
		}
		r.forwarded.Add(uint64(len(packet)))
	}
}

func (r *Relay) attach(s *Session, side Side, peer *relayPeer) *relaySession {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.Before(r.denyUntil) || now.Before(r.denied[s.grant.SessionID]) {
		return nil
	}
	for id, room := range r.sessions {
		if !room.session.active(now) {
			delete(r.sessions, id)
			for _, p := range room.peers {
				if p != nil {
					_ = p.conn.Close()
				}
			}
		}
	}
	id := s.grant.SessionID
	room := r.sessions[id]
	hash := sha256.Sum256(s.ticket)
	if room == nil {
		if len(r.sessions) >= 64 {
			return nil
		}
		room = &relaySession{session: s, hash: hash}
		r.sessions[id] = room
	}
	if room.hash != hash || room.revoked || room.joined[side] {
		return nil
	}
	room.joined[side] = true
	room.peers[side] = peer
	return room
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func tlsBinding(c net.Conn) ([]byte, error) {
	secure, ok := c.(*tls.Conn)
	if !ok {
		return nil, errors.New("P2P requires TLS")
	}
	if err := secure.Handshake(); err != nil {
		return nil, err
	}
	state := secure.ConnectionState()
	return state.ExportKeyingMaterial("BPC-P2P-RELAY-v1", nil, 32)
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxTicket*2 {
		return errors.New("invalid P2P frame length")
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func readFrame(r io.Reader, limit int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > uint32(limit) {
		return nil, errors.New("invalid P2P frame length")
	}
	payload := make([]byte, int(n))
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func wireGuardPacket(p []byte) bool {
	if len(p) < 4 {
		return false
	}
	switch binary.LittleEndian.Uint32(p[:4]) {
	case 1:
		return len(p) == 148
	case 2:
		return len(p) == 92
	case 3:
		return len(p) == 64
	case 4:
		return len(p) >= 32 && len(p) <= maxDatagram && len(p)%16 == 0
	default:
		return false
	}
}

// DialRelay verifies the relay certificate AND proves the selected Device's
// identity. The caller must have independently verified the grant via Controller
// trust. A relay must never supply the grant issuer's trust anchor.
func DialRelay(ctx context.Context, address string, config *tls.Config, s *Session, side Side, identity ed25519.PrivateKey) (net.Conn, error) {
	if config == nil || config.InsecureSkipVerify || config.ServerName == "" || s == nil || !side.valid() || len(identity) != ed25519.PrivateKeySize || !s.active(time.Now()) {
		return nil, errors.New("invalid P2P relay client trust")
	}
	expected, _ := base64.StdEncoding.DecodeString(s.grant.Participants[side].IdentityKey)
	if !bytes.Equal(identity.Public().(ed25519.PublicKey), expected) {
		return nil, errors.New("P2P Device identity mismatch")
	}
	cfg := config.Clone()
	cfg.MinVersion = tls.VersionTLS13
	dialer := tls.Dialer{Config: cfg, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
	c, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	// Honour cancellation during the application authentication, too.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	_ = c.SetDeadline(earlier(s.deadline, time.Now().Add(5*time.Second)))
	binding, err := tlsBinding(c)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	challenge, err := readFrame(c, 32)
	if err == nil && len(challenge) != 32 {
		err = errors.New("invalid P2P challenge")
	}
	if err == nil {
		auth, _ := json.Marshal(relayAuth{Ticket: s.ticket, Side: side, Proof: ed25519.Sign(identity, proofMessage(challenge, s.ticket, side, binding))})
		err = writeFrame(c, auth)
	}
	if err == nil {
		var ready []byte
		ready, err = readFrame(c, 32)
		if err == nil && string(ready) != "BPC-P2P-READY-v1" {
			err = errors.New("invalid P2P acknowledgement")
		}
	}
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(s.deadline)
	return c, nil
}

// RunEndpoint forwards ONLY encrypted WireGuard datagrams between a fixed
// loopback WG socket and an authenticated relay connection. Plaintext must pass
// FilterTUN; using this bridge alone is not service authorization.
func RunEndpoint(ctx context.Context, local *net.UDPConn, target *net.UDPAddr, relay net.Conn) error {
	if local == nil || target == nil || relay == nil || !target.IP.IsLoopback() || target.Port <= 0 {
		return errors.New("P2P bridge requires fixed loopback endpoints")
	}
	bind, ok := local.LocalAddr().(*net.UDPAddr)
	if !ok || !bind.IP.IsLoopback() {
		return errors.New("P2P bridge must bind loopback")
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = local.Close()
			_ = relay.Close()
		case <-done:
		}
	}()
	defer local.Close()
	defer relay.Close()
	errorsCh := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		buf := make([]byte, maxDatagram+1)
		for {
			n, source, err := local.ReadFromUDP(buf)
			if err != nil {
				errorsCh <- err
				return
			}
			if source.Port != target.Port || !source.IP.Equal(target.IP) || !wireGuardPacket(buf[:n]) {
				continue
			}
			if err = writeFrame(relay, buf[:n]); err != nil {
				errorsCh <- err
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			packet, err := readFrame(relay, maxDatagram)
			if err != nil {
				errorsCh <- err
				return
			}
			if !wireGuardPacket(packet) {
				continue
			}
			if _, err = local.WriteToUDP(packet, target); err != nil {
				errorsCh <- err
				return
			}
		}
	}()
	err := <-errorsCh
	_ = local.Close()
	_ = relay.Close()
	workers.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}
