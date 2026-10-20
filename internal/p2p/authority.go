package p2p

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

const MaxManagedSessions = 16

var policyBucket = []byte("bpc-p2p-authority-v1")

// Trust is bootstrapped from the authenticated Controller enrollment, NEVER
// from a relay/ticket. Opening an existing store requires the same trust pin.
type Trust struct {
	ClusterID string            `json:"cluster_id"`
	DeviceID  string            `json:"device_id"`
	Issuer    ed25519.PublicKey `json:"issuer"`
}

type policyEntry struct {
	SessionID    string `json:"session_id"`
	TicketSHA256 string `json:"ticket_sha256"`
}

type checkpoint struct {
	Version   int           `json:"version"`
	ClusterID string        `json:"cluster_id"`
	DeviceID  string        `json:"device_id"`
	Revision  uint64        `json:"revision"`
	IssuedAt  int64         `json:"issued_at"`
	ExpiresAt int64         `json:"expires_at"`
	Allowed   []policyEntry `json:"allowed"`
}

type policyState struct {
	Version  int              `json:"version"`
	Trust    Trust            `json:"trust"`
	Revision uint64           `json:"revision"`
	IssuedAt int64            `json:"issued_at"`
	Denied   map[string]int64 `json:"denied"`
	Reserved []netip.Addr     `json:"reserved,omitempty"`
}

// PolicyStore persists public trust, a revision/time floor and signed denials
// using existing bbolt atomic/fsync semantics. No cached authorization is
// restored: every process start requires a NEW Controller checkpoint.
// Its file and directory must be BPC-owned. Backing up/restoring an older DB by
// an administrator is outside local anti-rollback guarantees.
type PolicyStore struct {
	mu       sync.Mutex
	db       *bolt.DB
	trust    Trust
	sessions map[string]*Session
}

func CreatePolicyStore(path string, trust Trust) (*PolicyStore, error) {
	return openPolicyStore(path, trust, true)
}
func OpenPolicyStore(path string, trust Trust) (*PolicyStore, error) {
	return openPolicyStore(path, trust, false)
}

func openPolicyStore(path string, trust Trust, create bool) (*PolicyStore, error) {
	if trust.ClusterID == "" || trust.DeviceID == "" || len(trust.Issuer) != ed25519.PublicKeySize {
		return nil, errors.New("invalid P2P trust pin")
	}
	trust.Issuer = bytes.Clone(trust.Issuer)
	if create {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		if err = f.Close(); err != nil {
			return nil, err
		}
	} else if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	store := &PolicyStore{db: db, trust: trust, sessions: make(map[string]*Session)}
	err = db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(policyBucket)
		if create {
			var err error
			bucket, err = tx.CreateBucket(policyBucket)
			if err != nil {
				return err
			}
			return putPolicyState(bucket, policyState{Version: 1, Trust: trust, Denied: map[string]int64{}})
		}
		if bucket == nil {
			return errors.New("unowned P2P policy store")
		}
		_, err := store.state(bucket)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (p *PolicyStore) state(b *bolt.Bucket) (policyState, error) {
	var state policyState
	if b == nil {
		return state, errors.New("P2P policy state missing")
	}
	if err := decodeStrict(b.Get([]byte("state")), &state); err != nil {
		return state, err
	}
	if state.Version != 1 || state.Trust.ClusterID != p.trust.ClusterID || state.Trust.DeviceID != p.trust.DeviceID || !bytes.Equal(state.Trust.Issuer, p.trust.Issuer) || state.Denied == nil || len(state.Denied) > 4096 {
		return state, errors.New("P2P stored trust/state mismatch")
	}
	if len(state.Reserved) > MaxManagedSessions {
		return state, errors.New("invalid P2P reservations")
	}
	seen := make(map[netip.Addr]bool)
	for _, ip := range state.Reserved {
		if !ip.Is4() || !ip.IsPrivate() || seen[ip] {
			return state, errors.New("invalid P2P reservation")
		}
		seen[ip] = true
	}
	return state, nil
}

func putPolicyState(b *bolt.Bucket, state policyState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return b.Put([]byte("state"), raw)
}

func (p *PolicyStore) Track(ticket []byte) (*Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.db == nil {
		return nil, errors.New("P2P policy store closed")
	}
	s, err := VerifyGrant(ticket, p.trust.Issuer, p.trust.ClusterID, 0, time.Now())
	if err != nil {
		return nil, err
	}
	if s.grant.Participants[0].DeviceID != p.trust.DeviceID && s.grant.Participants[1].DeviceID != p.trust.DeviceID {
		return nil, errors.New("P2P grant belongs to another Device")
	}
	err = p.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(policyBucket)
		state, err := p.state(bucket)
		if err != nil {
			return err
		}
		if state.Denied[s.grant.SessionID] > time.Now().Unix() {
			return errors.New("P2P session was revoked")
		}
		remote := s.grant.Participants[0].Address
		if s.grant.Participants[0].DeviceID == p.trust.DeviceID {
			remote = s.grant.Participants[1].Address
		}
		for _, ip := range state.Reserved {
			if ip == remote {
				return nil
			}
		}
		if len(state.Reserved) >= MaxManagedSessions {
			return errors.New("P2P reservation capacity exhausted")
		}
		state.Reserved = append(state.Reserved, remote)
		return putPolicyState(bucket, state)
	})
	if err != nil {
		return nil, err
	}
	for id, old := range p.sessions {
		if time.Now().Unix() >= old.grant.ExpiresAt {
			old.authorization.Store(nil)
			delete(p.sessions, id)
		}
	}
	if old := p.sessions[s.grant.SessionID]; old != nil {
		if !bytes.Equal(old.ticket, ticket) {
			return nil, errors.New("P2P session ID reused")
		}
		return old, nil
	}
	if len(p.sessions) >= MaxManagedSessions {
		return nil, errors.New("too many managed P2P sessions")
	}
	s.managed = true
	p.sessions[s.grant.SessionID] = s
	return s, nil
}

// ReservedPeers restores only blackholes, never a cached allow. Call before
// starting gateway WG so a restart cannot route stale P2P traffic via gateway.
func (p *PolicyStore) ReservedPeers() ([]netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.db == nil {
		return nil, errors.New("P2P store closed")
	}
	var result []netip.Addr
	err := p.db.View(func(tx *bolt.Tx) error {
		state, err := p.state(tx.Bucket(policyBucket))
		if err != nil {
			return err
		}
		result = append(result, state.Reserved...)
		return nil
	})
	return result, err
}

// FailClosed must be called on sync/transport errors. It never advances a floor
// or renews authorization. A later fresh, signed checkpoint may restore access.
func (p *PolicyStore) FailClosed() { p.mu.Lock(); defer p.mu.Unlock(); p.failClosed() }

// Stop persists local terminal intent without advancing the Controller floor.
// A cancelled/failed pilot ticket cannot be reattached after process restart.
func (p *PolicyStore) Stop(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failClosed()
	if p.db == nil {
		return errors.New("P2P policy store closed")
	}
	s := p.sessions[id]
	if s == nil {
		return errors.New("unknown P2P session")
	}
	return p.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(policyBucket)
		state, err := p.state(b)
		if err != nil {
			return err
		}
		for id, expiry := range state.Denied {
			if expiry <= time.Now().Unix() {
				delete(state.Denied, id)
			}
		}
		if len(state.Denied) >= 4096 {
			return errors.New("P2P revocation capacity exhausted")
		}
		state.Denied[id] = s.grant.ExpiresAt
		return putPolicyState(b, state)
	})
}
func (p *PolicyStore) failClosed() {
	for _, s := range p.sessions {
		s.authorization.Store(nil)
	}
}

func (p *PolicyStore) Apply(ticket []byte) (revoked []string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	defer func() {
		if err != nil {
			p.failClosed()
		}
	}()
	if p.db == nil || len(ticket) > maxTicket {
		return nil, errors.New("invalid P2P checkpoint/store")
	}
	var envelope signedGrant
	if err = decodeStrict(ticket, &envelope); err != nil {
		return nil, err
	}
	if !ed25519.Verify(p.trust.Issuer, append([]byte("BPC-P2P-POLICY-v1\x00"), envelope.Payload...), envelope.Signature) {
		return nil, errors.New("invalid P2P policy signature")
	}
	var policy checkpoint
	if err = decodeStrict(envelope.Payload, &policy); err != nil {
		return nil, err
	}
	now := time.Now()
	if policy.Version != 1 || policy.ClusterID != p.trust.ClusterID || policy.DeviceID != p.trust.DeviceID || policy.Revision == 0 || policy.IssuedAt <= 0 || policy.IssuedAt > now.Unix() || policy.ExpiresAt <= now.Unix() || policy.ExpiresAt-policy.IssuedAt > 30 || len(policy.Allowed) > MaxManagedSessions {
		return nil, errors.New("invalid P2P policy scope/lifetime")
	}
	allowed := make(map[string]bool)
	for _, entry := range policy.Allowed {
		s := p.sessions[entry.SessionID]
		if s == nil || allowed[entry.SessionID] || policy.Revision < s.grant.Revision {
			return nil, errors.New("unknown/duplicate P2P policy session")
		}
		hash := sha256.Sum256(s.ticket)
		if entry.TicketSHA256 != hex.EncodeToString(hash[:]) {
			return nil, errors.New("P2P policy ticket mismatch")
		}
		allowed[entry.SessionID] = true
	}
	// Persist BEFORE activating the policy or acknowledging a local revoke.
	err = p.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(policyBucket)
		state, err := p.state(b)
		if err != nil {
			return err
		}
		if policy.Revision <= state.Revision || policy.IssuedAt < state.IssuedAt {
			return errors.New("P2P policy rollback/replay")
		}
		for id, expiry := range state.Denied {
			if expiry <= now.Unix() {
				delete(state.Denied, id)
			}
		}
		for id, s := range p.sessions {
			if !allowed[id] {
				state.Denied[id] = s.grant.ExpiresAt
				revoked = append(revoked, id)
			} else if state.Denied[id] > now.Unix() {
				return errors.New("revoked P2P ticket cannot be reauthorized")
			}
		}
		if len(state.Denied) > 4096 {
			return errors.New("P2P revocation capacity exhausted")
		}
		state.Revision = policy.Revision
		state.IssuedAt = policy.IssuedAt
		return putPolicyState(b, state)
	})
	if err != nil {
		return nil, err
	}
	deadline := now.Add(time.Unix(policy.ExpiresAt, 0).Sub(now))
	for id, s := range p.sessions {
		if allowed[id] {
			s.authorization.Store(&sessionAuthorization{deadline: earlier(deadline, s.deadline), expiresAt: policy.ExpiresAt})
		} else {
			s.authorization.Store(nil)
		}
	}
	sort.Strings(revoked)
	return revoked, nil
}

func (p *PolicyStore) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failClosed()
	if p.db == nil {
		return nil
	}
	err := p.db.Close()
	p.db = nil
	return err
}
