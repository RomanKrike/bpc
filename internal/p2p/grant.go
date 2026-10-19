// Package p2p implements the opt-in Device-to-Device session foundation.
// It is not wired into Controller issuance or the installed Windows Agent yet.
package p2p

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/RomanKrike/bpc/internal/agentctl"
)

const (
	Version   = 1
	Sunshine  = "sunshine-v1"
	MaxLease  = 60 * time.Second
	maxTicket = 8192
)

type Side uint8

const (
	Initiator Side = iota
	Host
)

func (s Side) valid() bool { return s == Initiator || s == Host }

type Participant struct {
	DeviceID     string     `json:"device_id"`
	UserID       string     `json:"user_id"`
	IdentityKey  string     `json:"identity_key"`
	WireGuardKey string     `json:"wireguard_key"`
	Address      netip.Addr `json:"address"`
}

// Grant contains public metadata only. The issuer must derive both participants
// and Access from committed Controller state, never from a requester-supplied
// UserID. Same-owner sessions are the only version-1 scope.
type Grant struct {
	Version      int            `json:"version"`
	ClusterID    string         `json:"cluster_id"`
	SessionID    string         `json:"session_id"`
	Revision     uint64         `json:"revision"`
	IssuedAt     int64          `json:"issued_at"`
	ExpiresAt    int64          `json:"expires_at"`
	Service      string         `json:"service"`
	Participants [2]Participant `json:"participants"`
}

type signedGrant struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// Session can only be constructed by VerifyGrant. Its grant is immutable;
// deadline retains the local monotonic clock to prevent clock rollback from
// extending a lease already received in this process.
type Session struct {
	grant         Grant
	ticket        []byte
	deadline      time.Time
	managed       bool
	authorization atomic.Pointer[sessionAuthorization]
}

type sessionAuthorization struct {
	deadline  time.Time
	expiresAt int64
}

func (s *Session) Grant() Grant { return s.grant }

func (s *Session) active(now time.Time) bool {
	if s.managed {
		policy := s.authorization.Load()
		if policy == nil || now.Unix() >= policy.expiresAt || !now.Before(policy.deadline) {
			return false
		}
	}
	return now.Unix() >= s.grant.IssuedAt && now.Unix() < s.grant.ExpiresAt && now.Before(s.deadline)
}

func (g Grant) validate(now time.Time) error {
	if g.Version != Version || g.Service != Sunshine || g.ClusterID == "" || len(g.ClusterID) > 128 || g.Revision == 0 {
		return errors.New("unsupported P2P grant scope")
	}
	id, err := hex.DecodeString(g.SessionID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != g.SessionID {
		return errors.New("invalid P2P session ID")
	}
	if g.IssuedAt <= 0 || g.IssuedAt > now.Unix() || g.ExpiresAt <= now.Unix() || g.ExpiresAt-g.IssuedAt > int64(MaxLease/time.Second) {
		return errors.New("P2P grant expired or invalid lifetime")
	}
	for _, p := range g.Participants {
		if p.DeviceID == "" || len(p.DeviceID) > 128 || p.UserID == "" || len(p.UserID) > 128 || !p.Address.Is4() || !p.Address.IsPrivate() {
			return errors.New("invalid P2P participant")
		}
		key, err := base64.StdEncoding.DecodeString(p.IdentityKey)
		if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != p.IdentityKey || bytes.Equal(key, make([]byte, ed25519.PublicKeySize)) {
			return errors.New("invalid Device identity key")
		}
		wgKey, err := agentctl.ParseWGKey(p.WireGuardKey, false)
		if err != nil || base64.StdEncoding.EncodeToString(wgKey[:]) != p.WireGuardKey {
			return errors.New("invalid Device WireGuard key")
		}
	}
	a, b := g.Participants[0], g.Participants[1]
	if a.UserID != b.UserID || a.DeviceID == b.DeviceID || a.Address == b.Address || a.IdentityKey == b.IdentityKey || a.WireGuardKey == b.WireGuardKey {
		return errors.New("P2P requires distinct Devices of the same owner")
	}
	return nil
}

// SignGrant does not create authorization: the caller owns the Controller
// authorization/consensus check. Keeping issuance out of the relay prevents it
// from granting itself access to a Device.
func SignGrant(g Grant, issuer ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(issuer) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid P2P issuer key")
	}
	if err := g.validate(now); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	return json.Marshal(signedGrant{Payload: payload, Signature: ed25519.Sign(issuer, append([]byte("BPC-P2P-GRANT-v1\x00"), payload...))})
}

func VerifyGrant(ticket []byte, issuer ed25519.PublicKey, cluster string, minRevision uint64, now time.Time) (*Session, error) {
	if len(issuer) != ed25519.PublicKeySize || cluster == "" || len(ticket) > maxTicket {
		return nil, errors.New("invalid P2P trust context")
	}
	var envelope signedGrant
	if err := decodeStrict(ticket, &envelope); err != nil {
		return nil, err
	}
	if !ed25519.Verify(issuer, append([]byte("BPC-P2P-GRANT-v1\x00"), envelope.Payload...), envelope.Signature) {
		return nil, errors.New("invalid P2P grant signature")
	}
	var g Grant
	if err := decodeStrict(envelope.Payload, &g); err != nil {
		return nil, err
	}
	if err := g.validate(now); err != nil {
		return nil, err
	}
	if g.ClusterID != cluster || g.Revision < minRevision {
		return nil, errors.New("P2P grant cluster/revision mismatch")
	}
	return &Session{grant: g, ticket: bytes.Clone(ticket), deadline: now.Add(time.Unix(g.ExpiresAt, 0).Sub(now))}, nil
}

func decodeStrict(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return errors.New("invalid P2P document")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing P2P document")
	}
	return nil
}

func proofMessage(challenge, ticket []byte, side Side, binding []byte) []byte {
	hash := sha256.Sum256(ticket)
	message := append([]byte("BPC-P2P-RELAY-PROOF-v1\x00"), challenge...)
	message = append(message, hash[:]...)
	message = append(message, byte(side))
	return append(message, binding...)
}
