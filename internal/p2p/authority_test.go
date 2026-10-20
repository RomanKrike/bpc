package p2p

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestManagedLocalStopAndReservationsSurviveRestart(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "policy.db")
	trust := fixtureTrust(f)
	store, err := CreatePolicyStore(path, trust)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Track(f.ticket); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Apply(signedPolicy(t, f, 8, true)); err != nil {
		t.Fatal(err)
	}
	if err = store.Stop(f.grant.SessionID); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	store, err = OpenPolicyStore(path, trust)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	peers, err := store.ReservedPeers()
	if err != nil || len(peers) != 1 || peers[0] != f.grant.Participants[0].Address {
		t.Fatal("restart lost peer blackhole", err)
	}
	if _, err = store.Track(f.ticket); err == nil {
		t.Fatal("locally stopped ticket reattached after restart")
	}
	// Only a deny reservation is restored into the TUN, never cached allow.
	raw := newPipeTUN()
	mux, _ := NewMuxTUN(raw)
	defer mux.Close()
	if err = mux.Reserve(peers[0]); err != nil {
		t.Fatal(err)
	}
	packet := ipPacket(f, true, 17, 51000, 47998, 0)
	gateway := append([]byte(nil), packet...)
	copy(gateway[16:20], netip.MustParseAddr("10.99.0.1").AsSlice())
	raw.in <- packet
	raw.in <- gateway
	got := readTestPacket(t, mux)
	if string(got) != string(gateway) {
		t.Fatal("restart leaked reserved peer via gateway")
	}
}

func fixtureTrust(f fixture) Trust {
	return Trust{ClusterID: f.grant.ClusterID, DeviceID: f.grant.Participants[1].DeviceID, Issuer: f.issuer.Public().(ed25519.PublicKey)}
}

func signedPolicy(t *testing.T, f fixture, revision uint64, allow bool) []byte {
	t.Helper()
	policy := checkpoint{Version: 1, ClusterID: f.grant.ClusterID, DeviceID: f.grant.Participants[1].DeviceID, Revision: revision, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 25, Allowed: []policyEntry{}}
	if allow {
		hash := sha256.Sum256(f.ticket)
		policy.Allowed = []policyEntry{{SessionID: f.grant.SessionID, TicketSHA256: hex.EncodeToString(hash[:])}}
	}
	return signPolicyValue(t, f.issuer, policy)
}

func signPolicyValue(t *testing.T, key ed25519.PrivateKey, policy checkpoint) []byte {
	t.Helper()
	payload, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signedGrant{Payload: payload, Signature: ed25519.Sign(key, append([]byte("BPC-P2P-POLICY-v1\x00"), payload...))})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestManagedPolicyRestartReplayAndRevoke(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "policy.db")
	trust := fixtureTrust(f)
	store, err := CreatePolicyStore(path, trust)
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Track(f.ticket)
	if err != nil {
		t.Fatal(err)
	}
	if session.active(time.Now()) {
		t.Fatal("grant alone authorized a managed session")
	}
	allow := signedPolicy(t, f, 8, true)
	if _, err = store.Apply(allow); err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(session, Host)
	if err != nil {
		t.Fatal(err)
	}
	packet := ipPacket(f, false, 17, 51000, 47998, 0)
	if !policy.Allowed(packet, false) {
		t.Fatal("fresh signed authorization denied")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if session.active(time.Now()) {
		t.Fatal("closing authority store left access active")
	}
	store, err = OpenPolicyStore(path, trust)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	session, err = store.Track(f.ticket)
	if err != nil {
		t.Fatal(err)
	}
	if session.active(time.Now()) {
		t.Fatal("restart restored cached authorization")
	}
	if _, err = store.Apply(allow); err == nil {
		t.Fatal("pre-restart checkpoint replayed")
	}
	if _, err = store.Apply(signedPolicy(t, f, 9, true)); err != nil {
		t.Fatal(err)
	}
	policy, err = NewPolicy(session, Host)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Allowed(packet, false) {
		t.Fatal("new checkpoint denied")
	}
	denied, err := store.Apply(signedPolicy(t, f, 10, false))
	if err != nil || len(denied) != 1 {
		t.Fatalf("revoke: %v", err)
	}
	if policy.Allowed(packet, false) {
		t.Fatal("policy update did not revoke established flow")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenPolicyStore(path, trust)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = store.Track(f.ticket); err == nil {
		t.Fatal("revoked grant restored after restart")
	}
}

func TestPolicyTrustPersistenceFailuresAndExpiry(t *testing.T) {
	f := newFixture(t)
	trust := fixtureTrust(f)
	path := filepath.Join(t.TempDir(), "policy.db")
	if _, err := OpenPolicyStore(path, trust); err == nil {
		t.Fatal("missing store silently bootstrapped")
	}
	store, err := CreatePolicyStore(path, trust)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Track(f.ticket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Apply(signedPolicy(t, f, 8, true)); err != nil {
		t.Fatal(err)
	}
	store.FailClosed()
	if s.active(time.Now()) {
		t.Fatal("sync error retained access")
	}
	if _, err = store.Apply(signedPolicy(t, f, 9, true)); err != nil {
		t.Fatal(err)
	}
	// Wall clock expiry also applies when the monotonic clock did not advance
	// during OS suspension. Both bounds independently fail closed.
	s.authorization.Store(&sessionAuthorization{deadline: time.Now().Add(time.Minute), expiresAt: time.Now().Unix() - 1})
	if s.active(time.Now()) {
		t.Fatal("suspend extended checkpoint lease")
	}
	s.authorization.Store(&sessionAuthorization{deadline: time.Now().Add(-time.Second), expiresAt: time.Now().Unix() + 25})
	if s.active(time.Now()) {
		t.Fatal("clock rollback extended checkpoint lease")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	trust.ClusterID = "another-cluster"
	if _, err = OpenPolicyStore(path, trust); err == nil {
		t.Fatal("stored pin overwritten")
	}
	if _, err = CreatePolicyStore(path, fixtureTrust(f)); err == nil {
		t.Fatal("existing store overwritten by bootstrap")
	}
}

func TestUntrustedCheckpointFailsClosed(t *testing.T) {
	f := newFixture(t)
	for _, change := range []struct {
		name   string
		modify func(*checkpoint)
	}{
		{"other-device", func(p *checkpoint) { p.DeviceID = "other" }},
		{"other-cluster", func(p *checkpoint) { p.ClusterID = "other" }},
		{"expired", func(p *checkpoint) { p.ExpiresAt = time.Now().Unix() }},
		{"future", func(p *checkpoint) { p.IssuedAt = time.Now().Unix() + 5 }},
		{"too-long", func(p *checkpoint) { p.ExpiresAt = p.IssuedAt + 31 }},
		{"unknown-session", func(p *checkpoint) { p.Allowed[0].SessionID = "unknown" }},
		{"ticket-substitution", func(p *checkpoint) { p.Allowed[0].TicketSHA256 = "00" }},
		{"duplicate", func(p *checkpoint) { p.Allowed = append(p.Allowed, p.Allowed[0]) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			store, err := CreatePolicyStore(filepath.Join(t.TempDir(), "policy.db"), fixtureTrust(f))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			s, err := store.Track(f.ticket)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.Apply(signedPolicy(t, f, 8, true)); err != nil {
				t.Fatal(err)
			}
			var envelope signedGrant
			_ = json.Unmarshal(signedPolicy(t, f, 9, true), &envelope)
			var policy checkpoint
			_ = json.Unmarshal(envelope.Payload, &policy)
			change.modify(&policy)
			if _, err = store.Apply(signPolicyValue(t, f.issuer, policy)); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
			if s.active(time.Now()) {
				t.Fatal("invalid checkpoint retained authorization")
			}
		})
	}
}

func TestManagedPolicyConcurrentReadAndReconcile(t *testing.T) {
	f := newFixture(t)
	store, err := CreatePolicyStore(filepath.Join(t.TempDir(), "policy.db"), fixtureTrust(f))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s, err := store.Track(f.ticket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Apply(signedPolicy(t, f, 8, true)); err != nil {
		t.Fatal(err)
	}
	policy, _ := NewPolicy(s, Host)
	packet := ipPacket(f, false, 17, 51000, 47998, 0)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				policy.Allowed(packet, false)
			}
		}()
	}
	if _, err = store.Apply(signedPolicy(t, f, 9, false)); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if policy.Allowed(packet, false) {
		t.Fatal("concurrent policy update failed")
	}
}

// The required control-runtime CI job supplies a Python-issued public vector.
// Standard Go jobs skip only this cross-language harness, not policy tests.
func TestControllerWireContract(t *testing.T) {
	path := os.Getenv("BPC_P2P_CONTRACT_FILE")
	if path == "" {
		t.Skip("Python control-runtime harness supplies the contract vector")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Trust      Trust  `json:"trust"`
		Ticket     []byte `json:"ticket"`
		Checkpoint []byte `json:"checkpoint"`
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	store, err := CreatePolicyStore(filepath.Join(t.TempDir(), "policy.db"), vector.Trust)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s, err := store.Track(vector.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Apply(vector.Checkpoint); err != nil {
		t.Fatal(err)
	}
	if !s.active(time.Now()) {
		t.Fatal("Python Controller authorization was not activated")
	}
}

func TestManagedPolicyPersistenceFailureClosesTraffic(t *testing.T) {
	f := newFixture(t)
	store, err := CreatePolicyStore(filepath.Join(t.TempDir(), "policy.db"), fixtureTrust(f))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	session, err := store.Track(f.ticket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Apply(signedPolicy(t, f, 8, true)); err != nil {
		t.Fatal(err)
	}
	// Simulate an unavailable local database independently of Controller trust.
	if err = store.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Apply(signedPolicy(t, f, 9, true)); err == nil {
		t.Fatal("unpersisted authorization accepted")
	}
	if session.active(time.Now()) {
		t.Fatal("database failure retained authorization")
	}
}
