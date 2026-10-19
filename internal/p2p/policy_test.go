package p2p

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/RomanKrike/bpc/internal/agentctl"
	"golang.zx2c4.com/wireguard/tun"
)

type fixture struct {
	grant      Grant
	issuer     ed25519.PrivateKey
	identities [2]ed25519.PrivateKey
	wgPrivate  [2]string
	ticket     []byte
	session    *Session
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	var f fixture
	_, f.issuer, _ = ed25519.GenerateKey(rand.Reader)
	f.grant = Grant{Version: Version, ClusterID: "test-cluster", SessionID: "00112233445566778899aabbccddeeff", Revision: 7, IssuedAt: time.Now().Unix() - 1, ExpiresAt: time.Now().Unix() + 55, Service: Sunshine}
	for i := range f.identities {
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.identities[i] = private
		wgPrivate, wgPublic, err := agentctl.GenerateWireGuardKeypair()
		if err != nil {
			t.Fatal(err)
		}
		f.wgPrivate[i] = wgPrivate
		f.grant.Participants[i] = Participant{DeviceID: []string{"client", "gaming-pc"}[i], UserID: "owner", IdentityKey: base64.StdEncoding.EncodeToString(pub), WireGuardKey: wgPublic, Address: netip.MustParseAddr([]string{"10.253.0.2", "10.253.0.3"}[i])}
	}
	var err error
	f.ticket, err = SignGrant(f.grant, f.issuer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.session, err = VerifyGrant(f.ticket, f.issuer.Public().(ed25519.PublicKey), f.grant.ClusterID, 7, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestGrantTrustBoundaries(t *testing.T) {
	f := newFixture(t)
	pub := f.issuer.Public().(ed25519.PublicKey)
	for _, test := range []struct {
		name     string
		ticket   []byte
		key      ed25519.PublicKey
		cluster  string
		revision uint64
		now      time.Time
	}{
		{"wrong-cluster", f.ticket, pub, "other", 7, time.Now()},
		{"stale-revision", f.ticket, pub, "test-cluster", 8, time.Now()},
		{"expired", f.ticket, pub, "test-cluster", 7, time.Unix(f.grant.ExpiresAt, 0)},
		{"future-issue", f.ticket, pub, "test-cluster", 7, time.Unix(f.grant.IssuedAt-1, 0)},
		{"wrong-issuer", f.ticket, f.identities[0].Public().(ed25519.PublicKey), "test-cluster", 7, time.Now()},
		{"oversize", bytes.Repeat([]byte("x"), maxTicket+1), pub, "test-cluster", 7, time.Now()},
		{"trailing", append(bytes.Clone(f.ticket), []byte(" {}")...), pub, "test-cluster", 7, time.Now()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyGrant(test.ticket, test.key, test.cluster, test.revision, test.now); err == nil {
				t.Fatal("untrusted grant accepted")
			}
		})
	}
	var envelope signedGrant
	if err := json.Unmarshal(f.ticket, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload = bytes.Replace(envelope.Payload, []byte("gaming-pc"), []byte("attacker!"), 1)
	tampered, _ := json.Marshal(envelope)
	if _, err := VerifyGrant(tampered, pub, "test-cluster", 0, time.Now()); err == nil {
		t.Fatal("tampered participant accepted")
	}
	for _, change := range []func(*Grant){
		func(g *Grant) { g.Participants[1].UserID = "other-owner" },
		func(g *Grant) { g.Participants[1] = g.Participants[0] },
		func(g *Grant) { g.ExpiresAt = g.IssuedAt + 61 },
		func(g *Grant) { g.Service = "all-ports" },
		func(g *Grant) { g.Version = 2 },
		func(g *Grant) { g.Participants[1].Address = netip.MustParseAddr("127.0.0.1") },
		func(g *Grant) { g.Participants[1].WireGuardKey = "invalid" },
	} {
		g := f.grant
		change(&g)
		if _, err := SignGrant(g, f.issuer, time.Now()); err == nil {
			t.Fatal("invalid grant signed")
		}
	}
	// Simulate a backwards wall-clock jump while the local deadline has passed.
	f.session.deadline = time.Now().Add(-time.Second)
	if f.session.active(time.Now()) {
		t.Fatal("local lease extended")
	}
}

func ipPacket(f fixture, reverse bool, proto byte, client, service uint16, flags byte) []byte {
	size := 28
	if proto == 6 {
		size = 40
	}
	p := make([]byte, size)
	p[0] = 0x45
	p[8] = 64
	p[9] = proto
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	a, b := f.grant.Participants[0].Address.As4(), f.grant.Participants[1].Address.As4()
	src, dst := client, service
	if reverse {
		a, b = b, a
		src, dst = service, client
	}
	copy(p[12:16], a[:])
	copy(p[16:20], b[:])
	binary.BigEndian.PutUint16(p[20:22], src)
	binary.BigEndian.PutUint16(p[22:24], dst)
	if proto == 6 {
		p[32] = 0x50
		p[33] = flags
	} else {
		binary.BigEndian.PutUint16(p[24:26], 8)
	}
	return p
}

func TestEndpointAccessAndEstablishedRevoke(t *testing.T) {
	f := newFixture(t)
	for _, proto := range []byte{6, 17} {
		client, _ := NewPolicy(f.session, Initiator)
		host, _ := NewPolicy(f.session, Host)
		port := uint16(47989)
		if proto == 17 {
			port = 47998
		}
		request := ipPacket(f, false, proto, 51000, port, 0x02)
		reply := ipPacket(f, true, proto, 51000, port, 0x12)
		if host.Allowed(reply, true) || client.Allowed(reply, false) {
			t.Fatal("unsolicited host initiation permitted")
		}
		if !client.Allowed(request, true) || !host.Allowed(request, false) {
			t.Fatal("authorized request denied")
		}
		if !host.Allowed(reply, true) || !client.Allowed(reply, false) {
			t.Fatal("authorized reply denied")
		}
		if proto == 6 && host.Allowed(ipPacket(f, true, proto, 51000, port, 0x02), true) {
			t.Fatal("reverse TCP initiation permitted")
		}
		client.Revoke()
		host.Revoke()
		if client.Allowed(request, true) || host.Allowed(request, false) || client.Allowed(reply, false) || host.Allowed(reply, true) {
			t.Fatal("established flow survived revoke")
		}
	}
}

func TestPolicyMalformedAndUnrelatedTraffic(t *testing.T) {
	f := newFixture(t)
	for _, change := range []struct {
		name  string
		apply func([]byte) []byte
	}{
		{"ssh", func(p []byte) []byte { binary.BigEndian.PutUint16(p[22:24], 22); return p }},
		{"admin-ui", func(p []byte) []byte { binary.BigEndian.PutUint16(p[22:24], 47990); return p }},
		{"fragment-offset", func(p []byte) []byte { p[7] = 1; return p }},
		{"more-fragments", func(p []byte) []byte { p[6] = 0x20; return p }},
		{"ipv6", func(p []byte) []byte { p[0] = 0x60; return p }},
		{"ip-options", func(p []byte) []byte { p[0] = 0x46; return p }},
		{"spoofed-source", func(p []byte) []byte { p[15] = 99; return p }},
		{"wrong-destination", func(p []byte) []byte { p[19] = 99; return p }},
		{"short", func(p []byte) []byte { return p[:19] }},
		{"length-mismatch", func(p []byte) []byte { return append(p, 0) }},
		{"udp-length", func(p []byte) []byte { p[25] = 0; return p }},
		{"icmp", func(p []byte) []byte { p[9] = 1; return p }},
	} {
		t.Run(change.name, func(t *testing.T) {
			policy, _ := NewPolicy(f.session, Host)
			if policy.Allowed(change.apply(ipPacket(f, false, 17, 51000, 47998, 0)), false) {
				t.Fatal("unrelated traffic admitted")
			}
		})
	}
	policy, _ := NewPolicy(f.session, Host)
	if policy.Allowed(ipPacket(f, false, 6, 51000, 47989, 0x10), false) {
		t.Fatal("midstream TCP creates authorization")
	}
	policy.session.deadline = time.Now().Add(-time.Second)
	if policy.Allowed(ipPacket(f, false, 17, 51000, 47998, 0), false) {
		t.Fatal("expired lease admitted")
	}
}

func FuzzUntrustedGrant(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte("{\"payload\":\"AA==\"}"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = VerifyGrant(packet, make(ed25519.PublicKey, 32), "test-cluster", 1, time.Now())
	})
}

type batchTUN struct {
	tun.Device
	packets [][]byte
	written [][]byte
}

func (b *batchTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(b.packets) == 0 {
		return 0, io.EOF
	}
	for i, p := range b.packets {
		copy(bufs[i][offset:], p)
		sizes[i] = len(p)
	}
	n := len(b.packets)
	b.packets = nil
	return n, nil
}
func (b *batchTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		b.written = append(b.written, bytes.Clone(buf[offset:]))
	}
	return len(bufs), nil
}

func TestFilterTUNBatchOffsetsAndRevoke(t *testing.T) {
	f := newFixture(t)
	policy, _ := NewPolicy(f.session, Initiator)
	good := ipPacket(f, false, 17, 51000, 47998, 0)
	bad := ipPacket(f, false, 17, 51000, 22, 0)
	raw := &batchTUN{packets: [][]byte{bad, good}}
	filtered, err := NewFilterTUN(raw, policy)
	if err != nil {
		t.Fatal(err)
	}
	bufs := [][]byte{make([]byte, 100), make([]byte, 100)}
	sizes := make([]int, 2)
	n, err := filtered.Read(bufs, sizes, 4)
	if err != nil || n != 1 || !bytes.Equal(bufs[0][4:4+sizes[0]], good) {
		t.Fatalf("filtered batch lost packet/offset: %v", err)
	}
	reply := append(make([]byte, 4), ipPacket(f, true, 17, 51000, 47998, 0)...)
	if n, err = filtered.Write([][]byte{reply}, 4); err != nil || n != 1 || len(raw.written) != 1 {
		t.Fatal("authorized reply not written")
	}
	policy.Revoke()
	if _, err = filtered.Write([][]byte{reply}, 4); err != nil || len(raw.written) != 1 {
		t.Fatal("revoked reply written")
	}
}

func TestPolicyConcurrentRevokeAndFlowBounds(t *testing.T) {
	f := newFixture(t)
	policy, _ := NewPolicy(f.session, Host)
	request := ipPacket(f, false, 17, 51000, 47998, 0)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				policy.Allowed(request, false)
			}
		}()
	}
	policy.Revoke()
	workers.Wait()
	if policy.Allowed(request, false) || len(policy.flows) != 0 {
		t.Fatal("concurrent revoke did not close flows")
	}
	policy, _ = NewPolicy(f.session, Host)
	for i := 0; i < maxFlows; i++ {
		if !policy.Allowed(ipPacket(f, false, 17, uint16(1024+i), 47998, 0), false) {
			t.Fatal("flow limit reached early")
		}
	}
	if policy.Allowed(ipPacket(f, false, 17, 60000, 47998, 0), false) || len(policy.flows) != maxFlows {
		t.Fatal("unbounded flow table")
	}
}
