package routed

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"
)

func TestSessionRestartRejectsOldTrafficAndAcceptsResetSequence(t *testing.T) {
	a := &meshPeer{localEpoch: [16]byte{1}}
	b := &meshPeer{localEpoch: [16]byte{2}}
	a.confirmRemoteEpoch(b.localEpoch[:])
	b.confirmRemoteEpoch(a.localEpoch[:])
	a.sendSeq.Store(10000)
	old, err := a.dataEnvelope([]byte("before"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.acceptDataEnvelope(old); !ok {
		t.Fatal("initial data rejected")
	}
	restarted := &meshPeer{localEpoch: [16]byte{3}}
	restarted.confirmRemoteEpoch(b.localEpoch[:])
	fresh, err := restarted.dataEnvelope([]byte("after"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.acceptDataEnvelope(fresh); ok {
		t.Fatal("unconfirmed incarnation accepted")
	}
	b.confirmRemoteEpoch(restarted.localEpoch[:])
	if _, ok := b.acceptDataEnvelope(fresh); !ok {
		t.Fatal("sender restart remains stuck behind old sequence")
	}
	if _, ok := b.acceptDataEnvelope(old); ok {
		t.Fatal("previous sender incarnation replayed")
	}
	b.confirmRemoteEpoch(restarted.localEpoch[:])
	if _, ok := b.acceptDataEnvelope(fresh); ok {
		t.Fatal("routine probe reset replay window")
	}
	receiverRestart := &meshPeer{localEpoch: [16]byte{4}}
	receiverRestart.confirmRemoteEpoch(restarted.localEpoch[:])
	if _, ok := receiverRestart.acceptDataEnvelope(fresh); ok {
		t.Fatal("old traffic replayed after receiver restart")
	}
	restarted.confirmRemoteEpoch(receiverRestart.localEpoch[:])
	after, _ := restarted.dataEnvelope([]byte("both restarted"))
	if _, ok := receiverRestart.acceptDataEnvelope(after); !ok {
		t.Fatal("receiver restart did not recover")
	}
}

func TestMeshUDPPrivateUplinkSurvivesPeerRestart(t *testing.T) {
	reserve := func() int {
		t.Helper()
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
		return port
	}
	aPort, bPort := reserve(), reserve()
	a, err := NewMesh("home", aPort, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	configA := LinkConfig{ID: "uplink", PeerNodeID: "public", PSK: psk, PeerEndpoint: (&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: bPort}).String()}
	configB := LinkConfig{ID: "uplink", PeerNodeID: "home", PSK: psk} // Private Node has no endpoint.
	if err := a.Reconcile([]LinkConfig{configA}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)
	received := make(chan string, 16)
	a.SetDataHandler(func(_ string, p []byte) { received <- string(p) })
	startPublic := func() (*Mesh, context.CancelFunc) {
		t.Helper()
		b, err := NewMesh("public", bPort, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Reconcile([]LinkConfig{configB}); err != nil {
			t.Fatal(err)
		}
		b.SetDataHandler(func(id string, p []byte) { _ = b.Send(id, p) })
		runCtx, stop := context.WithCancel(ctx)
		go b.Run(runCtx)
		return b, stop
	}
	b, stopB := startPublic()
	roundTrip := func(payload string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-deadline:
				t.Fatalf("UDP session did not recover: %s", payload)
			case <-tick.C:
				a.sendProbe(a.peer("public"), time.Now())
				_ = a.Send("public", []byte(payload))
			case response := <-received:
				if response == payload {
					return
				}
			}
		}
	}
	roundTrip("before restart")
	// A captured authenticated packet cannot move the learned endpoint when
	// replayed from another source address.
	plain, err := a.peer("public").dataEnvelope([]byte("replay check"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.peer("public").tx.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	publicAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: bPort}
	if _, err := a.conn.WriteToUDP(sealed, publicAddr); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("initial replay-check packet was not received")
	}
	rogue, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer rogue.Close()
	if _, err := rogue.WriteToUDP(sealed, publicAddr); err != nil {
		t.Fatal(err)
	}
	// Follow the replay with a probe from the same socket. Its reply proves
	// the receive loop processed both datagrams without relying on a sleep.
	probe, _ := a.peer("public").tx.SealProbe(make([]byte, 32))
	_, _ = rogue.WriteToUDP(probe, publicAddr)
	_ = rogue.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := rogue.ReadFromUDP(make([]byte, 512)); err != nil {
		t.Fatal(err)
	}
	if b.peer("home").address().Port != aPort {
		t.Fatal("replay hijacked learned private endpoint")
	}
	// Runtime reload must preserve sessions and be race-free during traffic.
	if err := a.Reconcile([]LinkConfig{configA}); err != nil {
		t.Fatal(err)
	}
	stopB()
	b.Close()
	b, stopB = startPublic()
	defer stopB()
	defer b.Close()
	roundTrip("after public restart")
}

func TestUnresolvedUplinkDoesNotBlockPoolOrDestroySession(t *testing.T) {
	failDNS := true
	m := &Mesh{localNodeID: "home", peers: map[string]*meshPeer{}, resolve: func(_ string, address string) (*net.UDPAddr, error) {
		if address == "ru-01.example:24446" && failDNS {
			return nil, &net.DNSError{Err: "temporary DNS failure", Name: "ru-01.example", IsTemporary: true}
		}
		return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 24446}, nil
	}}
	psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	links := []LinkConfig{{ID: "a", PeerNodeID: "ru-01", PeerEndpoint: "ru-01.example:24446", PSK: psk}, {ID: "b", PeerNodeID: "ru-02", PeerEndpoint: "ru-02.example:24446", PSK: psk}}
	if err := m.Reconcile(links); err != nil {
		t.Fatal(err)
	}
	if m.peer("ru-01").address() != nil || m.peer("ru-02").address() == nil {
		t.Fatal("DNS failure blocked usable uplink")
	}
	first := m.peer("ru-01")
	first.confirmRemoteEpoch([]byte("0123456789abcdef"))
	first.acceptSequence(100)
	failDNS = false
	if err := m.Reconcile(links); err != nil {
		t.Fatal(err)
	}
	if m.peer("ru-01") != first || first.address() == nil {
		t.Fatal("DNS recovery replaced the session or failed to resolve")
	}
	failDNS = true
	if err := m.Reconcile(links); err != nil {
		t.Fatal(err)
	}
	if first.address() == nil || first.acceptSequence(100) || !first.sessionReady() {
		t.Fatal("DNS failure lost endpoint/session or reset replay protection")
	}
}
