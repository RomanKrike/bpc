package p2p

import (
	"bytes"
	"io"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

type pipeTUN struct {
	in, out chan []byte
	done    chan struct{}
	events  chan tun.Event
	once    sync.Once
}

func newPipeTUN() *pipeTUN {
	return &pipeTUN{in: make(chan []byte, 256), out: make(chan []byte, 256), done: make(chan struct{}), events: make(chan tun.Event, 1)}
}
func (p *pipeTUN) File() *os.File           { return nil }
func (p *pipeTUN) Name() (string, error)    { return "owned-test", nil }
func (p *pipeTUN) MTU() (int, error)        { return 1280, nil }
func (p *pipeTUN) BatchSize() int           { return 1 }
func (p *pipeTUN) Events() <-chan tun.Event { return p.events }
func (p *pipeTUN) Close() error             { p.once.Do(func() { close(p.done); close(p.events) }); return nil }
func (p *pipeTUN) Read(b [][]byte, s []int, o int) (int, error) {
	return readPacket(p.in, p.done, b, s, o)
}
func (p *pipeTUN) Write(b [][]byte, o int) (int, error) {
	for _, v := range b {
		select {
		case p.out <- bytes.Clone(v[o:]):
		case <-p.done:
			return 0, io.EOF
		}
	}
	return len(b), nil
}

func readTestPacket(t *testing.T, device tun.Device) []byte {
	t.Helper()
	type result struct {
		packet []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, 2048)
		sizes := make([]int, 1)
		_, err := device.Read([][]byte{buf}, sizes, 4)
		done <- result{bytes.Clone(buf[4 : 4+sizes[0]]), err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.packet
	case <-time.After(time.Second):
		t.Fatal("TUN read timed out")
		return nil
	}
}

func TestMuxPreservesGatewayButNeverFallsBackForReservedPeer(t *testing.T) {
	f := newFixture(t)
	raw := newPipeTUN()
	mux, err := NewMuxTUN(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	request := ipPacket(f, false, 17, 51000, 47998, 0)
	gateway := bytes.Clone(request)
	copy(gateway[16:20], []byte{10, 99, 0, 1})
	raw.in <- gateway
	if !bytes.Equal(readTestPacket(t, mux), gateway) {
		t.Fatal("gateway changed")
	}
	policy, _ := NewPolicy(f.session, Initiator)
	// A packet queued before reservation must not escape after its ack.
	raw.in <- request
	until := time.Now().Add(time.Second)
	for len(mux.gateway) == 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	peer, err := mux.Attach(f.grant.Participants[1].Address, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	raw.in <- gateway
	if !bytes.Equal(readTestPacket(t, mux), gateway) {
		t.Fatal("queued peer packet escaped after reservation")
	}
	if _, err = mux.Attach(f.grant.Participants[1].Address, policy); err == nil {
		t.Fatal("duplicate live peer attached")
	}
	// Malformed length and forbidden service must go to the peer filter,
	// never escape to gateway. A following valid packet unblocks the read.
	malformed := bytes.Clone(request)
	malformed[2] = 0xff
	raw.in <- malformed
	raw.in <- ipPacket(f, false, 17, 51000, 47990, 0)
	raw.in <- request
	if !bytes.Equal(readTestPacket(t, peer), request) {
		t.Fatal("peer policy failed")
	}
	if len(mux.gateway) != 0 {
		t.Fatal("denied peer packet escaped to gateway")
	}
	reply := ipPacket(f, true, 17, 51000, 47998, 0)
	if _, err = mux.Write([][]byte{reply}, 0); err != nil {
		t.Fatal(err)
	}
	if len(raw.out) != 0 {
		t.Fatal("gateway ingress bypassed P2P policy")
	}
	if _, err = peer.Write([][]byte{reply}, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(<-raw.out, reply) {
		t.Fatal("authorized P2P reply missing")
	}
	other := bytes.Clone(reply)
	copy(other[12:16], []byte{10, 99, 0, 1})
	_, _ = mux.Write([][]byte{other}, 0)
	if !bytes.Equal(<-raw.out, other) {
		t.Fatal("ordinary gateway ingress changed")
	}
	policy.Revoke()
	_, _ = peer.Write([][]byte{reply}, 0)
	if len(raw.out) != 0 {
		t.Fatal("revoked P2P write reached OS")
	}
	_ = peer.Close()
	raw.in <- request
	raw.in <- gateway
	if !bytes.Equal(readTestPacket(t, mux), gateway) {
		t.Fatal("closed peer fell back to gateway")
	}
	if len(mux.gateway) != 0 {
		t.Fatal("closed peer leaked")
	}
	_ = mux.Close()
	_ = mux.Close()
}

func TestMuxReservationsBoundedAndReadersClose(t *testing.T) {
	raw := newPipeTUN()
	mux, _ := NewMuxTUN(raw)
	for i := 0; i < MaxManagedSessions; i++ {
		if err := mux.Reserve(netip.AddrFrom4([4]byte{10, 1, 0, byte(i + 1)})); err != nil {
			t.Fatal(err)
		}
	}
	if mux.Reserve(netip.MustParseAddr("10.2.0.1")) == nil {
		t.Fatal("unbounded reservations")
	}
	done := make(chan error, 1)
	go func() { _, err := mux.Read([][]byte{make([]byte, 1500)}, make([]int, 1), 0); done <- err }()
	_ = mux.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("reader leaked")
	}
	if mux.Reserve(netip.MustParseAddr("10.2.0.1")) == nil {
		t.Fatal("closed mux accepted peer")
	}
}
