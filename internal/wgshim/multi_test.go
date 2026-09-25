package wgshim

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func TestMultiServerRoutesIndependentPeers(t *testing.T) {
	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer targetConn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := targetConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
			_, _ = targetConn.WriteToUDP(buf[:n], addr)
		}
	}()

	serverProbe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := serverProbe.LocalAddr().String()
	_ = serverProbe.Close()

	type peerCodecs struct {
		c2s *Codec
		s2c *Codec
	}
	codecs := map[string]peerCodecs{}
	serverPeers := map[string]MultiServerPeer{}
	for _, id := range []string{"alpha", "beta"} {
		psk := make([]byte, 32)
		if _, err := rand.Read(psk); err != nil {
			t.Fatal(err)
		}
		c2sKey, _ := DeriveKey(psk, ClientToServer)
		s2cKey, _ := DeriveKey(psk, ServerToClient)
		c2s, _ := NewCodec(c2sKey, 0, 7)
		s2c, _ := NewCodec(s2cKey, 0, 7)
		codecs[id] = peerCodecs{c2s: c2s, s2c: s2c}
		serverPeers[id] = MultiServerPeer{
			Fingerprint: id,
			RX:          c2s,
			TX:          s2c,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- RunMultiServer(ctx, MultiServerConfig{
			Listen: serverAddr,
			Target: targetConn.LocalAddr().String(),
			LoadPeers: func() (map[string]MultiServerPeer, error) {
				return serverPeers, nil
			},
			ReloadInterval: 25 * time.Millisecond,
		})
	}()
	time.Sleep(50 * time.Millisecond)

	serverUDP, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	alpha, err := net.DialUDP("udp", nil, serverUDP)
	if err != nil {
		t.Fatal(err)
	}
	defer alpha.Close()
	beta, err := net.DialUDP("udp", nil, serverUDP)
	if err != nil {
		t.Fatal(err)
	}
	defer beta.Close()

	if _, err := alpha.Write(mustSeal(t, codecs["alpha"].c2s, []byte("alpha-payload"))); err != nil {
		t.Fatal(err)
	}
	if _, err := beta.Write(mustSeal(t, codecs["beta"].c2s, []byte("beta-payload"))); err != nil {
		t.Fatal(err)
	}

	assertOuterReply(t, alpha, codecs["alpha"].s2c, "alpha-payload")
	assertOuterReply(t, beta, codecs["beta"].s2c, "beta-payload")

	cancel()
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("multi-server exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("multi-server did not stop")
	}
}

func mustSeal(t *testing.T, codec *Codec, payload []byte) []byte {
	t.Helper()
	packet, err := codec.Seal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func assertOuterReply(t *testing.T, conn *net.UDPConn, codec *Codec, want string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.Open(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != want {
		t.Fatalf("unexpected reply: got %q want %q", payload, want)
	}
}
