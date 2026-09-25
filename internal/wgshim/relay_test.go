package wgshim

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func TestClientServerRelayRoundTrip(t *testing.T) {
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
			_, _ = targetConn.WriteToUDP(buf[:n], addr)
		}
	}()

	serverProbe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := serverProbe.LocalAddr().String()
	_ = serverProbe.Close()

	clientProbe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := clientProbe.LocalAddr().String()
	_ = clientProbe.Close()

	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	c2s, _ := DeriveKey(psk, ClientToServer)
	s2c, _ := DeriveKey(psk, ServerToClient)
	c2sCodec, _ := NewCodec(c2s, 0, 7)
	s2cCodec, _ := NewCodec(s2c, 0, 7)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverErr := make(chan error, 1)
	clientErr := make(chan error, 1)
	go func() {
		serverErr <- RunServer(ctx, ServerConfig{
			Listen: serverAddr,
			Target: targetConn.LocalAddr().String(),
			RX:     c2sCodec,
			TX:     s2cCodec,
		})
	}()
	time.Sleep(50 * time.Millisecond)
	go func() {
		clientErr <- RunClient(ctx, ClientConfig{
			LocalListen: clientAddr,
			Server:      serverAddr,
			TX:          c2sCodec,
			RX:          s2cCodec,
		})
	}()
	time.Sleep(50 * time.Millisecond)

	localAddr, err := net.ResolveUDPAddr("udp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	wgConn, err := net.DialUDP("udp", nil, localAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer wgConn.Close()
	if err := wgConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("wg-echo")
	if _, err := wgConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := wgConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("unexpected echo: %q", buf[:n])
	}

	cancel()
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
	select {
	case err := <-clientErr:
		if err != nil {
			t.Fatalf("client exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not stop")
	}
}

func TestAdaptiveClientSelectsReachableEndpoint(t *testing.T) {
	reserve := func() string {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		addr := conn.LocalAddr().String()
		_ = conn.Close()
		return addr
	}

	deadAddr := reserve()
	liveAddr := reserve()
	clientAddr := reserve()

	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer targetConn.Close()

	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	c2sKey, _ := DeriveKey(psk, ClientToServer)
	s2cKey, _ := DeriveKey(psk, ServerToClient)
	c2sCodec, _ := NewCodec(c2sKey, 0, 19)
	s2cCodec, _ := NewCodec(s2cKey, 0, 19)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- RunMultiServer(ctx, MultiServerConfig{
			Listen: liveAddr,
			Target: targetConn.LocalAddr().String(),
			LoadPeers: func() (map[string]MultiServerPeer, error) {
				return map[string]MultiServerPeer{
					"adaptive-peer": {
						Fingerprint: "adaptive-peer",
						RX:          c2sCodec,
						TX:          s2cCodec,
					},
				}, nil
			},
			ReloadInterval: 25 * time.Millisecond,
		})
	}()
	time.Sleep(50 * time.Millisecond)

	reports := make(chan EndpointReport, 16)
	clientErr := make(chan error, 1)
	go func() {
		clientErr <- RunAdaptiveClient(ctx, AdaptiveClientConfig{
			LocalListen:     clientAddr,
			Servers:         []string{deadAddr, liveAddr},
			TX:              c2sCodec,
			RX:              s2cCodec,
			ProbeTimeout:    150 * time.Millisecond,
			SwitchThreshold: 5 * time.Millisecond,
			OnEndpointReport: func(report EndpointReport) {
				reports <- report
			},
		})
	}()

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	selectedLive := false
	for !selectedLive {
		select {
		case report := <-reports:
			if report.Selected == liveAddr && report.Reachable == 1 && report.Switched {
				selectedLive = true
			}
		case <-deadline.C:
			t.Fatalf("adaptive client did not fail over to reachable endpoint %s", liveAddr)
		}
	}

	cancel()
	select {
	case err := <-clientErr:
		if err != nil {
			t.Fatalf("adaptive client exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("adaptive client did not stop")
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("adaptive server exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("adaptive server did not stop")
	}
}
