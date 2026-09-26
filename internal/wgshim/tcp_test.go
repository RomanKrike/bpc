package wgshim

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func reserveTCPAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	return addr
}

func reserveUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()
	return addr
}

func testPeerCodecs(t *testing.T) (*Codec, *Codec) {
	t.Helper()
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	c2sKey, err := DeriveKey(psk, ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	s2cKey, err := DeriveKey(psk, ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	c2s, err := NewCodec(c2sKey, 0, 11)
	if err != nil {
		t.Fatal(err)
	}
	s2c, err := NewCodec(s2cKey, 0, 11)
	if err != nil {
		t.Fatal(err)
	}
	return c2s, s2c
}

func startUDPEchoTarget(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, readErr := conn.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn
}

func TestTCPClientMultiServerRoundTrip(t *testing.T) {
	target := startUDPEchoTarget(t)
	defer target.Close()

	serverAddr := reserveTCPAddr(t)
	clientAddr := reserveUDPAddr(t)
	c2s, s2c := testPeerCodecs(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- RunTCPMultiServer(ctx, TCPMultiServerConfig{
			Listen: serverAddr,
			Target: target.LocalAddr().String(),
			LoadPeers: func() (map[string]MultiServerPeer, error) {
				return map[string]MultiServerPeer{
					"tcp-peer": {
						Fingerprint: "tcp-peer",
						RX:          c2s,
						TX:          s2c,
					},
				}, nil
			},
			ReloadInterval: 25 * time.Millisecond,
		})
	}()

	time.Sleep(50 * time.Millisecond)
	clientErr := make(chan error, 1)
	go func() {
		clientErr <- RunTCPClient(ctx, TCPClientConfig{
			LocalListen: clientAddr,
			Server:      serverAddr,
			TX:          c2s,
			RX:          s2c,
		})
	}()

	time.Sleep(100 * time.Millisecond)
	clientUDP, err := net.ResolveUDPAddr("udp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	wgConn, err := net.DialUDP("udp", nil, clientUDP)
	if err != nil {
		t.Fatal(err)
	}
	defer wgConn.Close()
	if err := wgConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	payload := []byte("tcp-wg-echo")
	if _, err := wgConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := wgConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("unexpected TCP relay echo: got %q want %q", buf[:n], payload)
	}

	cancel()
	select {
	case err := <-clientErr:
		if err != nil {
			t.Fatalf("TCP client exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP client did not stop")
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("TCP server exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP server did not stop")
	}
}

func TestAdaptiveTransportSelectsFasterTCP(t *testing.T) {
	target := startUDPEchoTarget(t)
	defer target.Close()

	tcpAddr := reserveTCPAddr(t)
	clientAddr := reserveUDPAddr(t)
	c2s, s2c := testPeerCodecs(t)

	slowUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer slowUDP.Close()
	slowUDPAddr := slowUDP.LocalAddr().String()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, readErr := slowUDP.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			packetType, inner, openErr := c2s.OpenTyped(buf[:n])
			if openErr != nil {
				continue
			}
			time.Sleep(35 * time.Millisecond)
			var outer []byte
			if IsProbe(packetType) {
				outer, _ = s2c.SealProbeReply(inner)
			} else if IsData(packetType) {
				outer, _ = s2c.Seal(inner)
			} else {
				continue
			}
			_, _ = slowUDP.WriteToUDP(outer, addr)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- RunTCPMultiServer(ctx, TCPMultiServerConfig{
			Listen: tcpAddr,
			Target: target.LocalAddr().String(),
			LoadPeers: func() (map[string]MultiServerPeer, error) {
				return map[string]MultiServerPeer{
					"hybrid-peer": {
						Fingerprint: "hybrid-peer",
						RX:          c2s,
						TX:          s2c,
					},
				}, nil
			},
			ReloadInterval: 25 * time.Millisecond,
		})
	}()

	reports := make(chan TransportReport, 8)
	clientErr := make(chan error, 1)
	go func() {
		clientErr <- RunAdaptiveTransportClient(ctx, AdaptiveTransportClientConfig{
			LocalListen:     clientAddr,
			UDPServer:       slowUDPAddr,
			TCPServer:       tcpAddr,
			TX:              c2s,
			RX:              s2c,
			ProbeInterval:   time.Second,
			ProbeTimeout:    250 * time.Millisecond,
			SwitchThreshold: 5 * time.Millisecond,
			OnTransportReport: func(report TransportReport) {
				reports <- report
			},
		})
	}()

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	selectedTCP := false
	for !selectedTCP {
		select {
		case report := <-reports:
			if report.Selected == TransportTCP && report.TCPReplies > 0 && report.UDPRTT > report.TCPRTT {
				selectedTCP = true
			}
		case <-deadline.C:
			t.Fatal("adaptive transport did not select faster TCP path")
		}
	}

	clientUDP, err := net.ResolveUDPAddr("udp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	wgConn, err := net.DialUDP("udp", nil, clientUDP)
	if err != nil {
		t.Fatal(err)
	}
	defer wgConn.Close()
	if err := wgConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("adaptive-tcp-data")
	if _, err := wgConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := wgConn.Read(buf)
	if err != nil {
		t.Fatalf("adaptive TCP data round-trip failed: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("unexpected adaptive reply: got %q want %q", buf[:n], payload)
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
			t.Fatalf("adaptive TCP server exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("adaptive TCP server did not stop")
	}
}
