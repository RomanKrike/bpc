package wgshim

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type independentResponder struct {
	device   *device.Device
	udp      net.Conn
	tcp      net.Listener
	received atomic.Uint64
}

func acceptanceKeyPair(t *testing.T) (string, string) {
	t.Helper()
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(private), hex.EncodeToString(public)
}

func reserveAcceptanceUDP(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()
	return addr
}

func startIndependentResponder(
	t *testing.T,
	serverKey string,
	clientPublic string,
	serverIP netip.Addr,
	clientIP netip.Addr,
) (*independentResponder, string) {
	t.Helper()
	tunDevice, stack, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	wgDevice := device.NewDevice(
		tunDevice,
		&acceptanceBind{},
		device.NewLogger(device.LogLevelError, "independent-responder "),
	)
	target := reserveAcceptanceUDP(t)
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		wgDevice.Close()
		t.Fatal(err)
	}
	if err := wgDevice.IpcSet(fmt.Sprintf(
		"private_key=%s\nlisten_port=%s\npublic_key=%s\nallowed_ip=%s/32\n",
		serverKey,
		port,
		clientPublic,
		clientIP,
	)); err != nil {
		wgDevice.Close()
		t.Fatal(err)
	}
	if err := wgDevice.Up(); err != nil {
		wgDevice.Close()
		t.Fatal(err)
	}

	udp, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(serverIP, 9010))
	if err != nil {
		wgDevice.Close()
		t.Fatal(err)
	}
	responder := &independentResponder{device: wgDevice, udp: udp}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, readErr := udp.ReadFrom(buf)
			if readErr != nil {
				return
			}
			responder.received.Add(1)
			_, _ = udp.WriteTo(buf[:n], addr)
		}
	}()

	tcp, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(serverIP, 9020))
	if err != nil {
		_ = udp.Close()
		wgDevice.Close()
		t.Fatal(err)
	}
	responder.tcp = tcp
	go func() {
		for {
			conn, acceptErr := tcp.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return responder, target
}

func (r *independentResponder) close() {
	if r == nil {
		return
	}
	if r.udp != nil {
		_ = r.udp.Close()
	}
	if r.tcp != nil {
		_ = r.tcp.Close()
	}
	if r.device != nil {
		r.device.Close()
	}
}

func stableAcceptanceUAPI(t *testing.T, client *device.Device) string {
	t.Helper()
	raw, err := client.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var stable []string
	for _, line := range strings.Split(raw, "\n") {
		for _, prefix := range []string{
			"private_key=",
			"public_key=",
			"preshared_key=",
			"allowed_ip=",
		} {
			if strings.HasPrefix(line, prefix) {
				stable = append(stable, line)
			}
		}
	}
	return strings.Join(stable, "\n")
}

// TestIndependentPublicNodeFailover exercises the architecture that production
// Public Nodes use: two independent WireGuard responders share only the same
// static overlay identity and Device peer material. The client keeps one
// userspace interface and one local WGShim endpoint. A cross-node transport
// switch explicitly reapplies the peer configuration, mirroring the Windows
// Agent's rehandshake without recreating the overlay interface.
//
// Existing TCP sessions are intentionally not asserted across this handoff:
// responder-local TCP/NAT/conntrack state is not replicated. The test proves
// unchanged overlay identity, an unchanged connected UDP application socket,
// and successful new TCP sessions after the new WireGuard handshake.
func TestIndependentPublicNodeFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("real cross-node transport acceptance")
	}

	clientKey, clientPublic := acceptanceKeyPair(t)
	serverKey, serverPublic := acceptanceKeyPair(t)
	clientIP := netip.MustParseAddr("10.253.0.2")
	serverIP := netip.MustParseAddr("10.253.0.1")

	responders := make([]*independentResponder, 2)
	targets := make([]string, 2)
	for i := range responders {
		responders[i], targets[i] = startIndependentResponder(
			t,
			serverKey,
			clientPublic,
			serverIP,
			clientIP,
		)
		defer responders[i].close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	psk := bytes.Repeat([]byte{73}, 32)
	txKey, err := DeriveKey(psk, ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	rxKey, err := DeriveKey(psk, ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	newCodec := func(key []byte) *Codec {
		codec, codecErr := NewCodec(key, 0, 31)
		if codecErr != nil {
			t.Fatal(codecErr)
		}
		return codec
	}

	endpoints := []string{reserveAcceptanceUDP(t), reserveAcceptanceUDP(t)}
	relayStops := make([]context.CancelFunc, len(endpoints))
	for i := range endpoints {
		relayCtx, stop := context.WithCancel(ctx)
		relayStops[i] = stop
		peer := MultiServerPeer{
			Fingerprint: "cross-node-device",
			RX:          newCodec(txKey),
			TX:          newCodec(rxKey),
		}
		endpoint := endpoints[i]
		target := targets[i]
		go func() {
			_ = RunMultiServer(relayCtx, MultiServerConfig{
				Listen: endpoint,
				Target: target,
				LoadPeers: func() (map[string]MultiServerPeer, error) {
					return map[string]MultiServerPeer{"device": peer}, nil
				},
			})
		}()
	}

	clientTun, clientStack, err := netstack.CreateNetTUN(
		[]netip.Addr{clientIP},
		nil,
		1280,
	)
	if err != nil {
		t.Fatal(err)
	}
	client := device.NewDevice(
		clientTun,
		&acceptanceBind{},
		device.NewLogger(device.LogLevelError, "cross-node-client "),
	)
	defer client.Close()

	local := reserveAcceptanceUDP(t)
	clientUAPI := fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=%s\n"+
			"persistent_keepalive_interval=1\nreplace_allowed_ips=true\nallowed_ip=%s/32\n",
		clientKey,
		serverPublic,
		local,
		serverIP,
	)

	reports := make(chan EndpointReport, 128)
	switched := make(chan time.Time, 1)
	rehandshakeErr := make(chan error, 1)
	go func() {
		_ = RunAdaptiveClient(ctx, AdaptiveClientConfig{
			LocalListen:   local,
			Servers:       endpoints,
			TX:            newCodec(txKey),
			RX:            newCodec(rxKey),
			ProbeTimeout:  400 * time.Millisecond,
			ProbeInterval: 250 * time.Millisecond,
			Policy: PathPolicy{
				MinimumImprovement:    time.Second,
				MinimumStableDuration: time.Hour,
			},
			OnEndpointReport: func(report EndpointReport) {
				select {
				case reports <- report:
				default:
				}
				if report.Switched && report.Selected == endpoints[1] {
					if setErr := client.IpcSet(clientUAPI); setErr != nil {
						select {
						case rehandshakeErr <- setErr:
						default:
						}
						return
					}
					select {
					case switched <- time.Now():
					default:
					}
				}
			},
		})
	}()

	warmDeadline := time.NewTimer(5 * time.Second)
	defer warmDeadline.Stop()
	for {
		select {
		case report := <-reports:
			if report.Selected != endpoints[0] {
				t.Fatalf("standby selected before fault: %s", report.Selected)
			}
			if report.Reachable == 2 {
				goto warmed
			}
		case <-warmDeadline.C:
			t.Fatal("independent Public Node paths did not warm")
		}
	}

warmed:
	if err := client.IpcSet(clientUAPI); err != nil {
		t.Fatal(err)
	}
	if err := client.Up(); err != nil {
		t.Fatal(err)
	}
	overlayBefore := stableAcceptanceUAPI(t, client)

	udp, err := clientStack.DialUDPAddrPort(
		netip.AddrPort{},
		netip.AddrPortFrom(serverIP, 9010),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpAddressBefore := udp.LocalAddr().String()

	exchangeUDP := func(payload []byte, timeout time.Duration) error {
		if err := udp.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		if _, err := udp.Write(payload); err != nil {
			return err
		}
		reply := make([]byte, len(payload))
		n, err := udp.Read(reply)
		if err != nil {
			return err
		}
		if !bytes.Equal(reply[:n], payload) {
			return fmt.Errorf("UDP payload mismatch: got %x want %x", reply[:n], payload)
		}
		return nil
	}

	if err := exchangeUDP([]byte("before-cross-node-failover"), 5*time.Second); err != nil {
		clientState, _ := client.IpcGet()
		serverState, _ := responders[0].device.IpcGet()
		t.Fatalf(
			"baseline UDP traffic failed: %v client_uapi=%q server_uapi=%q responder_rx=%d",
			err,
			clientState,
			serverState,
			responders[0].received.Load(),
		)
	}
	if responders[0].received.Load() == 0 {
		t.Fatal("baseline traffic did not reach the first responder")
	}

	fault := time.Now()
	relayStops[0]()
	responders[0].close()

	var switchedAt time.Time
	select {
	case switchedAt = <-switched:
	case err := <-rehandshakeErr:
		t.Fatalf("cross-node WireGuard rehandshake failed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("cross-node transport switch timed out")
	}
	if elapsed := switchedAt.Sub(fault); elapsed > 1500*time.Millisecond {
		t.Fatalf("cross-node path switch too slow: %s", elapsed)
	}

	recoveryDeadline := time.Now().Add(5 * time.Second)
	var recoveryErr error
	for attempt := 0; time.Now().Before(recoveryDeadline); attempt++ {
		payload := []byte(fmt.Sprintf("after-cross-node-failover-%d", attempt))
		recoveryErr = exchangeUDP(payload, 250*time.Millisecond)
		if recoveryErr == nil && responders[1].received.Load() > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if recoveryErr != nil {
		t.Fatalf("connected UDP socket did not recover through second responder: %v", recoveryErr)
	}
	if responders[1].received.Load() == 0 {
		t.Fatal("post-failover traffic did not reach the second responder")
	}
	if udp.LocalAddr().String() != udpAddressBefore {
		t.Fatalf(
			"connected UDP application socket changed across failover: before=%s after=%s",
			udpAddressBefore,
			udp.LocalAddr(),
		)
	}
	if stableAcceptanceUAPI(t, client) != overlayBefore {
		t.Fatal("overlay identity or AllowedIPs changed during cross-node failover")
	}

	tcpCtx, stopTCP := context.WithTimeout(ctx, 5*time.Second)
	tcp, err := clientStack.DialContextTCPAddrPort(
		tcpCtx,
		netip.AddrPortFrom(serverIP, 9020),
	)
	stopTCP()
	if err != nil {
		t.Fatalf("new TCP session did not establish after cross-node failover: %v", err)
	}
	defer tcp.Close()
	payload := []byte("new-tcp-after-cross-node-failover")
	if err := tcp.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := tcp.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(tcp, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatalf("new TCP payload mismatch: got %q want %q", reply, payload)
	}

	t.Logf(
		"independent Public Node failover switch=%s recovery=%s overlay=%s UDP_socket_preserved=true",
		switchedAt.Sub(fault),
		time.Since(fault),
		clientIP,
	)
}
