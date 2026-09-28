package wgshim

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type trafficMeasurement struct {
	Unit       string  `json:"unit"`
	Sent       uint64  `json:"sent"`
	Received   uint64  `json:"received"`
	Lost       uint64  `json:"lost"`
	MaxGapMS   float64 `json:"max_gap_ms"`
	Survived   bool    `json:"survived"`
	Error      string  `json:"error,omitempty"`
	last       time.Time
	afterFault uint64
	mu         sync.Mutex
}

func (m *trafficMeasurement) receive(fault time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if !m.last.IsZero() {
		gap := float64(now.Sub(m.last)) / float64(time.Millisecond)
		if gap > m.MaxGapMS {
			m.MaxGapMS = gap
		}
	}
	m.last = now
	m.Received++
	if !fault.IsZero() && now.After(fault) {
		m.afterFault++
	}
}

// This is actual WireGuard + WGShim + TCP/UDP/ICMP traffic over two localhost
// relay endpoints, not mocked packets. Both relays terminate at the SAME live
// overlay destination. It does not establish independent gateway/NAT HA, VPS
// reboot behavior or Windows Wintun acceptance.
func TestWireGuardPathFailoverTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("real transport acceptance")
	}
	reserve := func() string {
		t.Helper()
		c, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		a := c.LocalAddr().String()
		c.Close()
		return a
	}
	key := func() (string, string) {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		p, e := curve25519.X25519(b, curve25519.Basepoint)
		if e != nil {
			t.Fatal(e)
		}
		return hex.EncodeToString(b), hex.EncodeToString(p)
	}
	clientKey, clientPub := key()
	serverKey, serverPub := key()
	clientIP := netip.MustParseAddr("10.253.0.2")
	serverIP := netip.MustParseAddr("10.253.0.1")
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	client := device.NewDevice(clientTun, &acceptanceBind{}, device.NewLogger(device.LogLevelError, "client "))
	server := device.NewDevice(serverTun, &acceptanceBind{}, device.NewLogger(device.LogLevelError, "server "))
	defer client.Close()
	defer server.Close()
	target := reserve()
	_, port, _ := net.SplitHostPort(target)
	if err = server.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%s\npublic_key=%s\nallowed_ip=%s/32\n", serverKey, port, clientPub, clientIP)); err != nil {
		t.Fatal(err)
	}
	if err = server.Up(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	psk := bytes.Repeat([]byte{37}, 32)
	txKey, _ := DeriveKey(psk, ClientToServer)
	rxKey, _ := DeriveKey(psk, ServerToClient)
	codec := func(k []byte) *Codec {
		c, e := NewCodec(k, 0, 31)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	endpoints := []string{reserve(), reserve()}
	stops := make([]context.CancelFunc, 2)
	for i, endpoint := range endpoints {
		relayCtx, stop := context.WithCancel(ctx)
		stops[i] = stop
		peer := MultiServerPeer{Fingerprint: "test-device", RX: codec(txKey), TX: codec(rxKey)}
		go func() {
			_ = RunMultiServer(relayCtx, MultiServerConfig{Listen: endpoint, Target: target, LoadPeers: func() (map[string]MultiServerPeer, error) { return map[string]MultiServerPeer{"device": peer}, nil }})
		}()
	}
	local := reserve()
	reports := make(chan EndpointReport, 100)
	go func() {
		_ = RunAdaptiveClient(ctx, AdaptiveClientConfig{LocalListen: local, Servers: endpoints, TX: codec(txKey), RX: codec(rxKey), OnEndpointReport: func(r EndpointReport) {
			select {
			case reports <- r:
			default:
			}
		}})
	}()
	ready := time.After(5 * time.Second)
	for {
		select {
		case r := <-reports:
			if r.Reachable == 2 {
				goto warmed
			}
		case <-ready:
			t.Fatal("both paths did not warm")
		}
	}
warmed:
	if err = client.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=1\n", clientKey, serverPub, local, serverIP)); err != nil {
		t.Fatal(err)
	}
	if err = client.Up(); err != nil {
		t.Fatal(err)
	}
	var faultMu sync.RWMutex
	var fault time.Time
	getFault := func() time.Time { faultMu.RLock(); defer faultMu.RUnlock(); return fault }
	trafficCtx, stopTraffic := context.WithCancel(ctx)
	var traffic sync.WaitGroup
	metrics := map[string]*trafficMeasurement{}
	var tcpSockets []net.Conn
	var overlayAddressBefore string
	stableUAPI := func() string {
		raw, e := client.IpcGet()
		if e != nil {
			t.Fatal(e)
		}
		var stable []string
		for _, line := range strings.Split(raw, "\n") {
			for _, prefix := range []string{"private_key=", "public_key=", "preshared_key=", "allowed_ip="} {
				if strings.HasPrefix(line, prefix) {
					stable = append(stable, line)
				}
			}
		}
		return strings.Join(stable, "\n")
	}
	overlayBefore := stableUAPI()
	for i, name := range []string{"tcp_stream", "rdp_like_tcp"} {
		listener, e := serverNet.ListenTCPAddrPort(netip.AddrPortFrom(serverIP, uint16(9000+i)))
		if e != nil {
			t.Fatal(e)
		}
		defer listener.Close()
		go func() {
			c, e := listener.Accept()
			if e == nil {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}
		}()
		dialCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		c, e := clientNet.DialContextTCPAddrPort(dialCtx, netip.AddrPortFrom(serverIP, uint16(9000+i)))
		stop()
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		tcpSockets = append(tcpSockets, c)
		if overlayAddressBefore == "" {
			overlayAddressBefore = c.LocalAddr().(*net.TCPAddr).IP.String()
		}
		m := &trafficMeasurement{Unit: "application_messages"}
		metrics[name] = m
		size, interval := 32768, 10*time.Millisecond
		if i == 1 {
			size = 128
			interval = 50 * time.Millisecond
		}
		traffic.Add(1)
		go func() {
			defer traffic.Done()
			payload := bytes.Repeat([]byte{42}, size)
			reply := make([]byte, size)
			for trafficCtx.Err() == nil {
				c.SetDeadline(time.Now().Add(15 * time.Second))
				_, e := c.Write(payload)
				if e == nil {
					_, e = io.ReadFull(c, reply)
				}
				if e != nil {
					if trafficCtx.Err() == nil {
						m.Error = e.Error()
					}
					return
				}
				if !bytes.Equal(reply, payload) {
					m.Error = "TCP payload mismatch"
					return
				}
				m.mu.Lock()
				m.Sent++
				m.mu.Unlock()
				m.receive(getFault())
				select {
				case <-trafficCtx.Done():
					return
				case <-time.After(interval):
				}
			}
		}()
	}
	udpServer, e := serverNet.ListenUDPAddrPort(netip.AddrPortFrom(serverIP, 9010))
	if e != nil {
		t.Fatal(e)
	}
	defer udpServer.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, a, e := udpServer.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = udpServer.WriteTo(buf[:n], a)
		}
	}()
	udp, e := clientNet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(serverIP, 9010))
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	for name, c := range map[string]net.Conn{"udp": udp} {
		m := &trafficMeasurement{Unit: "datagrams"}
		metrics[name] = m
		traffic.Add(2)
		go func() {
			defer traffic.Done()
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			for seq := 0; ; seq++ {
				select {
				case <-trafficCtx.Done():
					return
				case <-ticker.C:
				}
				payload := make([]byte, 128)
				binary.BigEndian.PutUint64(payload, uint64(seq))

				if _, e := c.Write(payload); e != nil {
					if trafficCtx.Err() == nil {
						m.Error = e.Error()
					}
					return
				}
				m.mu.Lock()
				m.Sent++
				m.mu.Unlock()
			}
		}()
		go func() {
			defer traffic.Done()
			buf := make([]byte, 2048)
			seen := map[uint64]bool{}
			for trafficCtx.Err() == nil {
				c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, e := c.Read(buf)
				if e != nil {
					continue
				}
				payload := buf[:n]

				if len(payload) < 8 {
					continue
				}
				seq := binary.BigEndian.Uint64(payload)
				if seen[seq] {
					continue
				}
				seen[seq] = true
				m.receive(getFault())
			}
		}()
	}

	// The dependency's PingConn waits for a new readiness edge before reading
	// queued packets. Use independent ICMP exchanges so a timed-out exchange
	// cannot leave an unread queue that suppresses all subsequent notifications.
	pingMetric := &trafficMeasurement{Unit: "ICMP_exchanges"}
	metrics["ping"] = pingMetric
	traffic.Add(1)
	go func() {
		defer traffic.Done()
		for seq := 0; trafficCtx.Err() == nil; seq++ {
			c, e := clientNet.Dial("ping4", serverIP.String())
			if e != nil {
				pingMetric.Error = e.Error()
				return
			}
			payload, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{Seq: seq, Data: []byte("BPC acceptance")}}).Marshal(nil)
			c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, e = c.Write(payload)
			pingMetric.mu.Lock()
			pingMetric.Sent++
			pingMetric.mu.Unlock()
			if e == nil {
				buf := make([]byte, 1500)
				n, readErr := c.Read(buf)
				if readErr == nil {
					message, parseErr := icmp.ParseMessage(1, buf[:n])
					if parseErr == nil && message.Type == ipv4.ICMPTypeEchoReply {
						pingMetric.receive(getFault())
					}
				}
			}
			c.Close()
			select {
			case <-trafficCtx.Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	time.Sleep(time.Second)
	for name, m := range metrics {
		m.mu.Lock()
		count := m.Received
		m.mu.Unlock()
		if count == 0 {
			t.Fatalf("%s no baseline traffic", name)
		}
	}
	faultMu.Lock()
	fault = time.Now()
	faultMu.Unlock()
	stops[0]()
	var switched time.Time
	deadline := time.After(5 * time.Second)
	for switched.IsZero() {
		select {
		case r := <-reports:
			if r.Selected == endpoints[1] {
				switched = time.Now()
			}
		case <-deadline:
			t.Fatal("failover timed out")
		}
	}
	postSwitch := map[string]uint64{}
	for name, m := range metrics {
		m.mu.Lock()
		postSwitch[name] = m.Received
		m.mu.Unlock()
	}
	recoveryDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(recoveryDeadline) {
		recovered := true
		for name, m := range metrics {
			m.mu.Lock()
			if m.Received <= postSwitch[name] {
				recovered = false
			}
			m.mu.Unlock()
		}
		if recovered && time.Since(switched) >= 3*time.Second {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopTraffic()
	traffic.Wait()
	for name, m := range metrics {
		m.Lost = m.Sent - m.Received
		m.Survived = m.Error == "" && m.Received > postSwitch[name]
		if !m.Survived {
			t.Errorf("%s did not survive: %+v", name, m)
		}
	}
	overlayAddressAfter := tcpSockets[0].LocalAddr().(*net.TCPAddr).IP.String()
	if stableUAPI() != overlayBefore || overlayAddressAfter != overlayAddressBefore {
		t.Fatal("overlay identity or routes changed during failover")
	}
	report := map[string]any{"topology": "two WGShim relays, one unchanged WireGuard destination, localhost", "failover_ms": float64(switched.Sub(fault)) / float64(time.Millisecond), "overlay_ip_before": overlayAddressBefore, "overlay_ip_after": overlayAddressAfter, "wireguard_identity_and_routes_unchanged": true, "traffic": metrics, "gateway_failure_tested": false}
	raw, _ := json.MarshalIndent(report, "", "  ")
	t.Log(string(raw))
	if file := os.Getenv("BPC_PATH_REPORT"); file != "" {
		if e := os.WriteFile(file, append(raw, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
}
