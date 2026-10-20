package routed

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type acceptanceWriter struct {
	device tun.Device
	mu     sync.Mutex
}

func (w *acceptanceWriter) WritePacket(p []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.device.Write([][]byte{p}, 0)
	return err
}

type linkFaultProxy struct {
	conn    *net.UDPConn
	blocked atomic.Bool
}

func newLinkFaultProxy(t *testing.T, target *net.UDPAddr) *linkFaultProxy {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &linkFaultProxy{conn: c}
	go func() {
		buf := make([]byte, 65535)
		var private *net.UDPAddr
		for {
			n, source, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if p.blocked.Load() {
				continue
			}
			if source.String() == target.String() {
				if private != nil {
					_, _ = c.WriteToUDP(buf[:n], private)
				}
			} else {
				private = source
				_, _ = c.WriteToUDP(buf[:n], target)
			}
		}
	}()
	return p
}

type measuredFlow struct {
	mu       sync.Mutex
	Sent     uint64  `json:"sent"`
	Received uint64  `json:"received"`
	Lost     uint64  `json:"lost"`
	MaxGapMS float64 `json:"max_gap_ms"`
	Error    string  `json:"error,omitempty"`
	Survived bool    `json:"survived"`
	last     time.Time
}

func (m *measuredFlow) sent() { m.mu.Lock(); m.Sent++; m.mu.Unlock() }
func (m *measuredFlow) received() {
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
}
func (m *measuredFlow) count() uint64  { m.mu.Lock(); defer m.mu.Unlock(); return m.Received }
func (m *measuredFlow) fail(err error) { m.mu.Lock(); m.Error = err.Error(); m.mu.Unlock() }

// Actual authenticated UDP links and userspace IP/TCP stacks. The Device
// ingress is injected after WireGuard decapsulation; this does not assert
// Windows, kernel routing, Access firewall or Raft acceptance.
func TestRoutedDirectToMultiHopPersistentTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("routed traffic acceptance")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reserve := func() int {
		c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			t.Fatal(e)
		}
		port := c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
		return port
	}
	ids := []string{"ru-01", "ru-02", "home-01"}
	meshes := map[string]*Mesh{}
	endpoints := map[string]string{}
	for _, id := range ids {
		m, e := NewMesh(id, reserve(), nil)
		if e != nil {
			t.Fatal(e)
		}
		meshes[id] = m
		defer m.Close()
		endpoints[id] = (&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: m.conn.LocalAddr().(*net.UDPAddr).Port}).String()
	}
	publicAddr, _ := net.ResolveUDPAddr("udp", endpoints["ru-02"])
	proxy := newLinkFaultProxy(t, publicAddr)
	defer proxy.conn.Close()
	clientIP := netip.MustParseAddr("10.253.0.2")
	serverIP := netip.MustParseAddr("192.168.88.10")
	clientTun, clientNet, e := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1280)
	if e != nil {
		t.Fatal(e)
	}
	defer clientTun.Close()
	serverTun, serverNet, e := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1280)
	if e != nil {
		t.Fatal(e)
	}
	defer serverTun.Close()
	paths := []Path{
		{ID: "direct-1", OwnerNodeID: "home-01", CIDR: "192.168.88.0/24", Hops: []string{"ru-01", "home-01"}, Health: "healthy", Score: 10},
		{ID: "direct-2", OwnerNodeID: "home-01", CIDR: "192.168.88.0/24", Hops: []string{"ru-02", "home-01"}, Health: "healthy", Score: 10},
		{ID: "via-1", OwnerNodeID: "home-01", CIDR: "192.168.88.0/24", Hops: []string{"ru-02", "ru-01", "home-01"}, Health: "healthy", Score: 100},
	}
	routers := map[string]*Router{}
	for i, id := range ids {
		cfg := RoutingConfig{Version: 1, OverlaySubnet: "10.253.0.0/24", LocalPublic: id != "home-01", LocalSiteRouter: id == "home-01", Routes: []Route{{CIDR: "192.168.88.0/24", OwnerNodeID: "home-01"}}, Paths: paths, TransitPaths: paths}
		for j, peer := range ids {
			if peer == id {
				continue
			}
			key := make([]byte, 32)
			for n := range key {
				key[n] = byte(1 + i + j)
			}
			endpoint := ""
			if peer != "home-01" {
				endpoint = endpoints[peer]
			}
			if id == "home-01" && peer == "ru-02" {
				endpoint = proxy.conn.LocalAddr().String()
			}
			cfg.Links = append(cfg.Links, LinkConfig{ID: fmt.Sprintf("pair-%d", i+j), PeerNodeID: peer, PeerEndpoint: endpoint, PSK: base64.StdEncoding.EncodeToString(key)})
		}
		if e := meshes[id].Reconcile(cfg.Links); e != nil {
			t.Fatal(e)
		}
		output := clientTun
		if id == "home-01" {
			output = serverTun
		}
		r, e := NewRouter(id, cfg, meshes[id], &acceptanceWriter{device: output}, nil)
		if e != nil {
			t.Fatal(e)
		}
		routers[id] = r
		meshes[id].SetDataHandler(func(peer string, p []byte) { _ = r.HandleMeshData(peer, p) })
		go meshes[id].Run(ctx)
	}
	pump := func(d tun.Device, r *Router) {
		go func() {
			buf := make([]byte, 65535)
			sizes := make([]int, 1)
			for {
				n, err := d.Read([][]byte{buf}, sizes, 0)
				if err != nil {
					return
				}
				if n > 0 {
					_ = r.HandleTunPacket(buf[:sizes[0]])
				}
			}
		}()
	}
	pump(clientTun, routers["ru-02"])
	pump(serverTun, routers["home-01"])
	wait := func(timeout time.Duration, fn func() bool) {
		t.Helper()
		until := time.Now().Add(timeout)
		for time.Now().Before(until) {
			if fn() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("acceptance condition timed out")
	}
	wait(8*time.Second, func() bool {
		for id, m := range meshes {
			for _, peer := range ids {
				if peer != id && !m.CanSend(peer) {
					return false
				}
			}
		}
		return true
	})
	selected := func() string {
		v := routers["ru-02"].SelectedPaths()
		if len(v) == 0 {
			return ""
		}
		return v[0].PathID
	}
	if selected() != "direct-2" {
		t.Fatal("initial direct path not selected")
	}
	trafficCtx, stopTraffic := context.WithCancel(ctx)
	defer stopTraffic()
	var traffic sync.WaitGroup
	metrics := map[string]*measuredFlow{}
	var tcpSockets []net.Conn
	for index, size := range []int{16384, 128} {
		name := "tcp_stream"
		pause := 10 * time.Millisecond
		if index == 1 {
			name = "rdp_like_tcp"
			pause = 50 * time.Millisecond
		}
		listener, e := serverNet.ListenTCPAddrPort(netip.AddrPortFrom(serverIP, uint16(9010+index)))
		if e != nil {
			t.Fatal(e)
		}
		defer listener.Close()
		go func() {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
		c, e := clientNet.DialContextTCP(ctx, net.TCPAddrFromAddrPort(netip.AddrPortFrom(serverIP, uint16(9010+index))))
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		tcpSockets = append(tcpSockets, c)
		m := &measuredFlow{}
		metrics[name] = m
		traffic.Add(1)
		go func() {
			defer traffic.Done()
			payload := make([]byte, size)
			reply := make([]byte, size)
			for trafficCtx.Err() == nil {
				_ = c.SetDeadline(time.Now().Add(20 * time.Second))
				m.sent()
				if _, err := c.Write(payload); err != nil {
					m.fail(err)
					return
				}
				if _, err := io.ReadFull(c, reply); err != nil {
					m.fail(err)
					return
				}
				m.received()
				select {
				case <-trafficCtx.Done():
					return
				case <-time.After(pause):
				}
			}
		}()
	}
	udpServer, e := serverNet.ListenUDPAddrPort(netip.AddrPortFrom(serverIP, 9020))
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
	udp, e := clientNet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(serverIP, 9020))
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	udpM := &measuredFlow{}
	metrics["udp"] = udpM
	traffic.Add(2)
	go func() {
		defer traffic.Done()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for sequence := uint64(1); ; sequence++ {
			select {
			case <-trafficCtx.Done():
				return
			case <-tick.C:
			}
			p := make([]byte, 128)
			binary.BigEndian.PutUint64(p, sequence)
			udpM.sent()
			if _, e := udp.Write(p); e != nil {
				udpM.fail(e)
				return
			}
		}
	}()
	go func() {
		defer traffic.Done()
		seen := map[uint64]bool{}
		buf := make([]byte, 1500)
		for trafficCtx.Err() == nil {
			_ = udp.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, e := udp.Read(buf)
			if e != nil {
				continue
			}
			if n < 8 {
				continue
			}
			seq := binary.BigEndian.Uint64(buf)
			if !seen[seq] {
				seen[seq] = true
				udpM.received()
			}
		}
	}()
	pingM := &measuredFlow{}
	metrics["ping"] = pingM
	traffic.Add(1)
	go func() {
		defer traffic.Done()
		for seq := 0; trafficCtx.Err() == nil; seq++ {
			c, e := clientNet.Dial("ping4", serverIP.String())
			if e != nil {
				pingM.fail(e)
				return
			}
			p, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{Seq: seq, Data: []byte("BPC routed acceptance")}}).Marshal(nil)
			_ = c.SetDeadline(time.Now().Add(100 * time.Millisecond))
			pingM.sent()
			_, e = c.Write(p)
			if e == nil {
				buf := make([]byte, 1500)
				n, e := c.Read(buf)
				if e == nil {
					msg, err := icmp.ParseMessage(1, buf[:n])
					if err == nil && msg.Type == ipv4.ICMPTypeEchoReply {
						pingM.received()
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
	wait(3*time.Second, func() bool {
		for _, m := range metrics {
			if m.count() < 3 {
				return false
			}
		}
		return true
	})
	fault := time.Now()
	proxy.blocked.Store(true)
	wait(8*time.Second, func() bool { return selected() == "via-1" })
	switched := time.Now()
	if switched.Sub(fault) > 2*time.Second {
		t.Fatalf("warm multi-hop handoff exceeded 2s: %s", switched.Sub(fault))
	}
	after := map[string]uint64{}
	for name, m := range metrics {
		after[name] = m.count()
	}
	wait(16*time.Second, func() bool {
		for name, m := range metrics {
			if m.count() <= after[name] {
				return false
			}
		}
		return true
	})
	proxy.blocked.Store(false)
	wait(8*time.Second, func() bool { s, ok := meshes["ru-02"].LinkStatus("home-01"); return ok && s.Health == "healthy" })
	if selected() != "via-1" {
		t.Fatal("recovered direct path immediately stole traffic")
	}
	stopTraffic()
	traffic.Wait()
	for name, m := range metrics {
		m.Lost = m.Sent - m.Received
		m.Survived = m.Error == "" && m.count() > after[name]
		if m.Error != "" {
			t.Errorf("%s failed: %s", name, m.Error)
		}
	}
	overlayAfter := tcpSockets[0].LocalAddr().(*net.TCPAddr).IP.String()
	if overlayAfter != clientIP.String() {
		t.Fatal("overlay source address changed")
	}
	report := map[string]any{"scenario": "D: direct uplink blocked; routed multi-hop fallback", "selected_path_before": "ru-02 -> home-01", "selected_path_after": "ru-02 -> ru-01 -> home-01", "failover_ms": float64(switched.Sub(fault)) / float64(time.Millisecond), "overlay_ip_before": clientIP.String(), "overlay_ip_after": overlayAfter, "traffic": metrics, "control_plane": "static controller-approved fixture; Raft not exercised", "scope": "real localhost routed mesh with userspace IP stacks; no kernel/WireGuard ingress"}
	raw, _ := json.MarshalIndent(report, "", "  ")
	t.Log(string(raw))
	if path := os.Getenv("BPC_ROUTED_MESH_REPORT"); path != "" {
		if e := os.WriteFile(path, append(raw, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
}
