package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func startRelay(t *testing.T, f fixture) (*Relay, string, *tls.Config) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	server := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	client := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13}
	r, err := NewRelay(f.issuer.Public().(ed25519.PublicKey), f.grant.ClusterID, f.grant.Revision)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, l, server) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("relay leaked handlers")
		}
	})
	return r, l.Addr().String(), client
}

func dialTestRelay(t *testing.T, f fixture, address string, config *tls.Config, side Side) net.Conn {
	t.Helper()
	c, err := DialRelay(context.Background(), address, config, f.session, side, f.identities[side])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRelayAuthenticationRevocationAndOpaqueFrames(t *testing.T) {
	f := newFixture(t)
	r, address, config := startRelay(t, f)
	badConfig := config.Clone()
	badConfig.ServerName = "wrong-host"
	if c, err := DialRelay(context.Background(), address, badConfig, f.session, Initiator, f.identities[0]); err == nil {
		c.Close()
		t.Fatal("wrong relay certificate accepted")
	}
	if c, err := DialRelay(context.Background(), address, config, f.session, Host, f.identities[0]); err == nil {
		c.Close()
		t.Fatal("wrong Device key accepted")
	}
	a := dialTestRelay(t, f, address, config, Initiator)
	b := dialTestRelay(t, f, address, config, Host)
	if c, err := DialRelay(context.Background(), address, config, f.session, Initiator, f.identities[0]); err == nil {
		c.Close()
		t.Fatal("duplicate session side accepted")
	}
	// The relay sees only opaque WG envelopes. Full encrypted traffic is tested
	// separately below; this fixture tests framing and authenticated pairing.
	packet := make([]byte, 32)
	packet[0] = 4
	copy(packet[16:], []byte("opaque-test-data!"))
	if err := writeFrame(a, packet); err != nil {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	got, err := readFrame(b, maxDatagram)
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("opaque relay delivery failed: %v", err)
	}
	// Application delivery can finish just before the relay updates telemetry.
	for deadline := time.Now().Add(time.Second); r.ForwardedBytes() != 32 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if r.ForwardedBytes() != 32 {
		t.Fatal("relay byte counter incorrect")
	}
	r.Revoke(f.grant.SessionID)
	if _, err = readFrame(b, maxDatagram); err == nil {
		t.Fatal("revoked session still open")
	}
	if c, err := DialRelay(context.Background(), address, config, f.session, Host, f.identities[1]); err == nil {
		c.Close()
		t.Fatal("revoked ticket reattached")
	}
}

func TestRelayRevokeBeforeAdmission(t *testing.T) {
	f := newFixture(t)
	r, address, config := startRelay(t, f)
	r.Revoke(f.grant.SessionID)
	if c, err := DialRelay(context.Background(), address, config, f.session, Initiator, f.identities[0]); err == nil {
		c.Close()
		t.Fatal("pre-admission revoke lost")
	}
}

func TestRelayRejectsCopiedProof(t *testing.T) {
	f := newFixture(t)
	_, address, config := startRelay(t, f)
	connect := func() net.Conn {
		c, err := tls.Dial("tcp", address, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(time.Second))
		return c
	}
	a := connect()
	challenge, err := readFrame(a, 32)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := tlsBinding(a)
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := json.Marshal(relayAuth{Ticket: f.ticket, Side: Initiator, Proof: ed25519.Sign(f.identities[0], proofMessage(challenge, f.ticket, Initiator, binding))})
	b := connect()
	if _, err = readFrame(b, 32); err != nil {
		t.Fatal(err)
	}
	if err = writeFrame(b, auth); err != nil {
		t.Fatal(err)
	}
	if _, err = readFrame(b, 32); err == nil {
		t.Fatal("proof replayed on different connection")
	}
}

func TestFrameLimits(t *testing.T) {
	for _, input := range [][]byte{{0, 0, 0, 0}, {0, 1, 0, 0}, {0, 0, 0, 8, 1}} {
		if _, err := readFrame(bytes.NewReader(input), maxDatagram); err == nil {
			t.Fatal("malformed frame accepted")
		}
	}
}

func TestRelayClosesIdleExpiredSession(t *testing.T) {
	f := newFixture(t)
	f.grant.IssuedAt = time.Now().Unix() - 1
	f.grant.ExpiresAt = time.Now().Unix() + 2
	var err error
	f.ticket, err = SignGrant(f.grant, f.issuer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.session, err = VerifyGrant(f.ticket, f.issuer.Public().(ed25519.PublicKey), f.grant.ClusterID, 7, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, address, config := startRelay(t, f)
	a := dialTestRelay(t, f, address, config, Initiator)
	// No data is needed to expire an admitted idle connection. Remove the
	// client's own lease read deadline so only server closure can satisfy this.
	_ = a.SetReadDeadline(time.Now().Add(4 * time.Second))
	_, err = readFrame(a, maxDatagram)
	if err == nil {
		t.Fatal("idle session survived expiry")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("server did not close expired idle session")
	}
}

func wgHex(t *testing.T, key string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// TestWireGuardRelayEndpointAccess uses two independent userspace WG devices,
// actual TLS/UDP sockets and TCP/UDP application sockets. The initiator is
// deliberately UNFILTERED: a malicious client cannot bypass the HOST's Access.
// No OS routes, firewall rules or real gaming software are modified.
func TestWireGuardRelayEndpointAccess(t *testing.T) {
	runWireGuardRelayEndpointAccess(t, false)
}

func TestControllerPolicyRevokesWireGuardTraffic(t *testing.T) {
	runWireGuardRelayEndpointAccess(t, true)
}

func runWireGuardRelayEndpointAccess(t *testing.T, managed bool) {
	if testing.Short() {
		t.Skip("real userspace WireGuard/TLS/TCP/UDP acceptance")
	}
	f := newFixture(t)
	var hostStore *PolicyStore
	var hostSession *Session
	if managed {
		var err error
		hostStore, err = CreatePolicyStore(filepath.Join(t.TempDir(), "host-policy.db"), fixtureTrust(f))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = hostStore.Close() })
		hostSession, err = hostStore.Track(f.ticket)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = hostStore.Apply(signedPolicy(t, f, 8, true)); err != nil {
			t.Fatal(err)
		}
	}
	r, address, config := startRelay(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var devices [2]*device.Device
	var stacks [2]*netstack.Net
	var bridges [2]*net.UDPConn
	var policies [2]*Policy
	var relays [2]net.Conn
	for i := range devices {
		var err error
		bridges[i], err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { bridges[i].Close() })
		raw, stack, err := netstack.CreateNetTUN([]netip.Addr{f.grant.Participants[i].Address}, nil, 1280)
		if err != nil {
			t.Fatal(err)
		}
		stacks[i] = stack
		policySession := f.session
		if managed && i == int(Host) {
			policySession = hostSession
		}
		policies[i], err = NewPolicy(policySession, Side(i))
		if err != nil {
			t.Fatal(err)
		}
		var input tun.Device = raw
		if i == int(Host) {
			input, err = NewFilterTUN(raw, policies[i])
			if err != nil {
				t.Fatal(err)
			}
		}
		devices[i] = device.NewDevice(input, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "p2p-test "))
		t.Cleanup(func() { devices[i].Close() })
		uapi := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nendpoint=%s\nallowed_ip=%s/32\n", wgHex(t, f.wgPrivate[i]), wgHex(t, f.grant.Participants[1-i].WireGuardKey), bridges[i].LocalAddr(), f.grant.Participants[1-i].Address)
		if err = devices[i].IpcSet(uapi); err != nil {
			t.Fatal(err)
		}
		if err = devices[i].Up(); err != nil {
			t.Fatal(err)
		}
		relays[i] = dialTestRelay(t, f, address, config, Side(i))
	}
	bridgeDone := make(chan error, 2)
	for i := range devices {
		uapi, err := devices[i].IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		var port string
		for _, line := range strings.Split(uapi, "\n") {
			if strings.HasPrefix(line, "listen_port=") {
				port = strings.TrimPrefix(line, "listen_port=")
			}
		}
		target, err := net.ResolveUDPAddr("udp4", "127.0.0.1:"+port)
		if err != nil {
			t.Fatal(err)
		}
		go func() { bridgeDone <- RunEndpoint(ctx, bridges[i], target, relays[i]) }()
	}
	t.Cleanup(func() {
		cancel()
		for i := 0; i < 2; i++ {
			select {
			case <-bridgeDone:
			case <-time.After(time.Second):
				t.Error("endpoint leaked goroutines")
			}
		}
	})
	hostIP := f.grant.Participants[1].Address
	udp, err := stacks[1].ListenUDPAddrPort(netip.AddrPortFrom(hostIP, 47998))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buf[:n], from)
		}
	}()
	client, err := stacks[0].DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(hostIP, 47998))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(4 * time.Second))
	payload := []byte("p2p-encrypted-udp-roundtrip")
	if _, err = client.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	n, err := client.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("real WG UDP roundtrip: %v", err)
	}
	listener, err := stacks[1].ListenTCPAddrPort(netip.AddrPortFrom(hostIP, 47989))
	if err != nil {
		t.Fatal(err)
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
	tcp, err := stacks[0].DialContext(ctx, "tcp", netip.AddrPortFrom(hostIP, 47989).String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = tcp.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(tcp, buf[:len(payload)]); err != nil || !bytes.Equal(buf[:len(payload)], payload) {
		t.Fatalf("real WG TCP roundtrip: %v", err)
	}
	// The unfiltered initiator sends to a real forbidden host socket. Only the
	// post-decryption host FilterTUN can stop this packet.
	forbidden, err := stacks[1].ListenUDPAddrPort(netip.AddrPortFrom(hostIP, 47990))
	if err != nil {
		t.Fatal(err)
	}
	defer forbidden.Close()
	attack, err := stacks[0].DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(hostIP, 47990))
	if err != nil {
		t.Fatal(err)
	}
	defer attack.Close()
	if _, err = attack.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = forbidden.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, _, err = forbidden.ReadFrom(buf); err == nil {
		t.Fatal("forbidden host port received data")
	}
	// Local endpoint revoke must stop an established stream even with relay
	// transport still available and an adversarial initiator ignoring revoke.
	if managed {
		if _, err = hostStore.Apply(signedPolicy(t, f, 9, false)); err != nil {
			t.Fatal(err)
		}
	} else {
		policies[1].Revoke()
	}
	if _, err = client.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err = client.Read(buf); err == nil {
		t.Fatal("UDP continued after host revoke")
	}
	_, _ = tcp.Write(payload)
	_ = tcp.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err = tcp.Read(buf); err == nil {
		t.Fatal("established TCP continued after host revoke")
	}
	if r.ForwardedBytes() == 0 {
		t.Fatal("relay did not carry encrypted traffic")
	}
}
