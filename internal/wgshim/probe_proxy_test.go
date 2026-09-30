package wgshim

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A test-only network fault delays authenticated probe replies, leaving data
// and the old gateway alive so selection must use the healthy migration path.
type acceptanceProbeProxy struct {
	conn *net.UDPConn
	slow atomic.Bool
	done chan struct{}
}

func newAcceptanceProbeProxy(t *testing.T, target string, rx *Codec, handshakeDelay time.Duration) *acceptanceProbeProxy {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &acceptanceProbeProxy{conn: conn, done: make(chan struct{})}
	go func() {
		buf := make([]byte, 65535)
		var client *net.UDPAddr
		for {
			n, source, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if source.String() != remote.String() {
				client = cloneUDPAddr(source)
				_, _ = conn.WriteToUDP(buf[:n], remote)
				continue
			}
			if client == nil {
				continue
			}
			kind, inner, err := rx.OpenTyped(buf[:n])
			delay := time.Duration(0)
			if err == nil && IsProbeReply(kind) && p.slow.Load() {
				delay = 60 * time.Millisecond
			}
			if err == nil && IsData(kind) && len(inner) >= 4 && inner[0] == 2 {
				delay = handshakeDelay
			}
			if delay > 0 {
				packet := append([]byte(nil), buf[:n]...)
				destination := cloneUDPAddr(client)
				go func() {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-p.done:
					case <-timer.C:
						_, _ = conn.WriteToUDP(packet, destination)
					}
				}()
			} else {
				_, _ = conn.WriteToUDP(buf[:n], client)
			}
		}
	}()
	return p
}

func (p *acceptanceProbeProxy) Close() { close(p.done); p.conn.Close() }
