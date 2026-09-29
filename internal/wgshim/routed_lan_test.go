package wgshim

import (
	"net"
	"os"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// acceptanceLAN models a destination network outside either gateway. Gateway
// shutdown closes only its attachment; the destination TCP stack stays alive.
// Return packets use the gateway that most recently delivered an IP packet.
// No WireGuard session keys or NAT/conntrack state are shared by the gateways.
type acceptanceLAN struct {
	destination tun.Device
	ports       [2]*acceptanceLANPort
	active      atomic.Int32
	writeMu     sync.Mutex
}
type acceptanceLANPort struct {
	lan     *acceptanceLAN
	index   int
	packets chan []byte
	events  chan tun.Event
	done    chan struct{}
	once    sync.Once
}

func newAcceptanceLAN(destination tun.Device) *acceptanceLAN {
	lan := &acceptanceLAN{destination: destination}
	for i := range lan.ports {
		p := &acceptanceLANPort{lan: lan, index: i, packets: make(chan []byte, 256), events: make(chan tun.Event, 1), done: make(chan struct{})}
		p.events <- tun.EventUp
		lan.ports[i] = p
	}
	go func() {
		buf := make([]byte, 65535)
		sizes := make([]int, 1)
		for {
			n, err := destination.Read([][]byte{buf}, sizes, 0)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			packet := append([]byte(nil), buf[:sizes[0]]...)
			port := lan.ports[lan.active.Load()]
			select {
			case <-port.done:
			case port.packets <- packet:
			}
		}
	}()
	return lan
}
func (l *acceptanceLAN) Close() {
	for _, p := range l.ports {
		p.Close()
	}
	l.destination.Close()
}
func (p *acceptanceLANPort) File() *os.File           { return nil }
func (p *acceptanceLANPort) Name() (string, error)    { return "acceptance-lan", nil }
func (p *acceptanceLANPort) MTU() (int, error)        { return p.lan.destination.MTU() }
func (p *acceptanceLANPort) BatchSize() int           { return 1 }
func (p *acceptanceLANPort) Events() <-chan tun.Event { return p.events }
func (p *acceptanceLANPort) Close() error {
	p.once.Do(func() { close(p.done); close(p.events) })
	return nil
}
func (p *acceptanceLANPort) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	case packet := <-p.packets:
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	}
}
func (p *acceptanceLANPort) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	default:
	}
	p.lan.writeMu.Lock()
	defer p.lan.writeMu.Unlock()
	p.lan.active.Store(int32(p.index))
	return p.lan.destination.Write(bufs, offset)
}
