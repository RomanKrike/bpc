package wgshim

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// acceptanceBind uses ordinary localhost UDP sockets. It keeps actual WireGuard
// encryption/handshakes while avoiding platform-specific offload/socket options
// unavailable in restricted CI containers. It is NOT used by production code.
type acceptanceBind struct {
	mu     sync.Mutex
	socket *net.UDPConn
}

func (b *acceptanceBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.socket = socket
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		n, source, e := socket.ReadFromUDPAddrPort(packets[0])
		if e != nil {
			return 0, e
		}
		sizes[0] = n
		endpoints[0] = &conn.StdNetEndpoint{AddrPort: source}
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, uint16(socket.LocalAddr().(*net.UDPAddr).Port), nil
}
func (b *acceptanceBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket == nil {
		return nil
	}
	err := b.socket.Close()
	b.socket = nil
	return err
}
func (b *acceptanceBind) SetMark(mark uint32) error {
	if mark != 0 {
		return fmt.Errorf("test bind does not use routing marks")
	}
	return nil
}
func (b *acceptanceBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	b.mu.Lock()
	socket := b.socket
	b.mu.Unlock()
	if socket == nil {
		return net.ErrClosed
	}
	target, err := netip.ParseAddrPort(endpoint.DstToString())
	if err != nil {
		return err
	}
	for _, packet := range packets {
		if _, err = socket.WriteToUDPAddrPort(packet, target); err != nil {
			return err
		}
	}
	return nil
}
func (b *acceptanceBind) ParseEndpoint(raw string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(raw)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: addr}, nil
}
func (b *acceptanceBind) BatchSize() int { return 1 }
