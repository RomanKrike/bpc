package p2p

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

const maxFlows = 4096

type flow struct {
	protocol        byte
	client, service uint16
}

// Policy checks plaintext at BOTH sides of WireGuard. One policy belongs to
// exactly one session; the WireGuard peer MUST also bind the remote public key
// to its single /32. Relay reachability and AllowedIPs alone are not Access.
type Policy struct {
	mu        sync.Mutex
	session   *Session
	side      Side
	revoked   bool
	flows     map[flow]time.Time
	nextPrune time.Time
}

func NewPolicy(s *Session, side Side) (*Policy, error) {
	if s == nil || !side.valid() || !s.active(time.Now()) {
		return nil, errors.New("invalid P2P policy session")
	}
	return &Policy{session: s, side: side, flows: make(map[flow]time.Time)}, nil
}

// Revoke returns only after in-flight policy decisions have finished. A packet
// already handed to the OS cannot be recalled. Every later decision denies.
func (p *Policy) Revoke() { p.mu.Lock(); defer p.mu.Unlock(); p.revoked = true; clear(p.flows) }

func (p *Policy) Allowed(packet []byte, outbound bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.revoked || !p.session.active(now) {
		clear(p.flows)
		return false
	}
	// Version 1 accepts only unfragmented IPv4 TCP/UDP, no options, tunneling,
	// IPv6 or ICMP. Reject fragments before reading transport ports.
	if len(packet) < 20 || packet[0] != 0x45 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || binary.BigEndian.Uint16(packet[6:8])&0xbfff != 0 {
		return false
	}
	proto := packet[9]
	if proto != 6 && proto != 17 {
		return false
	}
	if len(packet) < 28 {
		return false
	}
	source := netip.AddrFrom4([4]byte(packet[12:16]))
	target := netip.AddrFrom4([4]byte(packet[16:20]))
	sender := p.side
	if !outbound {
		sender = 1 - sender
	}
	if source != p.session.grant.Participants[sender].Address || target != p.session.grant.Participants[1-sender].Address {
		return false
	}
	src, dst := binary.BigEndian.Uint16(packet[20:22]), binary.BigEndian.Uint16(packet[22:24])
	if src == 0 || dst == 0 {
		return false
	}
	var flags byte
	if proto == 6 {
		if len(packet) < 40 {
			return false
		}
		header := int(packet[32]>>4) * 4
		if header < 20 || 20+header > len(packet) {
			return false
		}
		flags = packet[33]
	} else if int(binary.BigEndian.Uint16(packet[24:26])) != len(packet)-20 {
		return false
	}
	key := flow{proto, src, dst}
	if sender == Host {
		key.client, key.service = dst, src
	}
	if !servicePort(proto, key.service) {
		return false
	}
	if !now.Before(p.nextPrune) {
		for f, until := range p.flows {
			if !now.Before(until) {
				delete(p.flows, f)
			}
		}
		p.nextPrune = now.Add(time.Second)
	}
	until, exists := p.flows[key]
	established := exists && now.Before(until)
	if sender == Host {
		if !established || (proto == 6 && (flags&0x02 != 0 && flags&0x10 == 0)) {
			return false
		}
	} else if !established {
		if len(p.flows) >= maxFlows || (proto == 6 && (flags&0x02 == 0 || flags&0x10 != 0)) {
			return false
		}
	}
	p.flows[key] = now.Add(30 * time.Second)
	if proto == 6 && flags&0x04 != 0 {
		delete(p.flows, key)
	}
	return true
}

func servicePort(protocol byte, port uint16) bool {
	if protocol == 6 {
		return port == 47984 || port == 47989 || port == 48010
	}
	return port == 47998 || port == 47999 || port == 48000 || port == 48002 || port == 48010
}

// FilterTUN drops denied packets before encryption and after decryption. It
// embeds all other Device methods without changing interface ownership/lifetime.
type FilterTUN struct {
	tun.Device
	policy *Policy
}

func NewFilterTUN(dev tun.Device, policy *Policy) (*FilterTUN, error) {
	if dev == nil || policy == nil {
		return nil, errors.New("P2P TUN and policy required")
	}
	return &FilterTUN{Device: dev, policy: policy}, nil
}

func (f *FilterTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		n, err := f.Device.Read(bufs, sizes, offset)
		kept := 0
		for i := 0; i < n; i++ {
			if sizes[i] >= 0 && offset >= 0 && offset+sizes[i] <= len(bufs[i]) && f.policy.Allowed(bufs[i][offset:offset+sizes[i]], true) {
				if i != kept {
					copy(bufs[kept][offset:], bufs[i][offset:offset+sizes[i]])
				}
				sizes[kept] = sizes[i]
				kept++
			}
		}
		if kept > 0 || err != nil {
			return kept, err
		}
	}
}

func (f *FilterTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		if offset >= 0 && offset <= len(buf) && f.policy.Allowed(buf[offset:], false) {
			if _, err := f.Device.Write([][]byte{buf}, offset); err != nil {
				return 0, err
			}
		}
	}
	// Denial is a consumed/dropped packet, not a TUN failure that should stop WG.
	return len(bufs), nil
}
