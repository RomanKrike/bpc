package routed

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// A routed session binds data to both process incarnations. Remote epochs are
// installed only after a fresh authenticated challenge, never from data or an
// unsolicited probe. Restarting either end invalidates captured old traffic.
func (p *meshPeer) configuration() LinkConfig {
	p.configMu.RLock()
	defer p.configMu.RUnlock()
	return p.config
}

func (p *meshPeer) sessionReady() bool {
	p.recvMu.Lock()
	defer p.recvMu.Unlock()
	return p.remoteEpoch != [16]byte{}
}

func (p *meshPeer) matchesRemoteEpoch(epoch []byte) bool {
	p.recvMu.Lock()
	defer p.recvMu.Unlock()
	return bytes.Equal(p.remoteEpoch[:], epoch)
}

func (p *meshPeer) confirmRemoteEpoch(epoch []byte) {
	if len(epoch) != 16 {
		return
	}
	p.recvMu.Lock()
	defer p.recvMu.Unlock()
	if !bytes.Equal(p.remoteEpoch[:], epoch) {
		copy(p.remoteEpoch[:], epoch)
		p.recvHigh, p.recvMask = 0, 0
	}
}

func (p *meshPeer) dataEnvelope(payload []byte) ([]byte, error) {
	p.recvMu.Lock()
	defer p.recvMu.Unlock()
	if p.remoteEpoch == [16]byte{} {
		return nil, fmt.Errorf("routed session is not authenticated yet")
	}
	sequence := p.nextSequence()
	if sequence == 0 {
		return nil, fmt.Errorf("routed sequence exhausted")
	}
	raw := make([]byte, 40+len(payload))
	copy(raw, p.localEpoch[:])
	copy(raw[16:], p.remoteEpoch[:])
	binary.BigEndian.PutUint64(raw[32:40], sequence)
	copy(raw[40:], payload)
	return raw, nil
}

func (p *meshPeer) acceptDataEnvelope(raw []byte) ([]byte, bool) {
	if len(raw) <= 40 {
		return nil, false
	}
	p.recvMu.Lock()
	defer p.recvMu.Unlock()
	if p.remoteEpoch == [16]byte{} || !bytes.Equal(raw[:16], p.remoteEpoch[:]) || !bytes.Equal(raw[16:32], p.localEpoch[:]) {
		return nil, false
	}
	if !p.acceptSequenceLocked(binary.BigEndian.Uint64(raw[32:40])) {
		return nil, false
	}
	return append([]byte(nil), raw[40:]...), true
}
