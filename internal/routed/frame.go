package routed

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

var frameMagic = [4]byte{'B', 'P', 'R', '1'}

const frameFlagReturn byte = 1

type Frame struct {
	PathID      string
	OwnerNodeID string
	Hops        []string
	HopIndex    int
	Return      bool
	Payload     []byte
}

func (f Frame) ValidateBasic() error {
	if len(f.PathID) == 0 || len(f.PathID) > 64 {
		return fmt.Errorf("invalid path id length")
	}
	if len(f.OwnerNodeID) == 0 || len(f.OwnerNodeID) > 128 {
		return fmt.Errorf("invalid route owner id")
	}
	if len(f.Hops) < 2 || len(f.Hops) > MaxPathHops {
		return fmt.Errorf("invalid hop count %d", len(f.Hops))
	}
	if f.HopIndex <= 0 || f.HopIndex >= len(f.Hops) {
		return fmt.Errorf("invalid receiving hop index %d", f.HopIndex)
	}
	seen := make(map[string]struct{}, len(f.Hops))
	for _, hop := range f.Hops {
		if len(hop) == 0 || len(hop) > 128 {
			return fmt.Errorf("invalid hop id")
		}
		if _, exists := seen[hop]; exists {
			return fmt.Errorf("routing loop detected in hop list")
		}
		seen[hop] = struct{}{}
	}
	if f.Return {
		if f.Hops[0] != f.OwnerNodeID {
			return fmt.Errorf("return path does not originate at route owner")
		}
	} else if f.Hops[len(f.Hops)-1] != f.OwnerNodeID {
		return fmt.Errorf("forward path does not terminate at route owner")
	}
	if len(f.Payload) == 0 || len(f.Payload) > 65535 {
		return fmt.Errorf("invalid inner packet length %d", len(f.Payload))
	}
	return nil
}

func MarshalFrame(f Frame) ([]byte, error) {
	if err := f.ValidateBasic(); err != nil {
		return nil, err
	}
	size := 4 + 4 + 1 + len(f.PathID) + 1 + len(f.OwnerNodeID) + 2 + len(f.Payload)
	for _, hop := range f.Hops {
		size += 1 + len(hop)
	}
	raw := make([]byte, 0, size)
	raw = append(raw, frameMagic[:]...)
	flags := byte(0)
	if f.Return {
		flags |= frameFlagReturn
	}
	raw = append(raw, flags, byte(f.HopIndex), byte(len(f.Hops)), byte(len(f.PathID)))
	raw = append(raw, f.PathID...)
	raw = append(raw, byte(len(f.OwnerNodeID)))
	raw = append(raw, f.OwnerNodeID...)
	for _, hop := range f.Hops {
		raw = append(raw, byte(len(hop)))
		raw = append(raw, hop...)
	}
	var payloadLen [2]byte
	binary.BigEndian.PutUint16(payloadLen[:], uint16(len(f.Payload)))
	raw = append(raw, payloadLen[:]...)
	raw = append(raw, f.Payload...)
	return raw, nil
}

func UnmarshalFrame(raw []byte) (Frame, error) {
	if len(raw) < 12 || !bytes.Equal(raw[:4], frameMagic[:]) {
		return Frame{}, fmt.Errorf("invalid routed frame header")
	}
	offset := 4
	flags := raw[offset]
	offset++
	hopIndex := int(raw[offset])
	offset++
	hopCount := int(raw[offset])
	offset++
	pathLen := int(raw[offset])
	offset++
	if pathLen == 0 || pathLen > 64 || offset+pathLen+1 > len(raw) {
		return Frame{}, fmt.Errorf("invalid routed frame path id")
	}
	pathID := string(raw[offset : offset+pathLen])
	offset += pathLen
	ownerLen := int(raw[offset])
	offset++
	if ownerLen == 0 || ownerLen > 128 || offset+ownerLen > len(raw) {
		return Frame{}, fmt.Errorf("invalid routed frame owner")
	}
	owner := string(raw[offset : offset+ownerLen])
	offset += ownerLen
	if hopCount < 2 || hopCount > MaxPathHops {
		return Frame{}, fmt.Errorf("invalid routed frame hop count")
	}
	hops := make([]string, 0, hopCount)
	for range hopCount {
		if offset >= len(raw) {
			return Frame{}, fmt.Errorf("truncated routed frame hop")
		}
		length := int(raw[offset])
		offset++
		if length == 0 || length > 128 || offset+length > len(raw) {
			return Frame{}, fmt.Errorf("invalid routed frame hop")
		}
		hops = append(hops, string(raw[offset:offset+length]))
		offset += length
	}
	if offset+2 > len(raw) {
		return Frame{}, fmt.Errorf("truncated routed frame payload length")
	}
	payloadLen := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	if payloadLen == 0 || offset+payloadLen != len(raw) {
		return Frame{}, fmt.Errorf("invalid routed frame payload length")
	}
	frame := Frame{
		PathID:      pathID,
		OwnerNodeID: owner,
		Hops:        hops,
		HopIndex:    hopIndex,
		Return:      flags&frameFlagReturn != 0,
		Payload:     append([]byte(nil), raw[offset:]...),
	}
	if flags&^frameFlagReturn != 0 {
		return Frame{}, fmt.Errorf("unsupported routed frame flags")
	}
	if err := frame.ValidateBasic(); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func reverseStrings(values []string) []string {
	result := make([]string, len(values))
	for index := range values {
		result[len(values)-1-index] = values[index]
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func ParseIPv4Endpoints(packet []byte) (netip.Addr, netip.Addr, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("inner packet is not IPv4")
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(packet) {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid IPv4 header length")
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < headerLen || totalLen > len(packet) {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid IPv4 total length")
	}
	var sourceRaw, destinationRaw [4]byte
	copy(sourceRaw[:], packet[12:16])
	copy(destinationRaw[:], packet[16:20])
	return netip.AddrFrom4(sourceRaw), netip.AddrFrom4(destinationRaw), nil
}

func ValidateFrameForNode(
	frame Frame,
	localNodeID string,
	senderPeerID string,
	config RoutingConfig,
) (Path, error) {
	if err := frame.ValidateBasic(); err != nil {
		return Path{}, err
	}
	if frame.Hops[frame.HopIndex] != localNodeID {
		return Path{}, fmt.Errorf("frame current hop is not local Node")
	}
	if frame.Hops[frame.HopIndex-1] != senderPeerID {
		return Path{}, fmt.Errorf("frame previous hop does not match authenticated peer")
	}
	path, ok := config.TransitPath(frame.PathID)
	if !ok {
		return Path{}, fmt.Errorf("path %s is not controller-approved", frame.PathID)
	}
	if path.OwnerNodeID != frame.OwnerNodeID {
		return Path{}, fmt.Errorf("path owner mismatch")
	}
	expectedHops := path.Hops
	if frame.Return {
		expectedHops = reverseStrings(path.Hops)
	}
	if !equalStrings(frame.Hops, expectedHops) {
		return Path{}, fmt.Errorf("hop list does not match controller-approved path")
	}

	source, destination, err := ParseIPv4Endpoints(frame.Payload)
	if err != nil {
		return Path{}, err
	}
	if frame.Return {
		if strings.TrimSpace(config.OverlaySubnet) == "" {
			return Path{}, fmt.Errorf("overlay subnet is unavailable")
		}
		overlay, err := netip.ParsePrefix(config.OverlaySubnet)
		if err != nil || !overlay.Contains(destination) {
			return Path{}, fmt.Errorf("return packet destination is outside overlay")
		}
		owned, ok := config.RouteFor(source)
		if !ok || owned.OwnerNodeID != frame.OwnerNodeID || owned.CIDR != path.CIDR {
			return Path{}, fmt.Errorf("return packet source is outside the route owner's approved CIDR")
		}
		return path, nil
	}
	overlay, err := netip.ParsePrefix(config.OverlaySubnet)
	if err != nil || !overlay.Contains(source) {
		return Path{}, fmt.Errorf("forward packet source is outside overlay")
	}

	prefix, err := netip.ParsePrefix(path.CIDR)
	if err != nil || !prefix.Contains(destination) {
		return Path{}, fmt.Errorf("forward packet destination is outside approved route")
	}
	route, ok := config.RouteFor(destination)
	if !ok || route.OwnerNodeID != frame.OwnerNodeID || route.CIDR != path.CIDR {
		return Path{}, fmt.Errorf("route owner validation failed")
	}
	return path, nil
}
