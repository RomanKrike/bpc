package routed

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

type fakeMesh struct {
	status map[string]LinkStatus
	sent   []string
}

func (m *fakeMesh) Send(peerID string, _ []byte) error {
	m.sent = append(m.sent, peerID)
	return nil
}

func (m *fakeMesh) CanSend(peerID string) bool {
	status, ok := m.status[peerID]
	return ok && status.Health != "failed"
}

func (m *fakeMesh) LinkStatus(peerID string) (LinkStatus, bool) {
	status, ok := m.status[peerID]
	return status, ok
}

type fakeWriter struct {
	packets [][]byte
}

func (w *fakeWriter) WritePacket(packet []byte) error {
	w.packets = append(w.packets, append([]byte(nil), packet...))
	return nil
}

func ipv4Packet(source, destination string) []byte {
	src := netip.MustParseAddr(source).As4()
	dst := netip.MustParseAddr(destination).As4()
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	return packet
}

func testRoutingConfig() RoutingConfig {
	return RoutingConfig{
		Version:         1,
		ListenPort:      DefaultMeshPort,
		OverlaySubnet:   "10.253.0.0/24",
		LocalPublic:     true,
		LocalSiteRouter: false,
		Links: []LinkConfig{
			{
				ID:           "link-home",
				PeerNodeID:   "home-01",
				PSK:          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				PeerEndpoint: "127.0.0.1:24446",
				PeerPublic:   false,
				Port:         DefaultMeshPort,
				Cost:         10,
			},
			{
				ID:           "link-ru-01",
				PeerNodeID:   "ru-01",
				PSK:          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				PeerEndpoint: "127.0.0.1:24447",
				PeerPublic:   true,
				Port:         DefaultMeshPort,
				Cost:         1,
			},
		},
		Paths: []Path{
			{
				ID:          "direct",
				OwnerNodeID: "home-01",
				CIDR:        "192.168.88.0/24",
				Hops:        []string{"ru-02", "home-01"},
				Health:      "healthy",
				Score:       100,
			},
			{
				ID:          "multi",
				OwnerNodeID: "home-01",
				CIDR:        "192.168.88.0/24",
				Hops:        []string{"ru-02", "ru-01", "home-01"},
				Health:      "healthy",
				Score:       120,
			},
		},
		TransitPaths: []Path{
			{
				ID:          "direct",
				OwnerNodeID: "home-01",
				CIDR:        "192.168.88.0/24",
				Hops:        []string{"ru-02", "home-01"},
				Health:      "healthy",
				Score:       100,
			},
			{
				ID:          "multi",
				OwnerNodeID: "home-01",
				CIDR:        "192.168.88.0/24",
				Hops:        []string{"ru-02", "ru-01", "home-01"},
				Health:      "healthy",
				Score:       120,
			},
		},
		Routes: []Route{
			{CIDR: "192.168.88.0/24", OwnerNodeID: "home-01"},
		},
	}
}

func TestFrameRoundTripAndLoopPrevention(t *testing.T) {
	frame := Frame{
		PathID:      "path-1",
		OwnerNodeID: "home-01",
		Hops:        []string{"ru-02", "ru-01", "home-01"},
		HopIndex:    1,
		Payload:     ipv4Packet("10.253.0.2", "192.168.88.1"),
	}
	raw, err := MarshalFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PathID != frame.PathID || decoded.HopIndex != 1 {
		t.Fatalf("unexpected decoded frame: %+v", decoded)
	}

	frame.Hops = []string{"ru-02", "ru-01", "ru-02", "home-01"}
	if _, err := MarshalFrame(frame); err == nil {
		t.Fatal("looped hop list was accepted")
	}
}

func TestValidateFrameRequiresControllerApprovedOwnerAndHopList(t *testing.T) {
	config := testRoutingConfig()
	frame := Frame{
		PathID:      "multi",
		OwnerNodeID: "home-01",
		Hops:        []string{"ru-02", "ru-01", "home-01"},
		HopIndex:    1,
		Payload:     ipv4Packet("10.253.0.2", "192.168.88.10"),
	}
	if _, err := ValidateFrameForNode(frame, "ru-01", "ru-02", config); err != nil {
		t.Fatalf("valid frame rejected: %v", err)
	}

	forged := frame
	forged.OwnerNodeID = "attacker"
	if _, err := ValidateFrameForNode(forged, "ru-01", "ru-02", config); err == nil {
		t.Fatal("forged owner was accepted")
	}

	forged = frame
	forged.Hops = []string{"ru-02", "evil", "home-01"}
	if _, err := ValidateFrameForNode(forged, "ru-01", "ru-02", config); err == nil {
		t.Fatal("forged hop list was accepted")
	}

	forged = frame
	forged.Payload = ipv4Packet("10.253.0.2", "10.10.10.10")
	if _, err := ValidateFrameForNode(forged, "ru-01", "ru-02", config); err == nil {
		t.Fatal("packet outside owned route was accepted")
	}
}

func TestPathFailoverIsImmediateButRecoveryIsSticky(t *testing.T) {
	config := testRoutingConfig()
	mesh := &fakeMesh{
		status: map[string]LinkStatus{
			"home-01": {To: "home-01", Health: "healthy", RTTMS: 5},
			"ru-01":   {To: "ru-01", Health: "healthy", RTTMS: 5},
		},
	}
	router, err := NewRouter("ru-02", config, mesh, &fakeWriter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	route := config.Routes[0]
	start := time.Unix(10_000, 0)

	selected, err := router.choosePath(route, config.Paths, start)
	if err != nil || selected.ID != "direct" {
		t.Fatalf("expected direct path, got %+v err=%v", selected, err)
	}

	mesh.status["home-01"] = LinkStatus{
		To:     "home-01",
		Health: "failed",
	}
	selected, err = router.choosePath(route, config.Paths, start.Add(time.Second))
	if err != nil || selected.ID != "multi" {
		t.Fatalf("expected immediate multi-hop failover, got %+v err=%v", selected, err)
	}

	mesh.status["home-01"] = LinkStatus{
		To:      "home-01",
		Health:  "healthy",
		RTTMS:   5,
		LossPercent: 0,
	}
	selected, err = router.choosePath(
		route,
		config.Paths,
		start.Add(pathRecoveryCooldown-time.Second),
	)
	if err != nil || selected.ID != "multi" {
		t.Fatalf("recovered direct path switched before cooldown: %+v err=%v", selected, err)
	}

	candidateAt := start.Add(pathRecoveryCooldown + 2*time.Second)
	selected, err = router.choosePath(route, config.Paths, candidateAt)
	if err != nil || selected.ID != "multi" {
		t.Fatalf("stable interval was not started on current path: %+v err=%v", selected, err)
	}

	selected, err = router.choosePath(
		route,
		config.Paths,
		candidateAt.Add(pathStableInterval+time.Second),
	)
	if err != nil || selected.ID != "direct" {
		t.Fatalf("expected direct recovery after hysteresis: %+v err=%v", selected, err)
	}
}

func TestMeshReplayWindowRejectsDuplicateSequence(t *testing.T) {
	peer := &meshPeer{}
	if !peer.acceptSequence(100) {
		t.Fatal("first sequence rejected")
	}
	if peer.acceptSequence(100) {
		t.Fatal("duplicate sequence accepted")
	}
	if !peer.acceptSequence(102) {
		t.Fatal("new sequence rejected")
	}
	if !peer.acceptSequence(101) {
		t.Fatal("in-window reordered sequence rejected")
	}
	if peer.acceptSequence(1) {
		t.Fatal("stale sequence outside replay window accepted")
	}
}
