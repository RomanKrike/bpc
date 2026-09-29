package routed

import (
	"encoding/binary"
	"net"
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
		To:          "home-01",
		Health:      "healthy",
		RTTMS:       5,
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
		candidateAt.Add(pathRecoveryCooldown+time.Second),
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

func TestRouteOwnerCannotSpoofAnotherSourcePrefix(t *testing.T) {
	cfg := testRoutingConfig()
	frame := Frame{PathID: "direct", OwnerNodeID: "home-01", Hops: []string{"home-01", "ru-02"}, HopIndex: 1, Return: true, Payload: ipv4Packet("192.168.88.1", "10.253.0.2")}
	if _, err := ValidateFrameForNode(frame, "ru-02", "home-01", cfg); err != nil {
		t.Fatal(err)
	}
	frame.Payload = ipv4Packet("192.168.99.1", "10.253.0.2")
	if _, err := ValidateFrameForNode(frame, "ru-02", "home-01", cfg); err == nil {
		t.Fatal("owner spoofed another site's source address")
	}
	frame.Payload = ipv4Packet("10.253.0.3", "10.253.0.2")
	if _, err := ValidateFrameForNode(frame, "ru-02", "home-01", cfg); err == nil {
		t.Fatal("owner spoofed a Device source address")
	}
	frame.Return = false
	frame.Hops = []string{"ru-02", "home-01"}
	frame.Payload = ipv4Packet("198.51.100.7", "192.168.88.1")
	if _, err := ValidateFrameForNode(frame, "home-01", "ru-02", cfg); err == nil {
		t.Fatal("forwarded source outside overlay")
	}
}

func TestDirectionalLinkFailsWithoutOwnProbeReplies(t *testing.T) {
	peer := &meshPeer{
		config:       LinkConfig{ID: "home-link", PeerNodeID: "home-01", Cost: 10},
		addr:         &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: DefaultMeshPort},
		addressSince: time.Unix(100, 0),
		lastAuth:     time.Unix(200, 0),
	}
	status := peer.status("ru-02", time.Unix(200, 0))
	if status.Health != "failed" {
		t.Fatalf("inbound-only activity kept outbound link alive: %+v", status)
	}

	peer.recordProbe(true, 25*time.Millisecond, time.Unix(201, 0))
	status = peer.status("ru-02", time.Unix(201, 0))
	if status.Health != "healthy" {
		t.Fatalf("fresh probe reply did not restore link: %+v", status)
	}
}

func TestPathRejectsThreePublicNodesBeforeOwner(t *testing.T) {
	path := Path{ID: "too-long", OwnerNodeID: "home-01", CIDR: "192.168.88.0/24", Hops: []string{"ru-02", "ru-01", "ge-01", "home-01"}}
	if path.Validate() == nil {
		t.Fatal("accepted three Public Nodes between Device and owner")
	}
}

func TestRecoveredPathCooldownStartsAfterLongOutage(t *testing.T) {
	config := testRoutingConfig()
	mesh := &fakeMesh{status: map[string]LinkStatus{"home-01": {Health: "healthy"}, "ru-01": {Health: "healthy"}}}
	router, err := NewRouter("ru-02", config, mesh, &fakeWriter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(10000, 0)
	check := func(at time.Time, want string) {
		t.Helper()
		got, err := router.choosePath(config.Routes[0], config.Paths, at)
		if err != nil || got.ID != want {
			t.Fatalf("at %v got %s, want %s: %v", at.Sub(start), got.ID, want, err)
		}
	}
	check(start, "direct")
	mesh.status["home-01"] = LinkStatus{Health: "failed"}
	check(start.Add(time.Second), "multi")
	recovered := start.Add(time.Hour)
	mesh.status["home-01"] = LinkStatus{Health: "healthy"}
	check(recovered, "multi")
	check(recovered.Add(pathStableInterval+time.Second), "multi")
	check(recovered.Add(pathRecoveryCooldown), "direct")
	// A second failure/recovery restarts the per-path cooldown.
	mesh.status["home-01"] = LinkStatus{Health: "failed"}
	check(recovered.Add(11*time.Second), "multi")
	mesh.status["home-01"] = LinkStatus{Health: "healthy"}
	check(recovered.Add(12*time.Second), "multi")
	// Emergency availability takes precedence over recovery stickiness.
	mesh.status["ru-01"] = LinkStatus{Health: "failed"}
	check(recovered.Add(13*time.Second), "direct")
}
