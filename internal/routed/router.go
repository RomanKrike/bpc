package routed

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	pathMinimumImprovement = 15.0
	pathStableInterval     = 5 * time.Second
	pathRecoveryCooldown   = 10 * time.Second
	reversePathTTL         = 10 * time.Minute
)

type MeshTransport interface {
	Send(peerID string, payload []byte) error
	CanSend(peerID string) bool
	LinkStatus(peerID string) (LinkStatus, bool)
}

type PacketWriter interface{ WritePacket(packet []byte) error }

type routeSelection struct {
	CurrentID      string
	LastSwitch     time.Time
	CandidateID    string
	CandidateSince time.Time
}

type reversePath struct {
	Path     Path
	LastSeen time.Time
}

type SelectedPathStatus struct {
	CIDR           string   `json:"cidr"`
	OwnerNodeID    string   `json:"owner_node_id"`
	PathID         string   `json:"path_id"`
	Hops           []string `json:"hops"`
	HopNames       []string `json:"hop_names"`
	Health         string   `json:"health"`
	RTTMS          float64  `json:"rtt_ms"`
	LossPercent    float64  `json:"loss_percent"`
	Cost           float64  `json:"cost"`
	StandbyPathIDs []string `json:"standby_path_ids"`
}

type Router struct {
	localNodeID string
	mesh        MeshTransport
	writer      PacketWriter
	logger      *log.Logger
	now         func() time.Time
	mu          sync.Mutex
	config      RoutingConfig
	selections  map[string]*routeSelection
	reverse     map[string]reversePath
}

func NewRouter(
	localNodeID string,
	config RoutingConfig,
	mesh MeshTransport,
	writer PacketWriter,
	logger *log.Logger,
) (*Router, error) {
	if localNodeID == "" || mesh == nil || writer == nil {
		return nil, fmt.Errorf("routed Router requires local Node, mesh and packet writer")
	}
	if err := config.Validate(localNodeID); err != nil {
		return nil, err
	}
	return &Router{
		localNodeID: localNodeID,
		mesh:        mesh,
		writer:      writer,
		logger:      logger,
		now:         time.Now,
		config:      config,
		selections:  make(map[string]*routeSelection),
		reverse:     make(map[string]reversePath),
	}, nil
}

func (r *Router) UpdateConfig(config RoutingConfig) error {
	if err := config.Validate(r.localNodeID); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config = config

	valid := make(map[string]struct{})
	all := append(append([]Path{}, config.Paths...), config.TransitPaths...)
	for _, path := range all {
		valid[path.ID] = struct{}{}
	}
	for key, state := range r.selections {
		if state.CurrentID == "" {
			continue
		}
		if _, ok := valid[state.CurrentID]; !ok {
			delete(r.selections, key)
		}
	}
	return nil
}

func routeKey(route Route) string {
	return route.OwnerNodeID + "|" + route.CIDR
}

func pathScore(path Path, status LinkStatus, ok bool) float64 {
	score := path.Score
	if score == 0 {
		score = path.Cost + path.RTTMS + path.LossPercent*10
		if path.Health == "degraded" || path.Health == "unknown" {
			score += 1000
		}
	}
	if ok {
		score += status.RTTMS + status.LossPercent*10
		if status.Health == "degraded" || status.Health == "unknown" {
			score += 100
		}
	}
	return score
}

func (r *Router) viablePath(path Path) (float64, bool) {
	if len(path.Hops) < 2 || path.Hops[0] != r.localNodeID || path.Health == "failed" {
		return 0, false
	}
	first := path.Hops[1]
	if !r.mesh.CanSend(first) {
		return 0, false
	}
	status, ok := r.mesh.LinkStatus(first)
	if ok && status.Health == "failed" {
		return 0, false
	}
	return pathScore(path, status, ok), true
}

func (r *Router) choosePath(route Route, paths []Path, now time.Time) (Path, error) {
	type scored struct {
		path  Path
		score float64
	}
	var candidates []scored
	for _, path := range paths {
		if score, ok := r.viablePath(path); ok {
			candidates = append(candidates, scored{path: path, score: score})
		}
	}
	if len(candidates) == 0 {
		return Path{}, fmt.Errorf("no healthy end-to-end path to owner %s", route.OwnerNodeID)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score == candidates[j].score {
			return candidates[i].path.ID < candidates[j].path.ID
		}
		return candidates[i].score < candidates[j].score
	})
	best := candidates[0]

	key := routeKey(route)
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.selections[key]
	if state == nil {
		state = &routeSelection{}
		r.selections[key] = state
	}

	var current *scored
	for index := range candidates {
		if candidates[index].path.ID == state.CurrentID {
			current = &candidates[index]
			break
		}
	}
	if current == nil {
		state.CurrentID = best.path.ID
		state.LastSwitch = now
		state.CandidateID = ""
		state.CandidateSince = time.Time{}
		return best.path, nil
	}
	if best.path.ID == current.path.ID {
		state.CandidateID = ""
		state.CandidateSince = time.Time{}
		return current.path, nil
	}

	// A failed current path disappears from candidates and switches immediately.
	// Recovery is deliberately sticky to prevent ping-pong.
	if now.Sub(state.LastSwitch) < pathRecoveryCooldown {
		return current.path, nil
	}
	if current.score-best.score < pathMinimumImprovement {
		state.CandidateID = ""
		state.CandidateSince = time.Time{}
		return current.path, nil
	}
	if state.CandidateID != best.path.ID {
		state.CandidateID = best.path.ID
		state.CandidateSince = now
		return current.path, nil
	}
	if now.Sub(state.CandidateSince) < pathStableInterval {
		return current.path, nil
	}

	state.CurrentID = best.path.ID
	state.LastSwitch = now
	state.CandidateID = ""
	state.CandidateSince = time.Time{}
	return best.path, nil
}

func (r *Router) configSnapshot() RoutingConfig {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.config
}

func (r *Router) rememberReverse(device netip.Addr, path Path, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, entry := range r.reverse {
		if now.Sub(entry.LastSeen) > reversePathTTL {
			delete(r.reverse, key)
		}
	}
	r.reverse[device.String()] = reversePath{Path: path, LastSeen: now}
}

func (r *Router) reverseFor(device netip.Addr, now time.Time) (Path, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.reverse[device.String()]
	if !ok || now.Sub(entry.LastSeen) > reversePathTTL {
		delete(r.reverse, device.String())
		return Path{}, false
	}
	entry.LastSeen = now
	r.reverse[device.String()] = entry
	return entry.Path, true
}

func (r *Router) sendFrame(frame Frame) error {
	if frame.HopIndex <= 0 || frame.HopIndex >= len(frame.Hops) {
		return fmt.Errorf("cannot send frame with invalid next hop index")
	}
	next := frame.Hops[frame.HopIndex]
	if !r.mesh.CanSend(next) {
		return fmt.Errorf("next hop %s is unhealthy", next)
	}
	raw, err := MarshalFrame(frame)
	if err != nil {
		return err
	}
	return r.mesh.Send(next, raw)
}

func (r *Router) HandleTunPacket(packet []byte) error {
	_, destination, err := ParseIPv4Endpoints(packet)
	if err != nil {
		return err
	}
	config := r.configSnapshot()
	now := r.now()

	if config.IsSiteRouter(r.localNodeID) {
		overlay, overlayErr := netip.ParsePrefix(config.OverlaySubnet)
		if overlayErr == nil && overlay.Contains(destination) {
			forward, ok := r.reverseFor(destination, now)
			if !ok {
				return fmt.Errorf("no reverse path learned for Device %s", destination)
			}
			hops := reverseStrings(forward.Hops)
			if len(hops) < 2 || hops[0] != r.localNodeID {
				return fmt.Errorf("invalid learned reverse path")
			}
			return r.sendFrame(Frame{
				PathID:      forward.ID,
				OwnerNodeID: r.localNodeID,
				Hops:        hops,
				HopIndex:    1,
				Return:      true,
				Payload:     append([]byte(nil), packet...),
			})
		}
	}

	route, ok := config.RouteFor(destination)
	if !ok {
		return fmt.Errorf("destination %s is not a BPC-owned site route", destination)
	}
	path, err := r.choosePath(route, config.SourcePaths(r.localNodeID, route), now)
	if err != nil {
		return err
	}
	return r.sendFrame(Frame{
		PathID:      path.ID,
		OwnerNodeID: route.OwnerNodeID,
		Hops:        append([]string(nil), path.Hops...),
		HopIndex:    1,
		Payload:     append([]byte(nil), packet...),
	})
}

func (r *Router) HandleMeshData(peerID string, raw []byte) error {
	frame, err := UnmarshalFrame(raw)
	if err != nil {
		return err
	}
	config := r.configSnapshot()
	path, err := ValidateFrameForNode(frame, r.localNodeID, peerID, config)
	if err != nil {
		return err
	}

	if frame.HopIndex == len(frame.Hops)-1 {
		if frame.Return {
			return r.writer.WritePacket(frame.Payload)
		}
		source, _, parseErr := ParseIPv4Endpoints(frame.Payload)
		if parseErr != nil {
			return parseErr
		}
		r.rememberReverse(source, path, r.now())
		return r.writer.WritePacket(frame.Payload)
	}

	frame.HopIndex++
	return r.sendFrame(frame)
}

func displayHopNames(hops []string, names map[string]string) []string {
	result := make([]string, len(hops))
	for index, hop := range hops {
		if name := names[hop]; name != "" {
			result[index] = name
		} else {
			result[index] = hop
		}
	}
	return result
}

func (r *Router) SelectedPaths() []SelectedPathStatus {
	config := r.configSnapshot()
	if !config.IsPublicNode(r.localNodeID) {
		return nil
	}
	now := r.now()
	var result []SelectedPathStatus
	for _, route := range config.Routes {
		paths := config.SourcePaths(r.localNodeID, route)
		if len(paths) == 0 {
			continue
		}
		selected, err := r.choosePath(route, paths, now)
		if err != nil {
			continue
		}
		var standby []string
		for _, candidate := range paths {
			if candidate.ID == selected.ID {
				continue
			}
			if _, ok := r.viablePath(candidate); ok {
				standby = append(standby, candidate.ID)
			}
		}
		result = append(result, SelectedPathStatus{
			CIDR:           route.CIDR,
			OwnerNodeID:    route.OwnerNodeID,
			PathID:         selected.ID,
			Hops:           append([]string(nil), selected.Hops...),
			HopNames:       displayHopNames(selected.Hops, config.NodeNames),
			Health:         selected.Health,
			RTTMS:          selected.RTTMS,
			LossPercent:    selected.LossPercent,
			Cost:           selected.Cost,
			StandbyPathIDs: standby,
		})
	}
	return result
}
