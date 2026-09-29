package routed

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
)

const (
	DefaultMeshPort = 24446
	// Device ingress is outside this hop list: at most two Public Nodes plus owner.
	MaxPathHops = 3
)

type Enrollment struct {
	NodeID string          `json:"node_id"`
	Name   string          `json:"name"`
	Roles  map[string]bool `json:"roles"`
	Config struct {
		Routing RoutingConfig `json:"routing"`
	} `json:"config"`
}

type RoutingConfig struct {
	Version         int               `json:"version"`
	ListenPort      int               `json:"listen_port"`
	OverlaySubnet   string            `json:"overlay_subnet"`
	LocalPublic     bool              `json:"local_public"`
	LocalSiteRouter bool              `json:"local_site_router"`
	NodeNames       map[string]string `json:"node_names"`
	Links           []LinkConfig      `json:"links"`
	Paths           []Path            `json:"paths"`
	TransitPaths    []Path            `json:"transit_paths"`
	Routes          []Route           `json:"routes"`
}

type LinkConfig struct {
	ID             string  `json:"id"`
	PeerNodeID     string  `json:"peer_node_id"`
	PeerName       string  `json:"peer_name"`
	PSK            string  `json:"psk"`
	PeerEndpoint   string  `json:"peer_endpoint"`
	PeerPublic     bool    `json:"peer_public"`
	PeerSiteRouter bool    `json:"peer_site_router"`
	Port           int     `json:"port"`
	Cost           float64 `json:"cost"`
}

type Path struct {
	ID          string   `json:"id"`
	OwnerNodeID string   `json:"owner_node_id"`
	CIDR        string   `json:"cidr"`
	Hops        []string `json:"hops"`
	Health      string   `json:"health"`
	RTTMS       float64  `json:"rtt_ms"`
	LossPercent float64  `json:"loss_percent"`
	Cost        float64  `json:"cost"`
	Score       float64  `json:"score"`
	LastSeen    int64    `json:"last_seen"`
}

type Route struct {
	CIDR        string `json:"cidr"`
	OwnerNodeID string `json:"owner_node_id"`
}

func LoadEnrollment(path string) (Enrollment, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Enrollment{}, fmt.Errorf("read enrollment: %w", err)
	}
	var value Enrollment
	if err := json.Unmarshal(raw, &value); err != nil {
		return Enrollment{}, fmt.Errorf("decode enrollment: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Enrollment{}, err
	}
	return value, nil
}

func (e Enrollment) Validate() error {
	if strings.TrimSpace(e.NodeID) == "" {
		return fmt.Errorf("routing enrollment has no node_id")
	}
	return e.Config.Routing.Validate(e.NodeID)
}

func (c RoutingConfig) Validate(localNodeID string) error {
	if c.Version == 0 {
		return fmt.Errorf("routed mesh is not configured")
	}
	if c.ListenPort == 0 {
		c.ListenPort = DefaultMeshPort
	}
	if c.ListenPort < 1024 || c.ListenPort > 65535 {
		return fmt.Errorf("invalid routed mesh listen port %d", c.ListenPort)
	}
	if c.OverlaySubnet != "" {
		prefix, err := netip.ParsePrefix(c.OverlaySubnet)
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("invalid overlay subnet %q", c.OverlaySubnet)
		}
	}
	seenPeers := make(map[string]struct{})
	for _, link := range c.Links {
		if err := link.Validate(localNodeID); err != nil {
			return err
		}
		if _, exists := seenPeers[link.PeerNodeID]; exists {
			return fmt.Errorf("duplicate routed link peer %q", link.PeerNodeID)
		}
		seenPeers[link.PeerNodeID] = struct{}{}
	}
	for _, route := range c.Routes {
		if _, err := route.Prefix(); err != nil {
			return err
		}
		if strings.TrimSpace(route.OwnerNodeID) == "" {
			return fmt.Errorf("route %q has no owner", route.CIDR)
		}
	}
	allPaths := append(append([]Path{}, c.Paths...), c.TransitPaths...)
	for _, path := range allPaths {
		if err := path.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (l LinkConfig) Validate(localNodeID string) error {
	if strings.TrimSpace(l.ID) == "" {
		return fmt.Errorf("routed link has no id")
	}
	if strings.TrimSpace(l.PeerNodeID) == "" || l.PeerNodeID == localNodeID {
		return fmt.Errorf("invalid routed link peer %q", l.PeerNodeID)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(l.PSK))
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("link %s has invalid PSK", l.ID)
	}
	port := l.Port
	if port == 0 {
		port = DefaultMeshPort
	}
	if port < 1024 || port > 65535 {
		return fmt.Errorf("link %s has invalid port %d", l.ID, port)
	}
	return nil
}

func (l LinkConfig) PSKBytes() ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(l.PSK))
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("link PSK must decode to 32 bytes")
	}
	return raw, nil
}

func (p Path) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("route path has no id")
	}
	if strings.TrimSpace(p.OwnerNodeID) == "" {
		return fmt.Errorf("route path %s has no owner", p.ID)
	}
	if len(p.Hops) < 2 || len(p.Hops) > MaxPathHops {
		return fmt.Errorf("route path %s has invalid hop count %d", p.ID, len(p.Hops))
	}
	seen := make(map[string]struct{}, len(p.Hops))
	for _, hop := range p.Hops {
		hop = strings.TrimSpace(hop)
		if hop == "" {
			return fmt.Errorf("route path %s has an empty hop", p.ID)
		}
		if _, exists := seen[hop]; exists {
			return fmt.Errorf("route path %s contains a loop", p.ID)
		}
		seen[hop] = struct{}{}
	}
	if p.Hops[len(p.Hops)-1] != p.OwnerNodeID {
		return fmt.Errorf("route path %s does not terminate at its owner", p.ID)
	}
	prefix, err := netip.ParsePrefix(p.CIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
		return fmt.Errorf("route path %s has invalid CIDR %q", p.ID, p.CIDR)
	}
	return nil
}

func (r Route) Prefix() (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(r.CIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("invalid owned route %q", r.CIDR)
	}
	return prefix.Masked(), nil
}

func (c RoutingConfig) IsPublicNode(localNodeID string) bool {
	return c.LocalPublic
}

func (c RoutingConfig) IsSiteRouter(localNodeID string) bool {
	return c.LocalSiteRouter
}

func (c RoutingConfig) RouteFor(addr netip.Addr) (Route, bool) {
	type candidate struct {
		route  Route
		prefix netip.Prefix
	}
	var matches []candidate
	for _, route := range c.Routes {
		prefix, err := route.Prefix()
		if err != nil || !prefix.Contains(addr) {
			continue
		}
		matches = append(matches, candidate{route: route, prefix: prefix})
	}
	if len(matches) == 0 {
		return Route{}, false
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].prefix.Bits() > matches[j].prefix.Bits()
	})
	return matches[0].route, true
}

func (c RoutingConfig) SourcePaths(localNodeID string, route Route) []Path {
	result := make([]Path, 0)
	for _, path := range c.Paths {
		if len(path.Hops) < 2 || path.Hops[0] != localNodeID {
			continue
		}
		if path.OwnerNodeID == route.OwnerNodeID && path.CIDR == route.CIDR {
			result = append(result, path)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Score == result[j].Score {
			return result[i].ID < result[j].ID
		}
		return result[i].Score < result[j].Score
	})
	return result
}

func (c RoutingConfig) TransitPath(pathID string) (Path, bool) {
	for _, path := range c.TransitPaths {
		if path.ID == pathID {
			return path, true
		}
	}
	return Path{}, false
}
