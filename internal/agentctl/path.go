package agentctl

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// TransportPath is a runtime route to the existing overlay peer, not a Node
// identity or a separate WireGuard profile. Independent gateway keys cannot be
// substituted for the overlay peer while retaining an established WG session.
type TransportPath struct {
	Node          string `json:"node,omitempty"`
	Endpoint      string `json:"endpoint"`
	PeerPublicKey string `json:"peer_public_key,omitempty"`
}

// TransportPaths accepts both generations of runtime configuration. Explicit
// paths take precedence; legacy pools retain their original order.
func (c RuntimeConfig) TransportPaths() []TransportPath {
	if len(c.Paths) > 0 {
		return append([]TransportPath(nil), c.Paths...)
	}
	servers := c.WGShimServers
	if len(servers) == 0 {
		servers = []string{c.WGShimServer}
	}
	paths := make([]TransportPath, 0, len(servers))
	for _, endpoint := range servers {
		paths = append(paths, TransportPath{Endpoint: endpoint})
	}
	return paths
}

func (c RuntimeConfig) ValidatePaths() error {
	paths := c.TransportPaths()
	if len(paths) == 0 || len(paths) > 16 {
		return fmt.Errorf("runtime path count must be between 1 and 16")
	}
	seen := map[string]bool{}
	for _, path := range paths {
		host, port, err := net.SplitHostPort(path.Endpoint)
		number, portErr := strconv.Atoi(port)
		if err != nil || host == "" || strings.ContainsAny(host, " /\\\t\r\n") || portErr != nil || number < 1 || number > 65535 {
			return fmt.Errorf("invalid transport path endpoint %q", path.Endpoint)
		}
		key := strings.ToLower(path.Endpoint)
		if seen[key] {
			return fmt.Errorf("duplicate transport path endpoint %q", path.Endpoint)
		}
		seen[key] = true
		if path.PeerPublicKey != "" && (c.WireGuard == nil || path.PeerPublicKey != c.WireGuard.PeerPublicKey) {
			return fmt.Errorf("path %q terminates a different overlay peer", path.Endpoint)
		}
	}
	return nil
}
