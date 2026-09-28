package agentctl

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestTransportPathCompatibility(t *testing.T) {
	for _, raw := range []string{
		`{"wgshim_server":"ru-01.example:24444"}`,
		`{"wgshim_server":"ru-01.example:24444","wgshim_servers":["ru-01.example:24444","ru-02.example:24444"]}`,
		`{"paths":[{"node":"ru-01","endpoint":"ru-01.example:24444"},{"node":"ru-02","endpoint":"ru-02.example:24444"}]}`,
	} {
		var cfg RuntimeConfig
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			t.Fatal(err)
		}
		if err := cfg.ValidatePaths(); err != nil {
			t.Fatal(err)
		}
		paths := cfg.TransportPaths()
		if paths[0].Endpoint != "ru-01.example:24444" {
			t.Fatal(paths)
		}
		paths[0].Endpoint = "mutated"
		if cfg.TransportPaths()[0].Endpoint == "mutated" {
			t.Fatal("paths alias config")
		}
	}
}

func TestPathSelectionDoesNotChangeOverlayIdentity(t *testing.T) {
	cfg := RuntimeConfig{Paths: []TransportPath{{Node: "ru-01", Endpoint: "ru-01.example:24444"}, {Node: "ru-02", Endpoint: "ru-02.example:24444"}}, WireGuard: &WireGuardProfile{Address: "10.253.0.2/32", PeerPublicKey: "overlay", AllowedIPs: []string{"192.168.88.0/24"}}}
	before, _ := json.Marshal(cfg.WireGuard)
	paths := cfg.TransportPaths()
	paths[0], paths[1] = paths[1], paths[0]
	after, _ := json.Marshal(cfg.WireGuard)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("overlay changed")
	}
	cfg.Paths[1].PeerPublicKey = "another-gateway"
	if cfg.ValidatePaths() == nil {
		t.Fatal("independent WG peer accepted")
	}
}

func TestInvalidTransportPaths(t *testing.T) {
	for _, endpoint := range []string{"", "ru-01.example", ":24444", "host:0", "host:65536", "host:abc", "bad host:24444"} {
		cfg := RuntimeConfig{Paths: []TransportPath{{Endpoint: endpoint}}}
		if cfg.ValidatePaths() == nil {
			t.Errorf("accepted %q", endpoint)
		}
	}
	cfg := RuntimeConfig{Paths: []TransportPath{{Endpoint: "HOST:42"}, {Endpoint: "host:42"}}}
	if cfg.ValidatePaths() == nil {
		t.Fatal("duplicate accepted")
	}
}
