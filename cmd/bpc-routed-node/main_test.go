package main

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/RomanKrike/bpc/internal/routed"
)

func TestRoutedRuntimeRefusesExistingInterface(t *testing.T) {
	if requireFreshInterface("bpcrt0", []net.Interface{{Name: "bpcrt0"}}) == nil {
		t.Fatal("adopted an unowned interface")
	}
	if err := requireFreshInterface("bpcrt0", []net.Interface{{Name: "wg0"}}); err != nil {
		t.Fatal(err)
	}
}

func TestRoutedRoutesNeverReplaceUnmanagedRoutes(t *testing.T) {
	calls := []string{}
	conflict := true
	k := &kernelState{interfaceID: "bpcrt0", routes: map[string]struct{}{}, command: func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		if conflict {
			return errors.New("File exists")
		}
		return nil
	}}
	cfg := routed.RoutingConfig{LocalPublic: true, Routes: []routed.Route{{CIDR: "192.168.88.0/24", OwnerNodeID: "home"}}}
	if k.reconcile(cfg) == nil {
		t.Fatal("route conflict was ignored")
	}
	if len(k.routes) != 0 {
		t.Fatal("failed add acquired route ownership")
	}
	if len(calls) != 1 || calls[0] != "ip route add 192.168.88.0/24 dev bpcrt0 proto 99" {
		t.Fatalf("unsafe route mutation: %v", calls)
	}
	conflict = false
	if err := k.reconcile(cfg); err != nil {
		t.Fatal(err)
	}
	if err := k.reconcile(cfg); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("unchanged owned route was recreated: %v", calls)
	}
	conflict = true
	if k.reconcile(routed.RoutingConfig{}) == nil {
		t.Fatal("failed deletion was hidden")
	}
	if len(k.routes) != 1 {
		t.Fatal("failed deletion lost ownership evidence")
	}
	conflict = false
	if err := k.reconcile(routed.RoutingConfig{}); err != nil {
		t.Fatal(err)
	}
	if len(k.routes) != 0 {
		t.Fatal("stale route was not retried")
	}
}
