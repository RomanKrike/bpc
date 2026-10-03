package main

import (
	"strings"
	"testing"

	"github.com/RomanKrike/bpc/internal/routed"
)

func TestPublicPolicyConflictRefusesForeignObjects(t *testing.T) {
	for _, rules := range []string{
		`[{"priority":120,"table":220}]`,
		`[{"priority":1000,"table":12530}]`,
		`[{"fwmark":"0x425043"}]`,
		`[{"fwmark":"0x420000","fwmask":"0xff0000"}]`,
		`[{"fwmark":"bad"}]`,
	} {
		if publicPolicyConflicts([]byte(rules), []byte(`[]`)) == nil {
			t.Fatalf("accepted foreign rule %s", rules)
		}
	}
	if publicPolicyConflicts([]byte(`[]`), []byte(`[{"dst":"192.168.88.0/24"}]`)) == nil {
		t.Fatal("adopted occupied table")
	}
	if publicPolicyConflicts([]byte(`invalid`), []byte(`[]`)) == nil {
		t.Fatal("ignored invalid inspection")
	}
	if err := publicPolicyConflicts([]byte(`[{"priority":220,"table":220},{"priority":32766,"table":254},{"fwmark":"0x100"}]`), []byte(`[]`)); err != nil {
		t.Fatal(err)
	}
}

func TestPublicMeshDoesNotInstallMainTableLANOrGlobalNonNAT(t *testing.T) {
	var calls []string
	k := &kernelState{interfaceID: "bpcrt0", routes: map[string]struct{}{}, command: func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}}
	cfg := routed.RoutingConfig{LocalPublic: true, OverlaySubnet: "10.253.0.0/24", Routes: []routed.Route{{CIDR: "192.168.88.0/24", OwnerNodeID: "home"}}}
	if err := k.reconcile(cfg); err != nil {
		t.Fatal(err)
	}
	for _, call := range calls {
		if strings.HasPrefix(call, "ip route add 192.168.88") && !strings.Contains(call, "table 12530") {
			t.Fatalf("stole main route: %s", call)
		}
		if strings.Contains(call, "POSTROUTING") && !strings.Contains(call, "-o bpcrt0") {
			t.Fatalf("global legacy NAT exception: %s", call)
		}
	}
	count := len(calls)
	if err := k.reconcile(cfg); err != nil {
		t.Fatal(err)
	}
	if len(calls) != count {
		t.Fatal("unchanged policy recreated")
	}
	cfg.Routes = nil
	if err := k.reconcile(cfg); err != nil {
		t.Fatal(err)
	}
	if !k.policyRule || !k.policyDefault {
		t.Fatal("route withdrawal removed fail-closed policy")
	}
	if len(k.routes) != 0 {
		t.Fatal("withdrawn route retained")
	}
	if err := k.reconcile(routed.RoutingConfig{}); err != nil {
		t.Fatal(err)
	}
	if k.policyRule || k.policyDefault {
		t.Fatal("shutdown leaked policy")
	}
}

func TestSiteOverlayReturnRouteRemainsInItsOwnedMainTable(t *testing.T) {
	var calls []string
	k := &kernelState{interfaceID: "bpcrt0", routes: map[string]struct{}{}, command: func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil }}
	if err := k.reconcile(routed.RoutingConfig{LocalSiteRouter: true, OverlaySubnet: "10.253.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != "ip route add 10.253.0.0/24 dev bpcrt0 proto 99" {
		t.Fatalf("private return route changed: %v", calls)
	}
}
