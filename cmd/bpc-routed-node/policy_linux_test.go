//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/RomanKrike/bpc/internal/routed"
)

func TestPublicPolicyRealNamespace(t *testing.T) {
	if os.Getenv("BPC_TEST_NETNS") != "1" {
		t.Skip("explicit privileged network namespace CI test")
	}
	ns := fmt.Sprintf("bpc-policy-test-%d", os.Getpid())
	if err := runCommand("ip", "netns", "add", ns); err != nil {
		t.Fatal(err)
	}
	defer bestEffort("ip", "netns", "del", ns)
	run := func(args ...string) error { return runCommand(append([]string{"ip", "netns", "exec", ns}, args...)...) }
	output := func(args ...string) (string, error) {
		out, err := exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...).CombinedOutput()
		return string(out), err
	}
	for _, args := range [][]string{
		{"ip", "link", "add", "wg0", "type", "dummy"},
		{"ip", "link", "add", "bpcrt0", "type", "dummy"},
		{"ip", "link", "set", "wg0", "up"},
		{"ip", "link", "set", "bpcrt0", "up"},
		{"ip", "addr", "add", "10.253.0.1/24", "dev", "wg0"},
		{"ip", "route", "add", "192.168.88.0/24", "dev", "wg0", "metric", "50"},
		{"ip", "rule", "add", "priority", "220", "lookup", "220"},
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.253.0.0/24", "!", "-d", "10.253.0.0/24", "-j", "MASQUERADE"},
	} {
		if err := run(args...); err != nil {
			t.Fatal(err)
		}
	}
	beforeRoutes, _ := output("ip", "-4", "route", "show", "table", "main")
	beforeRules, _ := output("ip", "-4", "rule", "show")
	beforeNAT, err := output("iptables", "-t", "nat", "-S")
	if err != nil {
		t.Fatal(err)
	}
	k := &kernelState{interfaceID: "bpcrt0", routes: map[string]struct{}{}, command: run}
	defer k.cleanup()
	cfg := routed.RoutingConfig{LocalPublic: true, OverlaySubnet: "10.253.0.0/24", Routes: []routed.Route{{CIDR: "192.168.88.0/24", OwnerNodeID: "home"}}}
	if err := k.reconcile(cfg); err != nil {
		t.Fatal(err)
	}
	checkRoute := func(marked bool, wanted string) {
		t.Helper()
		args := []string{"ip", "-4", "route", "get", "192.168.88.180"}
		if marked {
			args = append(args, "mark", meshRouteMark)
		}
		out, err := output(args...)
		if err != nil || !strings.Contains(out, "dev "+wanted) {
			t.Fatalf("marked=%v route=%s err=%v", marked, out, err)
		}
	}
	checkRoute(false, "wg0")
	checkRoute(true, "bpcrt0")
	if err := run("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", cfg.OverlaySubnet, "-d", "192.168.88.0/24", "-o", "bpcrt0", "-m", "comment", "--comment", "bpc-routed-nonat:bpcrt0:192.168.88.0/24", "-j", "ACCEPT"); err != nil {
		t.Fatal(err)
	}
	cfg.Routes = nil
	if err := k.reconcile(cfg); err != nil {
		t.Fatal(err)
	}
	if out, err := output("ip", "-4", "route", "get", "192.168.88.180", "mark", meshRouteMark); err == nil {
		t.Fatalf("withdrawn route fell through: %s", out)
	}
	checkRoute(false, "wg0")
	if err := k.reconcile(routed.RoutingConfig{}); err != nil {
		t.Fatal(err)
	}
	afterRoutes, _ := output("ip", "-4", "route", "show", "table", "main")
	afterRules, _ := output("ip", "-4", "rule", "show")
	afterNAT, err := output("iptables", "-t", "nat", "-S")
	if err != nil {
		t.Fatal(err)
	}
	if beforeNAT != afterNAT {
		t.Fatalf("legacy NAT changed:\n%s", afterNAT)
	}
	if beforeRoutes != afterRoutes || beforeRules != afterRules {
		t.Fatalf("legacy routes/rules changed:\n%s\n%s", afterRoutes, afterRules)
	}
	// Occupied priority and table must be refused, not adopted on restart.
	if err := run("ip", "rule", "add", "priority", meshRulePriority, "lookup", "220"); err != nil {
		t.Fatal(err)
	}
	rules, _ := output("ip", "-4", "-j", "rule", "show")
	if publicPolicyConflicts([]byte(rules), []byte(`[]`)) == nil {
		t.Fatal("foreign priority accepted")
	}
	if err := run("ip", "rule", "del", "priority", meshRulePriority, "lookup", "220"); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "route", "add", "192.0.2.0/24", "dev", "wg0", "table", meshRouteTable); err != nil {
		t.Fatal(err)
	}
	routes, err := output("ip", "-N", "-4", "-j", "route", "show", "table", meshRouteTable)
	if err != nil {
		t.Fatal(err)
	}
	if publicPolicyConflicts([]byte(`[]`), []byte(routes)) == nil {
		t.Fatal("foreign table accepted")
	}
}
