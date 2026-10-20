package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Public mesh site routes never participate in ordinary/compatibility routing.
// Only an explicitly marked packet can enter this table. Its unreachable
// default prevents a withdrawn mesh route from falling through to legacy WG.
const (
	meshRouteTable   = "12530"
	meshRouteMark    = "0x425043"
	meshRulePriority = "120"
)

func kernelRouteArgs(action, cidr, device, table string) []string {
	args := []string{"ip", "route", action, cidr, "dev", device, "proto", "99"}
	if table != "" {
		args = append(args, "table", table)
	}
	return args
}

func (k *kernelState) enablePublicPolicy(command func(...string) error) error {
	if !k.policyDefault {
		if err := command("ip", "route", "add", "unreachable", "default", "table", meshRouteTable, "proto", "99"); err != nil {
			return err
		}
		k.policyDefault = true
	}
	if !k.policyRule {
		if err := command("ip", "rule", "add", "priority", meshRulePriority, "fwmark", meshRouteMark, "lookup", meshRouteTable); err != nil {
			return err
		}
		k.policyRule = true
	}
	return nil
}

func (k *kernelState) disablePublicPolicy(command func(...string) error) error {
	if k.policyRule {
		if err := command("ip", "rule", "del", "priority", meshRulePriority, "fwmark", meshRouteMark, "lookup", meshRouteTable); err != nil {
			return err
		}
		k.policyRule = false
	}
	if k.policyDefault {
		if err := command("ip", "route", "del", "unreachable", "default", "table", meshRouteTable, "proto", "99"); err != nil {
			return err
		}
		k.policyDefault = false
	}
	return nil
}

func publicPolicyConflicts(rulesJSON, routesJSON []byte) error {
	var rules, routes []map[string]any
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		return fmt.Errorf("inspect policy rules: %w", err)
	}
	if err := json.Unmarshal(routesJSON, &routes); err != nil {
		return fmt.Errorf("inspect policy table: %w", err)
	}
	if len(routes) != 0 {
		return fmt.Errorf("mesh table %s is already occupied; refusing adoption", meshRouteTable)
	}
	mark, _ := strconv.ParseUint(meshRouteMark, 0, 32)
	for _, rule := range rules {
		if fmt.Sprint(rule["priority"]) == meshRulePriority || fmt.Sprint(rule["table"]) == meshRouteTable {
			return fmt.Errorf("mesh policy priority/table already occupied; refusing adoption")
		}
		if value, ok := rule["fwmark"]; ok {
			fields := strings.Split(fmt.Sprint(value), "/")
			other, err := strconv.ParseUint(fields[0], 0, 32)
			if err != nil {
				return fmt.Errorf("cannot inspect existing fwmark: %w", err)
			}
			mask := uint64(0xffffffff)
			if len(fields) == 2 {
				mask, err = strconv.ParseUint(fields[1], 0, 32)
			} else if value, ok := rule["fwmask"]; ok {
				mask, err = strconv.ParseUint(fmt.Sprint(value), 0, 32)
			}
			if err != nil {
				return fmt.Errorf("cannot inspect existing fwmask: %w", err)
			}
			if mark&mask == other&mask {
				return fmt.Errorf("mesh mark overlaps an existing policy rule")
			}
		}
	}
	return nil
}

func requireFreshPublicPolicy() error {
	rules, err := numericIPJSON("rule", "show").Output()
	if err != nil {
		return fmt.Errorf("inspect rules before mesh startup: %w", err)
	}
	command := numericIPJSON("route", "show", "table", meshRouteTable)
	routes, err := command.Output()
	if err != nil {
		// iproute2 reports an absent custom FIB table as an error, not [].
		failure, ok := err.(*exec.ExitError)
		if !ok || !strings.Contains(string(failure.Stderr), "FIB table does not exist") {
			return fmt.Errorf("inspect mesh table: %w", err)
		}
		routes = []byte("[]")
	}
	return publicPolicyConflicts(rules, routes)
}

// Numeric output avoids rt_tables aliases hiding a reserved table ID.
func numericIPJSON(args ...string) *exec.Cmd {
	command := exec.Command("ip", append([]string{"-N", "-4", "-j"}, args...)...)
	command.Env = append(os.Environ(), "LC_ALL=C")
	return command
}
