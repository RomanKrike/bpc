//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/RomanKrike/bpc/internal/agentctl"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const embeddedInterfaceName = "BPC"

func runEmbeddedWireGuard(
	ctx context.Context,
	cfg agentctl.RuntimeConfig,
	profile agentctl.WireGuardProfile,
	logger *log.Logger,
	reportTelemetry func(tunnelTelemetry),
	pathSwitches <-chan pathSwitchEvent,
) error {
	if err := agentctl.ValidateWireGuardProfile(profile); err != nil {
		return err
	}

	if cfg.LegacyTunnel != "" {
		_, _ = runCommand("sc.exe", "stop", "WireGuardTunnel$"+cfg.LegacyTunnel)
	}

	tunDevice, err := tun.CreateTUN(embeddedInterfaceName, profile.MTU)
	if err != nil {
		return fmt.Errorf("create Wintun adapter: %w", err)
	}
	interfaceName, err := tunDevice.Name()
	if err != nil {
		_ = tunDevice.Close()
		return fmt.Errorf("read Wintun adapter name: %w", err)
	}
	if err := configureEmbeddedInterface(interfaceName, cfg, profile); err != nil {
		_ = tunDevice.Close()
		return err
	}

	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			logger.Printf("wireguard: "+format, args...)
		},
		Errorf: func(format string, args ...any) {
			logger.Printf("wireguard error: "+format, args...)
		},
	}
	wgDevice := device.NewDevice(tunDevice, conn.NewDefaultBind(), wgLogger)

	uapi, err := embeddedUAPI(cfg, profile)
	if err != nil {
		wgDevice.Close()
		return err
	}
	if err := wgDevice.IpcSet(uapi); err != nil {
		wgDevice.Close()
		return fmt.Errorf("configure embedded WireGuard: %w", err)
	}
	if err := wgDevice.Up(); err != nil {
		wgDevice.Close()
		return fmt.Errorf("bring embedded WireGuard up: %w", err)
	}

	logger.Printf(
		"embedded WireGuard active interface=%s address=%s routes=%s mtu=%d",
		interfaceName,
		profile.Address,
		strings.Join(profile.AllowedIPs, ","),
		profile.MTU,
	)

	waitCh := wgDevice.Wait()
	telemetryTicker := time.NewTicker(2 * time.Second)
	defer telemetryTicker.Stop()

	if reportTelemetry != nil {
		reportTelemetry(readEmbeddedTelemetry(wgDevice))
	}

	for {
		select {
		case <-ctx.Done():
			wgDevice.Close()
			<-waitCh
			return nil
		case <-waitCh:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("embedded WireGuard device stopped unexpectedly")
		case event := <-pathSwitches:
			// A different Public Node has the same static overlay identity but not
			// the previous responder's ephemeral WireGuard session state. Reapply
			// replace_peers on the existing device to discard only peer session
			// state and force a fresh handshake without recreating Wintun, its IP,
			// or application routes.
			if err := wgDevice.IpcSet(uapi); err != nil {
				logger.Printf(
					"wireguard cross-node rehandshake failed from=%s to=%s: %v",
					event.FromNode,
					event.ToNode,
					err,
				)
			} else {
				logger.Printf(
					"wireguard cross-node rehandshake armed from=%s to=%s",
					event.FromNode,
					event.ToNode,
				)
			}
		case <-telemetryTicker.C:
			if reportTelemetry != nil {
				reportTelemetry(readEmbeddedTelemetry(wgDevice))
			}
		}
	}
}

func readEmbeddedTelemetry(wgDevice *device.Device) tunnelTelemetry {
	stats := tunnelTelemetry{UpdatedAt: time.Now().Unix()}
	raw, err := wgDevice.IpcGet()
	if err != nil {
		return stats
	}
	for _, rawLine := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(rawLine), "=")
		if !ok {
			continue
		}
		switch key {
		case "last_handshake_time_sec":
			if parsed, err := strconv.ParseInt(value, 10, 64); err == nil && parsed > stats.HandshakeAt {
				stats.HandshakeAt = parsed
			}
		case "rx_bytes":
			if parsed, err := strconv.ParseUint(value, 10, 64); err == nil {
				stats.RXBytes += parsed
			}
		case "tx_bytes":
			if parsed, err := strconv.ParseUint(value, 10, 64); err == nil {
				stats.TXBytes += parsed
			}
		}
	}
	return stats
}

func embeddedUAPI(cfg agentctl.RuntimeConfig, profile agentctl.WireGuardProfile) (string, error) {
	privateHex, err := agentctl.WGKeyHex(profile.PrivateKey, false)
	if err != nil {
		return "", err
	}
	peerHex, err := agentctl.WGKeyHex(profile.PeerPublicKey, false)
	if err != nil {
		return "", err
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "private_key=%s\n", privateHex)
	builder.WriteString("replace_peers=true\n")
	fmt.Fprintf(&builder, "public_key=%s\n", peerHex)
	if strings.TrimSpace(profile.PresharedKey) != "" {
		pskHex, err := agentctl.WGKeyHex(profile.PresharedKey, true)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&builder, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&builder, "endpoint=%s\n", cfg.WGShimListen)
	fmt.Fprintf(
		&builder,
		"persistent_keepalive_interval=%d\n",
		profile.PersistentKeepalive,
	)
	builder.WriteString("replace_allowed_ips=true\n")
	for _, allowed := range profile.AllowedIPs {
		fmt.Fprintf(&builder, "allowed_ip=%s\n", strings.TrimSpace(allowed))
	}
	builder.WriteString("\n")
	return builder.String(), nil
}

func configureEmbeddedInterface(
	name string,
	cfg agentctl.RuntimeConfig,
	profile agentctl.WireGuardProfile,
) error {
	address, err := netip.ParsePrefix(profile.Address)
	if err != nil {
		return err
	}
	serverIPs, err := resolveWGShimServerIPv4s(cfg.TransportPaths())
	if err != nil {
		return err
	}
	escapedName := psQuote(name)

	physicalRouteCommands := make([]string, 0, len(serverIPs))
	for _, serverIP := range serverIPs {
		physicalRouteCommands = append(
			physicalRouteCommands,
			fmt.Sprintf(
				"$route=Find-NetRoute -RemoteIPAddress '%s' | "+
					"Where-Object {$_.InterfaceAlias -ne '%s'} | "+
					"Sort-Object RouteMetric | Select-Object -First 1; "+
					"if ($null -eq $route) { throw 'No physical route to BPC relay %s' }; "+
					"$nextHop=$route.NextHop; if ([string]::IsNullOrWhiteSpace($nextHop)) {$nextHop='0.0.0.0'}; "+
					"Remove-NetRoute -DestinationPrefix '%s/32' -Confirm:$false -ErrorAction SilentlyContinue; "+
					"New-NetRoute -InterfaceIndex $route.InterfaceIndex -DestinationPrefix '%s/32' "+
					"-NextHop $nextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null",
				serverIP,
				escapedName,
				serverIP,
				serverIP,
				serverIP,
			),
		)
	}

	routeCommands := make([]string, 0, len(profile.AllowedIPs))
	for _, route := range profile.AllowedIPs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
		if err != nil {
			return err
		}
		if !prefix.Addr().Is4() {
			continue
		}
		routeCommands = append(
			routeCommands,
			fmt.Sprintf(
				"Remove-NetRoute -InterfaceAlias '%s' -DestinationPrefix '%s' "+
					"-Confirm:$false -ErrorAction SilentlyContinue; "+
					"New-NetRoute -InterfaceAlias '%s' -DestinationPrefix '%s' "+
					"-NextHop 0.0.0.0 -RouteMetric 5 -PolicyStore ActiveStore "+
					"-ErrorAction Stop | Out-Null",
				escapedName,
				prefix.String(),
				escapedName,
				prefix.String(),
			),
		)
	}

	script := fmt.Sprintf(
		"$ErrorActionPreference='Stop'; "+
			"Get-NetRoute -InterfaceAlias '%s' -ErrorAction SilentlyContinue | "+
			"Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; "+
			"%s; "+
			"Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv4 "+
			"-ErrorAction SilentlyContinue | "+
			"Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; "+
			"New-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -PrefixLength %d "+
			"-AddressFamily IPv4 -ErrorAction Stop | Out-Null; "+
			"Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 "+
			"-NlMtuBytes %d -ErrorAction Stop; %s",
		escapedName,
		strings.Join(physicalRouteCommands, "; "),
		escapedName,
		escapedName,
		address.Addr().String(),
		address.Bits(),
		escapedName,
		profile.MTU,
		strings.Join(routeCommands, "; "),
	)
	out, err := runCommand(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		script,
	)
	if err != nil {
		return fmt.Errorf(
			"configure embedded WireGuard interface: %w: %s",
			err,
			strings.TrimSpace(out),
		)
	}
	return nil
}

func resolveWGShimServerIPv4s(paths []agentctl.TransportPath) ([]string, error) {
	seen := map[string]struct{}{}
	var result []string
	var failures []string
	for _, path := range paths {
		addresses, err := resolveWGShimServerIPv4Candidates(path.Endpoint)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		for _, address := range addresses {
			if _, ok := seen[address]; ok {
				continue
			}
			seen[address] = struct{}{}
			result = append(result, address)
		}
	}
	if len(result) == 0 {
		if len(failures) == 0 {
			return nil, fmt.Errorf("no transport path has an IPv4 endpoint")
		}
		return nil, fmt.Errorf("resolve transport path endpoints: %s", strings.Join(failures, "; "))
	}
	return result, nil
}

func resolveWGShimServerIPv4(endpoint string) (string, error) {
	addresses, err := resolveWGShimServerIPv4Candidates(endpoint)
	if err != nil {
		return "", err
	}
	return addresses[0], nil
}

func resolveWGShimServerIPv4Candidates(endpoint string) ([]string, error) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil {
		return nil, fmt.Errorf("parse WGShim server endpoint: %w", err)
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []string{v4.String()}, nil
		}
		return nil, fmt.Errorf("WGShim server does not resolve to IPv4: %s", host)
	}
	addresses, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("resolve WGShim server %s: %w", host, err)
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(addresses))
	for _, ip := range addresses {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		value := v4.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("WGShim server has no IPv4 address: %s", host)
	}
	return result, nil
}
