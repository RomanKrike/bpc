//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strings"

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
	if err := configureEmbeddedInterface(interfaceName, profile); err != nil {
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

	select {
	case <-ctx.Done():
		wgDevice.Close()
		<-wgDevice.Wait()
		return nil
	case <-wgDevice.Wait():
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("embedded WireGuard device stopped unexpectedly")
	}
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

func configureEmbeddedInterface(name string, profile agentctl.WireGuardProfile) error {
	address, err := netip.ParsePrefix(profile.Address)
	if err != nil {
		return err
	}
	escapedName := psQuote(name)

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
			"Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv4 "+
			"-ErrorAction SilentlyContinue | "+
			"Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; "+
			"New-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -PrefixLength %d "+
			"-AddressFamily IPv4 -ErrorAction Stop | Out-Null; "+
			"Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 "+
			"-NlMtuBytes %d -ErrorAction Stop; %s",
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
