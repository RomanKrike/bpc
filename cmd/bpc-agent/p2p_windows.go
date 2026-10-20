//go:build windows

package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"github.com/RomanKrike/bpc/internal/agentctl"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

func secureP2PDirectory(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("P2P state must be an owned directory")
	}
	// Exact protected DACL; do not retain an explicit Users/Everyone grant.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func p2pOwnedRoute(native *tun.NativeTun, profile agentctl.WireGuardProfile) func(context.Context, netip.Addr) error {
	iphlp := windows.NewLazySystemDLL("iphlpapi.dll")
	toIndex := iphlp.NewProc("ConvertInterfaceLuidToIndex")
	toGUID := iphlp.NewProc("ConvertInterfaceLuidToGuid")
	// Only routes actually configured during this overlay lifetime are owned.
	owned := make(map[netip.Prefix]bool)
	for _, raw := range profile.AllowedIPs {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			owned[prefix] = true
		}
	}
	return func(ctx context.Context, peer netip.Addr) error {
		luid := native.LUID()
		if luid == 0 {
			return errors.New("BPC adapter closed")
		}
		var index uint32
		var guid windows.GUID
		result, _, _ := toIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index)))
		if result != 0 {
			return errors.New("BPC adapter index unavailable")
		}
		result, _, _ = toGUID.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&guid)))
		if result != 0 {
			return errors.New("BPC adapter identity unavailable")
		}
		script, err := p2pRouteScript(index, guid.String(), peer, owned[netip.PrefixFrom(peer, 32)])
		if err != nil {
			return err
		}
		deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(deadline, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err = cmd.Run(); err != nil {
			return errors.New("P2P route unavailable or conflicts with existing ownership")
		}
		owned[netip.PrefixFrom(peer, 32)] = true
		return nil
	}
}
