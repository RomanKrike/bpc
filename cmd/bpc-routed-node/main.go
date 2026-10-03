package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RomanKrike/bpc/internal/routed"
	"golang.zx2c4.com/wireguard/tun"
)

const version = "0.21.0-dev"

type tunWriter struct {
	device tun.Device
}

func (w *tunWriter) WritePacket(packet []byte) error {
	_, err := w.device.Write([][]byte{packet}, 0)
	return err
}

type runtimeStatus struct {
	Version       int                         `json:"version"`
	NodeID        string                      `json:"node_id"`
	Interface     string                      `json:"interface"`
	UpdatedAt     int64                       `json:"updated_at"`
	Links         []routed.LinkStatus         `json:"links"`
	SelectedPaths []routed.SelectedPathStatus `json:"selected_paths"`
}

type kernelState struct {
	command       func(...string) error
	mu            sync.Mutex
	localNodeID   string
	interfaceID   string
	overlaySubnet string
	routes        map[string]struct{}
	routeTables   map[string]string
	policyDefault bool
	policyRule    bool
	natNoSNAT     map[string]struct{}
	siteNAT       map[string]struct{}
	forward       map[string]struct{}
}

func runCommand(args ...string) error {
	completed := exec.Command(args[0], args[1:]...)
	output, err := completed.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func bestEffort(args ...string) {
	_ = runCommand(args...)
}

func (k *kernelState) reconcile(config routed.RoutingConfig) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	previousOverlay := k.overlaySubnet
	if previousOverlay == "" {
		previousOverlay = config.OverlaySubnet
	}
	desiredRoutes := make(map[string]string)
	if config.LocalPublic {
		for _, route := range config.Routes {
			desiredRoutes[route.CIDR] = meshRouteTable
		}
	}
	if config.LocalSiteRouter && config.OverlaySubnet != "" {
		desiredRoutes[config.OverlaySubnet] = ""
	}

	command := k.command
	if command == nil {
		command = runCommand
	}
	if k.routeTables == nil {
		k.routeTables = make(map[string]string)
	}
	if config.LocalPublic {
		// A running private Node can also be promoted by a policy refresh.
		if !k.policyDefault && k.command == nil {
			if err := requireFreshPublicPolicy(); err != nil {
				return err
			}
		}
		if err := k.enablePublicPolicy(command); err != nil {
			return err
		}
	}
	for cidr, table := range desiredRoutes {
		if _, ok := k.routes[cidr]; ok {
			continue
		}
		// Add exclusively: replacing an existing route can steal an unmanaged
		// route even when our newly created interface is BPC-owned.
		if err := command(kernelRouteArgs("add", cidr, k.interfaceID, table)...); err != nil {
			return err
		}
		k.routes[cidr] = struct{}{}
		k.routeTables[cidr] = table
	}
	for cidr := range k.routes {
		if _, ok := desiredRoutes[cidr]; ok {
			continue
		}
		if err := command(kernelRouteArgs("del", cidr, k.interfaceID, k.routeTables[cidr])...); err != nil {
			return err
		}
		delete(k.routes, cidr)
		delete(k.routeTables, cidr)
	}

	if !config.LocalPublic {
		if err := k.disablePublicPolicy(command); err != nil {
			return err
		}
	}

	desiredNoSNAT := make(map[string]struct{})
	if config.LocalPublic && config.OverlaySubnet != "" {
		for _, route := range config.Routes {
			desiredNoSNAT[route.CIDR] = struct{}{}
		}
	}
	for cidr := range desiredNoSNAT {
		if _, ok := k.natNoSNAT[cidr]; ok {
			continue
		}
		comment := "bpc-routed-nonat:" + k.interfaceID + ":" + cidr
		check := []string{
			"iptables", "-t", "nat", "-C", "POSTROUTING",
			"-s", config.OverlaySubnet,
			"-d", cidr,
			"-o", k.interfaceID,
			"-m", "comment", "--comment", comment,
			"-j", "ACCEPT",
		}
		if command(check...) != nil {
			insert := append([]string{}, check...)
			insert[3] = "-I"
			insert = append(insert[:5], append([]string{"1"}, insert[5:]...)...)
			if err := command(insert...); err != nil {
				return err
			}
		}
	}
	for cidr := range k.natNoSNAT {
		if _, ok := desiredNoSNAT[cidr]; ok {
			continue
		}
		comment := "bpc-routed-nonat:" + k.interfaceID + ":" + cidr
		_ = command(
			"iptables", "-t", "nat", "-D", "POSTROUTING",
			"-s", previousOverlay,
			"-d", cidr,
			"-o", k.interfaceID,
			"-m", "comment", "--comment", comment,
			"-j", "ACCEPT",
		)
	}
	k.natNoSNAT = desiredNoSNAT

	desiredSiteNAT := make(map[string]struct{})
	desiredForward := make(map[string]struct{})
	if config.LocalSiteRouter && config.OverlaySubnet != "" {
		for _, route := range config.Routes {
			if route.OwnerNodeID != k.localNodeID {
				continue
			}
			desiredSiteNAT[route.CIDR] = struct{}{}
			desiredForward[route.CIDR] = struct{}{}
		}
	}

	for cidr := range desiredSiteNAT {
		if _, ok := k.siteNAT[cidr]; !ok {
			comment := "bpc-routed-site-nat:" + k.interfaceID + ":" + cidr
			check := []string{
				"iptables", "-t", "nat", "-C", "POSTROUTING",
				"-s", config.OverlaySubnet,
				"-d", cidr,
				"-m", "comment", "--comment", comment,
				"-j", "MASQUERADE",
			}
			if command(check...) != nil {
				add := append([]string{}, check...)
				add[3] = "-A"
				if err := command(add...); err != nil {
					return err
				}
			}
		}
		if _, ok := k.forward[cidr]; !ok {
			inComment := "bpc-routed-forward-in:" + k.interfaceID + ":" + cidr
			if command(
				"iptables", "-C", "FORWARD",
				"-i", k.interfaceID,
				"-d", cidr,
				"-m", "comment", "--comment", inComment,
				"-j", "ACCEPT",
			) != nil {
				if err := command(
					"iptables", "-I", "FORWARD", "1",
					"-i", k.interfaceID,
					"-d", cidr,
					"-m", "comment", "--comment", inComment,
					"-j", "ACCEPT",
				); err != nil {
					return err
				}
			}
			outComment := "bpc-routed-forward-out:" + k.interfaceID + ":" + cidr
			if command(
				"iptables", "-C", "FORWARD",
				"-o", k.interfaceID,
				"-s", cidr,
				"-d", config.OverlaySubnet,
				"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
				"-m", "comment", "--comment", outComment,
				"-j", "ACCEPT",
			) != nil {
				if err := command(
					"iptables", "-I", "FORWARD", "1",
					"-o", k.interfaceID,
					"-s", cidr,
					"-d", config.OverlaySubnet,
					"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
					"-m", "comment", "--comment", outComment,
					"-j", "ACCEPT",
				); err != nil {
					return err
				}
			}
		}
	}

	for cidr := range k.siteNAT {
		if _, ok := desiredSiteNAT[cidr]; ok {
			continue
		}
		comment := "bpc-routed-site-nat:" + k.interfaceID + ":" + cidr
		_ = command(
			"iptables", "-t", "nat", "-D", "POSTROUTING",
			"-s", previousOverlay,
			"-d", cidr,
			"-m", "comment", "--comment", comment,
			"-j", "MASQUERADE",
		)
	}
	for cidr := range k.forward {
		if _, ok := desiredForward[cidr]; ok {
			continue
		}
		inComment := "bpc-routed-forward-in:" + k.interfaceID + ":" + cidr
		_ = command(
			"iptables", "-D", "FORWARD",
			"-i", k.interfaceID,
			"-d", cidr,
			"-m", "comment", "--comment", inComment,
			"-j", "ACCEPT",
		)
		outComment := "bpc-routed-forward-out:" + k.interfaceID + ":" + cidr
		_ = command(
			"iptables", "-D", "FORWARD",
			"-o", k.interfaceID,
			"-s", cidr,
			"-d", previousOverlay,
			"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
			"-m", "comment", "--comment", outComment,
			"-j", "ACCEPT",
		)
	}
	k.siteNAT = desiredSiteNAT
	k.forward = desiredForward
	k.overlaySubnet = config.OverlaySubnet
	return nil
}

func (k *kernelState) cleanup() {
	k.mu.Lock()
	overlay := k.overlaySubnet
	k.mu.Unlock()
	_ = k.reconcile(routed.RoutingConfig{OverlaySubnet: overlay})
}

func writeStatus(path string, value runtimeStatus) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func readTunLoop(
	ctx context.Context,
	device tun.Device,
	router *routed.Router,
	logger *log.Logger,
) error {
	batch := device.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for index := range bufs {
		bufs[index] = make([]byte, 65535)
	}
	for {
		count, err := device.Read(bufs, sizes, 0)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read routed TUN: %w", err)
		}
		for index := 0; index < count; index++ {
			size := sizes[index]
			if size <= 0 || size > len(bufs[index]) {
				continue
			}
			packet := append([]byte(nil), bufs[index][:size]...)
			if err := router.HandleTunPacket(packet); err != nil && logger != nil {
				logger.Printf("TUN packet dropped: %v", err)
			}
		}
	}
}

func main() {
	enrollmentPath := flag.String(
		"enrollment",
		"/etc/bpc-connect/enrollment.json",
		"BPC Node enrollment state",
	)
	interfaceName := flag.String("interface", "bpcrt0", "routed BPC TUN interface")
	mtu := flag.Int("mtu", 1360, "routed TUN MTU")
	statusPath := flag.String(
		"status",
		"/run/bpc-connect/routed-status.json",
		"runtime status JSON",
	)
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("bpc-routed-node %s\n", version)
		return
	}
	logger := log.New(os.Stdout, "bpc-routed ", log.LstdFlags|log.LUTC)

	enrollment, err := routed.LoadEnrollment(*enrollmentPath)
	if err != nil {
		logger.Fatal(err)
	}
	config := enrollment.Config.Routing
	if !config.PolicyValid(time.Now()) {
		logger.Fatal("routed Controller policy expired; refresh Node heartbeat before starting")
	}

	if config.LocalPublic {
		if err := requireFreshPublicPolicy(); err != nil {
			logger.Fatal(err)
		}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		logger.Fatalf("inspect interfaces before TUN creation: %v", err)
	}
	if err := requireFreshInterface(*interfaceName, interfaces); err != nil {
		logger.Fatal(err)
	}
	device, err := tun.CreateTUN(*interfaceName, *mtu)
	if err != nil {
		logger.Fatalf("create routed TUN: %v", err)
	}
	defer device.Close()
	actualName, err := device.Name()
	if err != nil {
		logger.Fatalf("resolve routed TUN name: %v", err)
	}
	if err := runCommand("ip", "link", "set", "dev", actualName, "up"); err != nil {
		logger.Fatal(err)
	}

	mesh, err := routed.NewMesh(enrollment.NodeID, config.ListenPort, logger)
	if err != nil {
		logger.Fatal(err)
	}
	defer mesh.Close()
	if err := mesh.Reconcile(config.Links); err != nil {
		logger.Fatal(err)
	}

	writer := &tunWriter{device: device}
	router, err := routed.NewRouter(enrollment.NodeID, config, mesh, writer, logger)
	if err != nil {
		logger.Fatal(err)
	}
	mesh.SetDataHandler(func(peerID string, payload []byte) {
		if err := router.HandleMeshData(peerID, payload); err != nil {
			logger.Printf("mesh packet dropped peer=%s: %v", peerID, err)
		}
	})

	kernel := &kernelState{
		localNodeID: enrollment.NodeID,
		interfaceID: actualName,
		routes:      make(map[string]struct{}),
		natNoSNAT:   make(map[string]struct{}),
		siteNAT:     make(map[string]struct{}),
		forward:     make(map[string]struct{}),
	}
	if err := kernel.reconcile(config); err != nil {
		kernel.cleanup()
		logger.Fatal(err)
	}
	defer kernel.cleanup()

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	errCh := make(chan error, 2)
	go func() { errCh <- mesh.Run(ctx) }()
	go func() { errCh <- readTunLoop(ctx, device, router, logger) }()

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				next, loadErr := routed.LoadEnrollment(*enrollmentPath)
				if loadErr != nil {
					logger.Printf("routing config reload failed: %v", loadErr)
					continue
				}
				nextConfig := next.Config.Routing
				if !nextConfig.PolicyValid(time.Now()) {
					logger.Printf("routed Controller policy expired; data traffic denied until refresh")
					continue
				}
				if reconcileErr := mesh.Reconcile(nextConfig.Links); reconcileErr != nil {
					logger.Printf("mesh reconcile failed: %v", reconcileErr)
					continue
				}
				if updateErr := router.UpdateConfig(nextConfig); updateErr != nil {
					logger.Printf("router config rejected: %v", updateErr)
					continue
				}
				if kernelErr := kernel.reconcile(nextConfig); kernelErr != nil {
					logger.Printf("kernel route reconcile failed: %v", kernelErr)
					continue
				}
				config = nextConfig
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				links := mesh.Status()
				sort.Slice(links, func(i, j int) bool { return links[i].To < links[j].To })
				writeStatus(
					*statusPath,
					runtimeStatus{
						Version:       1,
						NodeID:        enrollment.NodeID,
						Interface:     actualName,
						UpdatedAt:     now.Unix(),
						Links:         links,
						SelectedPaths: router.SelectedPaths(),
					},
				)
			}
		}
	}()

	err = <-errCh
	stop()
	if err != nil {
		logger.Printf("routed runtime stopped: %v", err)
	}
}

// Existing interfaces have no ownership proof for this runtime. A normal
// process restart closes the nonpersistent TUN and removes its attached routes.
func requireFreshInterface(name string, interfaces []net.Interface) error {
	if name == "" {
		return fmt.Errorf("routed interface name is required")
	}
	for _, iface := range interfaces {
		if iface.Name == name {
			return fmt.Errorf("refusing existing interface %s: BPC ownership is not proven", name)
		}
	}
	return nil
}
