//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun"
)

// Exercise the real offload-enabled Linux TUN, including kernel ICMP reply.
// A separate process ensures all Go threads belong to the isolated namespace.
func TestTunWriterRealNamespace(t *testing.T) {
	if os.Getenv("BPC_TEST_NETNS") != "1" {
		t.Skip("explicit privileged network namespace CI test")
	}
	if os.Getenv("BPC_TUN_TEST_CHILD") != "1" {
		ns := fmt.Sprintf("bpc-tun-test-%d", os.Getpid())
		if err := runCommand("ip", "netns", "add", ns); err != nil {
			t.Fatal(err)
		}
		defer bestEffort("ip", "netns", "del", ns)
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("ip", "netns", "exec", ns, exe, "-test.run", "^TestTunWriterRealNamespace$", "-test.v")
		cmd.Env = append(os.Environ(), "BPC_TUN_TEST_CHILD=1")
		out, err := cmd.CombinedOutput()
		t.Log(string(out))
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	dev, err := tun.CreateTUN("bpctest0", 1360)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if dev.BatchSize() <= 1 {
		t.Fatal("test requires offload-enabled Linux TUN")
	}
	for _, args := range [][]string{
		{"ip", "addr", "add", "10.253.0.1/24", "dev", "bpctest0"},
		{"ip", "link", "set", "bpctest0", "up"},
	} {
		if err := runCommand(args...); err != nil {
			t.Fatal(err)
		}
	}
	body, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 42, Seq: 1, Data: []byte("BPC TUN injection")}}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 20+len(body))
	packet[0], packet[8], packet[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], net.ParseIP("10.253.0.2").To4())
	copy(packet[16:20], net.ParseIP("10.253.0.1").To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
	copy(packet[20:], body)
	if _, err := dev.Write([][]byte{append([]byte(nil), packet...)}, 0); err == nil {
		t.Fatal("zero-offset regression control unexpectedly succeeded")
	}
	if err := (&tunWriter{device: dev}).WritePacket(packet); err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(5*time.Second, func() { dev.Close() })
	defer timer.Stop()
	bufs, sizes := make([][]byte, dev.BatchSize()), make([]int, dev.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	for {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			t.Fatalf("kernel reply not received: %v", err)
		}
		for i := 0; i < n; i++ {
			p := bufs[i][:sizes[i]]
			if len(p) < 20 || p[0]>>4 != 4 || p[9] != 1 {
				continue
			}
			msg, err := icmp.ParseMessage(1, p[int(p[0]&15)*4:])
			if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			echo, ok := msg.Body.(*icmp.Echo)
			if ok && echo.ID == 42 && echo.Seq == 1 && string(echo.Data) == "BPC TUN injection" {
				return
			}
		}
	}
}
