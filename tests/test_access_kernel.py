"""Real kernel compatibility forwarding and bidirectional established Access revocation."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import bpc_access as access  # noqa: E402


def test_access_real_namespace(tmp_path):
    if os.environ.get("BPC_INGRESS_CHILD"):
        exercise_kernel(tmp_path)
        return
    if os.environ.get("BPC_TEST_NETNS") != "1":
        pytest.skip("requires privileged isolated Linux namespaces")
    tag = uuid.uuid4().hex[:8]
    names = [f"bpc-{tag}-{role}" for role in ("gw", "client", "site")]
    try:
        for name in names:
            subprocess.run(["ip", "netns", "add", name], check=True)
        env = dict(os.environ, BPC_INGRESS_CHILD="1", BPC_INGRESS_CLIENT=names[1],
                   BPC_INGRESS_SITE=names[2], BPC_INGRESS_GATEWAY=names[0])
        subprocess.run(["ip", "netns", "exec", names[0], sys.executable,
                        "-m", "pytest", str(Path(__file__).resolve()), "-q", "-s"],
                       env=env, check=True, timeout=45)
    finally:
        for name in reversed(names):
            subprocess.run(["ip", "netns", "del", name], check=False)


def exercise_kernel(tmp_path):
    client, site = os.environ["BPC_INGRESS_CLIENT"], os.environ["BPC_INGRESS_SITE"]

    def run(*args, ns=None, check=True):
        cmd = (["ip", "netns", "exec", ns] if ns else []) + list(args)
        return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=8)

    for interface, peer, ns, addr, remote in (
        ("bpcag0", "client0", client, "10.253.0.1/24", "10.253.0.2/24"),
        ("bpcrt0", "site0", site, "192.168.88.1/24", "192.168.88.12/24"),
    ):
        run("ip", "link", "add", interface, "type", "veth", "peer", "name", peer)
        run("ip", "link", "set", peer, "netns", ns)
        run("ip", "addr", "add", addr, "dev", interface, "noprefixroute")
        run("ip", "link", "set", interface, "up")
        run("ip", "addr", "add", remote, "dev", peer, ns=ns)
        run("ip", "link", "set", peer, "up", ns=ns)
        run("ip", "link", "set", "lo", "up", ns=ns)
    run("ip", "route", "add", "10.253.0.0/24", "dev", "bpcag0")
    run("ip", "route", "add", "192.168.88.0/24", "via", "10.253.0.1", ns=client)
    run("ip", "route", "add", "10.253.0.0/24", "via", "192.168.88.1", ns=site)
    run("ip", "route", "add", "192.168.88.0/24", "dev", "bpcrt0")
    run("sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0",
        "net.ipv4.conf.default.rp_filter=0", "net.ipv4.conf.bpcrt0.rp_filter=0")
    root = tmp_path / "control"
    keys = tmp_path / "agent" / "wgshim-keys"
    access.atomic_json(root / "config.json", {"wireguard_interface": "bpcag0",
                                              "wgshim_key_dir": str(keys)})
    access.atomic_json(keys.parent / "ownership.json", {
        "owner": "bpc", "kind": "wireguard-interface", "name": "bpcag0",
    })
    access.atomic_json(root / "devices" / "d1.json", {
        "id": "d1", "wireguard_address": "10.253.0.2/32", "enabled": True,
    })
    access.atomic_json(tmp_path / "enrollment.json", {"config": {"routing": {
        "version": 1, "local_public": True,
        "routes": [{"cidr": "192.168.88.0/24", "owner_node_id": "site"}],
    }}})
    access.set_access(root, "device", "d1", "allow", ["192.168.88.0/24"])
    access.sync_access_firewall(root)
    access.sync_access_firewall(root)  # Restart/reconcile must not add duplicate jumps.
    assert run("iptables", "-S", "FORWARD").stdout.count("-j BPC-ACCESS") == 2
    assert run("ping", "-n", "-c", "1", "-W", "1", "192.168.88.12", ns=client).returncode == 0

    check_device_reply_compatibility(root, run, client, site)

    # A real established TCP session: revoke Access between two exchanges.
    server_code = '''import socket
s=socket.socket(); s.bind(("192.168.88.12", 2222)); s.listen()
print("ready", flush=True)
c,a=s.accept(); print(a[0], flush=True)
d=c.recv(32); c.sendall(d)
input()
c.sendall(b"unsolicited-after-revoke")
while True:
 d=c.recv(32)
 if not d: break
 c.sendall(d)
'''
    client_code = '''import socket,sys
s=socket.create_connection(("192.168.88.12",2222),3)
s.sendall(b"before"); assert s.recv(32)==b"before"
print("connected",flush=True); sys.stdin.readline()
s.settimeout(2)
try:
 d=s.recv(32)
 print("leaked" if d else "blocked",flush=True)
except TimeoutError: print("blocked",flush=True)
s.sendall(b"after")
try:
 d=s.recv(32)
 print("leaked" if d else "blocked",flush=True)
except TimeoutError: print("blocked",flush=True)
'''
    server = subprocess.Popen(
        ["ip", "netns", "exec", site, sys.executable, "-u", "-c", server_code],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    connection = None
    try:
        assert server.stdout.readline().strip() == "ready"
        connection = subprocess.Popen(
            ["ip", "netns", "exec", client, sys.executable, "-u", "-c", client_code],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        assert connection.stdout.readline().strip() == "connected"
        assert server.stdout.readline().strip() == "10.253.0.2"  # No source NAT.
        access.set_access(root, "device", "d1", "deny", ["192.168.88.0/24"])
        access.sync_access_firewall(root)
        server.stdin.write("go\n")
        server.stdin.flush()
        connection.stdin.write("go\n")
        connection.stdin.flush()
        assert connection.stdout.readline().strip() == "blocked"
        assert connection.stdout.readline().strip() == "blocked"
        assert connection.wait(timeout=5) == 0
    finally:
        if connection and connection.poll() is None:
            connection.kill()
            connection.wait()
        server.terminate()
        server.wait(timeout=5)

    print(json.dumps({"tcp_source": "10.253.0.2", "revocation": "blocked both TCP directions"}))


def check_device_reply_compatibility(root, run, client, site):
    # Represent another registered Device on the far-side veth. Only d1 is
    # granted initiation; d2 must still be allowed to return conntrack replies.
    run("ip", "addr", "add", "10.253.0.3/32", "dev", "site0", ns=site)
    run("ip", "route", "add", "10.253.0.3/32", "dev", "bpcrt0")
    run("ip", "route", "add", "10.253.0.3/32", "via", "10.253.0.1", ns=client)
    access.atomic_json(root / "devices" / "d2.json", {
        "id": "d2", "wireguard_address": "10.253.0.3/32", "enabled": True,
    })
    access.set_access(root, "device", "d1", "allow", ["10.253.0.3/32"])
    access.sync_access_firewall(root)
    assert run("ping", "-n", "-c", "1", "-W", "1", "10.253.0.3",
               ns=client, check=False).returncode == 0, "authorized peer replies were blocked"
    assert run("ping", "-n", "-c", "1", "-W", "1", "-I", "10.253.0.3", "10.253.0.2",
               ns=site, check=False).returncode != 0, "ungranted peer initiation was allowed"
    access.atomic_json(root / "devices" / "d2.json", {
        "id": "d2", "wireguard_address": "10.253.0.3/32", "enabled": False, "revoked": True,
    })
    access.sync_access_firewall(root)
    assert run("ping", "-n", "-c", "1", "-W", "1", "10.253.0.3",
               ns=client, check=False).returncode != 0, "revoked responder remained reachable"
