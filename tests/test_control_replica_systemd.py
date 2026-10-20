"""Replica sandbox regression: real systemd and WG, only in a disposable netns."""
from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def replica_families() -> list[str]:
    installer = (ROOT / "deploy/bpc-enable-control-replica.sh").read_text()
    service = installer.split("[Service]\n", 1)[1].split("[Install]", 1)[0]
    directives = [line.partition("=")[2].split() for line in service.splitlines()
                  if line.startswith("RestrictAddressFamilies=")]
    assert len(directives) == 1
    return directives[0]


def test_replica_allows_owned_gateway_netlink():
    assert set(replica_families()) == {"AF_INET", "AF_INET6", "AF_NETLINK"}


@pytest.mark.skipif(os.environ.get("BPC_TEST_SYSTEMD") != "1",
                    reason="requires privileged Linux systemd and isolated network namespaces")
@pytest.mark.parametrize("legacy", [True, False])
def test_replica_wireguard_under_real_address_family_filter(legacy):
    tag = uuid.uuid4().hex[:12]
    namespace = "bpc-api-wg-" + tag
    unit = "bpc-api-wg-test-" + tag
    families = replica_families()
    if legacy:
        families = [family for family in families if family != "AF_NETLINK"]

    def run(*args, check=True):
        return subprocess.run(args, check=check, capture_output=True, text=True, timeout=20)

    created = False
    try:
        run("ip", "netns", "add", namespace)
        created = True
        run("ip", "-n", namespace, "link", "add", "bpcwgtest0", "type", "wireguard")
        # All kernel queries run inside this empty namespace, never on a live WG interface.
        probe = (
            "import socket,subprocess; "
            "s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,16); s.close(); "
            "subprocess.run(['wg','show','bpcwgtest0','peers'],check=True)"
        )
        result = run(
            "systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit", unit,
            "--property=Type=exec", "--property=RuntimeMaxSec=15",
            "--property=NetworkNamespacePath=/run/netns/" + namespace,
            "--property=RestrictAddressFamilies=" + " ".join(families),
            "--property=NoNewPrivileges=true", "--property=PrivateTmp=true",
            "--property=PrivateDevices=true", "--property=ProtectSystem=strict",
            "--property=ProtectHome=true", "/usr/bin/python3", "-c", probe,
            check=False,
        )
        if legacy:
            assert result.returncode != 0, "old replica sandbox unexpectedly allowed netlink"
            assert "Address family not supported" in result.stderr, result.stderr
        else:
            assert result.returncode == 0, result.stdout + result.stderr
    finally:
        run("systemctl", "stop", unit + ".service", check=False)
        if created:
            run("ip", "netns", "del", namespace)
