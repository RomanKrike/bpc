"""Bounded, source-scoped mesh MARK probes with independent systemd rollback.

Run this saved file as root; keep it in place until the timer is gone.
Never accepts arbitrary firewall commands or changes INPUT/OUTPUT/policy.
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import re
import subprocess
import sys
import uuid
from pathlib import Path


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, timeout=10, **kwargs)


def rule(interface, source, destination, token, icmp):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", interface):
        raise ValueError("invalid ingress interface")
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        raise ValueError("invalid probe token")
    source = str(ipaddress.IPv4Address(source)) + "/32"
    destination = str(ipaddress.IPv4Address(destination)) + "/32"
    return ["-i", interface, "-s", source, "-d", destination,
            *(["-p", "icmp"] if icmp else []),
            "-m", "comment", "--comment", "bpc-probe-" + token,
            "-j", "MARK", "--set-xmark", "0x425043/0xffffffff"]


def cleanup(spec):
    # Exact unique spec only. Do not restore a stale full firewall snapshot.
    result = subprocess.run(["iptables", "-w", "5", "-t", "mangle", "-C",
                             "PREROUTING", *spec], check=False, timeout=10,
                            capture_output=True)
    if result.returncode == 0:
        run(["iptables", "-w", "5", "-t", "mangle", "-D", "PREROUTING", *spec])
    elif result.returncode != 1:
        raise RuntimeError("cannot verify probe cleanup; retain rollback timer")


def require_host_namespace():
    if Path("/proc/self/ns/net").stat().st_ino != Path("/proc/1/ns/net").stat().st_ino:
        raise RuntimeError("probe requires the host network namespace for systemd rollback")


def probe(args):
    import fcntl

    spec = rule(args.interface, args.source, args.destination, args.token, args.icmp)
    require_host_namespace()
    unit = ("bpc-mesh-icmp-rollback-" if args.icmp else "bpc-mark-rollback-") + args.token
    lock_path = Path("/run") / (unit + ".lock")
    with lock_path.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.cleanup:
            cleanup(spec)
            return 0
        cleanup_argv = [sys.executable, str(Path(__file__).resolve()),
                        "--cleanup", "--token", args.token, "--interface", args.interface,
                        "--source", args.source, "--destination", args.destination]
        if args.icmp:
            cleanup_argv.append("--icmp")
        # Persistent timer is armed AND checked before the first mutation.
        # Retry cleanup errors independently of the calling SSH session.
        deadline = (datetime.datetime.now(datetime.UTC)
                    + datetime.timedelta(seconds=args.seconds)).strftime("%Y-%m-%d %H:%M:%S UTC")
        run(["systemd-run", "--unit", unit, "--on-calendar", deadline,
             "--timer-property=AccuracySec=1s", "--timer-property=Persistent=true",
             "--property=Restart=on-failure",
             "--property=RestartSec=5s", *cleanup_argv])
        run(["systemctl", "is-active", "--quiet", unit + ".timer"])
        try:
            run(["iptables", "-w", "5", "-t", "mangle", "-I", "PREROUTING", "1", *spec])
        except BaseException:
            cleanup(spec)
            raise
    try:
        # A failed or timed-out command still takes the cleanup path.
        return subprocess.run(args.command, check=False, timeout=args.seconds - 5).returncode
    finally:
        with lock_path.open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            cleanup(spec)
        # Leave the watchdog armed if cleanup raises.
        run(["systemctl", "stop", unit + ".timer"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--source", required=True, help="one test Device IPv4 address")
    parser.add_argument("--destination", required=True, help="one test LAN IPv4 address")
    parser.add_argument("--icmp", action="store_true")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--token", default=uuid.uuid4().hex)
    parser.add_argument("--cleanup", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not 10 <= args.seconds <= 300:
        parser.error("seconds must be between 10 and 300")
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.cleanup and not args.command:
        parser.error("a bounded test command is required after --")
    return probe(args)


if __name__ == "__main__":
    raise SystemExit(main())
