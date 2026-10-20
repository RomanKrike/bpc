#!/usr/bin/env python3
"""Portable traffic evidence collector; never claims combined mesh acceptance."""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import threading
import time
from pathlib import Path


def agent_view(raw: dict) -> dict:
    transport = raw.get("transport") or {}
    return {
        "device_id": raw.get("device_id", ""),
        "tunnel_address": raw.get("tunnel_address", ""),
        "routes": sorted(raw.get("routes") or []),
        "service": raw.get("service", ""),
        "transport": {
            key: transport[key]
            for key in ("endpoint", "mode", "updated_at") if key in transport
        },
    }


def read_agent(executable: str) -> dict:
    result = subprocess.run(
        [executable, "status-json"], capture_output=True, text=True, timeout=5, check=True,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("Agent status is not an object")
    return agent_view(value)


class Traffic:
    def __init__(self, target: str, port: int, duration: float, interval: float):
        self.target, self.port = target, port
        self.duration, self.interval = duration, interval
        self.started = time.monotonic()
        self.deadline = self.started + duration
        self.stop = threading.Event()
        self.results = {
            name: {"samples": [], "fatal_error": "", "connection_count": 0}
            for name in ("tcp_small", "tcp_stream", "udp", "icmp")
        }

    def sample(self, name: str, ok: bool) -> None:
        self.results[name]["samples"].append({
            "elapsed_ms": round((time.monotonic() - self.started) * 1000, 3), "ok": ok,
        })

    def active(self) -> bool:
        return not self.stop.is_set() and time.monotonic() < self.deadline

    def tcp(self, name: str, size: int) -> None:
        result = self.results[name]
        try:
            with socket.create_connection((self.target, self.port), timeout=3) as sock:
                result["connection_count"] = 1
                result["source_before"] = list(sock.getsockname())
                sock.settimeout(0.2)
                sequence = 0
                while self.active():
                    payload = sequence.to_bytes(8, "big") + os.urandom(size - 8)
                    # No reconnect or retransmission of application messages.
                    # TCP handles loss; retain partial reads across timeouts.
                    sock.sendall(payload)
                    response = bytearray()
                    while len(response) < size and self.active():
                        try:
                            part = sock.recv(size - len(response))
                        except TimeoutError:
                            self.sample(name, False)
                            continue
                        if not part:
                            raise ConnectionError("persistent TCP socket closed")
                        response.extend(part)
                    if len(response) != size:
                        self.sample(name, False)
                        result["pending_at_end"] = True
                        break
                    if response != payload:
                        raise ValueError("TCP echo data mismatch")
                    self.sample(name, True)
                    sequence += 1
                    self.stop.wait(self.interval)
                result["source_after"] = list(sock.getsockname())
        except (OSError, ValueError) as error:
            result["fatal_error"] = str(error)
            self.sample(name, False)

    def udp(self) -> None:
        result = self.results["udp"]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((self.target, self.port))
                sock.settimeout(self.interval)
                sequence = 0
                nonce = os.urandom(16)
                while self.active():
                    payload = nonce + sequence.to_bytes(8, "big")
                    sock.send(payload)
                    until = min(self.deadline, time.monotonic() + self.interval)
                    ok = False
                    while time.monotonic() < until:
                        try:
                            received = sock.recv(65535)
                        except TimeoutError:
                            break
                        if received == payload:
                            ok = True
                            break
                        if (len(received) != 24 or not received.startswith(nonce)
                                or int.from_bytes(received[16:], "big") >= sequence):
                            raise ValueError("UDP echo data mismatch")
                        result["late_replies"] = result.get("late_replies", 0) + 1
                    self.sample("udp", ok)
                    sequence += 1
                    self.stop.wait(max(0, until - time.monotonic()))
        except (OSError, ValueError) as error:
            result["fatal_error"] = str(error)
            self.sample("udp", False)

    def icmp(self) -> None:
        command = ["ping", "-n", "1", "-w", "1000", self.target] if (
            platform.system() == "Windows"
        ) else ["ping", "-n", "-c", "1", "-W", "1", self.target]
        try:
            while self.active():
                result = subprocess.run(
                    command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=2, check=False,
                )
                self.sample("icmp", result.returncode == 0)
                self.stop.wait(self.interval)
        except (OSError, subprocess.TimeoutExpired) as error:
            self.results["icmp"]["fatal_error"] = str(error)
            self.sample("icmp", False)

    def start(self, *, include_icmp: bool = True) -> list[threading.Thread]:
        actions = [(self.tcp, ("tcp_small", 64)), (self.tcp, ("tcp_stream", 65536)),
                   (self.udp, ())]
        if include_icmp:
            actions.append((self.icmp, ()))
        threads = [threading.Thread(target=action, args=args) for action, args in actions]
        for thread in threads:
            thread.start()
        return threads

    def report(self) -> dict:
        elapsed = (time.monotonic() - self.started) * 1000
        for result in self.results.values():
            successes = [sample["elapsed_ms"] for sample in result["samples"] if sample["ok"]]
            boundaries = [0, *successes, elapsed]
            result["successes"] = len(successes)
            result["failures"] = len(result["samples"]) - len(successes)
            result["max_success_gap_ms"] = round(max(
                b - a for a, b in zip(boundaries, boundaries[1:], strict=False)
            ), 3)
        return self.results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="IPv4 LAN target behind site-router")
    parser.add_argument("--port", type=int, default=19090)
    parser.add_argument("--duration", type=float, default=90)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--agent", help="Windows bpc-agent.exe for status-json")
    parser.add_argument("--scenario", choices=list("ABCDEFGH"), required=True)
    parser.add_argument("--scope", choices=["live-mesh", "harness-validation"], default="live-mesh")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        socket.inet_pton(socket.AF_INET, args.target)
    except OSError:
        parser.error("--target must be an IPv4 address")
    if not 1 <= args.duration <= 1800 or not 20 <= args.interval_ms <= 5000:
        parser.error("duration must be 1..1800 seconds; interval 20..5000 ms")
    if not 1024 <= args.port <= 65535:
        parser.error("port must be 1024..65535")
    if args.scope == "live-mesh" and not args.agent:
        parser.error("live-mesh requires --agent; local probes cannot establish mesh acceptance")
    traffic = Traffic(args.target, args.port, args.duration, args.interval_ms / 1000)
    threads = traffic.start()
    agent_samples = []
    interrupted = False
    try:
        while traffic.active():
            if args.agent:
                try:
                    value = read_agent(args.agent)
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    value = {"error": str(error)}
                agent_samples.append({"elapsed_ms": round(
                    (time.monotonic() - traffic.started) * 1000, 3,
                ), "status": value})
            traffic.stop.wait(0.5)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        traffic.stop.set()
        for thread in threads:
            thread.join()
    results = traffic.report()
    identities = [(item["status"].get("device_id"), item["status"].get("tunnel_address"),
                   item["status"].get("routes")) for item in agent_samples]
    identity_unchanged = bool(identities) and all(
        identity == identities[0] and identity[0] and identity[1] for identity in identities
    )
    complete = not interrupted and all(
        not result["fatal_error"] and result["successes"] > 0 for result in results.values()
    ) and (args.scope != "live-mesh" or identity_unchanged)
    report = {
        "version": 1, "scope": args.scope, "scenario": args.scenario,
        "started_at_unix": time.time() - (time.monotonic() - traffic.started),
        "duration_ms": round((time.monotonic() - traffic.started) * 1000, 3),
        "target": args.target, "port": args.port,
        "measurement_complete": complete, "interrupted": interrupted,
        "acceptance_status": "unreviewed", "live_mesh_passed": False,
        "identity_unchanged": identity_unchanged,
        "traffic": results, "agent_samples": agent_samples,
        "scope_limit": (
            "Traffic evidence only; verify faults, topology, kernel, policy and Raft separately."
        ),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.report.with_suffix(args.report.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        os.chmod(temporary, 0o600)
        json.dump(report, handle, indent=2)
        handle.write("\n")
    temporary.replace(args.report)
    print(json.dumps({"measurement_complete": complete, "report": str(args.report),
                      "acceptance_status": "unreviewed"}))
    return 0 if complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
