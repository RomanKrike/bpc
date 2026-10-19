"""Opt-in P2P authority over existing canonical identity and Access records.

No session addresses or transport state are replicated. Conditional puts of
unchanged security records fence authorization against concurrent revocation.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import time
from pathlib import Path
from typing import Any

import bpc_control_state
from bpc_gateway_snapshot import GatewaySnapshotError, _cluster_signing_identity
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CAPABILITY = "p2p-session-v1"
SERVICE = "sunshine-v1"
GRANT_DOMAIN = b"BPC-P2P-GRANT-v1\x00"
POLICY_DOMAIN = b"BPC-P2P-POLICY-v1\x00"
MAX_SESSIONS = 16


class P2PError(RuntimeError):
    def __init__(self, message: str, status: int = 403):
        super().__init__(message)
        self.status = status


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: Any, size: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise P2PError("invalid P2P encoding", 400)
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise P2PError("invalid P2P encoding", 400) from exc
    if _b64(raw) != value or (size is not None and len(raw) != size):
        raise P2PError("invalid P2P encoding", 400)
    return raw


def _id(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise P2PError("invalid Device identifier", 400)
    return value


class _Snapshot:
    def __init__(self, root: Path, token: str):
        self.root = root
        self.values: dict[Path, bytes | None] = {}
        self.started = int(time.time())
        if not bpc_control_state.cluster_enabled(root):
            raise P2PError("P2P requires distributed Controller state", 412)
        barrier = bpc_control_state.strong_read(root)
        self.revision = int(barrier["revision"])
        if self.revision <= 0:
            raise P2PError("P2P authority is not ready", 503)
        config = self.read(root / "config.json")
        if config.get("p2p_enabled") is not True:
            raise P2PError("P2P is not enabled", 404)
        cluster = self.read(root.parent / "cluster" / "cluster.json")
        self.cluster = str(cluster.get("cluster_id", ""))
        if not self.cluster or len(self.cluster) > 128:
            raise P2PError("P2P cluster is unavailable", 503)
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            raise P2PError("Device credential required", 401)
        self.credential = self.read(
            root / "identity" / "access" / f"{hashlib.sha256(token.encode()).hexdigest()}.json"
        )
        self.expires = int(self.credential.get("expires_at", 0))
        if self.credential.get("scope") != "device" or self.expires <= self.started:
            raise P2PError("active Device credential required", 401)
        self.owner = _id(self.credential.get("user_id"))
        self.device = _id(self.credential.get("device_id"))
        user = self.read(root / "identity" / "users" / f"{self.owner}.json")
        if user.get("id") != self.owner or user.get("enabled") is not True:
            raise P2PError("P2P identity is unavailable")
        self.participant(self.device)
        try:
            self.signer, self.public, self.key_id = _cluster_signing_identity(root.parent)
        except (GatewaySnapshotError, ValueError) as exc:
            raise P2PError("P2P signing trust is unavailable", 503) from exc

    def read(self, path: Path, *, optional: bool = False) -> dict[str, Any]:
        if path not in self.values:
            try:
                self.values[path] = path.read_bytes()
            except FileNotFoundError as exc:
                if not optional:
                    raise P2PError("P2P identity or policy is unavailable") from exc
                self.values[path] = None
        raw = self.values[path]
        if raw is None:
            return {}
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise P2PError("invalid P2P authority state", 503)
        return value

    def access(self, kind: str, subject: str) -> dict[str, Any]:
        path = self.root / "access" / f"{kind}-{subject}.json"
        value = self.read(path, optional=True)
        if value and (
            value.get("version") != 1
            or value.get("subject_type") != kind
            or value.get("subject_id") != subject
        ):
            raise P2PError("invalid P2P Access subject", 503)
        return value

    def participant(self, device_id: str) -> dict[str, str]:
        value = self.read(self.root / "devices" / f"{_id(device_id)}.json")
        if (
            value.get("id", value.get("device_id")) != device_id
            or value.get("user_id") != self.owner
            or value.get("enabled", True) is not True
            or value.get("revoked", False) is not False
            or value.get("revoked_at") not in (None, "", 0)
        ):
            raise P2PError("P2P peer is unavailable")
        identity = str(value.get("public_key", ""))
        wireguard = str(value.get("wireguard_public_key", ""))
        if not any(_decode(identity, 32)) or not any(_decode(wireguard, 32)):
            raise P2PError("P2P Device keys are unavailable")
        address = ipaddress.ip_interface(str(value.get("wireguard_address", "")))
        if address.version != 4 or not any(
            address.ip in ipaddress.ip_network(network)
            for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        ):
            raise P2PError("P2P Device address is unavailable")
        return {
            "device_id": device_id,
            "user_id": self.owner,
            "identity_key": identity,
            "wireguard_key": wireguard,
            "address": str(address.ip),
        }

    def pair(self, initiator: str, host: str) -> list[dict[str, str]]:
        peers = [self.participant(initiator), self.participant(host)]
        if any(
            peers[0][key] == peers[1][key]
            for key in ("device_id", "identity_key", "wireguard_key", "address")
        ):
            raise P2PError("P2P requires distinct Devices")
        policies = [self.access("device", device_id) for device_id in (initiator, host)]
        if any(policy.get("p2p_enabled") is not True for policy in policies):
            raise P2PError("both Devices must consent to P2P")
        # Same CIDR union/deny precedence as Access, evaluated from the exact
        # bytes guarded by this transaction. No legacy managed_routes grant.
        target = ipaddress.ip_address(peers[1]["address"])
        allow = False
        for policy in (self.access("user", self.owner), policies[0]):
            for effect in ("deny", "allow"):
                rules = policy.get(effect, [])
                if not isinstance(rules, list):
                    raise P2PError("invalid P2P Access rules", 503)
                for rule in rules:
                    network = ipaddress.ip_network(rule, strict=True)
                    if network.version != 4 or network.prefixlen == 0:
                        raise P2PError("invalid P2P Access CIDR", 503)
                    if target in network:
                        if effect == "deny":
                            raise P2PError("P2P peer is unavailable")
                        allow = True
        if not allow:
            raise P2PError("P2P peer is unavailable")
        return peers

    def commit(self, kind: str, overrides: dict[Path, bytes] | None = None) -> int:
        overrides = overrides or {}
        operations = []
        for path, raw in self.values.items():
            # An absent record is guarded by delete+if_absent: an existing
            # compatible operation, not a new FSM opcode or replicated prefix.
            operation: dict[str, Any] = {
                "op": "put" if raw is not None or path in overrides else "delete",
                "path": path,
            }
            if raw is None:
                operation["if_absent"] = True
            else:
                operation["expected_sha256"] = hashlib.sha256(raw).hexdigest()
            if operation["op"] == "put":
                operation["data"] = overrides.get(path, raw)
            operations.append(operation)
        result = bpc_control_state.mutation(self.root, kind, operations)
        revision = int(result.get("revision", 0))
        if result.get("ok") is not True or revision <= self.revision:
            raise P2PError("P2P authorization did not commit", 503)
        if int(time.time()) >= min(self.expires, self.started + 30):
            raise P2PError("P2P authorization expired while committing", 503)
        return revision

    def sign(self, domain: bytes, payload: dict[str, Any]) -> str:
        raw = _json(payload)
        return _b64(
            _json({"payload": _b64(raw), "signature": _b64(self.signer.sign(domain + raw))})
        )


def _request(body: dict[str, Any], fields: set[str]) -> None:
    if set(body) != fields | {"capabilities"} or body.get("capabilities") != [CAPABILITY]:
        raise P2PError("unsupported P2P request or capabilities", 400)


def info(root: Path, token: str) -> dict[str, Any]:
    snapshot = _Snapshot(root, token)
    policy = snapshot.access("device", snapshot.device)
    path = root / "access" / f"device-{snapshot.device}.json"
    raw = snapshot.values[path]
    snapshot.commit("ReadP2PConsent")
    return {
        "capabilities": [CAPABILITY],
        "cluster_id": snapshot.cluster,
        "device_id": snapshot.device,
        "issuer_public_key": snapshot.public,
        "issuer_certificate_sha256": snapshot.key_id,
        "enabled": policy.get("p2p_enabled") is True,
        "access_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else "",
    }


def consent_message(token: str, device: str, enabled: bool, expected: str) -> bytes:
    return (
        f"BPC-P2P-CONSENT-v1\n{hashlib.sha256(token.encode()).hexdigest()}\n"
        f"{device}\n{str(enabled).lower()}\n{expected}"
    ).encode()


def consent(root: Path, token: str, body: dict[str, Any]) -> dict[str, Any]:
    _request(body, {"enabled", "expected_sha256", "signature"})
    if type(body["enabled"]) is not bool or not isinstance(body["expected_sha256"], str):
        raise P2PError("invalid P2P consent", 400)
    snapshot = _Snapshot(root, token)
    policy = snapshot.access("device", snapshot.device)
    path = root / "access" / f"device-{snapshot.device}.json"
    raw = snapshot.values[path]
    digest = hashlib.sha256(raw).hexdigest() if raw is not None else ""
    if body["expected_sha256"] != digest:
        raise P2PError("P2P consent changed; refresh Device state", 409)
    public = _decode(snapshot.participant(snapshot.device)["identity_key"], 32)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            _decode(body["signature"], 64),
            consent_message(token, snapshot.device, body["enabled"], digest),
        )
    except InvalidSignature as exc:
        raise P2PError("invalid Device consent proof", 401) from exc
    if not policy:
        policy = {
            "version": 1,
            "subject_type": "device",
            "subject_id": snapshot.device,
            "allow": [],
            "deny": [],
        }
    policy.update(p2p_enabled=body["enabled"], p2p_change=secrets.token_hex(16))
    revision = snapshot.commit("SetP2PConsent", {path: _json(policy)})
    return {"ok": True, "revision": revision, "enabled": body["enabled"]}


def issue(root: Path, token: str, body: dict[str, Any]) -> dict[str, Any]:
    _request(body, {"host_device_id"})
    snapshot = _Snapshot(root, token)
    peers = snapshot.pair(snapshot.device, _id(body["host_device_id"]))
    revision = snapshot.commit("AuthorizeP2PSession")
    grant = {
        "version": 1,
        "cluster_id": snapshot.cluster,
        "session_id": secrets.token_hex(16),
        "revision": revision,
        "issued_at": snapshot.started,
        "expires_at": min(snapshot.started + 60, snapshot.expires),
        "service": SERVICE,
        "participants": peers,
    }
    return {"ticket": snapshot.sign(GRANT_DOMAIN, grant)}


def _grant(snapshot: _Snapshot, ticket: str) -> dict[str, Any]:
    envelope = _decode(ticket)
    if len(envelope) > 8192:
        raise P2PError("P2P ticket too large", 400)
    document = json.loads(envelope)
    if set(document) != {"payload", "signature"}:
        raise P2PError("invalid P2P ticket", 400)
    payload = _decode(document["payload"])
    try:
        Ed25519PublicKey.from_public_bytes(_decode(snapshot.public, 32)).verify(
            _decode(document["signature"], 64), GRANT_DOMAIN + payload
        )
    except InvalidSignature as exc:
        raise P2PError("invalid P2P ticket", 400) from exc
    grant = json.loads(payload)
    if set(grant) != {
        "version",
        "cluster_id",
        "session_id",
        "revision",
        "issued_at",
        "expires_at",
        "service",
        "participants",
    }:
        raise P2PError("invalid P2P grant fields", 400)
    if (
        grant["version"] != 1
        or grant["cluster_id"] != snapshot.cluster
        or grant["service"] != SERVICE
        or type(grant["revision"]) is not int
        or not 0 < grant["revision"] <= snapshot.revision
        or type(grant["issued_at"]) is not int
        or type(grant["expires_at"]) is not int
        or not grant["issued_at"] <= snapshot.started < grant["expires_at"]
        or grant["expires_at"] - grant["issued_at"] > 60
    ):
        raise P2PError("invalid or expired P2P grant", 400)
    _id(grant["session_id"])
    peers = grant["participants"]
    if not isinstance(peers, list) or len(peers) != 2:
        raise P2PError("invalid P2P participants", 400)
    if snapshot.device not in [p.get("device_id") for p in peers if isinstance(p, dict)]:
        raise P2PError("P2P grant belongs to another Device")
    return grant


def sync(root: Path, token: str, body: dict[str, Any]) -> dict[str, Any]:
    _request(body, {"tickets"})
    tickets = body["tickets"]
    if not isinstance(tickets, list) or len(tickets) > MAX_SESSIONS:
        raise P2PError("too many P2P sessions", 400)
    snapshot = _Snapshot(root, token)
    allowed = []
    seen = set()
    for ticket in tickets:
        grant = _grant(snapshot, ticket)
        session_id = grant["session_id"]
        if session_id in seen:
            raise P2PError("duplicate P2P session", 400)
        seen.add(session_id)
        try:
            peers = snapshot.pair(*(p["device_id"] for p in grant["participants"]))
            if peers == grant["participants"]:
                allowed.append(
                    {
                        "session_id": session_id,
                        "ticket_sha256": hashlib.sha256(_decode(ticket)).hexdigest(),
                    }
                )
        except P2PError as exc:
            if exc.status != 403:
                raise
            # A signed denial is delivered as omission from the complete list.
    revision = snapshot.commit("ReconcileP2PPolicy")
    policy = {
        "version": 1,
        "cluster_id": snapshot.cluster,
        "device_id": snapshot.device,
        "revision": revision,
        "issued_at": snapshot.started,
        "expires_at": min(snapshot.started + 30, snapshot.expires),
        "allowed": allowed,
    }
    return {"checkpoint": snapshot.sign(POLICY_DOMAIN, policy)}
