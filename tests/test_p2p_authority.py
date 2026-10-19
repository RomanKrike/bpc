from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from p2p_support import seed_p2p, write_json

sys.path.insert(0, str(Path(__file__).parents[1] / "deploy"))
import bpc_control_state as state  # noqa: E402
import bpc_p2p as p2p  # noqa: E402


class FakeConsensus:
    def __init__(self):
        self.revision = 5
        self.before_commit = None
        self.lock = threading.Lock()

    def barrier(self, root):
        return {"revision": self.revision}

    def commit(self, root, kind, operations):
        with self.lock:
            if self.before_commit:
                self.before_commit()
                self.before_commit = None
            for op in operations:
                path = op["path"]
                raw = path.read_bytes() if path.exists() else None
                if (op.get("if_absent") and raw is not None) or (
                    "expected_sha256" in op
                    and (raw is None or hashlib.sha256(raw).hexdigest() != op["expected_sha256"])
                ):
                    raise state.ControlStateError("precondition conflict", 409)
            for op in operations:
                path = op["path"]
                if op["op"] == "put":
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(op["data"])
                else:
                    path.unlink(missing_ok=True)
            self.revision += 1
            return {"ok": True, "revision": self.revision}


@pytest.fixture
def authority(tmp_path, monkeypatch):
    context = seed_p2p(tmp_path)
    consensus = FakeConsensus()
    monkeypatch.setattr(state, "strong_read", consensus.barrier)
    monkeypatch.setattr(state, "mutation", consensus.commit)
    context["consensus"] = consensus
    return context


def request(**fields):
    return {"capabilities": [p2p.CAPABILITY], **fields}


def decode_signed(encoded):
    envelope = json.loads(base64.b64decode(encoded))
    return json.loads(base64.b64decode(envelope["payload"]))


def issued(context):
    return p2p.issue(
        context["control"],
        context["tokens"][0],
        request(
            host_device_id=context["devices"][1]["id"],
        ),
    )["ticket"]


def change_json(path, **values):
    document = json.loads(path.read_text())
    document.update(values)
    write_json(path, document)


def test_issue_sync_and_access_revoke(authority):
    c = authority
    ticket = issued(c)
    grant = decode_signed(ticket)
    assert grant["participants"][0]["user_id"] == c["owner"]
    assert grant["participants"][1]["device_id"] == c["devices"][1]["id"]
    assert grant["expires_at"] - grant["issued_at"] == 60
    assert grant["revision"] == c["consensus"].revision
    assert "password_hash" not in json.dumps(grant)
    policy = p2p.sync(c["control"], c["tokens"][1], request(tickets=[ticket]))
    allowed = decode_signed(policy["checkpoint"])
    assert allowed["allowed"] == [
        {
            "session_id": grant["session_id"],
            "ticket_sha256": hashlib.sha256(base64.b64decode(ticket)).hexdigest(),
        }
    ]
    access = c["control"] / "access" / f"device-{c['devices'][0]['id']}.json"
    change_json(access, deny=["10.253.0.0/24"])
    denied = p2p.sync(c["control"], c["tokens"][1], request(tickets=[ticket]))
    checkpoint = decode_signed(denied["checkpoint"])
    assert checkpoint["allowed"] == []
    assert checkpoint["revision"] > allowed["revision"]


@pytest.mark.parametrize("kind", ["foreign", "revoked", "disabled", "consent", "deny", "no-allow"])
def test_issue_rejects_unauthorized_peer(authority, kind):
    c = authority
    host = c["devices"][1]["id"]
    path = c["control"] / "devices" / f"{host}.json"
    if kind == "foreign":
        change_json(path, user_id="d" * 32)
    elif kind == "revoked":
        change_json(path, revoked=True)
    elif kind == "disabled":
        change_json(path, enabled=False)
    elif kind == "consent":
        change_json(c["control"] / "access" / f"device-{host}.json", p2p_enabled=False)
    else:
        path = c["control"] / "access" / f"device-{c['devices'][0]['id']}.json"
        change_json(path, **({"deny": ["10.253.0.3/32"]} if kind == "deny" else {"allow": []}))
    with pytest.raises(p2p.P2PError):
        issued(c)


@pytest.mark.parametrize("record", ["device", "user", "access", "credential", "config"])
def test_authorization_is_fenced_against_concurrent_mutation(authority, record):
    c = authority
    paths = {
        "device": c["control"] / "devices" / f"{c['devices'][1]['id']}.json",
        "user": c["control"] / "identity" / "users" / f"{c['owner']}.json",
        "access": c["control"] / "access" / f"device-{c['devices'][0]['id']}.json",
        "credential": c["control"]
        / "identity"
        / "access"
        / f"{hashlib.sha256(c['tokens'][0].encode()).hexdigest()}.json",
        "config": c["control"] / "config.json",
    }
    c["consensus"].before_commit = lambda: change_json(paths[record], concurrent_change=True)
    with pytest.raises(state.ControlStateError, match="conflict"):
        issued(c)


def test_absent_access_is_guarded_against_concurrent_new_deny(authority):
    c = authority
    path = c["control"] / "access" / f"user-{c['owner']}.json"
    c["consensus"].before_commit = lambda: write_json(
        path,
        {
            "version": 1,
            "subject_type": "user",
            "subject_id": c["owner"],
            "allow": [],
            "deny": ["10.253.0.0/24"],
        },
    )
    with pytest.raises(state.ControlStateError, match="conflict"):
        issued(c)
    assert json.loads(path.read_text())["deny"] == ["10.253.0.0/24"]


def test_consent_requires_device_proof_and_cas(authority):
    c = authority
    token = c["tokens"][1]
    info = p2p.info(c["control"], token)
    message = p2p.consent_message(token, info["device_id"], False, info["access_sha256"])
    body = request(
        enabled=False,
        expected_sha256=info["access_sha256"],
        signature=base64.b64encode(c["keys"][0].sign(message)).decode(),
    )
    with pytest.raises(p2p.P2PError, match="proof"):
        p2p.consent(c["control"], token, body)
    body["signature"] = base64.b64encode(c["keys"][1].sign(message)).decode()
    result = p2p.consent(c["control"], token, body)
    assert result["enabled"] is False
    with pytest.raises(p2p.P2PError) as replay:
        p2p.consent(c["control"], token, body)
    assert replay.value.status == 409
    with pytest.raises(p2p.P2PError):
        issued(c)


def test_default_disabled_and_no_compatibility_fallback(authority):
    c = authority
    change_json(c["control"] / "config.json", p2p_enabled=False)
    with pytest.raises(p2p.P2PError) as disabled:
        p2p.info(c["control"], c["tokens"][0])
    assert disabled.value.status == 404
    (c["control"].parent / "cluster" / "controller.json").unlink()
    with pytest.raises(p2p.P2PError) as legacy:
        p2p.info(c["control"], c["tokens"][0])
    assert legacy.value.status == 412


def test_quorum_loss_and_commit_expiry_fail_closed(authority, monkeypatch):
    c = authority

    def unavailable(*args, **kwargs):
        raise state.ControlStateError("quorum unavailable", 503)

    monkeypatch.setattr(state, "mutation", unavailable)
    with pytest.raises(state.ControlStateError):
        issued(c)
    monkeypatch.setattr(state, "mutation", c["consensus"].commit)
    start = int(time.time())
    monkeypatch.setattr(p2p, "time", SimpleNamespace(time=lambda: start))
    c["consensus"].before_commit = lambda: monkeypatch.setattr(
        p2p,
        "time",
        SimpleNamespace(time=lambda: start + 900),
    )
    with pytest.raises(p2p.P2PError, match="expired while committing"):
        issued(c)


def test_capability_fields_keys_and_oversize_requests(authority):
    c = authority
    for body in (
        {"host_device_id": c["devices"][1]["id"]},
        request(host_device_id=c["devices"][1]["id"], user_id=c["owner"]),
        request(host_device_id="../../escape"),
    ):
        with pytest.raises(p2p.P2PError):
            p2p.issue(c["control"], c["tokens"][0], body)
    with pytest.raises(p2p.P2PError):
        p2p.sync(c["control"], c["tokens"][0], request(tickets=["x"] * 17))
    path = c["control"] / "devices" / f"{c['devices'][1]['id']}.json"
    change_json(path, public_key=c["devices"][0]["public_key"] + "\n")
    with pytest.raises(p2p.P2PError):
        issued(c)


def test_python_wire_contract_in_go(authority, tmp_path):
    binary = os.environ.get("BPC_P2P_TEST_BINARY")
    if not binary:
        pytest.skip("control-runtime CI supplies BPC_P2P_TEST_BINARY for Go interoperability")
    c = authority
    ticket = issued(c)
    checkpoint = p2p.sync(c["control"], c["tokens"][1], request(tickets=[ticket]))["checkpoint"]
    path = tmp_path / "public-contract.json"
    write_json(
        path,
        {
            "trust": {
                "cluster_id": "p2p-test",
                "device_id": c["devices"][1]["id"],
                "issuer": base64.b64encode(
                    c["ca_key"]
                    .public_key()
                    .public_bytes(
                        serialization.Encoding.Raw,
                        serialization.PublicFormat.Raw,
                    )
                ).decode(),
            },
            "ticket": ticket,
            "checkpoint": checkpoint,
        },
    )
    env = {**os.environ, "BPC_P2P_CONTRACT_FILE": str(path)}
    subprocess.run(
        [binary, "-test.run=^TestControllerWireContract$", "-test.v"],
        check=True,
        timeout=20,
        env=env,
    )
