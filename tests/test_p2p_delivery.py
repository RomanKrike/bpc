"""Account delivery keeps the existing signed endpoint boundary."""
import base64
import hashlib
import json
import sys
import time
from pathlib import Path

import pytest
from p2p_support import seed_p2p
from test_p2p_authority import FakeConsensus, change_json, decode_signed, request

sys.path.insert(0, str(Path(__file__).parents[1] / "deploy"))
import bpc_control_state as state  # noqa: E402
import bpc_p2p as p2p  # noqa: E402


@pytest.fixture
def authority(tmp_path, monkeypatch):
    c = seed_p2p(tmp_path)
    consensus = FakeConsensus()
    monkeypatch.setattr(state, "strong_read", consensus.barrier)
    monkeypatch.setattr(state, "mutation", consensus.commit)
    c["consensus"] = consensus
    return c


def account(c):
    change_json(c["control"] / "config.json", p2p_account_mode=True,
                p2p_relay="relay.example.test:24446")
    return c["control"], c["tokens"][0], request(host_device_id=c["devices"][1]["id"])


def test_account_default_off_and_caller_cannot_supply_relay(authority):
    c = authority
    with pytest.raises(p2p.P2PError, match="not enabled"):
        p2p.connect(c["control"], c["tokens"][0], request(host_device_id=c["devices"][1]["id"]))
    args = account(c)
    with pytest.raises(p2p.P2PError, match="unsupported"):
        p2p.connect(args[0], args[1], dict(args[2], relay="attacker.test:443"))


def test_both_devices_receive_same_public_grant_without_accepting(authority):
    c = authority
    args = account(c)
    listed = p2p.peers(args[0], args[1], request())["peers"]
    assert [p["id"] for p in listed] == [c["devices"][1]["id"]]
    assert p2p.connect(*args)["queued"] is True
    offers = [p2p.inbox(args[0], token, request())["offer"] for token in c["tokens"]]
    assert offers[0] == offers[1]
    assert offers[0]["relay"] == "relay.example.test:24446"
    grant = decode_signed(offers[0]["ticket"])
    assert grant["expires_at"] - grant["issued_at"] <= 60
    for offer in offers:
        assert set(offer) == {"ticket", "relay", "expires_at"}
        assert set(json.loads(base64.b64decode(offer["ticket"]))) == {
            "payload", "signature"
        }


@pytest.mark.parametrize("mutation", ["deny", "consent", "owner", "revoke"])
def test_delivery_hides_forbidden_peers_and_rechecks_after_queue(authority, mutation):
    c = authority
    args = account(c)
    p2p.connect(*args)
    host = c["devices"][1]["id"]
    if mutation == "deny":
        change_json(args[0] / "access" / f"device-{c['devices'][0]['id']}.json",
                    deny=["10.253.0.3/32"])
    elif mutation == "consent":
        change_json(args[0] / "access" / f"device-{host}.json", p2p_enabled=False)
    elif mutation == "owner":
        change_json(args[0] / "devices" / f"{host}.json", user_id="d" * 32)
    else:
        change_json(args[0] / "devices" / f"{host}.json", revoked=True)
    assert p2p.inbox(args[0], args[1], request())["offer"] is None
    assert p2p.peers(args[0], args[1], request())["peers"] == []
    with pytest.raises(p2p.P2PError):
        p2p.connect(*args)


def test_expiry_busy_and_one_retained_slot_per_device(authority, monkeypatch):
    c = authority
    args = account(c)
    now = int(time.time())
    monkeypatch.setattr(p2p.time, "time", lambda: now)
    p2p.connect(*args)
    with pytest.raises(p2p.P2PError, match="already pending"):
        p2p.connect(*args)
    now += 61
    assert p2p.inbox(args[0], args[1], request())["offer"] is None
    p2p.connect(*args)
    assert len(list((args[0] / "p2p-delivery").glob("*.json"))) == 2


def test_delivery_cas_blocks_revoke_between_grant_and_publication(authority):
    c = authority
    args = account(c)
    original = c["consensus"].commit

    def commit(root, kind, operations):
        if kind == "DeliverP2PSession":
            change_json(root / "devices" / f"{c['devices'][1]['id']}.json", revoked=True)
        return original(root, kind, operations)

    state.mutation = commit
    try:
        with pytest.raises(state.ControlStateError, match="conflict"):
            p2p.connect(*args)
        assert not (args[0] / "p2p-delivery").exists()
    finally:
        state.mutation = original


def test_inbox_credential_and_quorum_failure(authority, monkeypatch):
    args = account(authority)
    p2p.connect(*args)
    with pytest.raises(p2p.P2PError):
        p2p.inbox(args[0], "0" * 64, request())
    def no_quorum(*args, **kwargs):
        raise state.ControlStateError("no quorum")
    monkeypatch.setattr(state, "strong_read", no_quorum)
    with pytest.raises(state.ControlStateError):
        p2p.inbox(args[0], args[1], request())


def test_delivery_race_does_not_replace_live_slot(authority, monkeypatch):
    args = account(authority)
    original = authority["consensus"].commit
    competing = {}

    def commit(root, kind, operations):
        if kind == "DeliverP2PSession":
            # Another publisher won after our snapshot; all-or-nothing CAS
            # must preserve that exact slot, not overwrite it or its peer.
            operation = next(op for op in operations if "p2p-delivery" in op["path"].parts)
            path = operation["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(operation["data"])
            competing[path] = path.read_bytes()
        return original(root, kind, operations)

    monkeypatch.setattr(state, "mutation", commit)
    with pytest.raises(state.ControlStateError, match="conflict"):
        p2p.connect(*args)
    assert len(list((args[0] / "p2p-delivery").glob("*.json"))) == 1
    for path, raw in competing.items():
        assert path.read_bytes() == raw


def test_delivery_prefix_is_canonical_and_bounded_to_state_root(authority):
    root = authority["control"]
    path = root / "p2p-delivery" / ("a" * 32 + ".json")
    assert state.is_replicated_path(root, path)
    assert not state.is_replicated_path(root, root / "private-runtime" / "x.json")
    # Delivery contains public material only; it is independent of credential path.
    assert hashlib.sha256(authority["tokens"][0].encode()).hexdigest() not in str(path)
