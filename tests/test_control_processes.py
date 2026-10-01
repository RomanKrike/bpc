"""Real bpc-controld processes over loopback mTLS; no host network mutations."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).parents[1] / "deploy"))
import bpc_node_enrollment as enrollment  # noqa: E402

BINARY = os.environ.get("BPC_CONTROLD_BINARY")
LEGACY_BINARY = os.environ.get("BPC_LEGACY_CONTROLD_BINARY")
pytestmark = pytest.mark.skipif(not BINARY, reason="set BPC_CONTROLD_BINARY for process acceptance")


def free_address():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{sock.getsockname()[1]}"


def until(function, timeout=30):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            result = function()
            if result:
                return result
        except (OSError, ValueError, AssertionError, enrollment.EnrollmentError) as error:
            last = error
        time.sleep(0.1)
    raise AssertionError(f"condition did not converge: {last}")


def test_three_real_controller_processes(tmp_path, monkeypatch):
    ca_key = Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "process-test")])
    now = datetime.now(UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, None)
    )
    nodes = []
    for index in range(3):
        node_id = f"{index + 1:032x}"
        root = tmp_path / f"node-{index + 1}"
        cluster = root / "cluster"
        cluster.mkdir(parents=True)
        (root / "control").mkdir()
        key = Ed25519PrivateKey.generate()
        from urllib.parse import urlparse

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]))
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                        x509.UniformResourceIdentifier(
                            urlparse(f"bpc://process-test/controller/{node_id}").geturl()
                        ),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH,
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
            .sign(ca_key, None)
        )
        (cluster / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (cluster / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (cluster / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (cluster / "cluster.json").write_text(
            json.dumps({"version": 1, "cluster_id": "process-test"})
        )
        (cluster / "controller.json").write_text("{}")
        secret = secrets.token_hex(32)
        (cluster / "local-api.token").write_text(secret)
        record = {
            "node_id": node_id,
            "raft_address": free_address(),
            "api_address": free_address(),
            "public_url": f"https://ru-0{index + 1}.example:8444",
            "state": "voter" if index == 0 else "pending",
            "protocol_version": 1,
            "state_schema_version": 1,
            "certificate_sha256": hashlib.sha256(
                cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
        }
        nodes.append({"root": root, "record": record, "local": free_address(), "token": secret})
    for node in nodes:
        members = node["root"] / "cluster" / "controllers"
        members.mkdir()
        for other in nodes:
            record = other["record"]
            (members / f"{record['node_id']}.json").write_text(json.dumps(record))

    def api(node, path, payload=None):
        request = urllib.request.Request(
            "http://" + node["local"] + path,
            data=None if payload is None else json.dumps(payload).encode(),
            headers={
                "Authorization": "Bearer " + node["token"],
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=90) as response:
            return json.load(response)

    def controller_command(node, bootstrap=False):
        root = node["root"]
        cluster = root / "cluster"
        command = [
            BINARY,
            "--node-id",
            node["record"]["node_id"],
            "--raft-address",
            node["record"]["raft_address"],
            "--cluster-api-address",
            node["record"]["api_address"],
            "--local-api-address",
            node["local"],
            "--state-root",
            str(root),
            "--data-dir",
            str(cluster / "raft"),
            "--cert-file",
            str(cluster / "cert.pem"),
            "--key-file",
            str(cluster / "key.pem"),
            "--ca-file",
            str(cluster / "ca.pem"),
            "--local-api-token-file",
            str(cluster / "local-api.token"),
        ]
        if bootstrap:
            command.append("--bootstrap")
        return command

    def start(node, bootstrap=False, binary=None):
        root = node["root"]
        command = controller_command(node, bootstrap)
        if binary:
            command[0] = binary
        log = (root / "process.log").open("ab")
        node["process"] = subprocess.Popen(command, stdout=log, stderr=log)
        log.close()
        until(lambda: api(node, "/v1/health"))

    try:
        start(nodes[0], True)
        until(lambda: api(nodes[0], "/v1/health")["raft_role"] == "Leader")
        for node in nodes[1:]:
            start(node, binary=LEGACY_BINARY if node is nodes[2] else None)
            request = {**node["record"], "voter": False}
            assert api(nodes[0], "/v1/members/add", request)["state"] == "nonvoter"
            request["voter"] = True
            assert api(nodes[0], "/v1/members/add", request)["state"] == "voter"
        monkeypatch.setattr(
            enrollment.bpc_control_state, "LOCAL_API", "http://" + nodes[0]["local"]
        )
        token = enrollment.create_join_token(
            nodes[0]["root"] / "control",
            controller_url="https://ru-01.example:8444",
            roles=["site_router"],
            advertised_routes=["192.168.88.0/24"],
            name="home-01",
            endpoints=[{"host": "home.internal", "public": False}],
        )
        joined = enrollment.enroll_node(
            nodes[0]["root"] / "control",
            token=token,
            public_key=base64.b64encode(os.urandom(32)).decode(),
            presented_name="ignored",
        )
        relative = Path("control/nodes") / f"{joined['node_id']}.json"
        expected = (nodes[0]["root"] / relative).read_bytes()
        for node in nodes:
            until(lambda node=node: (node["root"] / relative).read_bytes() == expected)
        if LEGACY_BINARY:
            # Actual pre-watermark binary must block administrative recovery.
            before_revision = api(nodes[0], "/v1/health")["revision"]
            with pytest.raises(urllib.error.HTTPError) as mixed:
                api(nodes[0], "/v1/reconcile-revision", {"gateway_receipts": {}})
            assert mixed.value.code == 503
            assert api(nodes[0], "/v1/health")["revision"] == before_revision
            assert (nodes[0]["root"] / relative).read_bytes() == expected
            nodes[2]["process"].terminate()
            nodes[2]["process"].wait(timeout=10)
            # Reproduce legacy no-snapshot replay only in this temporary fixture.
            shutil.rmtree(nodes[2]["root"] / "cluster/raft/snapshots", ignore_errors=True)
            start(nodes[2], binary=LEGACY_BINARY)
            until(lambda: api(nodes[2], "/v1/barrier", {}))
            legacy_floor = api(nodes[2], "/v1/health")["revision"]
            assert legacy_floor > before_revision
            nodes[2]["process"].terminate()
            nodes[2]["process"].wait(timeout=10)
            checkpoint = subprocess.run(
                controller_command(nodes[2]) + [
                    "--replay-checkpoint-source", "https://" + nodes[0]["record"]["api_address"],
                ], capture_output=True, text=True, timeout=40,
            )
            assert checkpoint.returncode == 0, checkpoint.stderr
            start(nodes[2])
            assert not api(nodes[2], "/v1/health")["ok"]
            reconciled = api(nodes[0], "/v1/reconcile-revision", {"gateway_receipts": {}})
            assert reconciled["revision"] >= legacy_floor
            for node in nodes:
                api(node, "/v1/barrier", {})
                assert api(node, "/v1/health")["ok"]
                assert api(node, "/v1/health")["revision"] == reconciled["revision"]
                assert (node["root"] / relative).read_bytes() == expected

        # A Gateway can hold a signed revision above every current Controller.
        from bpc_gateway_snapshot import (
            _signing_bytes,
            build_security_snapshot,
            install_security_snapshot,
            load_valid_security_snapshot,
        )
        pki = nodes[0]["root"] / "cluster/pki"
        pki.mkdir(exist_ok=True)
        (pki / "cluster-ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (pki / "cluster-ca.key").write_bytes(ca_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        gateway_id = "a" * 32
        api(nodes[0], "/v1/mutate", {
            "version": 1, "id": "gateway-proof", "kind": "NodePut",
            "operations": [{"op": "put", "path": f"control/nodes/{gateway_id}.json",
                            "data": base64.b64encode(json.dumps({
                                "node_id": gateway_id, "roles": {"gateway": True},
                            }).encode()).decode()}],
        })
        high_revision = api(nodes[0], "/v1/health")["revision"] + 1000
        receipt, verification_key = build_security_snapshot(
            nodes[0]["root"] / "control", revision=high_revision,
        )
        gateway = tmp_path / "gateway"
        install_security_snapshot(gateway, receipt, verification_key)
        proof = {"signed": base64.b64encode(_signing_bytes(receipt)).decode(),
                 "signature": receipt["signature"]}
        recovery_request = {"gateway_receipts": {gateway_id: proof}}
        for invalid in ({"gateway_receipts": {}}, {"gateway_receipts": {
            gateway_id: {**proof, "signature": base64.b64encode(bytes(64)).decode()},
        }}):
            before = api(nodes[0], "/v1/health")["revision"]
            with pytest.raises(urllib.error.HTTPError) as rejected:
                api(nodes[0], "/v1/reconcile-revision", invalid)
            assert rejected.value.code == 503
            assert api(nodes[0], "/v1/health")["revision"] == before
        result = api(nodes[0], "/v1/reconcile-revision", recovery_request)
        assert result["revision"] == high_revision
        current, _ = build_security_snapshot(
            nodes[0]["root"] / "control", revision=result["revision"],
        )
        install_security_snapshot(gateway, current, verification_key)
        assert load_valid_security_snapshot(gateway)["revision"] == high_revision
        for node in nodes:
            assert (node["root"] / relative).read_bytes() == expected
        # Persistence: restart the second actual process with the same Raft DB.
        api(nodes[1], "/v1/barrier", {})
        restart_revision = api(nodes[1], "/v1/health")["revision"]
        online_import = subprocess.run(
            controller_command(nodes[1]) + [
                "--replay-checkpoint-source", "https://" + nodes[0]["record"]["api_address"],
            ], capture_output=True, text=True, timeout=15,
        )
        assert online_import.returncode != 0
        assert "stop recipient bpc-controld" in online_import.stderr
        nodes[1]["process"].terminate()
        nodes[1]["process"].wait(timeout=10)
        rejected_import = subprocess.run(
            controller_command(nodes[1]) + [
                "--replay-checkpoint-source", "https://" + nodes[2]["record"]["api_address"],
            ], capture_output=True, text=True, timeout=15,
        )
        assert rejected_import.returncode != 0
        assert "HTTP 409" in rejected_import.stderr
        assert not (nodes[1]["root"] / "cluster/raft/replay-backups").exists()
        donor_record = (
            nodes[1]["root"] / "cluster/controllers"
            / f"{nodes[0]['record']['node_id']}.json"
        )
        trusted_record = donor_record.read_bytes()
        mismatched = json.loads(trusted_record)
        mismatched["certificate_sha256"] = "00" * 32
        donor_record.write_text(json.dumps(mismatched))
        try:
            untrusted_import = subprocess.run(
                controller_command(nodes[1]) + [
                    "--replay-checkpoint-source",
                    "https://" + nodes[0]["record"]["api_address"],
                ], capture_output=True, text=True, timeout=15,
            )
            assert untrusted_import.returncode != 0
            assert "fingerprint mismatch" in untrusted_import.stderr
            assert not (nodes[1]["root"] / "cluster/raft/replay-backups").exists()
        finally:
            donor_record.write_bytes(trusted_record)
        private_key = (nodes[1]["root"] / "cluster/key.pem").read_bytes()
        # Import through the actual offline binary and loopback mTLS source.
        # Import must not mutate current policy before normal Raft restoration.
        imported = subprocess.run(
            controller_command(nodes[1]) + [
                "--replay-checkpoint-source", "https://" + nodes[0]["record"]["api_address"],
            ], capture_output=True, text=True, timeout=40,
        )
        assert imported.returncode == 0, imported.stderr
        assert (nodes[1]["root"] / relative).read_bytes() == expected
        assert (nodes[1]["root"] / "cluster/key.pem").read_bytes() == private_key
        assert list((nodes[1]["root"] / "cluster/raft/replay-backups").glob("*.db"))
        start(nodes[1])
        until(lambda: api(nodes[1], "/v1/barrier", {}))
        assert (nodes[1]["root"] / relative).read_bytes() == expected
        assert api(nodes[1], "/v1/health")["revision"] == restart_revision
        assert api(nodes[1], "/v1/health")["revision_floor"] == restart_revision
        assert api(nodes[1], "/v1/health")["ok"]
        # Stop the leader, then write through the surviving cluster.
        nodes[0]["process"].terminate()
        nodes[0]["process"].wait(timeout=10)
        successor = until(
            lambda: next(
                (node for node in nodes[1:] if api(node, "/v1/health")["raft_role"] == "Leader"),
                None,
            )
        )
        monkeypatch.setattr(
            enrollment.bpc_control_state, "LOCAL_API", "http://" + successor["local"]
        )
        assert enrollment.node_heartbeat(
            successor["root"] / "control",
            credential=joined["credential"],
            payload={"advertised_routes": ["192.168.88.0/24"]},
        )["ok"]
        # Route grants replicate independently of transient advertisements.
        enrollment.authorize_site_routes(
            successor["root"] / "control", joined["node_id"], ["10.10.0.0/16"],
        )
        approved = (successor["root"] / relative).read_bytes()
        survivor = next(node for node in nodes[1:] if node is not successor)
        until(lambda: (survivor["root"] / relative).read_bytes() == approved)
        survivor["process"].terminate()
        survivor["process"].wait(timeout=10)
        with pytest.raises(enrollment.EnrollmentError) as failed_write:
            enrollment.authorize_site_routes(
                successor["root"] / "control", joined["node_id"], ["10.20.0.0/16"],
            )
        assert failed_write.value.status == 503
        assert (successor["root"] / relative).read_bytes() == approved
        with pytest.raises(enrollment.EnrollmentError):
            enrollment.node_heartbeat(
                successor["root"] / "control", credential=joined["credential"],
                payload={"advertised_routes": ["192.168.88.0/24"]},
            )
        # A stopped recipient must not accept a checkpoint from an isolated
        # former leader. Failed export must leave every persisted file intact.
        def persisted_files(node):
            return {
                str(path.relative_to(node["root"])): hashlib.sha256(path.read_bytes()).digest()
                for path in node["root"].rglob("*")
                if path.is_file() and path.name != "process.log"
            }

        before_failed_import = persisted_files(survivor)
        with pytest.raises(urllib.error.HTTPError) as isolated_recovery:
            api(successor, "/v1/reconcile-revision", recovery_request)
        assert isolated_recovery.value.code in (409, 503)
        isolated_import = subprocess.run(
            controller_command(survivor) + [
                "--replay-checkpoint-source",
                "https://" + successor["record"]["api_address"],
            ], capture_output=True, text=True, timeout=40,
        )
        assert isolated_import.returncode != 0
        assert any(code in isolated_import.stderr for code in ("HTTP 409", "HTTP 503"))
        assert persisted_files(survivor) == before_failed_import
        # Rejoin an existing voter using its persisted log and wait for quorum.
        start(nodes[0])
        until(lambda: api(successor, "/v1/barrier", {}))
        recovered = enrollment.node_heartbeat(
            successor["root"] / "control", credential=joined["credential"],
            payload={"advertised_routes": ["10.10.0.0/16"]},
        )
        assert recovered["config"]["routing"]["policy_expires_at"] > int(time.time())
        converged = (successor["root"] / relative).read_bytes()
        until(lambda: (nodes[0]["root"] / relative).read_bytes() == converged)
        assert "10.20.0.0/16" not in json.loads(converged)["authorized_routes"]
        # Retry the same offline operation after quorum returns. The source
        # may have changed leadership; choose the actual current leader.
        donor = until(lambda: next(
            (node for node in [nodes[0], successor]
             if api(node, "/v1/health")["raft_role"] == "Leader"),
            None,
        ))
        retry_import = subprocess.run(
            controller_command(survivor) + [
                "--replay-checkpoint-source", "https://" + donor["record"]["api_address"],
            ], capture_output=True, text=True, timeout=40,
        )
        assert retry_import.returncode == 0, retry_import.stderr
        assert (survivor["root"] / relative).read_bytes() == approved
        start(survivor)
        until(lambda: api(survivor, "/v1/barrier", {}))
        assert (survivor["root"] / relative).read_bytes() == converged
        assert api(survivor, "/v1/health")["ok"]
        live = [nodes[0], successor]
        follower = until(lambda: next(
            (node for node in live if api(node, "/v1/health")["raft_role"] == "Follower"),
            None,
        ))
        monkeypatch.setattr(
            enrollment.bpc_control_state, "LOCAL_API", "http://" + follower["local"],
        )
        enrollment.authorize_site_routes(
            follower["root"] / "control", joined["node_id"], ["10.30.0.0/16"],
        )
        # No polling/barrier: successful follower mutation must already be local.
        assert "10.30.0.0/16" in json.loads(
            (follower["root"] / relative).read_bytes()
        )["authorized_routes"]
        forwarded = enrollment.node_heartbeat(
            follower["root"] / "control", credential=joined["credential"],
            payload={"advertised_routes": ["10.30.0.0/16"]},
        )
        assert {"cidr": "10.30.0.0/16", "owner_node_id": joined["node_id"]} in (
            forwarded["config"]["routing"]["routes"]
        )
        for node in nodes:
            api(node, "/v1/barrier", {})
        assert len({api(node, "/v1/health")["revision"] for node in nodes}) == 1
        print(
            "3 processes: mTLS, membership, replication, restart, leader/quorum "
            "failover, route grants, policy renewal, convergence, revision recovery, "
            "Gateway receipts and follower writes PASS"
        )
    finally:
        for node in nodes:
            process = node.get("process")
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
