from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "deploy"))

from bpc_controller_enrollment import (  # noqa: E402
    activate_controller_marker,
    build_controller_enrollment,
    ensure_controller_csr,
    install_controller_enrollment,
)


def seed_cluster_signing_identity(state_root: Path) -> None:
    pki = state_root / "cluster" / "pki"
    pki.mkdir(parents=True)
    ca_key = Ed25519PrivateKey.generate()
    now = datetime.now(tz=UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "BPC test cluster")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, algorithm=None)
    )
    (pki / "cluster-ca.key").write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(pki / "cluster-ca.key", 0o600)
    (pki / "cluster-ca.crt").write_bytes(
        ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    (state_root / "cluster" / "cluster.json").write_text(
        json.dumps(
            {
                "version": 1,
                "cluster_id": "cluster-test",
                "controller_node_id": "a" * 32,
            }
        ),
        encoding="utf-8",
    )
    members = state_root / "cluster" / "controllers"
    members.mkdir()
    (members / f"{'a' * 32}.json").write_text(
        json.dumps(
            {
                "node_id": "a" * 32,
                "raft_address": "controller-a.example:9445",
                "api_address": "controller-a.example:9447",
                "state": "voter",
                "certificate_sha256": "0" * 64,
            }
        ),
        encoding="utf-8",
    )


def test_controller_enrollment_keeps_private_key_local(tmp_path: Path) -> None:
    controller_state = tmp_path / "controller"
    control_dir = controller_state / "control"
    control_dir.mkdir(parents=True)
    seed_cluster_signing_identity(controller_state)

    joining_state = tmp_path / "joining"
    csr = ensure_controller_csr(joining_state)
    node_id = "b" * 32
    payload, operation = build_controller_enrollment(
        control_dir,
        node_id=node_id,
        advertise_host="controller-b.example",
        csr_pem=csr,
        software_version="0.18.0",
        now=1_000,
    )

    assert operation["op"] == "put"
    assert operation["if_absent"] is True
    assert str(operation["path"]).endswith(f"cluster/controllers/{node_id}.json")
    pending = json.loads(operation["data"])
    assert pending["state"] == "pending"
    assert pending["node_id"] == node_id
    assert pending["raft_address"] == "controller-b.example:9445"

    local_key_before = (joining_state / "cluster" / "pki" / "controller.key").read_bytes()
    install_controller_enrollment(joining_state, payload)
    local_key_after = (joining_state / "cluster" / "pki" / "controller.key").read_bytes()
    assert local_key_after == local_key_before

    cert = x509.load_pem_x509_certificate(
        (joining_state / "cluster" / "pki" / "controller.crt").read_bytes()
    )
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == node_id
    assert (
        f"bpc://cluster-test/controller/{node_id}"
        in [uri.value for uri in cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)]
    )
    assert not (joining_state / "cluster" / "controller.json").exists()

    activate_controller_marker(
        joining_state,
        node_id=node_id,
        payload=payload,
        software_version="0.18.0",
    )
    marker = json.loads(
        (joining_state / "cluster" / "controller.json").read_text(encoding="utf-8")
    )
    assert marker["node_id"] == node_id
    assert marker["raft_address"] == "controller-b.example:9445"
