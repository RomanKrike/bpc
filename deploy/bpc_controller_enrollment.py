from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RAFT_PORT = 9445
CLUSTER_API_PORT = 9447
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


class ControllerEnrollmentError(RuntimeError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _atomic_bytes(path: Path, value: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_bytes(value)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ControllerEnrollmentError(f"{path} does not contain a JSON object")
    return value


def normalize_advertise_host(value: str) -> str:
    host = value.strip()
    if not host or len(host) > 253 or ":" in host:
        raise ControllerEnrollmentError(
            "controller advertise host must be a DNS name or IPv4 address"
        )
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.fullmatch(host):
            raise ControllerEnrollmentError("invalid controller advertise hostname")
        return host.lower()
    if address.version != 4:
        raise ControllerEnrollmentError("controller advertise host currently supports IPv4 only")
    return str(address)


def ensure_controller_csr(state_dir: Path) -> str:
    pki = state_dir / "cluster" / "pki"
    pki.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(pki, 0o700)
    key_path = pki / "controller.key"
    if key_path.is_file():
        private_key = serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=None,
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ControllerEnrollmentError("existing Controller key is not Ed25519")
    else:
        private_key = Ed25519PrivateKey.generate()
        raw_key = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        _atomic_bytes(key_path, raw_key, 0o600)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        "bpc-controller-enrollment",
                    )
                ]
            )
        )
        .sign(private_key, algorithm=None)
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _controller_san(cluster_id: str, node_id: str, host: str) -> x509.SubjectAlternativeName:
    names: list[x509.GeneralName] = [
        x509.UniformResourceIdentifier(
            f"bpc://{cluster_id}/controller/{node_id}"
        )
    ]
    try:
        names.insert(0, x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        names.insert(0, x509.DNSName(host))
    return x509.SubjectAlternativeName(names)


def _controller_records(state_root: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    directory = state_root / "cluster" / "controllers"
    if not directory.is_dir():
        return result
    for path in sorted(directory.glob("*.json")):
        try:
            value = _read_json(path)
        except (OSError, ValueError, json.JSONDecodeError, ControllerEnrollmentError):
            continue
        result.append(value)
    return result


def build_controller_enrollment(
    control_dir: Path,
    *,
    node_id: str,
    advertise_host: str,
    csr_pem: str,
    software_version: str,
    now: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    state_root = control_dir.parent
    host = normalize_advertise_host(advertise_host)
    cluster = _read_json(state_root / "cluster" / "cluster.json")
    cluster_id = str(cluster.get("cluster_id", "")).strip()
    if not cluster_id:
        raise ControllerEnrollmentError("canonical cluster_id is missing", 503)

    pki = state_root / "cluster" / "pki"
    ca_cert_path = pki / "cluster-ca.crt"
    ca_key_path = pki / "cluster-ca.key"
    try:
        ca_cert_pem = ca_cert_path.read_bytes()
        ca_key_pem = ca_key_path.read_bytes()
    except OSError as exc:
        raise ControllerEnrollmentError(
            "cluster signing identity is unavailable",
            503,
        ) from exc

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    if not isinstance(ca_key, Ed25519PrivateKey):
        raise ControllerEnrollmentError("cluster CA key is not Ed25519")

    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ControllerEnrollmentError("invalid Controller CSR") from exc
    if not csr.is_signature_valid:
        raise ControllerEnrollmentError("Controller CSR signature is invalid")
    public_key = csr.public_key()
    if not isinstance(public_key, Ed25519PublicKey):
        raise ControllerEnrollmentError("Controller CSR key must be Ed25519")

    timestamp = int(time.time()) if now is None else int(now)
    valid_from = datetime.fromtimestamp(timestamp, tz=timezone.utc) - timedelta(minutes=5)
    valid_until = valid_from + timedelta(days=825)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
        )
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(_controller_san(cluster_id, node_id, host), critical=False)
        .sign(ca_key, algorithm=None)
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(certificate.public_bytes(serialization.Encoding.DER))
    cert_sha256 = fingerprint.finalize().hex()

    record = {
        "node_id": node_id,
        "raft_address": f"{host}:{RAFT_PORT}",
        "api_address": f"{host}:{CLUSTER_API_PORT}",
        "state": "pending",
        "software_version": software_version[:64],
        "protocol_version": 1,
        "state_schema_version": 1,
        "certificate_sha256": cert_sha256,
        "updated_at": timestamp,
    }
    records = _controller_records(state_root)
    records = [item for item in records if str(item.get("node_id", "")) != node_id]
    records.append(record)

    response = {
        "cluster": cluster,
        "cluster_ca_cert": ca_cert_pem.decode("ascii"),
        "cluster_ca_key": ca_key_pem.decode("ascii"),
        "controller_cert": cert_pem.decode("ascii"),
        "certificate_sha256": cert_sha256,
        "advertise_host": host,
        "raft_address": record["raft_address"],
        "cluster_api_address": record["api_address"],
        "controllers": records,
        "protocol_version": 1,
        "state_schema_version": 1,
    }
    operation = {
        "op": "put",
        "path": state_root / "cluster" / "controllers" / f"{node_id}.json",
        "data": json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        "if_absent": True,
    }
    return response, operation


def install_controller_enrollment(state_dir: Path, payload: dict[str, Any]) -> None:
    cluster = payload.get("cluster")
    controllers = payload.get("controllers")
    if not isinstance(cluster, dict) or not isinstance(controllers, list):
        raise ControllerEnrollmentError("invalid Controller enrollment payload")
    cluster_id = str(cluster.get("cluster_id", "")).strip()
    if not cluster_id:
        raise ControllerEnrollmentError("Controller enrollment is missing cluster_id")

    pki = state_dir / "cluster" / "pki"
    key_path = pki / "controller.key"
    if not key_path.is_file():
        raise ControllerEnrollmentError("local Controller private key is missing")
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ControllerEnrollmentError("local Controller private key is not Ed25519")

    try:
        cert_pem = str(payload["controller_cert"]).encode("ascii")
        ca_cert_pem = str(payload["cluster_ca_cert"]).encode("ascii")
        ca_key_pem = str(payload["cluster_ca_key"]).encode("ascii")
    except (KeyError, UnicodeEncodeError) as exc:
        raise ControllerEnrollmentError("incomplete Controller trust material") from exc

    certificate = x509.load_pem_x509_certificate(cert_pem)
    local_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    cert_public = certificate.public_key()
    if not isinstance(cert_public, Ed25519PublicKey):
        raise ControllerEnrollmentError("Controller certificate key is not Ed25519")
    if cert_public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ) != local_public:
        raise ControllerEnrollmentError(
            "Controller certificate does not match the local private key"
        )

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    if not isinstance(ca_key, Ed25519PrivateKey):
        raise ControllerEnrollmentError("cluster CA key is not Ed25519")
    ca_public = ca_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    cert_ca_public = ca_cert.public_key()
    if not isinstance(cert_ca_public, Ed25519PublicKey):
        raise ControllerEnrollmentError("cluster CA certificate key is not Ed25519")
    if cert_ca_public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ) != ca_public:
        raise ControllerEnrollmentError("cluster CA certificate/key mismatch")

    _atomic_bytes(pki / "controller.crt", cert_pem, 0o644)
    _atomic_bytes(pki / "cluster-ca.crt", ca_cert_pem, 0o644)
    _atomic_bytes(pki / "cluster-ca.key", ca_key_pem, 0o600)
    _atomic_bytes(
        state_dir / "cluster" / "cluster.json",
        (json.dumps(cluster, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        0o600,
    )

    members = state_dir / "cluster" / "controllers"
    members.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(members, 0o700)
    for item in controllers:
        if not isinstance(item, dict):
            raise ControllerEnrollmentError("invalid Controller membership seed")
        node_id = str(item.get("node_id", "")).strip()
        if not re.fullmatch(r"[0-9a-f]{32}", node_id):
            raise ControllerEnrollmentError("invalid Controller membership node_id")
        _atomic_bytes(
            members / f"{node_id}.json",
            (json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8"
            ),
            0o600,
        )


def activate_controller_marker(
    state_dir: Path,
    *,
    node_id: str,
    payload: dict[str, Any],
    software_version: str,
) -> None:
    raft_address = str(payload.get("raft_address", "")).strip()
    api_address = str(payload.get("cluster_api_address", "")).strip()
    if not raft_address or not api_address:
        raise ControllerEnrollmentError("Controller endpoints are missing")
    value = {
        "version": 1,
        "node_id": node_id,
        "raft_address": raft_address,
        "cluster_api_address": api_address,
        "local_api_address": "127.0.0.1:9446",
        "certificate_file": str(state_dir / "cluster" / "pki" / "controller.crt"),
        "key_file": str(state_dir / "cluster" / "pki" / "controller.key"),
        "ca_file": str(state_dir / "cluster" / "pki" / "cluster-ca.crt"),
        "local_api_token_file": str(state_dir / "cluster" / "local-api.token"),
        "software_version": software_version[:64],
        "protocol_version": int(payload.get("protocol_version", 1)),
        "state_schema_version": int(payload.get("state_schema_version", 1)),
    }
    _atomic_bytes(
        state_dir / "cluster" / "controller.json",
        (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        0o600,
    )
