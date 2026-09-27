from __future__ import annotations

import base64
import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .node import load_node_config, set_node_identity
from .state import StateLayout


class NodeIdentityError(RuntimeError):
    pass


@dataclass(frozen=True)
class NodeIdentityResult:
    public_key: str
    private_key_created: bool
    public_key_file_updated: bool
    node_config_updated: bool

    @property
    def changed(self) -> bool:
        return (
            self.private_key_created
            or self.public_key_file_updated
            or self.node_config_updated
        )


def _openssl_error(completed: subprocess.CompletedProcess[bytes], fallback: str) -> str:
    stderr = completed.stderr or b""
    message = stderr.decode("utf-8", errors="replace").strip()
    return message or fallback


def ensure_node_identity(state_dir: str | Path) -> NodeIdentityResult:
    """Create or verify the local Ed25519 Node identity without rotating it.

    Existing configured identities are fail-closed: if node.yaml contains a
    public key but the private key is missing or derives to a different public
    key, this function refuses to generate/replace credentials.
    """

    state = StateLayout.from_root(state_dir)
    identity_dir = state.identity_dir
    identity_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(identity_dir, 0o700)

    configured_public_key = ""
    if state.node_config.is_file():
        configured_public_key = load_node_config(state.node_config).node.public_key.strip()

    private_path = identity_dir / "node.key"
    public_path = identity_dir / "node.pub"

    if configured_public_key and not private_path.is_file():
        raise NodeIdentityError(
            "node.yaml contains a Node public key but identity/node.key is missing; "
            "refusing to rotate Node identity automatically"
        )

    private_created = False
    if not private_path.is_file():
        tmp = identity_dir / f".node.key.{secrets.token_hex(4)}.tmp"
        completed = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(tmp)],
            check=False,
            capture_output=True,
        )
        if completed.returncode != 0:
            tmp.unlink(missing_ok=True)
            raise NodeIdentityError(
                _openssl_error(completed, "failed to generate Ed25519 Node identity")
            )
        os.chmod(tmp, 0o600)
        os.replace(tmp, private_path)
        private_created = True
    os.chmod(private_path, 0o600)

    completed = subprocess.run(
        ["openssl", "pkey", "-in", str(private_path), "-pubout", "-outform", "DER"],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0 or not completed.stdout:
        raise NodeIdentityError(
            _openssl_error(completed, "failed to derive Node public key")
        )
    public_key = base64.b64encode(completed.stdout).decode("ascii")

    if configured_public_key and configured_public_key != public_key:
        raise NodeIdentityError(
            "identity/node.key does not match node.yaml public_key; "
            "refusing to rotate or overwrite Node identity"
        )

    public_file_updated = True
    if public_path.is_file():
        try:
            public_file_updated = public_path.read_text(encoding="utf-8").strip() != public_key
        except OSError:
            public_file_updated = True
    if public_file_updated:
        tmp_public = identity_dir / f".node.pub.{secrets.token_hex(4)}.tmp"
        tmp_public.write_text(public_key + "\n", encoding="utf-8")
        os.chmod(tmp_public, 0o644)
        os.replace(tmp_public, public_path)
    else:
        os.chmod(public_path, 0o644)

    node_config_updated = False
    if state.node_config.is_file() and not configured_public_key:
        set_node_identity(state.node_config, public_key)
        node_config_updated = True

    return NodeIdentityResult(
        public_key=public_key,
        private_key_created=private_created,
        public_key_file_updated=public_file_updated,
        node_config_updated=node_config_updated,
    )
