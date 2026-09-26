from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StateLayout:
    """Canonical BPC state layout.

    New core code must resolve state through this object instead of depending on
    historical transport directory names.
    """

    root: Path

    @classmethod
    def from_root(cls, root: str | Path) -> "StateLayout":
        return cls(Path(root))

    @property
    def node_config(self) -> Path:
        return self.root / "node.yaml"

    @property
    def identity_dir(self) -> Path:
        return self.root / "identity"

    @property
    def cluster_dir(self) -> Path:
        return self.root / "cluster"

    @property
    def control_dir(self) -> Path:
        return self.root / "control"

    @property
    def runtime_dir(self) -> Path:
        return self.root / "runtime"

    @property
    def transport_dir(self) -> Path:
        return self.root / "transports"

    @property
    def compat_dir(self) -> Path:
        return self.root / "compat"

    @property
    def backups_dir(self) -> Path:
        return self.root / "backups"

    def ensure_core_dirs(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for path in (
            self.identity_dir,
            self.cluster_dir,
            self.control_dir,
            self.runtime_dir,
            self.transport_dir,
            self.compat_dir,
            self.backups_dir,
        ):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
