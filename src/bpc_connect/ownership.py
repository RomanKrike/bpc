from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class Ownership(StrEnum):
    OWNED_BY_BPC = "OWNED_BY_BPC"
    LEGACY_BPC = "LEGACY_BPC"
    EXTERNAL = "EXTERNAL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class OwnershipEvidence:
    ownership: Ownership
    reason: str
    metadata_path: Path | None = None


def require_mutable(evidence: OwnershipEvidence) -> None:
    if evidence.ownership not in {Ownership.OWNED_BY_BPC, Ownership.LEGACY_BPC}:
        raise PermissionError(
            f"refusing to modify object with ownership={evidence.ownership.value}: "
            f"{evidence.reason}"
        )
