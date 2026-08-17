from pathlib import Path

import pytest
import yaml

from bpc_connect.config import load_gateway_config
from bpc_connect.errors import BPCConfigError

EXAMPLE = Path(__file__).parents[1] / "config" / "gateway.example.yaml"


def _write(tmp_path: Path, mutate) -> Path:
    data = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def test_duplicate_priority_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, lambda d: d["transports"][1].update(priority=10))
    with pytest.raises(BPCConfigError, match="Duplicate transport priority"):
        load_gateway_config(path)


def test_no_enabled_transport_is_rejected(tmp_path: Path) -> None:
    def mutate(data):
        for transport in data["transports"]:
            transport["enabled"] = False

    path = _write(tmp_path, mutate)
    with pytest.raises(BPCConfigError, match="At least one transport"):
        load_gateway_config(path)


def test_bad_cidr_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, lambda d: d.update(home_cidrs=["not-a-network"]))
    with pytest.raises(BPCConfigError, match="Invalid home CIDR"):
        load_gateway_config(path)
