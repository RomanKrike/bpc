from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_runtime_firewall_never_deletes_untagged_rules(tmp_path):
    source = (ROOT / "deploy/bpc-enable-agent-dataplane.sh").read_text()
    helper = source.split("cat > /usr/local/sbin/bpc-agent-dataplane-firewall <<'SCRIPT'\n", 1)[1]
    helper = helper.split("\nSCRIPT", 1)[0]
    script = tmp_path / "firewall.sh"
    script.write_text(helper)
    runtime = tmp_path / "state/ru-node/agent/runtime.env"
    runtime.parent.mkdir(parents=True)
    runtime.write_text(
        "AGENT_WG_INTERFACE=bpcag0\nAGENT_WG_SUBNET=10.253.0.0/24\nAGENT_WG_PORT=51821\n"
    )
    binary = tmp_path / "bin/iptables"
    binary.parent.mkdir()
    binary.write_text(
        "#!/usr/bin/env python3\nimport json,os,sys\n"
        "with open(os.environ['BPC_TEST_LOG'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
        "sys.exit(1 if '-C' in sys.argv else 0)\n"
    )
    binary.chmod(0o755)
    log = tmp_path / "rules.jsonl"
    env = {
        **os.environ,
        "PATH": f"{binary.parent}:{os.environ['PATH']}",
        "BPC_STATE_DIR": str(tmp_path / "state"),
        "BPC_ROOT": str(tmp_path / "code"),
        "BPC_TEST_LOG": str(log),
    }
    for action in ("up", "down"):
        subprocess.run(["bash", str(script), action], env=env, check=True)
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    assert any("-D" in command for command in commands)
    for command in commands:
        assert command[-4:] == ["-m", "comment", "--comment", "bpc-agent-dataplane:bpcag0"]
