"""Generate branded Windows resources using pinned go-winres v0.3.3."""
import argparse
import base64
import json
import re
import subprocess
import tempfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = (root / 'cmd/bpc-agent/ui_windows.go').read_text(encoding='utf-8')
    logo = re.search(r'const bpcConnectLogoPNGBase64 = "([A-Za-z0-9+/=]+)"', source)
    if logo is None:
        raise SystemExit('BPC logo not found')
    tool = str(Path(args.tool).resolve())
    build = root / 'build'
    build.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=build) as folder:
        directory = Path(folder)
        assert directory.resolve().is_relative_to(build.resolve())
        (directory / 'logo.png').write_bytes(base64.b64decode(logo[1], validate=True))
        config = {'RT_GROUP_ICON': {'APP': {'0000': 'logo.png'}}}
        (directory / 'winres.json').write_text(json.dumps(config), encoding='utf-8')
        subprocess.run([tool, 'make', '--in', 'winres.json', '--arch', 'amd64',
                        '--out', str(root / 'cmd/bpc-agent/rsrc')],
                       cwd=directory, check=True)


if __name__ == '__main__':
    main()
