#!/usr/bin/env python3
"""Verify a pinned candidate before extracting or executing its code."""
import argparse
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path, PurePosixPath, PureWindowsPath


def verify(bundle: Path, expected: str, destination: Path | None = None) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Expected SHA256 must be 64 lowercase hex characters")
    data = bundle.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Bundle SHA256 mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        files = {}
        members = []
        names = set()
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                    or PureWindowsPath(member.name).drive
                    or any(":" in part or part.endswith((".", " "))
                           or PureWindowsPath(part).is_reserved() for part in path.parts)
                    or (member.isfile() and not path.parts)):
                raise ValueError("Unsafe archive path")
            name = path.as_posix()
            if name in names or not (member.isfile() or member.isdir()):
                raise ValueError("Duplicate path, link or special archive member")
            names.add(name)
            if member.mode & 0o7000:
                raise ValueError("Privileged archive mode")
            members.append((member, name))
            if member.isfile():
                files[name] = archive.extractfile(member).read()
        for name in names:
            if any(parent.as_posix() in files for parent in PurePosixPath(name).parents
                   if parent.parts):
                raise ValueError("Archive file conflicts with a directory")
        manifest = json.loads(files["CANDIDATE.json"])
        sha = manifest["source_sha"]
        version = manifest["version"]
        if (manifest.get("schema") != 1 or manifest.get("channel") != "mesh-test"
                or manifest.get("live_acceptance") != "pending"
                or not re.fullmatch(r"[0-9a-f]{40}", sha)
                or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-mesh\." + sha, version)
                or files["VERSION"].decode().strip() != version):
            raise ValueError("Invalid candidate provenance")
        hashes = {name: hashlib.sha256(content).hexdigest()
                  for name, content in files.items() if name != "CANDIDATE.json"}
        if hashes != manifest["files"]:
            raise ValueError("Candidate file manifest mismatch")
        required = {"deploy/bpc-migrate.sh", "deploy/bpc-healthcheck.sh"}
        required.update(f"bin/{binary}-linux-{arch}"
                        for binary in ("bpc-controld", "bpc-routed-node", "bpc-wgshim",
                                       "bpc-agent-relay") for arch in ("amd64", "arm64"))
        required.update(("bin/bpc-agent-windows-amd64.exe",
                         "bin/bpc-wgshim-windows-amd64.exe",
                         "bin/wintun-windows-amd64.dll"))
        if not required <= files.keys():
            raise ValueError("Incomplete candidate runtime")
        # Validate everything first; never partially extract a rejected archive.
        if destination is not None:
            if destination.exists() and any(destination.iterdir()):
                raise ValueError("Extraction destination must be empty")
            destination.mkdir(parents=True, exist_ok=True)
            for member, name in members:
                target = destination / name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(files[name])
                    target.chmod(member.mode & 0o777)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("sha256", help="Trusted checksum obtained from the pinned CI artifact")
    parser.add_argument("--extract", type=Path)
    args = parser.parse_args()
    try:
        manifest = verify(args.bundle, args.sha256, args.extract)
    except (ValueError, KeyError, TypeError, OSError, tarfile.TarError) as error:
        parser.exit(2, f"Candidate rejected: {error}\n")
    print(json.dumps({key: manifest[key] for key in
                      ("version", "source_sha", "go_toolchain", "live_acceptance")}))


if __name__ == "__main__":
    main()
