#!/usr/bin/env python3
"""Install the checksum-pinned Containerlab binary in the repository cache."""
import hashlib
import io
import json
import platform
from pathlib import Path
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def prepare():
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise RuntimeError("the pinned lab host is Linux amd64")
    versions = json.loads((ROOT / "lab/s02/versions.json").read_text())
    with urllib.request.urlopen(versions["containerlab_archive_url"], timeout=60) as response:
        archive = response.read(150 * 1024 * 1024 + 1)
    if hashlib.sha256(archive).hexdigest() != versions["containerlab_archive_sha256"]:
        raise RuntimeError("Containerlab archive checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        members = [member for member in package.getmembers()
                   if Path(member.name).name == "containerlab" and member.isfile()]
        if len(members) != 1:
            raise RuntimeError("archive must contain exactly one Containerlab binary")
        binary = package.extractfile(members[0]).read()
    if hashlib.sha256(binary).hexdigest() != versions["containerlab_binary_sha256"]:
        raise RuntimeError("Containerlab binary checksum mismatch")
    destination = ROOT / ".cache/tools/containerlab"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(binary)
    destination.chmod(0o755)
    metadata = dict(versions, containerlab_binary_sha256=hashlib.sha256(binary).hexdigest())
    destination.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Verified Containerlab {versions['containerlab_version']}: {destination}")


if __name__ == "__main__":
    prepare()
