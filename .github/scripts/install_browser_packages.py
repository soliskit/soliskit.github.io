"""Install the operating-system packages named by the pinned browser manifest."""

import json
import os
import pathlib
import re
import subprocess
import sys

PLATFORM = "ubuntu24.04-x64"
NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{1,63}")
MAX_PACKAGES = 100
MAX_BYTES = 65536


def load_packages(path):
    manifest = pathlib.Path(path)
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("manifest must be a regular file")
    if manifest.stat().st_size > MAX_BYTES:
        raise ValueError("manifest is too large")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise ValueError("unsupported manifest schema")
    if data.get("platform") != PLATFORM:
        raise ValueError("unexpected manifest platform")
    packages = data.get("packages")
    if not isinstance(packages, list) or not 1 <= len(packages) <= MAX_PACKAGES:
        raise ValueError("unexpected package list")
    for name in packages:
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError("unexpected package name")
    if len(set(packages)) != len(packages):
        raise ValueError("duplicate package name")
    return packages


def install(packages, run=subprocess.run):
    path = os.environ["PATH"]
    base = ["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"]
    run([*base, "apt-get", "update"], check=True, timeout=180, env={"PATH": path})
    run(
        [*base, "apt-get", "install", "-y", "--no-install-recommends", "--", *packages],
        check=True,
        timeout=600,
        env={"PATH": path},
    )


def main(argv):
    if len(argv) != 2:
        raise ValueError("expected exactly one manifest path")
    packages = load_packages(argv[1])
    install(packages)
    print(f"Installed or confirmed {len(packages)} pinned browser packages.")


if __name__ == "__main__":
    main(sys.argv)
