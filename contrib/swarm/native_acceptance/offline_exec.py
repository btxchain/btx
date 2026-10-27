#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Verify an extracted runtime's exact manifest before executing a named binary."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform

try:
    from .evidence import EvidenceError, HEX64, sha256_file, strict_json
    from .offline_image import MAX_TOTAL, REQUIRED, safe_name
except ImportError:
    from evidence import EvidenceError, HEX64, sha256_file, strict_json
    from offline_image import MAX_TOTAL, REQUIRED, safe_name


def verify_installed(root: Path, manifest_sha256: str) -> dict:
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or not HEX64.fullmatch(manifest_sha256):
        raise EvidenceError("invalid installed runtime root or manifest pin")
    manifest_path = root / "manifest.json"
    if sha256_file(manifest_path, 8 * 1024 * 1024) != manifest_sha256:
        raise EvidenceError("installed runtime manifest pin differs")
    manifest = strict_json(manifest_path.read_bytes())
    system = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(platform.system(), "UNKNOWN")
    if manifest.get("schema") != "BTX-OFFLINE-RUNTIME/1" or not manifest.get("platform", "").startswith(system + "-"):
        raise EvidenceError("installed runtime is for a different native operating system")
    architecture = {"AMD64": "x86_64", "arm64": "aarch64"}.get(platform.machine(), platform.machine())
    expected_arch = "aarch64" if manifest["platform"].endswith(("arm64", "aarch64")) else "x86_64"
    if architecture != expected_arch:
        raise EvidenceError("installed runtime is for a different native CPU")
    expected, total = {"manifest.json"}, 0
    for row in manifest.get("files", []):
        name = safe_name(row.get("path", ""))
        if name in expected:
            raise EvidenceError("installed runtime manifest contains duplicate paths")
        expected.add(name)
        target = root / name
        if target.is_symlink() or not target.resolve().is_relative_to(root.resolve()):
            raise EvidenceError("installed runtime path escapes its verified root")
        if sha256_file(target, MAX_TOTAL) != row.get("sha256") or target.stat().st_size != row.get("size"):
            raise EvidenceError("installed runtime bytes differ: " + name)
        if os.name != "nt" and target.stat().st_mode & 0o777 != row.get("mode"):
            raise EvidenceError("installed runtime file mode differs: " + name)
        total += target.stat().st_size
        if total > MAX_TOTAL:
            raise EvidenceError("installed runtime exceeds bound")
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise EvidenceError("installed runtime contains a symbolic link")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != expected:
        raise EvidenceError("installed runtime has unpinned or missing files")
    suffix = ".exe" if system == "windows" else ""
    if {"bin/" + name + suffix for name in REQUIRED} - expected:
        raise EvidenceError("installed runtime misses a required packaged helper")
    return manifest


def runtime_environment(root: Path) -> dict:
    env = dict(os.environ)
    lib = str((Path(root) / "lib").resolve())
    if platform.system() == "Linux":
        env["LD_LIBRARY_PATH"] = lib
    elif platform.system() == "Darwin":
        env["DYLD_LIBRARY_PATH"] = lib
    else:
        env["PATH"] = str((Path(root) / "bin").resolve()) + os.pathsep + env.get("PATH", "")
    env.update({"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_DATASETS_OFFLINE": "1"})
    return env


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--program", choices=REQUIRED + ("btx-native-qualify",), required=True)
    parser.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        verify_installed(args.root, args.manifest_sha256)
        suffix = ".exe" if platform.system() == "Windows" else ""
        executable = (args.root / "bin" / (args.program + suffix)).resolve(strict=True)
        tail = args.args[1:] if args.args[:1] == ["--"] else args.args
        os.execve(str(executable), [str(executable)] + tail, runtime_environment(args.root))
    except (EvidenceError, OSError, ValueError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
