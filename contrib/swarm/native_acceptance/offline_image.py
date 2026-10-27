#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Build and verify deterministic, content-pinned BTX offline runtime archives.

No download is performed. Every input is a local pinned file. The manifest is
cryptographically bound by the separately published archive SHA-256. An archive
proves packaging integrity; native launch and confinement need separate receipts.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile

try:
    from .evidence import EvidenceError, HEX64, atomic_json, canonical, sha256_file, strict_json
except ImportError:
    from evidence import EvidenceError, HEX64, atomic_json, canonical, sha256_file, strict_json

SCHEMA = "BTX-OFFLINE-RUNTIME/1"
REQUIRED = ("btxd", "btx-cli", "btx-modeld", "btx-guardd", "btx-hcpd")
PLATFORMS = {"linux-x86_64", "linux-aarch64", "macos-arm64", "macos-x86_64", "windows-x86_64"}
MAX_MEMBERS = 20000
MAX_TOTAL = 64 * 1024 ** 3
MAX_MANIFEST = 8 * 1024 ** 2


def safe_name(name: str) -> str:
    if not isinstance(name, str) or not name or "\\" in name or "\0" in name:
        raise EvidenceError("invalid archive member name")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {".", "..", ""} for part in name.split("/")):
        raise EvidenceError("archive member escapes runtime root")
    if ":" in name or name.endswith("/") or any(ord(c) < 32 for c in name):
        raise EvidenceError("nonportable archive member")
    return name


def validate_lock(lock: dict) -> list[dict]:
    if lock.get("schema") != "BTX-OFFLINE-LOCK/1" or lock.get("platform") not in PLATFORMS:
        raise EvidenceError("invalid offline image lock")
    if not re.fullmatch(r"[0-9a-f]{40}", str(lock.get("source_commit", ""))):
        raise EvidenceError("offline image requires a pinned source commit")
    if not HEX64.fullmatch(str(lock.get("source_tree_sha256", ""))):
        raise EvidenceError("offline image requires the complete candidate source digest")
    entries = lock.get("files", [])
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_MEMBERS:
        raise EvidenceError("invalid runtime file count")
    names, cases, total = set(), set(), 0
    for entry in entries:
        name = safe_name(entry.get("path", ""))
        if name == "manifest.json" or name in names or name.casefold() in cases:
            raise EvidenceError("duplicate, case-conflicting, or reserved runtime path")
        names.add(name)
        cases.add(name.casefold())
        local = Path(entry.get("source", ""))
        if not local.is_absolute() or not HEX64.fullmatch(str(entry.get("sha256", ""))):
            raise EvidenceError("runtime inputs require absolute local paths and SHA-256 pins")
        if sha256_file(local, MAX_TOTAL) != entry["sha256"]:
            raise EvidenceError("runtime input digest mismatch: " + name)
        if type(entry.get("executable", False)) is not bool:
            raise EvidenceError("invalid executable mode")
        total += local.stat().st_size
    if total > MAX_TOTAL:
        raise EvidenceError("offline image exceeds total size ceiling")
    suffix = ".exe" if lock["platform"].startswith("windows-") else ""
    missing = {"bin/" + item + suffix for item in REQUIRED} - names
    if missing:
        raise EvidenceError("missing required native runtime binaries: " + ", ".join(sorted(missing)))
    for entry in entries:
        if entry["path"].startswith("bin/") and not entry.get("executable", False):
            raise EvidenceError("native runtime binaries require executable metadata")
    # Runtimes, tokenizer/configuration files, and licenses are pinned explicitly;
    # a manifest cannot claim dependencies are present without naming their bytes.
    if not isinstance(lock.get("dependency_closure"), list) or not lock["dependency_closure"]:
        raise EvidenceError("dependency closure must enumerate exact packaged paths")
    if any(item not in names for item in lock["dependency_closure"]):
        raise EvidenceError("a declared runtime dependency is absent")
    return entries


def _tar_info(name: str, size: int, executable: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o755 if executable else 0o644
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ""
    return info


def build(lock: dict, output: Path) -> dict:
    entries = validate_lock(lock)
    manifest = {"schema": SCHEMA, "platform": lock["platform"],
                "source_commit": lock["source_commit"], "source_tree_sha256": lock["source_tree_sha256"],
                "dependency_closure": lock["dependency_closure"],
                "files": [{"path": item["path"], "sha256": item["sha256"],
                           "size": Path(item["source"]).stat().st_size,
                           "mode": 0o755 if item.get("executable", False) else 0o644}
                          for item in sorted(entries, key=lambda item: item["path"])],
                "native_qualification": "NOT_RUN", "automatic_spend_atoms": "0"}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or output.exists():
        raise EvidenceError("offline output must be a new path")
    fd, temporary = tempfile.mkstemp(prefix=".runtime-build-", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0, compresslevel=9) as gz:
                with tarfile.open(mode="w|", fileobj=gz, format=tarfile.USTAR_FORMAT) as archive:
                    raw = canonical(manifest)
                    archive.addfile(_tar_info("manifest.json", len(raw)), io.BytesIO(raw))
                    for entry in sorted(entries, key=lambda item: item["path"]):
                        path = Path(entry["source"])
                        with path.open("rb") as contents:
                            archive.addfile(_tar_info(entry["path"], path.stat().st_size,
                                                      entry.get("executable", False)), contents)
                        if sha256_file(path, MAX_TOTAL) != entry["sha256"]:
                            raise EvidenceError("runtime input changed during archive creation")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        archive_digest = sha256_file(output, MAX_TOTAL)
        verify(output, archive_digest)
        return {"archive": str(output), "sha256": archive_digest, "manifest_sha256": hashlib.sha256(canonical(manifest)).hexdigest(),
                "platform": lock["platform"], "files": len(entries), "native_qualification": "NOT_RUN"}
    except Exception:
        if output.exists():
            output.unlink()
        raise
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def verify(archive_path: Path, expected_sha256: str, destination: Path | None = None) -> dict:
    if not HEX64.fullmatch(expected_sha256) or sha256_file(archive_path, MAX_TOTAL) != expected_sha256:
        raise EvidenceError("offline archive digest mismatch")
    # Validate every member before creating the destination; never call extractall.
    manifest, manifest_bytes, records, seen, total = None, None, [], set(), 0
    with tarfile.open(archive_path, "r:gz") as archive:
        for index, info in enumerate(archive):
            name = safe_name(info.name)
            if index > MAX_MEMBERS or name.casefold() in seen or not info.isfile() or info.islnk() or info.issym():
                raise EvidenceError("invalid, duplicated, or nonregular archive member")
            seen.add(name.casefold())
            if info.mode not in {0o644, 0o755} or info.uid or info.gid or info.mtime:
                raise EvidenceError("noncanonical offline runtime metadata")
            total += info.size
            if info.size < 0 or total > MAX_TOTAL:
                raise EvidenceError("offline archive expands beyond size bound")
            stream = archive.extractfile(info)
            if stream is None:
                raise EvidenceError("archive member has no bytes")
            if index == 0:
                if name != "manifest.json" or info.size > MAX_MANIFEST:
                    raise EvidenceError("offline image must begin with a bounded manifest")
                manifest_bytes = stream.read(MAX_MANIFEST + 1)
                manifest = strict_json(manifest_bytes)
                if manifest.get("schema") != SCHEMA or manifest.get("platform") not in PLATFORMS:
                    raise EvidenceError("invalid offline runtime manifest")
                if not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("source_commit", ""))) or not HEX64.fullmatch(str(manifest.get("source_tree_sha256", ""))):
                    raise EvidenceError("offline runtime source identity is missing or malformed")
                continue
            hasher, size = hashlib.sha256(), 0
            while block := stream.read(1024 * 1024):
                size += len(block)
                hasher.update(block)
            if size != info.size:
                raise EvidenceError("truncated runtime file")
            records.append({"path": name, "sha256": hasher.hexdigest(), "size": size, "mode": info.mode})
    if manifest is None or records != manifest.get("files"):
        raise EvidenceError("archive contents do not equal the pinned manifest")
    if not records:
        raise EvidenceError("empty offline runtime")
    suffix = ".exe" if manifest["platform"].startswith("windows-") else ""
    names = {row["path"] for row in records}
    if {"bin/" + item + suffix for item in REQUIRED} - names:
        raise EvidenceError("incomplete native runtime image")
    if not manifest.get("dependency_closure") or any(item not in names for item in manifest["dependency_closure"]):
        raise EvidenceError("runtime dependency closure incomplete")
    if destination is not None:
        destination = Path(destination)
        if destination.exists() or destination.is_symlink():
            raise EvidenceError("extract destination must not already exist")
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".runtime-extract-", dir=destination.parent))
        try:
            expected = {row["path"]: row for row in records}
            expected["manifest.json"] = {"size": len(manifest_bytes), "mode": 0o644,
                                         "sha256": hashlib.sha256(manifest_bytes).hexdigest()}
            extracted = set()
            with tarfile.open(archive_path, "r:gz") as archive:
                for info in archive:
                    name = safe_name(info.name)
                    row = expected.get(name)
                    if row is None or name in extracted or not info.isfile() or info.islnk() or info.issym() or info.size != row["size"] or info.mode != row["mode"]:
                        raise EvidenceError("archive member changed between verification and extraction")
                    extracted.add(name)
                    target = staging / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as output:
                        shutil.copyfileobj(archive.extractfile(info), output, length=1024 * 1024)
                    target.chmod(info.mode)
                    if sha256_file(target, MAX_TOTAL) != row["sha256"]:
                        raise EvidenceError("archive bytes changed between verification and extraction")
            if extracted != set(expected):
                raise EvidenceError("archive lost members between verification and extraction")
            # Recheck the actual extracted bytes before exposing the tree.
            for row in records:
                if sha256_file(staging / row["path"], MAX_TOTAL) != row["sha256"]:
                    raise EvidenceError("extracted runtime digest mismatch")
            if sha256_file(archive_path, MAX_TOTAL) != expected_sha256:
                raise EvidenceError("offline archive changed during extraction")
            os.rename(staging, destination)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    return {"schema": "BTX-OFFLINE-VERIFY/1", "archive_sha256": expected_sha256,
            "platform": manifest["platform"], "source_commit": manifest["source_commit"],
            "source_tree_sha256": manifest["source_tree_sha256"], "files_verified": len(records),
            "bytes_verified": sum(item["size"] for item in records), "integrity_verified": True,
            "native_qualification": "NOT_RUN"}


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("build")
    make.add_argument("--lock", type=Path, required=True)
    make.add_argument("--out", type=Path, required=True)
    check = commands.add_parser("verify")
    check.add_argument("--archive", type=Path, required=True)
    check.add_argument("--sha256", required=True)
    check.add_argument("--extract", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build(strict_json(args.lock.read_bytes()), args.out)
            atomic_json(args.out.with_name(args.out.name + ".receipt.json"), result)
        else:
            result = verify(args.archive, args.sha256, args.extract)
        print(json.dumps(result, indent=2))
        return 0
    except (EvidenceError, OSError, tarfile.TarError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "native_qualification": "NOT_RUN"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
