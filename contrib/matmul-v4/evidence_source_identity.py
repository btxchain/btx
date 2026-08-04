#!/usr/bin/env python3
"""Fail-closed source and binary identity helpers for MatMul evidence tools."""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any


HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
FINGERPRINT_PATHS = ("CMakeLists.txt", "cmake", "src", "contrib/matmul-v4")
FINGERPRINT_EXCLUDE = (
    b"src/matmul/matmul_v4_rc_production_golden_manifest.data",
)


class EvidenceIdentityError(ValueError):
    pass


def require_hex(value: Any, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise EvidenceIdentityError(f"{field} is not canonical lowercase hex")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise EvidenceIdentityError(f"cannot hash {path.name}: {error}") from error
    return digest.hexdigest()


def resolve_commit(root: Path, revision: str) -> str:
    revision = require_hex(revision, HEX40, "source_revision")
    proc = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", f"{revision}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or proc.stdout.strip().lower() != revision:
        raise EvidenceIdentityError(
            f"source revision is not the exact commit {revision}"
        )
    return revision


def tree_fingerprint(root: Path, revision: str) -> str:
    revision = resolve_commit(root, revision)
    proc = subprocess.run(
        [
            "git", "-C", str(root), "ls-tree", "-r", "--full-tree", revision,
            "--", *FINGERPRINT_PATHS,
        ],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        raise EvidenceIdentityError(
            f"cannot fingerprint source revision: {revision}"
        )
    kept = [
        line for line in proc.stdout.splitlines(keepends=True)
        if not any(
            line.rstrip(b"\n").endswith(b"\t" + excluded)
            for excluded in FINGERPRINT_EXCLUDE
        )
    ]
    return hashlib.sha256(b"".join(kept)).hexdigest()


def verify_binary(path: Path, expected_sha256: str, field: str) -> str:
    expected = require_hex(expected_sha256, HEX64, field)
    if not path.is_file():
        raise EvidenceIdentityError(f"{field} binary is not a file: {path}")
    actual = sha256_file(path)
    if actual != expected:
        raise EvidenceIdentityError(
            f"{field} SHA256 mismatch: expected {expected}, got {actual}"
        )
    return actual


def validate_canary_build_identity(
    canary: dict[str, Any], *, revision: str, fingerprint: str, prefix: str,
) -> None:
    revision = require_hex(revision, HEX40, "source_revision")
    fingerprint = require_hex(fingerprint, HEX64, "source_tree_fingerprint")
    if require_hex(
        canary.get("build_source_revision"), HEX40,
        f"{prefix}.build_source_revision",
    ) != revision:
        raise EvidenceIdentityError(
            f"{prefix}.build_source_revision does not match requested revision"
        )
    if require_hex(
        canary.get("build_source_tree_fingerprint"), HEX64,
        f"{prefix}.build_source_tree_fingerprint",
    ) != fingerprint:
        raise EvidenceIdentityError(
            f"{prefix}.build_source_tree_fingerprint mismatch"
        )
    if canary.get("build_source_dirty") is not False:
        raise EvidenceIdentityError(f"{prefix}.build_source_dirty must be false")
    if canary.get("build_provenance_matches") is not True:
        raise EvidenceIdentityError(
            f"{prefix}.build_provenance_matches must be true"
        )
