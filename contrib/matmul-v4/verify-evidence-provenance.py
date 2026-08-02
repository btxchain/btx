#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify that recorded evidence provenance describes real code.

Every artifact under ``doc/evidence`` may declare a ``source_revision`` (and,
for production-golden corpora, a ``source_tree_fingerprint``). Those two strings
are the only link between a measurement and the code that produced it, and the
C++ comparator in ``matmul_v4_rc_production_canary.cpp`` only length-checks the
hex. A well-formed but non-existent commit id therefore passes every automated
check while attesting to nothing -- which is exactly what happened to the
final-freeze corpus before this tool existed.

This tool closes that gap by resolving each declared revision against the
repository and, where a fingerprint is present, recomputing it from that
revision's tree.

Usage:
    contrib/matmul-v4/verify-evidence-provenance.py [--root DIR] [--strict]

Exit status is non-zero when any declared revision does not resolve or any
declared fingerprint does not match its revision. ``--strict`` additionally
fails on artifacts that declare a fingerprint without a revision (or the
reverse), which cannot be cross-checked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

# Build-relevant paths. Must stay in sync with the fingerprint definition in
# contrib/matmul-v4/multi-gpu-golden-corpus.sh and with the policy in
# doc/btx-matmul-v4.7-production-golden-policy.md.
BUILD_RELEVANT = ("CMakeLists.txt", "cmake", "src")

REVISION_KEYS = ("source_revision", "git_tip", "tip_sha")
FINGERPRINT_KEY = "source_tree_fingerprint"


def repo_root(start: Path) -> Path:
    out = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    )
    return Path(out.stdout.strip())


def revision_exists(root: Path, rev: str) -> bool:
    return subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{rev}^{{commit}}"],
        capture_output=True,
    ).returncode == 0


def tree_fingerprint(root: Path, rev: str) -> str | None:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-tree", "-r", "--full-tree", rev, "--", *BUILD_RELEVANT],
        capture_output=True, check=False,
    )
    if out.returncode != 0 or not out.stdout:
        return None
    return hashlib.sha256(out.stdout).hexdigest()


def walk(node, found: dict[str, set[str]]) -> None:
    """Collect every provenance string anywhere in a JSON document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in REVISION_KEYS and isinstance(value, str):
                found.setdefault("revisions", set()).add(value)
            elif key == FINGERPRINT_KEY and isinstance(value, str):
                found.setdefault("fingerprints", set()).add(value)
            else:
                walk(value, found)
    elif isinstance(node, list):
        for item in node:
            walk(item, found)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None, help="repository root (default: autodetect)")
    parser.add_argument("--evidence-dir", default="doc/evidence")
    parser.add_argument("--strict", action="store_true",
                        help="also fail on provenance that cannot be cross-checked")
    args = parser.parse_args()

    root = Path(args.root) if args.root else repo_root(Path(__file__).resolve().parent)
    evidence = root / args.evidence_dir
    if not evidence.is_dir():
        print(f"verify-evidence-provenance: no such directory: {evidence}", file=sys.stderr)
        return 2

    failures: list[str] = []
    warnings: list[str] = []
    checked_files = 0
    checked_revisions = 0

    for path in sorted(evidence.rglob("*.json")):
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"{path.relative_to(root)}: unreadable JSON ({exc})")
            continue

        found: dict[str, set[str]] = {}
        walk(payload, found)
        revisions = found.get("revisions", set())
        fingerprints = found.get("fingerprints", set())
        if not revisions and not fingerprints:
            continue
        checked_files += 1

        for rev in sorted(revisions):
            checked_revisions += 1
            # Abbreviated ids are accepted when they resolve unambiguously;
            # older harness builds recorded 10-character short revisions.
            is_hex = 7 <= len(rev) <= 40 and all(
                c in "0123456789abcdef" for c in rev.lower()
            )
            if not is_hex:
                failures.append(f"{path.relative_to(root)}: malformed revision {rev!r}")
                continue
            if not revision_exists(root, rev):
                failures.append(
                    f"{path.relative_to(root)}: revision {rev} does not resolve to a commit "
                    "in this repository"
                )

        for fingerprint in sorted(fingerprints):
            resolvable = [r for r in sorted(revisions) if revision_exists(root, r)]
            if not resolvable:
                warnings.append(
                    f"{path.relative_to(root)}: fingerprint {fingerprint} has no resolvable "
                    "revision to check it against"
                )
                continue
            if not any(tree_fingerprint(root, r) == fingerprint for r in resolvable):
                actual = ", ".join(f"{r}={tree_fingerprint(root, r)}" for r in resolvable)
                failures.append(
                    f"{path.relative_to(root)}: fingerprint {fingerprint} matches none of "
                    f"its declared revisions ({actual})"
                )

    for warning in warnings:
        print(f"WARN  {warning}")
    for failure in failures:
        print(f"FAIL  {failure}")

    print(
        f"verify-evidence-provenance: {checked_files} artifact(s), "
        f"{checked_revisions} revision reference(s), "
        f"{len(failures)} failure(s), {len(warnings)} warning(s)"
    )

    if failures:
        return 1
    if args.strict and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
