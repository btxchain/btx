#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify that recorded evidence provenance describes real code.

Every artifact under ``doc/evidence`` may declare a ``source_revision`` and,
for production-golden corpora, a ``source_tree_fingerprint``. These strings
bind a measurement to the code that produced it. The in-process C++ gate can
only shape-check the hex; this tool resolves the commits and recomputes each
object-local revision/fingerprint pair.

Object-local binding matters. A document containing revision A plus
fingerprint B in one record and revision B plus fingerprint A in another must
not pass merely because its document-wide sets happen to contain both values.

Historical measurements whose source revision was never captured may be
excluded only through the explicit registry. Every exclusion is reported,
must state that it is not production-admissible, and is rejected by ``--strict``
if it no longer matches an artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


# Must stay in sync with multi-gpu-golden-corpus.sh and the production-golden
# policy. Any change in these paths invalidates evidence equivalence.
BUILD_RELEVANT = ("CMakeLists.txt", "cmake", "src", "contrib/matmul-v4")

# The inert manifest data file that holds the fingerprint is excluded from it.
# Its bytes are converted to a C++ byte array by fingerprinted CMake logic and
# parsed by fingerprinted C++, so the excluded surface cannot inject code.
# Sealing is otherwise a fixed point. Keep this identical to the shell helper.
EXCLUDED_FROM_FINGERPRINT = (
    b"src/matmul/matmul_v4_rc_production_golden_manifest.data",
)
# git_tip_sha is used by doc/evidence/cuda-blackwell-16gib-profile1-loaded-*/;
# omitting it meant that artifact's revision was never resolved at all.
REVISION_KEYS = ("source_revision", "git_tip", "git_tip_sha", "tip_sha")
FINGERPRINT_KEY = "source_tree_fingerprint"
DEFAULT_EXCLUSIONS = "contrib/matmul-v4/evidence-provenance-exclusions.json"
PRODUCTION_MANIFEST = Path(
    "src/matmul/matmul_v4_rc_production_golden_manifest.data"
)


def repo_root(start: Path) -> Path:
    out = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    )
    return Path(out.stdout.strip())


def revision_exists(root: Path, revision: str) -> bool:
    return subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{revision}^{{commit}}"],
        capture_output=True,
    ).returncode == 0


def tree_fingerprint(root: Path, revision: str) -> str | None:
    out = subprocess.run(
        [
            "git", "-C", str(root), "ls-tree", "-r", "--full-tree",
            revision, "--", *BUILD_RELEVANT,
        ],
        capture_output=True,
        check=False,
    )
    if out.returncode != 0 or not out.stdout:
        return None
    # git ls-tree emits "<mode> <type> <sha>\t<path>\n"; drop whole lines whose
    # path is excluded, preserving the trailing newline of every kept line so
    # this hashes exactly what the shell helper hashes.
    kept = [
        line
        for line in out.stdout.splitlines(keepends=True)
        if not any(
            line.rstrip(b"\n").endswith(b"\t" + excluded)
            for excluded in EXCLUDED_FROM_FINGERPRINT
        )
    ]
    return hashlib.sha256(b"".join(kept)).hexdigest()


def walk_objects(node, location: str = "$"):
    """Yield provenance fields grouped by their containing JSON object."""
    if isinstance(node, dict):
        revisions = {
            value
            for key, value in node.items()
            if key in REVISION_KEYS and isinstance(value, str)
        }
        fingerprints = {
            value
            for key, value in node.items()
            if key == FINGERPRINT_KEY and isinstance(value, str)
        }
        if revisions or fingerprints:
            yield location, revisions, fingerprints
        for key, value in node.items():
            yield from walk_objects(value, f"{location}.{key}")
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from walk_objects(item, f"{location}[{index}]")


def load_exclusions(
    root: Path, configured: str
) -> tuple[dict[tuple[str, str], str], list[str]]:
    path = Path(configured)
    if not path.is_absolute():
        path = root / path
    errors: list[str] = []
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return {}, [f"exclusion registry {path}: unreadable JSON ({exc})"]
    if payload.get("schema_version") != 1 or not isinstance(
        payload.get("exclusions"), list
    ):
        return {}, [
            f"exclusion registry {path}: expected schema_version=1 and exclusions array"
        ]

    exclusions: dict[tuple[str, str], str] = {}
    for index, entry in enumerate(payload["exclusions"]):
        label = f"exclusion registry {path}: entry {index}"
        if not isinstance(entry, dict):
            errors.append(f"{label} is not an object")
            continue
        evidence_path = entry.get("evidence_path")
        revision = entry.get("revision")
        reason = entry.get("reason")
        if not all(
            isinstance(value, str) and value.strip()
            for value in (evidence_path, revision, reason)
        ):
            errors.append(
                f"{label} requires nonempty evidence_path, revision, and reason"
            )
            continue
        relative = Path(evidence_path)
        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"{label} evidence_path must be repository-relative")
            continue
        if entry.get("production_admissible") is not False:
            errors.append(
                f"{label} must explicitly set production_admissible=false"
            )
            continue
        key = (relative.as_posix(), revision)
        if key in exclusions:
            errors.append(f"{label} duplicates {evidence_path} revision {revision}")
            continue
        exclusions[key] = reason.strip()
    return exclusions, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None, help="repository root (default: autodetect)")
    parser.add_argument("--evidence-dir", default="doc/evidence")
    parser.add_argument(
        "--exclusions", default=DEFAULT_EXCLUSIONS,
        help="explicit historical exclusion registry",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="fail on unbound fingerprints and stale exclusions",
    )
    args = parser.parse_args()

    root = Path(args.root) if args.root else repo_root(Path(__file__).resolve().parent)
    evidence = root / args.evidence_dir
    if not evidence.is_dir():
        print(f"verify-evidence-provenance: no such directory: {evidence}", file=sys.stderr)
        return 2

    exclusions, exclusion_errors = load_exclusions(root, args.exclusions)
    failures: list[str] = list(exclusion_errors)
    warnings: list[str] = []
    used_exclusions: set[tuple[str, str]] = set()
    checked_files = 0
    checked_revisions = 0

    for path in sorted(evidence.rglob("*.json")):
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"{path.relative_to(root)}: unreadable JSON ({exc})")
            continue

        objects = list(walk_objects(payload))
        if not objects:
            continue
        checked_files += 1
        relative_path = path.relative_to(root).as_posix()

        for location, revisions, fingerprints in objects:
            valid_revisions: list[str] = []
            for revision in sorted(revisions):
                checked_revisions += 1
                exclusion_key = (relative_path, revision)
                if exclusion_key in exclusions:
                    used_exclusions.add(exclusion_key)
                    print(
                        f"EXCLUDED {relative_path} {location}: revision {revision!r} "
                        f"({exclusions[exclusion_key]}; production_admissible=false)"
                    )
                    continue
                is_hex = 7 <= len(revision) <= 40 and all(
                    char in "0123456789abcdef" for char in revision.lower()
                )
                if not is_hex:
                    failures.append(
                        f"{relative_path} {location}: malformed revision {revision!r}"
                    )
                    continue
                if not revision_exists(root, revision):
                    failures.append(
                        f"{relative_path} {location}: revision {revision} does not "
                        "resolve to a commit in this repository"
                    )
                    continue
                valid_revisions.append(revision)

            for fingerprint in sorted(fingerprints):
                is_hex = len(fingerprint) == 64 and all(
                    char in "0123456789abcdef" for char in fingerprint.lower()
                )
                if not is_hex:
                    failures.append(
                        f"{relative_path} {location}: malformed fingerprint {fingerprint!r}"
                    )
                    continue
                if not revisions:
                    warnings.append(
                        f"{relative_path} {location}: fingerprint {fingerprint} has no "
                        "object-local revision to check it against"
                    )
                    continue
                for revision in valid_revisions:
                    actual = tree_fingerprint(root, revision)
                    if actual != fingerprint:
                        failures.append(
                            f"{relative_path} {location}: fingerprint {fingerprint} does "
                            f"not match revision {revision} ({actual})"
                        )

    if args.strict:
        for evidence_path, revision in sorted(set(exclusions) - used_exclusions):
            failures.append(
                f"unused historical exclusion: {evidence_path} revision {revision!r}"
            )

        # A populated production manifest is more than another provenance
        # string.  It is a release seal over an exact CUDA+Metal corpus and a
        # freeze commit.  Validate the raw artifacts, canonical headers,
        # provider metadata, harness identities, and freeze -> seal ancestry as
        # one atomic gate.  Historical fixture repositories without the
        # manifest are intentionally unaffected.
        production_manifest = root / PRODUCTION_MANIFEST
        if production_manifest.is_file():
            seal_script = Path(__file__).with_name(
                "verify-production-golden-seal.py"
            )
            seal = subprocess.run(
                [
                    sys.executable,
                    str(seal_script),
                    "seal",
                    "--root",
                    str(root),
                    "--manifest",
                    PRODUCTION_MANIFEST.as_posix(),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if seal.returncode:
                detail = (seal.stderr or seal.stdout).strip()
                failures.append(f"production golden seal failed: {detail}")
            elif seal.stdout.strip():
                print(seal.stdout.strip())

    for warning in warnings:
        print(f"WARN  {warning}")
    for failure in failures:
        print(f"FAIL  {failure}")
    print(
        f"verify-evidence-provenance: {checked_files} artifact(s), "
        f"{checked_revisions} revision reference(s), "
        f"{len(used_exclusions)} explicit exclusion(s), "
        f"{len(failures)} failure(s), {len(warnings)} warning(s)"
    )

    if failures:
        return 1
    if args.strict and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
