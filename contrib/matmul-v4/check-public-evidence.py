#!/usr/bin/env python3
"""Fail closed when public MatMul evidence contains creator-machine details."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PATHS = (
    REPO_ROOT / "doc/evidence",
    REPO_ROOT / "contrib/matmul-v4/two-node-trusted-mirror-rehearsal.py",
)

# Public evidence may name an OS and hardware *class*. It must not carry the
# creator's account, workspace, temporary directory, credentials, or network
# identity. Keep this list intentionally narrow enough that ordinary technical
# prose and example paths elsewhere in the repository are unaffected.
FORBIDDEN_TEXT = (
    ("macOS user path", re.compile(r"/Users/[^/\s]+/")),
    ("Unix home path", re.compile(r"/home/[^/\s]+/")),
    ("creator temporary path", re.compile(r"/(?:private/)?tmp/[^\s`\"']+")),
    ("mDNS hostname", re.compile(r"\b[A-Z0-9][A-Z0-9._-]*\.local\b", re.IGNORECASE)),
    ("Windows user path", re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+[\\/]", re.IGNORECASE)),
    ("email address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("private key filename", re.compile(r"\b(?:github|porkbun|digitalocean|api|secret)\.(?:key|token)\b", re.IGNORECASE)),
    ("SSH private key filename", re.compile(r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b", re.IGNORECASE)),
)

FORBIDDEN_JSON_KEYS = {
    "cwd",
    "env",
    "environment",
    "home",
    "hostname",
    "ip_address",
    "mac_address",
    "output_path",
    "pwd",
    "source_path",
    "user",
    "username",
    "workdir",
    "workspace",
}


def evidence_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.is_file())
        elif path.is_file():
            yield path
        else:
            raise FileNotFoundError(path)


def walk_json_keys(value: Any, prefix: str = "$") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            yield prefix, key_text
            yield from walk_json_keys(item, f"{prefix}.{key_text}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_json_keys(item, f"{prefix}[{index}]")


def check_file(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [f"{path}: non-UTF-8 evidence is not reviewable as public text"]

    failures: list[str] = []
    for label, pattern in FORBIDDEN_TEXT:
        match = pattern.search(text)
        if match:
            failures.append(f"{path}: contains {label}: {match.group(0)!r}")

    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as error:
            failures.append(f"{path}: malformed JSON: {error}")
        else:
            for prefix, key in walk_json_keys(payload):
                if key.lower() in FORBIDDEN_JSON_KEYS:
                    failures.append(f"{path}: forbidden identity/path key {prefix}.{key}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Evidence files or directories (defaults to every committed evidence artifact and publication helper)",
    )
    args = parser.parse_args()

    failures: list[str] = []
    try:
        files = list(evidence_files(args.paths or DEFAULT_PATHS))
    except FileNotFoundError as error:
        print(f"missing evidence path: {error}", file=sys.stderr)
        return 1
    if not files:
        print("no evidence files selected", file=sys.stderr)
        return 1

    for path in files:
        failures.extend(check_file(path))
    if failures:
        print("public MatMul evidence privacy check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"public MatMul evidence privacy check passed ({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
