#!/usr/bin/env python3
"""Fail lint if marker keywords remain in first-party source/test paths.

This check is intentionally scoped to first-party code and tests. It searches
for standalone marker words to avoid false positives in fixture blobs.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# First-party scope requested by project policy.
PATHS = [
    "src/wallet",
    "src/rpc",
    "src/util",
    "src/validation.cpp",
    "src/test",
    "test/functional",
]

# Standalone marker words only.
PATTERN = r"\\b(" + "|".join(["TO-DO", "FIX-ME", "X{3}"]) + r")\\b"


def main() -> int:
    cmd = [
        "git",
        "--no-pager",
        "grep",
        "-nI",
        "--perl-regexp",
        PATTERN,
        "--",
        *PATHS,
    ]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode == 1:
        return 0
    if proc.returncode == 0:
        sys.stderr.write(
            "Marker keywords remain in first-party paths. Remove TO-DO/FIX-ME/X{3}:\n"
        )
        sys.stderr.write(proc.stdout)
        return 1

    # Any other return code indicates command failure.
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
