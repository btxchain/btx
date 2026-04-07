#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Fail if placeholder SMILE helpers leak back into non-test code paths.

The commitment-derived placeholder spend-key helpers remain in-tree only for
test fixtures and historical comparison. Live BTX code must not call them.
"""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT / "src"
ALLOWED_PATHS = {
    SRC_DIR / "shielded" / "smile2" / "wallet_bridge.h",
    SRC_DIR / "shielded" / "smile2" / "wallet_bridge.cpp",
}
TOKENS = ("DeriveSmileKeyPair(", "BuildPlaceholderRingMember(")
SUFFIXES = (".h", ".hpp", ".cpp", ".cxx", ".cc")


def main() -> int:
    offenders = []
    for path in sorted(SRC_DIR.rglob("*")):
        if (
            path.is_dir()
            or path.suffix not in SUFFIXES
            or path in ALLOWED_PATHS
            or "test" in path.relative_to(SRC_DIR).parts
        ):
            continue
        text = path.read_text(encoding="utf-8")
        hits = [token for token in TOKENS if token in text]
        if hits:
            offenders.append((path.relative_to(ROOT), hits))

    if not offenders:
        return 0

    print("ERROR: placeholder SMILE key/ring helpers must not be used in non-test live code.")
    for offender, hits in offenders:
        print(f" - {offender}: {', '.join(hits)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
