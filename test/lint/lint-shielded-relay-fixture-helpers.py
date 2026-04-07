#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Keep relay-fixture helpers centralized in bridge_utils.

This prevents stale copies of the helper logic from drifting across
functionals and hiding binary/source mismatches behind opaque shielded
reject reasons.
"""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
FUNCTIONAL_DIR = ROOT / "test" / "functional"
SHARED_HELPER = FUNCTIONAL_DIR / "test_framework" / "bridge_utils.py"
DUPLICATE_MARKERS = (
    "def build_signed_shielded_relay_fixture_tx(",
    "def build_unsigned_shielded_relay_fixture_tx(",
    "gen_shielded_relay_fixture_tx",
)


def main() -> int:
    offenders = []
    for path in sorted(FUNCTIONAL_DIR.rglob("*.py")):
        if path == SHARED_HELPER:
            continue
        text = path.read_text(encoding="utf-8")
        if any(marker in text for marker in DUPLICATE_MARKERS):
            offenders.append(path.relative_to(ROOT))

    if not offenders:
        return 0

    print("ERROR: shielded relay fixture helpers must be imported from test_framework.bridge_utils.")
    for offender in offenders:
        print(f" - {offender}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
