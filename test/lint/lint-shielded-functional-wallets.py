#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Fail if shielded functional tests skip encrypted-wallet setup.

This guards the launch policy that shielded key generation/import requires an
explicit encrypted-wallet flow in functional tests as well as production.
"""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
FUNCTIONAL_DIR = ROOT / "test" / "functional"
SHIELDED_APIS = ("z_getnewaddress(", "z_importviewingkey(")
SETUP_MARKERS = (
    "encryptwallet(",
    "encrypt_and_unlock_wallet(",
    "create_bridge_wallet(",
    "unlock_wallet(",
)


def main() -> int:
    offenders = []
    for path in sorted(FUNCTIONAL_DIR.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if not any(api in text for api in SHIELDED_APIS):
            continue
        if any(marker in text for marker in SETUP_MARKERS):
            continue
        offenders.append(path.relative_to(ROOT))

    if not offenders:
        return 0

    print("ERROR: shielded functional tests must explicitly set up encrypted wallets before shielded key APIs.")
    for offender in offenders:
        print(f" - {offender}")
    print("Expected one of:", ", ".join(SETUP_MARKERS))
    return 1


if __name__ == "__main__":
    sys.exit(main())
