#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Recompute HCP/1 body_id for each unsigned example envelope.

Imports body_id / canonical_body from btx_hcp in this directory. Does not
submit intents, sign spends, or talk to a wallet. automatic_spend_atoms stays 0.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from btx_hcp import body_id, canonical_body  # noqa: E402

EXAMPLES_DIR = Path(
    "/home/administrator/btx-0.34.7-private/src/modelnet/hcp/examples"
)


def main() -> int:
    files = sorted(EXAMPLES_DIR.glob("*.unsigned.json"))
    if not files:
        print(f"FAIL no *.unsigned.json under {EXAMPLES_DIR}")
        return 1

    matched = 0
    failed = 0
    for path in files:
        with path.open(encoding="utf-8") as fh:
            env = json.load(fh)
        kind = env.get("object_type")
        body = env.get("body")
        expected = env.get("body_id")
        if not isinstance(kind, str) or not isinstance(body, dict) or not isinstance(expected, str):
            print(f"FAIL {path.name} missing object_type/body/body_id")
            failed += 1
            continue
        canon = canonical_body(body)
        if not isinstance(canon, (bytes, bytearray)) or not canon:
            print(f"FAIL {path.name} canonical_body empty")
            failed += 1
            continue
        got = body_id(kind, body)
        if got == expected:
            print(f"PASS {path.name}")
            matched += 1
        else:
            print(f"FAIL {path.name}")
            print(f"  object_type={kind}")
            print(f"  expected={expected}")
            print(f"  got     ={got}")
            print(f"  canonical_body_len={len(canon)}")
            failed += 1

    print(f"{matched}/{len(files)} matched")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
