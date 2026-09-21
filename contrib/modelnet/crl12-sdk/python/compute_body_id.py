#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""CLI: print body_id for an HCP envelope JSON file (object_type + body)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from btx_crl12 import body_id  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: compute_body_id.py ENVELOPE.json", file=sys.stderr)
        return 2
    env = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(body_id(env["object_type"], env["body"]), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
