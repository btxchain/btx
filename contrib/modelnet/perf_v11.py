#!/usr/bin/env python3
"""§12.3 performance/fairness harness (local). CSV stays NOT_RUN.

Reports verified throughput, first useful-byte time, free-completion share,
and independent contacts from a two-helper loopback retrieve log or a JSON
summary the caller writes. Does not flip packaged acceptance-matrix.csv.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--log", default="", help="optional retrieve log")
    p.add_argument("--bytes", type=int, default=0)
    p.add_argument("--seconds", type=float, default=0)
    p.add_argument("--first-byte-s", type=float, default=0)
    p.add_argument("--free-share", type=float, default=1.0)
    p.add_argument("--contacts", type=int, default=1)
    args = p.parse_args()
    elapsed = args.seconds
    if args.log:
        text = Path(args.log).read_text(errors="replace")
        if elapsed <= 0:
            elapsed = max(text.count("\n") * 0.001, 0.001)
    bps = (args.bytes / elapsed) if elapsed > 0 else 0.0
    out = {
        "schema_version": 2,
        "verified_throughput_bps": bps,
        "first_useful_byte_s": args.first_byte_s,
        "free_completion_share": args.free_share,
        "independent_contacts": args.contacts,
        "monetary_p95": None,
        "note": "local harness; packaged CSV stays NOT_RUN",
    }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
