#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
"""ENC_RC Stage E verification bake-off launcher.

Prefers the C++ binary `matmul-v4-rc-verify-bakeoff` (real toy measurements).
Does not emit stub numbers. Does not raise nMatMulRCHeight.

Usage:
  contrib/matmul-v4/rc-verify-bakeoff.py
  contrib/matmul-v4/rc-verify-bakeoff.py --out /tmp/bakeoff.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def die(msg: str, code: int = 2) -> None:
    sys.stderr.write("rc-verify-bakeoff: " + msg + "\n")
    sys.exit(code)


def find_binary() -> Path | None:
    env = os.environ.get("BTX_RC_VERIFY_BAKEOFF")
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    which = shutil.which("matmul-v4-rc-verify-bakeoff")
    if which:
        return Path(which)
    root = Path(__file__).resolve().parents[2]
    candidates = [
        root / "build" / "bin" / "matmul-v4-rc-verify-bakeoff",
        root / "build" / "src" / "matmul-v4-rc-verify-bakeoff",
    ]
    for d in sorted(root.glob("build*")):
        candidates.append(d / "bin" / "matmul-v4-rc-verify-bakeoff")
        candidates.append(d / "src" / "matmul-v4-rc-verify-bakeoff")
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c
    for d in sorted(root.glob("build*")):
        for hit in d.rglob("matmul-v4-rc-verify-bakeoff"):
            if hit.is_file() and os.access(hit, os.X_OK) and "CMakeFiles" not in str(hit):
                return hit
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "ENC_RC Stage E bake-off launcher. Delegates to "
            "matmul-v4-rc-verify-bakeoff (toy only). Production extrapolations "
            "are NOT EVIDENCE."
        ),
    )
    ap.add_argument("--out", default="", help="Optional path to write JSON body")
    ap.add_argument(
        "--print-leaning",
        action="store_true",
        help="Print E5 DECIDED direction reminder to stderr",
    )
    args = ap.parse_args()

    binary = find_binary()
    if binary is None:
        die(
            "matmul-v4-rc-verify-bakeoff not found. Build with CMake "
            "(target matmul-v4-rc-verify-bakeoff) or set BTX_RC_VERIFY_BAKEOFF.",
        )

    proc = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        die(f"binary failed rc={proc.returncode}: {proc.stderr}", code=proc.returncode or 2)

    # Binary prints JSON object then # comment lines.
    json_lines: list[str] = []
    comments: list[str] = []
    in_json = False
    depth = 0
    for line in proc.stdout.splitlines():
        if line.startswith("#"):
            comments.append(line)
            continue
        if not in_json and line.strip().startswith("{"):
            in_json = True
        if in_json:
            json_lines.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                in_json = False

    raw = "\n".join(json_lines)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        die(f"failed to parse bakeoff JSON: {e}\n---\n{proc.stdout[:2000]}")

    if args.out:
        Path(args.out).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)

    print(json.dumps(data, indent=2))
    for c in comments:
        print(c, file=sys.stderr)

    print(
        "E5 DECIDED: winner-only GKR/sumcheck. Fraud-proof deferred. "
        "Shrink is fallback if GKR verify fails Stage-I budget. "
        "See doc/btx-matmul-v4.5-rc-stage-e-winner-gkr-decision-2026-07-20.md. "
        "nMatMulRCHeight stays INT32_MAX.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
