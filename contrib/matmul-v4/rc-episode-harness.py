#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
"""ENC_RC episode harness launcher — prefers the C++ measurement binary.

See doc/btx-matmul-v4.4-resident-curriculum-unified-proposal-2026-07-20.md §8 / §R.

Preferred path: subprocess `matmul-v4-rc-harness` (real CPU episodes, stub:false).
Fallback: refuse with exit 2 if the binary is missing (no fake stub JSON).

Usage:
  contrib/matmul-v4/rc-episode-harness.py --toy --out /tmp/rc.json
  contrib/matmul-v4/rc-episode-harness.py --backend cpu --episodes 3 --out /tmp/rc.json
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

VALID_PROFILES = ("episode", "extractmx")
DEFAULT_OUT = "rc-report.json"


def die(msg: str, code: int = 2) -> None:
    sys.stderr.write("rc-episode-harness: " + msg + "\n")
    sys.exit(code)


def find_harness_binary() -> Path | None:
    env = os.environ.get("BTX_RC_HARNESS")
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    which = shutil.which("matmul-v4-rc-harness")
    if which:
        return Path(which)
    root = Path(__file__).resolve().parents[2]
    candidates = [
        root / "build" / "bin" / "matmul-v4-rc-harness",
        root / "build-measure-cpu" / "bin" / "matmul-v4-rc-harness",
    ]
    # Also scan build-* dirs
    for d in sorted(root.glob("build*")):
        candidates.append(d / "bin" / "matmul-v4-rc-harness")
        candidates.append(d / "src" / "matmul-v4-rc-harness")
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c
    # find via name under build trees
    for d in sorted(root.glob("build*")):
        for hit in d.rglob("matmul-v4-rc-harness"):
            if hit.is_file() and os.access(hit, os.X_OK) and "CMakeFiles" not in str(hit):
                return hit
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "ENC_RC measurement harness launcher. Delegates to matmul-v4-rc-harness "
            "(real CPU runs). Does not emit stub JSON."
        ),
    )
    ap.add_argument(
        "--profile",
        default="episode",
        choices=VALID_PROFILES,
        help="Measurement profile (forwarded as note; C++ tool always runs episode)",
    )
    ap.add_argument("--backend", default="cpu", help="Backend id (default: cpu)")
    ap.add_argument(
        "--mem-cap",
        type=int,
        default=0,
        metavar="BYTES",
        help="Allocator memory cap in bytes (0 = unlimited)",
    )
    ap.add_argument("--out", default=DEFAULT_OUT, metavar="PATH", help="Output JSON path")
    ap.add_argument(
        "--toy",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Tiny dims (default: true). --no-toy refused by C++ harness.",
    )
    ap.add_argument("--episodes", type=int, default=3, help="Episode count (default: 3)")
    ap.add_argument("--rounds", type=int, default=0, help="Override rounds (0 = params default)")
    args = ap.parse_args()

    if args.mem_cap < 0:
        die("--mem-cap must be >= 0", 2)
    if args.episodes < 1:
        die("--episodes must be >= 1", 2)

    bin_path = find_harness_binary()
    if bin_path is None:
        die(
            "matmul-v4-rc-harness not found. Build it first:\n"
            "  cmake --build <build> --target matmul-v4-rc-harness\n"
            "Or set BTX_RC_HARNESS=/path/to/matmul-v4-rc-harness",
            2,
        )

    cmd = [
        str(bin_path),
        "--backend",
        args.backend,
        "--out",
        args.out,
        "--episodes",
        str(args.episodes),
        "--mem-cap",
        str(args.mem_cap),
    ]
    if args.toy:
        cmd.append("--toy")
    else:
        cmd.append("--no-toy")
    if args.rounds > 0:
        cmd.extend(["--rounds", str(args.rounds)])

    print(f"rc-episode-harness: exec {cmd[0]} (profile={args.profile})")
    try:
        proc = subprocess.run(cmd, check=False)
    except OSError as e:
        die(f"failed to exec {bin_path}: {e}", 2)
    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
