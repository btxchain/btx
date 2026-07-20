#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
"""ENC_RC episode / ExtractMX measurement harness — STUB (Step 1–4 surface).

See doc/btx-matmul-v4.4-resident-curriculum-unified-proposal-2026-07-20.md §8
(prototype & measurement roadmap G1–G4) and §R (normative exact-integer spec).

WHAT THIS IS. Prototype CLI surface for the Resident Curriculum measurement
campaign. Emits ONE machine-readable JSON per invocation so rc-gate.py can
aggregate later. Extends the measure-hardware.sh / *-gate.py idiom.

WHAT THIS IS NOT. This stub does NOT run ExtractMX self-qual, Phase-1 residency
sweeps, Phase-2 k-curves, or integrated 3-phase episodes. It does NOT touch
C++ episode sources and never raises nMatMulRCHeight. Activation stays NO-GO.

Usage:
  contrib/matmul-v4/rc-episode-harness.py --profile extractmx --backend cpu
  contrib/matmul-v4/rc-episode-harness.py --profile episode --toy --out /tmp/rc.json
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

VALID_PROFILES = ("episode", "extractmx")
DEFAULT_OUT = "rc-report.json"


def die(msg: str, code: int = 2) -> None:
    sys.stderr.write("rc-episode-harness: " + msg + "\n")
    sys.exit(code)


def build_stub_report(args: argparse.Namespace) -> dict:
    """Fill the §8 report shape with honest not_run / null placeholders."""
    # extractmx profile acknowledges the G1 surface was requested but not executed.
    qual_status = "pending" if args.profile == "extractmx" else "not_run"
    return {
        "tool": "rc-episode-harness",
        "schema_version": 1,
        "stub": True,
        "device_id": "cpu-ref" if args.backend == "cpu" else f"{args.backend}:{platform.node()}",
        "backend": args.backend,
        "profile": args.profile,
        "mem_cap_bytes": int(args.mem_cap),
        "toy": bool(args.toy),
        "extractmx_self_qual": {
            "status": qual_status,
            "episodes": None,
            "boundary_vectors": (
                "not exercised — stub only; G1 requires ≥1e4 episodes/platform "
                "incl. high-magnitude boundary vectors with on-device runtime markers "
                "(doc §8 step 1 / Gate G1)"
            ),
            "digest_vs_reference": None,
        },
        "phase_wall_s": {
            "phase1_associative_recall": None,
            "phase2_micro_training": None,
            "phase3_tile_tree": None,
        },
        "k_curve": None,
        "residency_sweep": None,
        "allocation_cap_verdicts": {
            "512MiB": "not_run",
            "2GiB": "not_run",
            "8GiB": "not_run",
        },
        "consensus_note": (
            "nMatMulRCHeight remains INT32_MAX; ENC_RC activation is NO-GO until "
            "G1–G4 measurement gates pass (doc §8 / §9). This stub never raises height."
        ),
    }


def print_summary(report: dict, out_path: Path) -> None:
    print("MatMul ENC_RC — episode harness (STUB)")
    print(f"  device_id:   {report['device_id']}")
    print(f"  backend:     {report['backend']}")
    print(f"  profile:     {report['profile']}")
    print(f"  mem_cap:     {report['mem_cap_bytes']} bytes"
          + (" (unlimited)" if report["mem_cap_bytes"] == 0 else ""))
    print(f"  toy dims:    {report['toy']}")
    qual = report["extractmx_self_qual"]
    print(f"  ExtractMX:   status={qual['status']!r} (boundary vectors not exercised)")
    print(f"  phase_wall:  all null (not measured)")
    print(f"  k_curve:     null")
    print(f"  residency:   null")
    caps = report["allocation_cap_verdicts"]
    print(f"  alloc caps:  " + ", ".join(f"{k}={v}" for k, v in caps.items()))
    print(f"  consensus:   {report['consensus_note']}")
    print(f"  wrote:       {out_path}")
    print("VERDICT hint: NO-GO (stub — no G1–G4 data).")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="ENC_RC measurement harness stub (§8 / §R). Emits one JSON; does not run C++ episodes.",
    )
    ap.add_argument(
        "--profile",
        default="episode",
        choices=VALID_PROFILES,
        help="Measurement profile: extractmx (G1) or episode (G2–G4 surface; default)",
    )
    ap.add_argument(
        "--backend",
        default="cpu",
        help="Backend id (stub accepts any string; default: cpu)",
    )
    ap.add_argument(
        "--mem-cap",
        type=int,
        default=0,
        metavar="BYTES",
        help="Allocator memory cap in bytes (0 = unlimited; never cgroups)",
    )
    ap.add_argument(
        "--out",
        default=DEFAULT_OUT,
        metavar="PATH",
        help=f"Output JSON path (default: {DEFAULT_OUT})",
    )
    ap.add_argument(
        "--toy",
        action="store_true",
        help="Request tiny dims (recorded in JSON; stub does not execute workloads)",
    )
    args = ap.parse_args()

    if args.profile not in VALID_PROFILES:
        # argparse choices normally catch this; keep explicit exit 2 for unknown.
        die(f"unknown --profile {args.profile!r}; use episode|extractmx", 2)

    if args.mem_cap < 0:
        die("--mem-cap must be >= 0", 2)

    report = build_stub_report(args)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print_summary(report, out_path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as e:  # pragma: no cover — stub should not raise
        die(str(e), 2)
