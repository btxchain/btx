#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
"""ENC_RC GO/NO-GO aggregator for rc-episode-harness JSON reports — STUB.

See doc/btx-matmul-v4.4-resident-curriculum-unified-proposal-2026-07-20.md §8
(prototype & measurement roadmap G1–G4) and §R (normative exact-integer spec).

Mirrors contrib/matmul-v4/lt-gate.py / k2b-gate.py lightly: point at one or more
rc-episode-harness JSON paths (files or directories of *.json), print a single
GO / NO-GO verdict, and optionally write summary.json.

HARD RULE: invent nothing. Fail closed. GO requires extractmx_self_qual.status
== "pass" AND future G2–G4 fields filled; until then verdict is always NO-GO.
This tool never raises nMatMulRCHeight.

Usage:
  contrib/matmul-v4/rc-gate.py /tmp/rc.json --out /tmp/summary.json
  contrib/matmul-v4/rc-gate.py results/
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path
from typing import Any


def die(msg: str, code: int = 2) -> None:
    sys.stderr.write("rc-gate: " + msg + "\n")
    sys.exit(code)


def load_reports(paths: list[str]) -> list[dict[str, Any]]:
    files: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "*.json"))))
        else:
            files.append(p)
    if not files:
        die("no JSON reports found in the given path(s)")

    reports: list[dict[str, Any]] = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as e:
            die(f"cannot parse {f}: {e}")
        tool = data.get("tool")
        if tool not in (None, "rc-episode-harness"):
            # Allow bare stub JSONs without tool; reject foreign matmul reports.
            die(f"{f} is not an rc-episode-harness JSON (tool={tool!r})")
        data["_file"] = os.path.basename(f)
        data["_path"] = f
        reports.append(data)
    return reports


def gate_report(rep: dict[str, Any]) -> list[str]:
    """Return blocking reasons for one report (empty => locally clear)."""
    reasons: list[str] = []
    qual = rep.get("extractmx_self_qual")
    if not isinstance(qual, dict):
        reasons.append(f"{rep['_file']}: missing extractmx_self_qual object")
    else:
        status = qual.get("status")
        if status != "pass":
            reasons.append(
                f"{rep['_file']}: G1 ExtractMX self-qual status={status!r} "
                "(need status=='pass'; doc §8 Gate G1)"
            )

    # Future G2–G4: residency_sweep, k_curve, phase_wall_s, allocation caps.
    if rep.get("residency_sweep") in (None, {}, []):
        reasons.append(
            f"{rep['_file']}: G2 residency_sweep empty/null "
            "(Phase-1 Associative Recall Maze not measured)"
        )
    if rep.get("k_curve") in (None, {}, []):
        reasons.append(
            f"{rep['_file']}: G3 k_curve empty/null "
            "(Phase-2 k-curve not measured)"
        )
    walls = rep.get("phase_wall_s")
    if walls is None or (
        isinstance(walls, dict) and all(v is None for v in walls.values())
    ):
        reasons.append(
            f"{rep['_file']}: G4 phase_wall_s unset "
            "(integrated 3-phase episode not measured)"
        )

    caps = rep.get("allocation_cap_verdicts")
    if not isinstance(caps, dict):
        reasons.append(f"{rep['_file']}: missing allocation_cap_verdicts")
    else:
        for key in ("512MiB", "2GiB", "8GiB"):
            v = caps.get(key)
            if v != "pass":
                reasons.append(
                    f"{rep['_file']}: allocation_cap_verdicts[{key}]={v!r} "
                    "(need 'pass')"
                )
    return reasons


def aggregate(reports: list[dict[str, Any]]) -> dict[str, Any]:
    blockers: list[str] = []
    for rep in reports:
        blockers.extend(gate_report(rep))

    go = len(blockers) == 0
    verdict = "GO" if go else "NO-GO"
    summary = {
        "tool": "rc-gate",
        "schema_version": 1,
        "verdict": verdict,
        "go": go,
        "n_reports": len(reports),
        "reports": [
            {
                "file": r["_file"],
                "device_id": r.get("device_id"),
                "backend": r.get("backend"),
                "profile": r.get("profile"),
                "extractmx_self_qual_status": (
                    (r.get("extractmx_self_qual") or {}).get("status")
                ),
            }
            for r in reports
        ],
        "blocking_reasons": blockers,
        "consensus_note": (
            "nMatMulRCHeight remains INT32_MAX; ENC_RC activation is NO-GO until "
            "extractmx_self_qual.status=='pass' and G2–G4 fields are filled "
            "(doc §8 / §9). Offline tally only — never wires consensus."
        ),
    }
    return summary


def print_human(summary: dict[str, Any]) -> None:
    print("MatMul ENC_RC — GO/NO-GO aggregate verdict")
    print(f"  reports:  {summary['n_reports']}")
    for r in summary["reports"]:
        print(
            f"    - {r['file']}: device={r.get('device_id')} "
            f"backend={r.get('backend')} profile={r.get('profile')} "
            f"extractmx={r.get('extractmx_self_qual_status')!r}"
        )
    if summary["blocking_reasons"]:
        print("  blocking reasons:")
        for b in summary["blocking_reasons"]:
            print(f"    * {b}")
    else:
        print("  blocking reasons: (none)")
    print(f"  consensus: {summary['consensus_note']}")
    if summary["go"]:
        print("VERDICT: GO — G1–G4 satisfied in this offline tally.")
    else:
        print(
            "VERDICT: NO-GO — see blocking reasons. "
            "nMatMulRCHeight stays INT32_MAX."
        )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Aggregate ENC_RC rc-episode-harness JSONs into a fail-closed "
            "GO/NO-GO verdict (doc §8 / §R)."
        ),
    )
    ap.add_argument(
        "inputs",
        nargs="+",
        metavar="PATH",
        help="JSON file(s) and/or directories containing *.json reports",
    )
    ap.add_argument(
        "--out",
        default="summary.json",
        metavar="PATH",
        help="Write machine-readable summary JSON (default: summary.json)",
    )
    args = ap.parse_args()

    reports = load_reports(args.inputs)
    summary = aggregate(reports)
    print_human(summary)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Strip nothing — summary is already clean.
    out_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote:    {out_path}")

    # Exit 0 (GO) / 1 (NO-GO) / 2 (usage) — same idiom as k2b-gate / lt-gate.
    return 0 if summary["go"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
