#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
"""ENC_RC GO/NO-GO aggregator for rc-episode-harness JSON reports.

See doc/btx-matmul-v4.4-resident-curriculum-unified-proposal-2026-07-20.md §8
(prototype & measurement roadmap G1–G4) and §R (normative exact-integer spec).

Mirrors contrib/matmul-v4/lt-gate.py / k2b-gate.py lightly: point at one or more
rc-episode-harness JSON paths (files or directories of *.json), print a single
GO / PARTIAL / NO-GO verdict, and optionally write summary.json.

HARD RULE: invent nothing. Fail closed.
  - G1 pass requires stub:false AND extractmx_self_qual.status=="pass"
  - Full GO requires G1–G4 real pass criteria (non-toy consensus-scale evidence)
  - Toy harness output with present G2–G4 fields yields PARTIAL (toy-pass), never GO
  - Never recommends raising nMatMulRCHeight

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
            die(f"{f} is not an rc-episode-harness JSON (tool={tool!r})")
        data["_file"] = os.path.basename(f)
        data["_path"] = f
        reports.append(data)
    return reports


def _walls_measured(walls: Any) -> bool:
    if not isinstance(walls, dict) or not walls:
        return False
    # Accept either short keys (phase1/phase2/phase3/total) or legacy long names.
    vals = [v for v in walls.values() if v is not None]
    return len(vals) > 0 and any(
        isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals
    )


def gate_report(rep: dict[str, Any]) -> dict[str, Any]:
    """Per-report gate statuses + blocking reasons."""
    reasons: list[str] = []
    toy = bool(rep.get("toy"))
    stub = rep.get("stub", True)
    if stub is True:
        # Honest stub path — G1 cannot pass.
        pass

    # --- G1 ---
    g1 = "fail"
    qual = rep.get("extractmx_self_qual")
    if not isinstance(qual, dict):
        reasons.append(f"{rep['_file']}: missing extractmx_self_qual object")
        g1 = "fail"
    elif stub is not False:
        status = qual.get("status")
        reasons.append(
            f"{rep['_file']}: G1 requires stub:false + status=='pass' "
            f"(got stub={stub!r} status={status!r})"
        )
        g1 = "fail"
    elif qual.get("status") == "pass":
        g1 = "pass"
    else:
        reasons.append(
            f"{rep['_file']}: G1 ExtractMX self-qual status={qual.get('status')!r} "
            "(need status=='pass'; doc §8 Gate G1)"
        )
        g1 = "fail"

    # --- G2 residency ---
    g2 = "fail"
    sweep = rep.get("residency_sweep")
    if sweep in (None, {}, []):
        reasons.append(
            f"{rep['_file']}: G2 residency_sweep empty/null "
            "(Phase-1 Associative Recall Maze not measured)"
        )
        g2 = "fail"
    elif toy:
        g2 = "toy-pass"
    else:
        g2 = "pass"

    # --- G3 k_curve ---
    g3 = "fail"
    kcurve = rep.get("k_curve")
    if kcurve in (None, {}, []):
        reasons.append(
            f"{rep['_file']}: G3 k_curve empty/null "
            "(Phase-2 k-curve not measured)"
        )
        g3 = "fail"
    elif toy:
        g3 = "toy-pass"
    else:
        g3 = "pass"

    # --- G4 phase walls ---
    g4 = "fail"
    walls = rep.get("phase_wall_s")
    if not _walls_measured(walls):
        reasons.append(
            f"{rep['_file']}: G4 phase_wall_s unset "
            "(integrated 3-phase episode not measured)"
        )
        g4 = "fail"
    elif toy:
        g4 = "toy-pass"
    else:
        g4 = "pass"

    # Allocation caps: toy skips are OK for PARTIAL; full GO needs pass.
    caps = rep.get("allocation_cap_verdicts")
    cap_ok_full = False
    if not isinstance(caps, dict):
        reasons.append(f"{rep['_file']}: missing allocation_cap_verdicts")
    else:
        cap_vals = [caps.get(k) for k in ("512MiB", "2GiB", "8GiB")]
        if toy:
            # skip/pass/toy-pass all acceptable for PARTIAL; reject not_run/fail.
            if any(v in (None, "not_run", "fail") for v in cap_vals):
                reasons.append(
                    f"{rep['_file']}: toy allocation_cap_verdicts incomplete/fail: {cap_vals}"
                )
        else:
            cap_ok_full = all(v == "pass" for v in cap_vals)
            if not cap_ok_full:
                for key in ("512MiB", "2GiB", "8GiB"):
                    v = caps.get(key)
                    if v != "pass":
                        reasons.append(
                            f"{rep['_file']}: allocation_cap_verdicts[{key}]={v!r} "
                            "(need 'pass' for full GO)"
                        )

    full_pass = (
        g1 == "pass"
        and g2 == "pass"
        and g3 == "pass"
        and g4 == "pass"
        and not toy
        and cap_ok_full
    )
    toy_partial = (
        g1 == "pass"
        and g2 == "toy-pass"
        and g3 == "toy-pass"
        and g4 == "toy-pass"
        and toy
        and stub is False
    )

    return {
        "g1": g1,
        "g2": g2,
        "g3": g3,
        "g4": g4,
        "full_pass": full_pass,
        "toy_partial": toy_partial,
        "reasons": reasons,
        "toy": toy,
        "stub": stub,
    }


def aggregate(reports: list[dict[str, Any]]) -> dict[str, Any]:
    blockers: list[str] = []
    per: list[dict[str, Any]] = []
    any_full = True
    any_partial = True

    for rep in reports:
        g = gate_report(rep)
        blockers.extend(g["reasons"])
        per.append(
            {
                "file": rep["_file"],
                "device_id": rep.get("device_id"),
                "backend": rep.get("backend"),
                "profile": rep.get("profile"),
                "stub": rep.get("stub"),
                "toy": rep.get("toy"),
                "extractmx_self_qual_status": (
                    (rep.get("extractmx_self_qual") or {}).get("status")
                ),
                "G1": g["g1"],
                "G2": g["g2"],
                "G3": g["g3"],
                "G4": g["g4"],
            }
        )
        if not g["full_pass"]:
            any_full = False
        if not g["toy_partial"]:
            any_partial = False

    if not reports:
        any_full = False
        any_partial = False

    if any_full:
        verdict = "GO"
        go = True
    elif any_partial and all(
        (r.get("G1") == "pass" and r.get("toy")) for r in per
    ):
        verdict = "PARTIAL"
        go = False
        blockers = [
            b
            for b in blockers
            if "G2 residency" not in b and "G3 k_curve" not in b and "G4 phase_wall" not in b
        ]
        blockers.append(
            "PARTIAL: toy G2–G4 present (toy-pass); full GO requires non-toy "
            "consensus-dim G2–G4 with pass criteria"
        )
    else:
        verdict = "NO-GO"
        go = False

    summary = {
        "tool": "rc-gate",
        "schema_version": 1,
        "verdict": verdict,
        "go": go,
        "n_reports": len(reports),
        "reports": per,
        "blocking_reasons": blockers,
        "consensus_note": (
            "nMatMulRCHeight remains INT32_MAX; ENC_RC activation is NO-GO. "
            "Offline tally never wires consensus and never recommends raising "
            "height from toy measurements (doc §8 / §9)."
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
            f"stub={r.get('stub')} toy={r.get('toy')} "
            f"G1={r.get('G1')} G2={r.get('G2')} G3={r.get('G3')} G4={r.get('G4')}"
        )
    if summary["blocking_reasons"]:
        print("  blocking reasons:")
        for b in summary["blocking_reasons"]:
            print(f"    * {b}")
    else:
        print("  blocking reasons: (none)")
    print(f"  consensus: {summary['consensus_note']}")
    v = summary["verdict"]
    if v == "GO":
        print("VERDICT: GO — G1–G4 satisfied in this offline tally.")
        print("  (Activation height still NO-GO — see consensus_note.)")
    elif v == "PARTIAL":
        print(
            "VERDICT: PARTIAL — G1 pass + toy G2–G4 present. "
            "nMatMulRCHeight stays INT32_MAX; not a raise-height signal."
        )
    else:
        print(
            "VERDICT: NO-GO — see blocking reasons. "
            "nMatMulRCHeight stays INT32_MAX."
        )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Aggregate ENC_RC rc-episode-harness JSONs into a fail-closed "
            "GO/PARTIAL/NO-GO verdict (doc §8 / §R)."
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
    out_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote:    {out_path}")

    # Exit 0 for GO or PARTIAL (measurement path succeeded); 1 for NO-GO; 2 usage.
    return 0 if summary["verdict"] in ("GO", "PARTIAL") else 1


if __name__ == "__main__":
    raise SystemExit(main())
