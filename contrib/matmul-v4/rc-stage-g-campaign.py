#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
"""ENC_RC Stage G same-tip campaign driver (CPU-box honest path).

Drives multi-run campaigns for profiles:
  coupled | coupled-medium | rc-toy | rc-medium

Emits campaign JSON matching rc-gate schema (evidence_kind, device_resident,
tip provenance, walls, RSS, variance across ≥3 runs).

HARD RULES:
  - Invent nothing. Real chrono walls only.
  - Interconnect NVLink-vs-PCIe model is SIMULATED / NOT Stage-I gate 4 evidence.
  - Missing GPU/B200/NVLink campaigns are explicit blockers.
  - Never recommends raising nMatMulRCHeight (stays INT32_MAX).

Usage:
  contrib/matmul-v4/rc-stage-g-campaign.py --profile rc-toy --runs 5 \\
      --out /tmp/stage-g-rc-toy.json
  contrib/matmul-v4/rc-stage-g-campaign.py --all --runs 5 --outdir /tmp/stage-g
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

VALID_PROFILES = ("coupled", "coupled-medium", "rc-toy", "rc-medium")
STAGE_I_GATE4_MIN = 7.0


def die(msg: str, code: int = 2) -> None:
    sys.stderr.write("rc-stage-g-campaign: " + msg + "\n")
    sys.exit(code)


def git_tip(root: Path) -> str:
    env = os.environ.get("BTX_SOURCE_REVISION")
    if env and env.strip():
        return env.strip()
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True, stderr=subprocess.DEVNULL
        )
        return out.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def find_harness(root: Path) -> Path:
    env = os.environ.get("BTX_RC_HARNESS")
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    which = shutil.which("matmul-v4-rc-harness")
    if which:
        return Path(which)
    for d in sorted(root.glob("build*")):
        for hit in d.rglob("matmul-v4-rc-harness"):
            if hit.is_file() and os.access(hit, os.X_OK) and "CMakeFiles" not in str(hit):
                return hit
    die("matmul-v4-rc-harness not found; build target matmul-v4-rc-harness first")


def coeff_var(xs: list[float]) -> float:
    if len(xs) < 2:
        return 0.0
    mean = statistics.mean(xs)
    if not (mean > 0.0):
        return 0.0
    return statistics.stdev(xs) / mean


def simulate_netcost(
    fabric_us: float = 5.0, pcie_us: float = 80.0, barriers: int = 4
) -> dict[str, Any]:
    """SIMULATED interconnect model — NOT Stage-I gate 4 evidence."""
    fab = fabric_us * barriers
    pci = pcie_us * barriers
    factor = (pci / fab) if fab > 0 else 0.0
    return {
        "simulated": True,
        "stage_i_gate4_evidence": False,
        "label": (
            "SIMULATED / NOT EVIDENCE for Stage-I gate 4 "
            f"(≥{STAGE_I_GATE4_MIN}× on same chips)"
        ),
        "fabric_us_per_barrier": fabric_us,
        "pcie_us_per_barrier": pcie_us,
        "barriers": barriers,
        "fabric_exchange_us": fab,
        "pcie_exchange_us": pci,
        "exchange_slowdown_factor": factor,
        "stage_i_gate4_threshold": STAGE_I_GATE4_MIN,
        # Simulated results NEVER pass Stage-I gate 4.
        "stage_i_gate4_pass": False,
        "note": (
            "Software latency inject only. Real B200/MI355X NVLink-vs-PCIe "
            "silicon campaigns still required."
        ),
    }


def nvidia_ok() -> bool:
    try:
        r = subprocess.run(
            ["nvidia-smi"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return r.returncode == 0
    except OSError:
        return False


def run_one(
    harness: Path,
    profile: str,
    tip: str,
    out_path: Path,
    episodes: int,
) -> dict[str, Any]:
    cmd = [
        str(harness),
        "--backend",
        "cpu",
        "--episodes",
        str(episodes),
        "--out",
        str(out_path),
    ]
    if tip:
        cmd.extend(["--source-revision", tip])

    if profile == "rc-toy":
        cmd.append("--toy")
    elif profile == "rc-medium":
        cmd.append("--medium")
    elif profile == "coupled":
        cmd.append("--coupled")
    elif profile == "coupled-medium":
        cmd.append("--coupled-medium")
    else:
        die(f"unknown profile {profile}")

    # Mode sweep only applies to RC episode profiles.
    if profile.startswith("rc-"):
        cmd.append("--mode-sweep")

    print(f"rc-stage-g-campaign: exec {' '.join(cmd)}")
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, check=False)
    wall = time.perf_counter() - t0
    if proc.returncode != 0:
        die(f"harness failed (rc={proc.returncode}) for profile={profile}", 1)
    with open(out_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data["_campaign_proc_wall_s"] = wall
    return data


def aggregate_runs(
    profile: str, tip: str, runs: list[dict[str, Any]]
) -> dict[str, Any]:
    walls = []
    rss = []
    for r in runs:
        pw = r.get("phase_wall_s") or {}
        w = pw.get("total")
        if isinstance(w, (int, float)):
            walls.append(float(w))
        rk = r.get("peak_rss_kib")
        if isinstance(rk, (int, float)):
            rss.append(float(rk))

    cv = coeff_var(walls)
    mean_wall = statistics.mean(walls) if walls else None
    mean_rss = statistics.mean(rss) if rss else None

    # Pull mode sweep / coupled from last run (digest-stable; walls averaged).
    last = runs[-1]
    mode_rows: list[dict[str, Any]] = []
    streamed_over_resident = None
    sweep = last.get("exec_mode_sweep")
    if isinstance(sweep, dict):
        streamed_over_resident = sweep.get("streamed_over_resident")
        modes = sweep.get("modes")
        if isinstance(modes, list):
            # Average walls across runs when present.
            by_mode: dict[str, list[float]] = {}
            rss_by: dict[str, list[float]] = {}
            for r in runs:
                s = r.get("exec_mode_sweep") or {}
                for m in s.get("modes") or []:
                    if not isinstance(m, dict):
                        continue
                    name = m.get("mode")
                    if not isinstance(name, str):
                        continue
                    w = m.get("wall_s")
                    if isinstance(w, (int, float)):
                        by_mode.setdefault(name, []).append(float(w))
                    rk = m.get("peak_rss_kib")
                    if isinstance(rk, (int, float)):
                        rss_by.setdefault(name, []).append(float(rk))
            for name, ws in by_mode.items():
                mode_rows.append(
                    {
                        "mode": name,
                        "wall_s_mean": statistics.mean(ws),
                        "wall_s_cv": coeff_var(ws),
                        "peak_rss_kib_mean": (
                            statistics.mean(rss_by[name]) if name in rss_by else None
                        ),
                        "n_runs": len(ws),
                    }
                )

    coupled_summary = None
    if "coupled" in profile:
        coupled_rows: list[dict[str, Any]] = []
        by_mode: dict[str, list[float]] = {}
        nps_by: dict[str, list[float]] = {}
        rss_by: dict[str, list[float]] = {}
        for r in runs:
            c = r.get("coupled") or {}
            mode_list = c.get("modes") or r.get("mode_walls") or []
            for m in mode_list:
                if not isinstance(m, dict):
                    continue
                name = m.get("mode")
                if not isinstance(name, str):
                    continue
                # Normalize SequentialLobes → Sequential
                if name == "SequentialLobes":
                    name = "Sequential"
                w = m.get("wall_s")
                if w is None:
                    w = m.get("total_s")
                if isinstance(w, (int, float)):
                    by_mode.setdefault(name, []).append(float(w))
                nps = m.get("nonce_per_s")
                if isinstance(nps, (int, float)):
                    nps_by.setdefault(name, []).append(float(nps))
                rk = m.get("peak_rss_kib")
                if isinstance(rk, (int, float)):
                    rss_by.setdefault(name, []).append(float(rk))
        for name, ws in by_mode.items():
            coupled_rows.append(
                {
                    "mode": name,
                    "wall_s_mean": statistics.mean(ws),
                    "wall_s_cv": coeff_var(ws),
                    "nonce_per_s_mean": (
                        statistics.mean(nps_by[name])
                        if name in nps_by
                        else (1.0 / statistics.mean(ws) if statistics.mean(ws) > 0 else None)
                    ),
                    "peak_rss_kib_mean": (
                        statistics.mean(rss_by[name]) if name in rss_by else None
                    ),
                    "n_runs": len(ws),
                }
            )
        note = (last.get("coupled") or {}).get("note", "")
        missing = (last.get("coupled") or {}).get("modes_missing", "")
        stream_over = (last.get("coupled") or {}).get("streamed_over_resident")
        coupled_summary = {
            "modes": coupled_rows,
            "modes_missing": missing,
            "note": note,
            "streamed_over_resident": stream_over,
            "interconnect_sim": simulate_netcost(
                barriers=int(((last.get("params") or {}).get("barriers") or 4))
            ),
        }

    gpu = nvidia_ok()
    blockers = []
    if not gpu:
        blockers.append(
            "GPU campaign missing: nvidia-smi failed — no B200/5090/MI355X "
            "device-resident walls on this box"
        )
    blockers.append(
        "NVLink-vs-PCIe silicon campaign missing — Stage-I gate 4 (≥7×) UNMEASURED "
        "(SIMULATED factor recorded separately; NOT EVIDENCE)"
    )
    if not tip:
        blockers.append("same-tip provenance missing (git tip empty)")
    if mean_wall is None:
        blockers.append("measured walls missing")
    if len(walls) < 3:
        blockers.append(f"variance requires ≥3 runs (got {len(walls)})")

    # Base report fields for rc-gate (uses last run's structural fields).
    base = dict(last)
    for k in ("_file", "_path", "_campaign_proc_wall_s"):
        base.pop(k, None)

    toy = profile in ("rc-toy", "coupled")
    medium = profile in ("rc-medium", "coupled-medium")

    campaign = {
        "tool": "rc-stage-g-campaign",
        "schema_version": 2,
        "stub": False,
        "profile": profile,
        "campaign_profile": profile,
        "toy": toy and not medium,
        "medium": medium,
        "production_dims": False,
        "source_revision": tip,
        "git_tip": tip,
        "evidence_kind": "toy_chrono_measured" if toy and not medium else "chrono_measured",
        "wall_clock_provenance": "chrono_steady_clock",
        "device_resident": False,
        "native_path_eligible": False,
        "gpu_campaign_present": gpu,
        "nvlink_campaign_present": False,
        "stage_g_blockers": blockers,
        "n_runs": len(runs),
        "run_variance": {
            "episode_cv": cv,
            "wall_variance": cv,
            "n_runs": len(runs),
            "walls_s": walls,
            "peak_rss_kib": rss,
        },
        "phase_wall_s": {
            "total": mean_wall,
            "phase1": statistics.mean(
                [
                    float((r.get("phase_wall_s") or {}).get("phase1") or 0)
                    for r in runs
                    if (r.get("phase_wall_s") or {}).get("phase1") is not None
                ]
                or [0.0]
            ),
            "phase2": statistics.mean(
                [
                    float((r.get("phase_wall_s") or {}).get("phase2") or 0)
                    for r in runs
                    if (r.get("phase_wall_s") or {}).get("phase2") is not None
                ]
                or [0.0]
            ),
            "phase3": statistics.mean(
                [
                    float((r.get("phase_wall_s") or {}).get("phase3") or 0)
                    for r in runs
                    if (r.get("phase_wall_s") or {}).get("phase3") is not None
                ]
                or [0.0]
            ),
            "provenance": "chrono_steady_clock",
            "evidence_kind": (
                "toy_chrono_measured" if toy and not medium else "chrono_measured"
            ),
        },
        "peak_rss_kib": mean_rss,
        "exec_mode_sweep_agg": {
            "modes": mode_rows,
            "streamed_over_resident": streamed_over_resident,
            "note": (
                "RC episode Resident/Checkpointed/Streamed via OptionsForExecMode. "
                "Expect Streamed wall ≥ Resident (paging)."
            ),
        },
        "coupled_agg": coupled_summary,
        "interconnect_sim": simulate_netcost(),
        "extractmx_self_qual": base.get("extractmx_self_qual"),
        "k_curve": base.get("k_curve"),
        "residency_sweep": base.get("residency_sweep"),
        "allocation_cap_verdicts": base.get("allocation_cap_verdicts"),
        "verifier_floor": base.get("verifier_floor"),
        "params": base.get("params"),
        "device_id": base.get("device_id"),
        "backend": base.get("backend", "cpu"),
        "per_run_files": [r.get("_campaign_out") for r in runs],
        "consensus_note": (
            "nMatMulRCHeight remains INT32_MAX. Stage G on this box is PARTIAL/NO-GO: "
            "CPU chrono only; GPU+NVLink campaigns absent; interconnect factor is "
            "SIMULATED / NOT EVIDENCE for Stage-I gate 4."
        ),
    }
    return campaign


def run_profile(
    root: Path,
    harness: Path,
    profile: str,
    tip: str,
    runs: int,
    episodes: int,
    out_path: Path,
) -> dict[str, Any]:
    if runs < 3:
        die("--runs must be ≥3 for variance (Stage G)")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    work = out_path.parent / f".stage-g-{profile}-runs"
    work.mkdir(parents=True, exist_ok=True)

    collected: list[dict[str, Any]] = []
    for i in range(runs):
        run_out = work / f"run-{i + 1}.json"
        data = run_one(harness, profile, tip, run_out, episodes)
        data["_campaign_out"] = str(run_out)
        collected.append(data)

    campaign = aggregate_runs(profile, tip, collected)
    out_path.write_text(json.dumps(campaign, indent=2) + "\n", encoding="utf-8")
    print(f"rc-stage-g-campaign: wrote {out_path}")
    return campaign


def main() -> int:
    ap = argparse.ArgumentParser(description="ENC_RC Stage G same-tip campaign driver")
    ap.add_argument(
        "--profile",
        choices=VALID_PROFILES,
        help="Single campaign profile",
    )
    ap.add_argument(
        "--all",
        action="store_true",
        help="Run all profiles (coupled, coupled-medium, rc-toy, rc-medium)",
    )
    ap.add_argument("--runs", type=int, default=5, help="Independent runs (default 5)")
    ap.add_argument(
        "--episodes",
        type=int,
        default=3,
        help="Episodes per harness invocation (default 3)",
    )
    ap.add_argument("--out", default="", help="Output JSON path (single profile)")
    ap.add_argument(
        "--outdir",
        default="/tmp/stage-g",
        help="Output directory for --all (default /tmp/stage-g)",
    )
    ap.add_argument(
        "--gate",
        action="store_true",
        help="After campaign(s), invoke rc-gate.py on outputs",
    )
    args = ap.parse_args()

    if not args.profile and not args.all:
        die("pass --profile PROFILE or --all")

    root = Path(__file__).resolve().parents[2]
    tip = git_tip(root)
    harness = find_harness(root)
    print(f"rc-stage-g-campaign: tip={tip or '(none)'} harness={harness}")
    print(f"rc-stage-g-campaign: nvidia_ok={nvidia_ok()}")

    profiles = list(VALID_PROFILES) if args.all else [args.profile]
    outputs: list[Path] = []
    for p in profiles:
        assert p is not None
        if args.all:
            out = Path(args.outdir) / f"campaign-{p}.json"
        else:
            out = Path(args.out) if args.out else Path(args.outdir) / f"campaign-{p}.json"
        try:
            run_profile(root, harness, p, tip, args.runs, args.episodes, out)
            outputs.append(out)
        except SystemExit:
            raise
        except Exception as e:
            # coupled-medium may fail if medium+coupled interaction is harsh;
            # still record a blocker stub.
            stub = {
                "tool": "rc-stage-g-campaign",
                "schema_version": 2,
                "stub": False,
                "profile": p,
                "toy": p == "coupled",
                "medium": "medium" in p,
                "production_dims": False,
                "source_revision": tip,
                "git_tip": tip,
                "evidence_kind": "chrono_measured",
                "wall_clock_provenance": "chrono_steady_clock",
                "device_resident": False,
                "phase_wall_s": None,
                "run_variance": {},
                "stage_g_blockers": [f"campaign failed: {e}"],
                "gpu_campaign_present": nvidia_ok(),
                "nvlink_campaign_present": False,
                "interconnect_sim": simulate_netcost(),
                "extractmx_self_qual": {"status": "fail"},
                "consensus_note": "nMatMulRCHeight=INT32_MAX; campaign error",
            }
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(stub, indent=2) + "\n", encoding="utf-8")
            outputs.append(out)
            print(f"rc-stage-g-campaign: profile {p} failed: {e}", file=sys.stderr)

    if args.gate and outputs:
        gate = root / "contrib" / "matmul-v4" / "rc-gate.py"
        cmd = [sys.executable, str(gate), *[str(o) for o in outputs], "--out", str(Path(args.outdir) / "stage-g-summary.json")]
        print("rc-stage-g-campaign: " + " ".join(cmd))
        return subprocess.run(cmd, check=False).returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
