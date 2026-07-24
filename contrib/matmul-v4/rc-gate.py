#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
"""ENC_RC GO/NO-GO aggregator for rc-episode-harness JSON reports.

See doc/btx-matmul-v4.4-resident-curriculum-unified-proposal-2026-07-20.md §8
(prototype & measurement roadmap G1–G4) and §R (normative exact-integer spec).

Point at one or more
rc-episode-harness JSON paths (files or directories of *.json), print a single
GO / PARTIAL / NO-GO verdict, and optionally write summary.json.

HARD RULE: invent nothing. Fail closed.
  - G1 pass requires stub:false AND extractmx_self_qual.status=="pass"
  - Full GO requires G1–G4 *measured* pass criteria at production dims
  - Same-tip provenance, device-residency proof, run-to-run variance bounds,
    native-path evidence, and REAL full-episode + full-verification wall-clock
  - Hard-fail (never GO) on structural / MAC-count estimates / projected curves
  - Verifier-floor is the binding constraint and MUST be measured, not modeled
  - Toy harness output yields PARTIAL (toy-pass), never GO
  - --curve-only is PROVISIONAL / NOT EVIDENCE → NO-GO (never GO, never raise height)
  - Never recommends raising nMatMulRCHeight; never invents silicon rates

Usage:
  contrib/matmul-v4/rc-gate.py /tmp/rc.json --out /tmp/summary.json
  contrib/matmul-v4/rc-gate.py results/
  contrib/matmul-v4/rc-gate.py --curve-only --curve-epochs 16
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path
from typing import Any


# --- §8 normative thresholds (Go criteria) ---
G2_CLIFF_MIN = 1.5
G2_STREAM_UTIL_MIN = 0.40
G2_CLIFF_BYTES_LO = 96 * 1024 * 1024
G2_CLIFF_BYTES_HI = 256 * 1024 * 1024
G3_K_MIN_AT_24GB = 1.3
G3_K_VARIANCE_MAX = 0.05
G4_VERIFY_FRAC_MAX = 0.01
G4_VARIANCE_MAX = 0.05
# Kill criteria (doc §8): variance >10% is an automatic fail.
VARIANCE_KILL = 0.10
# Stage-I gate 4 (real silicon only): NVLink-vs-PCIe ≥7× on same chips.
STAGE_I_GATE4_NVLINK_MIN = 7.0

# Evidence kinds / modes that are NEVER admissible for GO.
_PROJECTION_TOKENS = frozenset(
    {
        "projected",
        "projection",
        "provisional",
        "mac_estimate",
        "mac_count",
        "macs",
        "structural",
        "modeled",
        "modelled",
        "heuristic",
        "synthetic",
        "toy_synthetic_structure",
        "estimated",
        "estimate",
        "replay_heuristic",
        "replay_s_heuristic",
        "not_evidence",
        # Also accept top-level projected_mac_count style fabricated labels.
        "projected_mac",
        "projected_mac_count",
    }
)

_MEASURED_TOKENS = frozenset(
    {
        "measured",
        "chrono_measured",
        "chrono_steady_clock",
        "wall_clock_measured",
        "device_measured",
        "silicon_measured",
        "production_measured",
        "toy_chrono_measured",
        "toy_measured_wall_clock",
    }
)


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
        if tool not in (None, "rc-episode-harness", "rc-stage-g-campaign"):
            die(f"{f} is not an rc-episode-harness/rc-stage-g-campaign JSON (tool={tool!r})")
        # Campaign wrappers may embed a child report list — flatten for gating.
        children = data.get("reports")
        if tool == "rc-stage-g-campaign" and isinstance(children, list) and children:
            for i, child in enumerate(children):
                if not isinstance(child, dict):
                    continue
                c = dict(child)
                c["_file"] = f"{os.path.basename(f)}#child{i}"
                c["_path"] = f
                c.setdefault("tool", "rc-episode-harness")
                # Inherit campaign tip / blockers when child omits them.
                for key in (
                    "source_revision",
                    "git_tip",
                    "stage_g_blockers",
                    "gpu_campaign_present",
                    "nvlink_campaign_present",
                    "interconnect_sim",
                    "run_variance",
                    "device_resident",
                    "evidence_kind",
                    "wall_clock_provenance",
                ):
                    if key not in c and key in data:
                        c[key] = data[key]
                reports.append(c)
            # Also gate the campaign aggregate itself (walls/variance/residency).
        data["_file"] = os.path.basename(f)
        data["_path"] = f
        reports.append(data)
    return reports


def stage_g_campaign_blockers(rep: dict[str, Any]) -> list[str]:
    """Explicit Stage G blockers (missing GPU / SIMULATED interconnect / etc.).

    Explicit False always blocks. Omitted/empty campaign fields block non-toy
    reports (assessment #6: missing≠pass). Toy PARTIAL may omit campaigns.
    """
    blockers: list[str] = []
    fname = rep["_file"]
    toy = bool(rep.get("toy"))
    for b in rep.get("stage_g_blockers") or []:
        if isinstance(b, str) and b.strip():
            blockers.append(f"{fname}: {b}")
    gpu = rep.get("gpu_campaign_present")
    nvlink = rep.get("nvlink_campaign_present")
    if gpu is False or (not toy and gpu is not True):
        blockers.append(
            f"{fname}: GPU campaign absent/omitted "
            "(device-resident B200/MI355X/5090 walls required; "
            "gpu_campaign_present must be true — missing≠pass)"
        )
    if nvlink is False or (not toy and nvlink is not True):
        blockers.append(
            f"{fname}: NVLink-vs-PCIe silicon campaign absent/omitted "
            f"(Stage-I gate 4 needs ≥{STAGE_I_GATE4_NVLINK_MIN}× on same chips; "
            "nvlink_campaign_present must be true — missing≠pass)"
        )
    sim = rep.get("interconnect_sim")
    if isinstance(sim, dict):
        if sim.get("simulated") is True or sim.get("stage_i_gate4_evidence") is False:
            factor = _as_float(sim.get("exchange_slowdown_factor"))
            blockers.append(
                f"{fname}: interconnect factor={factor!r} is SIMULATED / "
                "NOT EVIDENCE for Stage-I gate 4 (real silicon still required)"
            )
        if sim.get("stage_i_gate4_pass") is True and sim.get("simulated") is True:
            blockers.append(
                f"{fname}: HARD-FAIL — simulated interconnect must never claim "
                "stage_i_gate4_pass=true"
            )
    return blockers


def require_measured_walls_variance_residency(
    rep: dict[str, Any], reasons: list[str]
) -> bool:
    """Stage G: NEVER GO without measured walls + variance + residency fields.

    Missing/empty fields → NO-GO. Nonempty string values are not numeric pass.
    """
    fname = rep["_file"]
    ok = True
    walls = rep.get("phase_wall_s")
    if not _walls_measured(walls):
        reasons.append(
            f"{fname}: Stage G requires measured phase_wall_s "
            "(never GO without numeric walls; nonempty string≠pass)"
        )
        ok = False
    var = rep.get("run_variance") or rep.get("variance")
    if not isinstance(var, dict) or not any(
        _as_float(var.get(k)) is not None
        for k in (
            "episode_cv",
            "episode_variance",
            "wall_cv",
            "wall_variance",
            "max_cv",
        )
    ):
        reasons.append(
            f"{fname}: Stage G requires numeric run_variance.* "
            "(never GO without variance across ≥3 runs; "
            "missing/empty/non-numeric≠pass)"
        )
        ok = False
    # Residency must be an explicit boolean True (or proof.ok True) — not a
    # nonempty string / placeholder key.
    if not device_residency_ok(rep):
        reasons.append(
            f"{fname}: Stage G requires residency proof "
            "(device_resident=true / residency_proof.ok=true — "
            "missing/empty/non-true≠pass)"
        )
        ok = False
    return ok


def _as_float(v: Any) -> float | None:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        x = float(v)
        if x != x or x in (float("inf"), float("-inf")):  # NaN/inf
            return None
        return x
    return None


def _walls_measured(walls: Any) -> bool:
    if not isinstance(walls, dict) or not walls:
        return False
    vals = [v for v in walls.values() if v is not None]
    return len(vals) > 0 and any(_as_float(v) is not None for v in vals)


def _norm_token(s: Any) -> str:
    if not isinstance(s, str):
        return ""
    return s.strip().lower().replace("-", "_").replace(" ", "_")


def _token_is_projection(tok: str) -> bool:
    if not tok:
        return False
    if tok in _PROJECTION_TOKENS:
        return True
    return any(p in tok for p in _PROJECTION_TOKENS)


def _token_is_measured(tok: str) -> bool:
    if not tok:
        return False
    if tok in _MEASURED_TOKENS:
        return True
    return "measured" in tok and not _token_is_projection(tok)


def _collect_evidence_labels(rep: dict[str, Any]) -> list[str]:
    """Gather structured labels that declare how walls / curves were produced.

    Free-form `note` strings are ignored here — they often say "estimated" in
    prose without presenting a projection as GO evidence.
    """
    labels: list[str] = []
    for key in (
        "evidence_kind",
        "wall_clock_provenance",
        "rate_provenance",
        "timing_provenance",
        "verifier_floor_provenance",
    ):
        v = rep.get(key)
        if isinstance(v, str) and v.strip():
            labels.append(v)
    walls = rep.get("phase_wall_s")
    if isinstance(walls, dict):
        for key in ("provenance", "evidence_kind", "source"):
            v = walls.get(key)
            if isinstance(v, str) and v.strip():
                labels.append(v)
    kcurve = rep.get("k_curve")
    if isinstance(kcurve, dict):
        for key in ("mode", "evidence_kind", "provenance"):
            v = kcurve.get(key)
            if isinstance(v, str) and v.strip():
                labels.append(v)
    vf = rep.get("verifier_floor")
    if isinstance(vf, dict):
        for key in ("evidence_kind", "provenance", "mode"):
            v = vf.get(key)
            if isinstance(v, str) and v.strip():
                labels.append(v)
        if vf.get("modeled") is True or vf.get("projected") is True:
            labels.append("projected")
        if _as_float(vf.get("replay_s_heuristic")) is not None and vf.get("measured") is not True:
            labels.append("replay_s_heuristic")
        if _as_float(vf.get("macs")) is not None and vf.get("measured") is not True:
            labels.append("mac_count")
    # Bare MAC / heuristic fields on the report root are projection signals
    # when no measured walls exist.
    if _as_float(rep.get("replay_s_heuristic")) is not None:
        labels.append("replay_s_heuristic")
    if _as_float(rep.get("MACs")) is not None or _as_float(rep.get("macs")) is not None:
        if rep.get("evidence_kind") is None and not _walls_measured(rep.get("phase_wall_s")):
            labels.append("mac_count")
    return labels


def projection_blockers(rep: dict[str, Any]) -> list[str]:
    """Hard-fail reasons when structural/MAC/projected curves are offered as GO evidence.

    Toy chrono-measured reports may still carry honest labels like
    k_curve.mode=toy_synthetic_structure or verifier_floor.measured=false;
    those block full GO but do not by themselves forbid PARTIAL.
    """
    blockers: list[str] = []
    fname = rep["_file"]
    toy = bool(rep.get("toy"))
    for lab in _collect_evidence_labels(rep):
        tok = _norm_token(lab)
        if not _token_is_projection(tok):
            continue
        # Honest toy harness labels — recorded later as PARTIAL notes, not taint.
        if toy and tok in (
            "toy_synthetic_structure",
            "synthetic",
            "unmeasured",
            "verifier_floor_unmeasured",
        ):
            continue
        blockers.append(
            f"{fname}: REFUSE projection/estimate evidence_kind={lab!r} "
            "(structural/MAC-count/projected curves are NOT EVIDENCE for GO)"
        )
    # Explicit flags — always taint (even on toy) if someone marks projected=true.
    if rep.get("projected") is True or rep.get("modeled") is True:
        blockers.append(f"{fname}: projected/modeled=true — NOT EVIDENCE for GO")
    vf = rep.get("verifier_floor")
    if isinstance(vf, dict) and not toy:
        # Non-toy reports that only offer modeled/heuristic floors are tainted.
        if vf.get("measured") is not True and (
            vf.get("presented_as_evidence") is True
            or _as_float(vf.get("replay_s_heuristic")) is not None
            or _as_float(vf.get("macs")) is not None
            or _token_is_projection(_norm_token(vf.get("evidence_kind")))
            or _token_is_projection(_norm_token(vf.get("provenance")))
        ):
            blockers.append(
                f"{fname}: verifier_floor modeled/MAC heuristic presented as "
                "evidence — REFUSED (binding floor MUST be measured)"
            )
    return blockers

def tip_id(rep: dict[str, Any]) -> str | None:
    for key in ("source_revision", "git_tip", "git_commit", "tip", "build_id"):
        v = rep.get(key)
        if isinstance(v, str) and v.strip():
            tip = v.strip()
            if tip.endswith("-dirty"):
                return None
            return tip
    return None


def device_residency_ok(rep: dict[str, Any]) -> bool:
    """Device-residency proof required for full GO (not host-orchestrated CPU alone)."""
    if rep.get("device_resident") is True:
        return True
    if rep.get("device_residency_proof") is True:
        return True
    path = _norm_token(rep.get("execution_path"))
    if path and "device_resident" in path:
        return True
    # Explicit residency object from harness.
    proof = rep.get("residency_proof") or rep.get("device_residency")
    if isinstance(proof, dict) and proof.get("ok") is True:
        return True
    return False


def native_path_ok(rep: dict[str, Any]) -> bool:
    if rep.get("native_path_eligible") is True:
        return True
    if rep.get("native_path_evidence") is True:
        return True
    qual = rep.get("extractmx_self_qual")
    if isinstance(qual, dict):
        if qual.get("native_mxfp4_qualified") is True or qual.get("native_fp8_qualified") is True:
            return True
        if qual.get("native_path_eligible") is True:
            return True
    return False


def scalar_fp4_native_claim_blockers(rep: dict[str, Any]) -> list[str]:
    """Refuse fabricated native_mxfp4 claims on scalar-decode backends."""
    blockers: list[str] = []
    fname = rep.get("_file", "?")
    candidates: list[dict[str, Any]] = []
    for key in ("extractmx_self_qual", "ozaki_mxfp4", "mx_self_qual", "lt"):
        obj = rep.get(key)
        if isinstance(obj, dict):
            candidates.append(obj)
    for obj in candidates:
        backend = str(obj.get("mx_backend") or obj.get("backend") or "").lower()
        if "scalar-decode" not in backend and "scalar_fp4" not in backend:
            continue
        if obj.get("native_mxfp4_qualified") is True or obj.get("native_fp8_qualified") is True:
            blockers.append(
                f"{fname}: REFUSE scalar-decode MXFP4 labeled native_*_qualified "
                f"(backend={backend!r}; scalar-decode is not native tensor)"
            )
    return blockers


def variance_ok(rep: dict[str, Any], reasons: list[str], *, for_go: bool) -> bool:
    """Run-to-run variance bounds (G3/G4 ≤5%; >10% kill)."""
    fname = rep["_file"]
    var = rep.get("run_variance") or rep.get("variance") or {}
    if not isinstance(var, dict):
        var = {}
    vals: list[tuple[str, float]] = []
    for key in (
        "episode_cv",
        "episode_variance",
        "wall_cv",
        "wall_variance",
        "verify_cv",
        "verify_variance",
        "k_variance",
        "max_cv",
    ):
        x = _as_float(var.get(key))
        if x is not None:
            vals.append((key, x))
    # Also accept top-level k_curve variance.
    kcurve = rep.get("k_curve")
    if isinstance(kcurve, dict):
        x = _as_float(kcurve.get("k_variance"))
        if x is not None:
            vals.append(("k_curve.k_variance", x))
    if for_go and not vals:
        reasons.append(
            f"{fname}: missing run-to-run variance bounds "
            "(need run_variance.* ≤ {G4_VARIANCE_MAX} for GO)"
        )
        return False
    ok = True
    for key, x in vals:
        if x > VARIANCE_KILL:
            reasons.append(
                f"{fname}: {key}={x:.4f} exceeds kill threshold {VARIANCE_KILL} (doc §8)"
            )
            ok = False
        elif for_go and x > G4_VARIANCE_MAX:
            reasons.append(
                f"{fname}: {key}={x:.4f} exceeds GO bound {G4_VARIANCE_MAX} (doc §8)"
            )
            ok = False
    return ok


def production_dims_ok(rep: dict[str, Any]) -> bool:
    if rep.get("toy") is True:
        return False
    if rep.get("production_dims") is True:
        return True
    if rep.get("consensus_dims") is True:
        return True
    # Medium is still not production/consensus-scale evidence.
    if rep.get("medium") is True:
        return False
    params = rep.get("params")
    if isinstance(params, dict):
        # Consensus table epoch-0: n_ctx≈786432, d_model=4096, L=16, b_seq≈16384.
        n_ctx = params.get("n_ctx")
        d_model = params.get("d_model")
        L = params.get("L_lyr") or params.get("L")
        if (
            isinstance(n_ctx, int)
            and n_ctx >= 786432
            and isinstance(d_model, int)
            and d_model >= 4096
            and isinstance(L, int)
            and L >= 16
        ):
            return True
    return False


def measured_verifier_floor_ok(rep: dict[str, Any], reasons: list[str]) -> bool:
    """Verifier-floor MUST be measured full-episode + full-verify wall-clock."""
    fname = rep["_file"]
    vf = rep.get("verifier_floor")
    walls = rep.get("phase_wall_s") if isinstance(rep.get("phase_wall_s"), dict) else {}

    episode_s = None
    verify_s = None
    measured = False

    if isinstance(vf, dict):
        measured = vf.get("measured") is True
        episode_s = _as_float(vf.get("full_episode_wall_s")) or _as_float(
            vf.get("episode_wall_s")
        )
        verify_s = _as_float(vf.get("full_verify_wall_s")) or _as_float(
            vf.get("verify_wall_s")
        )
        # Refuse heuristics even if measured flag is wrongfully set.
        if _token_is_projection(_norm_token(vf.get("provenance"))) or _token_is_projection(
            _norm_token(vf.get("evidence_kind"))
        ):
            reasons.append(
                f"{fname}: verifier_floor provenance is projected/heuristic — REFUSED"
            )
            return False
        if _as_float(vf.get("replay_s_heuristic")) is not None and not measured:
            reasons.append(
                f"{fname}: verifier_floor.replay_s_heuristic is NOT EVIDENCE "
                "(MAC/1e9 model refused)"
            )
            return False

    if episode_s is None:
        episode_s = _as_float(walls.get("total")) or _as_float(walls.get("episode"))
    if verify_s is None:
        verify_s = _as_float(walls.get("verify")) or _as_float(walls.get("full_verify"))

    if not measured:
        reasons.append(
            f"{fname}: verifier_floor.measured!=true — binding verifier-floor "
            "MUST be measured, not modeled (doc §R.7.6)"
        )
        return False
    if episode_s is None or episode_s <= 0:
        reasons.append(
            f"{fname}: missing measured full-episode wall-clock "
            "(verifier_floor.full_episode_wall_s / phase_wall_s.total)"
        )
        return False
    if verify_s is None or verify_s < 0:
        reasons.append(
            f"{fname}: missing measured full-verification wall-clock "
            "(verifier_floor.full_verify_wall_s / phase_wall_s.verify)"
        )
        return False
    if episode_s > 0 and verify_s / episode_s > G4_VERIFY_FRAC_MAX:
        reasons.append(
            f"{fname}: verify/episode={verify_s / episode_s:.4f} exceeds "
            f"G4 bound {G4_VERIFY_FRAC_MAX} (doc §8)"
        )
        return False
    return True


def g2_threshold_pass(rep: dict[str, Any], reasons: list[str], *, for_go: bool) -> str:
    """G2 residency: cliff ≥1.5× in 96–256 MB; optional STREAM util ≥40%.

    Stage G / final-form: a nonempty report must never receive status ``pass``
    without actually applying these numeric thresholds. Empty/null sweeps fail
    closed; toy/partial paths may use ``toy-pass`` / ``partial`` only.
    """
    fname = rep["_file"]
    sweep = rep.get("residency_sweep")
    if sweep in (None, {}, []):
        reasons.append(
            f"{fname}: G2 residency_sweep empty/null "
            "(Phase-1 Associative Recall Maze not measured)"
        )
        return "fail"

    points: list[dict[str, Any]] = []
    if isinstance(sweep, list):
        points = [p for p in sweep if isinstance(p, dict)]
    elif isinstance(sweep, dict):
        pts = sweep.get("points")
        if isinstance(pts, list):
            points = [p for p in pts if isinstance(p, dict)]
        else:
            points = [sweep]

    # Explicit cliff_ratio wins if present.
    cliff = None
    cliff_obj = rep.get("residency_cliff") if isinstance(rep.get("residency_cliff"), dict) else {}
    cliff = _as_float(cliff_obj.get("ratio")) if cliff_obj else None
    if cliff is None and isinstance(sweep, dict):
        cliff = _as_float(sweep.get("cliff_ratio"))

    in_band: list[tuple[float, float]] = []
    for p in points:
        ws = _as_float(p.get("working_set_bytes"))
        wall = _as_float(p.get("wall_s")) or _as_float(p.get("bandwidth_GBs"))
        if ws is None or wall is None or wall <= 0:
            continue
        if G2_CLIFF_BYTES_LO <= ws <= G2_CLIFF_BYTES_HI:
            in_band.append((ws, wall))
        cr = _as_float(p.get("cliff_ratio"))
        if cr is not None:
            cliff = cr if cliff is None else max(cliff, cr)

    if cliff is None and len(in_band) >= 2:
        # Slowest/fastest wall in band → cliff ratio (higher wall = cliff).
        walls_sorted = sorted(w for _, w in in_band)
        if walls_sorted[0] > 0:
            cliff = walls_sorted[-1] / walls_sorted[0]

    # Non-GO paths: nonempty sweep alone is never "pass" — only toy-pass/partial
    # after a soft presence check (numeric pass reserved for for_go).
    if not for_go:
        if cliff is None and not in_band and not points:
            reasons.append(f"{fname}: G2 residency_sweep nonempty but no numeric points")
            return "fail"
        return "toy-pass" if rep.get("toy") else "partial"

    if cliff is None or cliff < G2_CLIFF_MIN:
        reasons.append(
            f"{fname}: G2 residency cliff unmet "
            f"(need ≥{G2_CLIFF_MIN}× in 96–256 MB; got {cliff!r})"
        )
        return "fail"

    stream = _as_float(rep.get("stream_util_frac"))
    if stream is None and isinstance(sweep, dict):
        stream = _as_float(sweep.get("stream_util_frac"))
    if stream is None and cliff_obj:
        stream = _as_float(cliff_obj.get("stream_util_frac"))
    if stream is not None and stream < G2_STREAM_UTIL_MIN:
        reasons.append(
            f"{fname}: G2 STREAM util={stream:.3f} < {G2_STREAM_UTIL_MIN} (doc §8)"
        )
        return "fail"

    return "pass"


def g3_threshold_pass(rep: dict[str, Any], reasons: list[str], *, for_go: bool) -> str:
    """G3 k-curve: digests match; k variance ≤5%; k ≥ 1.3 at 24 GB."""
    fname = rep["_file"]
    kcurve = rep.get("k_curve")
    if kcurve in (None, {}, []):
        reasons.append(
            f"{fname}: G3 k_curve empty/null (Phase-2 k-curve not measured)"
        )
        return "fail"
    if not isinstance(kcurve, dict):
        reasons.append(f"{fname}: G3 k_curve is not an object")
        return "fail"

    mode = _norm_token(kcurve.get("mode"))
    if _token_is_projection(mode):
        if for_go or not rep.get("toy"):
            reasons.append(
                f"{fname}: G3 k_curve.mode={kcurve.get('mode')!r} is projection/synthetic "
                "— REFUSED as GO evidence"
            )
            return "fail"
        # Toy harness honestly labels synthetic structure → PARTIAL only.
        return "toy-pass"

    if not for_go:
        return "toy-pass" if rep.get("toy") else "partial"

    if kcurve.get("digests_match") is not True and kcurve.get("digests_identical") is not True:
        reasons.append(f"{fname}: G3 digests_match!=true (doc §8)")
        return "fail"

    k24 = _as_float(kcurve.get("k_at_24gb")) or _as_float(kcurve.get("k_24gb"))
    if k24 is None:
        # Accept a points[] entry labeled 24GB / 25769803776 bytes.
        pts = kcurve.get("points")
        if isinstance(pts, list):
            for p in pts:
                if not isinstance(p, dict):
                    continue
                label = _norm_token(p.get("cap") or p.get("label") or p.get("mem"))
                mem = _as_float(p.get("bytes") or p.get("working_set_bytes"))
                if "24" in label or (mem is not None and abs(mem - 24 * 1024**3) < 1e6):
                    k24 = _as_float(p.get("k")) or _as_float(p.get("recompute_ratio"))
                    break
    if k24 is None:
        reasons.append(
            f"{fname}: G3 missing measured k_at_24gb (decisive gate; doc §8 / §9)"
        )
        return "fail"
    if k24 < G3_K_MIN_AT_24GB:
        reasons.append(
            f"{fname}: G3 k_at_24gb={k24:.4f} < {G3_K_MIN_AT_24GB} (doc §8 Go criteria)"
        )
        return "fail"

    kvar = _as_float(kcurve.get("k_variance"))
    if kvar is None:
        reasons.append(f"{fname}: G3 missing k_variance (need ≤{G3_K_VARIANCE_MAX})")
        return "fail"
    if kvar > G3_K_VARIANCE_MAX:
        reasons.append(
            f"{fname}: G3 k_variance={kvar:.4f} > {G3_K_VARIANCE_MAX} (doc §8)"
        )
        return "fail"

    return "pass"


def g4_threshold_pass(rep: dict[str, Any], reasons: list[str], *, for_go: bool) -> str:
    """G4 integrated episode: measured walls + verify fraction + variance."""
    fname = rep["_file"]
    walls = rep.get("phase_wall_s")
    if not _walls_measured(walls):
        reasons.append(
            f"{fname}: G4 phase_wall_s unset "
            "(integrated 3-phase episode not measured)"
        )
        return "fail"

    # Refuse walls whose provenance is projected/MAC-estimated.
    if isinstance(walls, dict):
        for key in ("provenance", "evidence_kind", "source"):
            tok = _norm_token(walls.get(key))
            if _token_is_projection(tok):
                reasons.append(
                    f"{fname}: G4 phase_wall_s.{key}={walls.get(key)!r} is "
                    "projection/estimate — REFUSED"
                )
                return "fail"

    if not for_go:
        return "toy-pass" if rep.get("toy") else "partial"

    if not measured_verifier_floor_ok(rep, reasons):
        return "fail"
    if not variance_ok(rep, reasons, for_go=True):
        return "fail"
    return "pass"


def gate_report(rep: dict[str, Any]) -> dict[str, Any]:
    """Per-report gate statuses + blocking reasons."""
    reasons: list[str] = []
    toy = bool(rep.get("toy"))
    stub = rep.get("stub", True)
    fname = rep["_file"]

    # Projection / estimate evidence can never produce GO.
    proj = projection_blockers(rep)
    reasons.extend(proj)
    projection_taint = bool(proj)

    # Scalar-decode MXFP4 labeled as native_* must never produce GO.
    scalar_blockers = scalar_fp4_native_claim_blockers(rep)
    reasons.extend(scalar_blockers)
    if scalar_blockers:
        projection_taint = True

    # Stage G campaign blockers (missing GPU / SIMULATED interconnect).
    reasons.extend(stage_g_campaign_blockers(rep))

    # --- G1 ---
    g1 = "fail"
    qual = rep.get("extractmx_self_qual")
    if not isinstance(qual, dict):
        reasons.append(f"{fname}: missing extractmx_self_qual object")
        g1 = "fail"
    elif stub is not False:
        status = qual.get("status")
        reasons.append(
            f"{fname}: G1 requires stub:false + status=='pass' "
            f"(got stub={stub!r} status={status!r})"
        )
        g1 = "fail"
    elif qual.get("status") == "pass":
        g1 = "pass"
    else:
        reasons.append(
            f"{fname}: G1 ExtractMX self-qual status={qual.get('status')!r} "
            "(need status=='pass'; doc §8 Gate G1)"
        )
        g1 = "fail"

    # Non-toy reports always receive full GO threshold evaluation so missing
    # measured evidence is surfaced even when provenance is incomplete.
    evaluate_go_thresholds = (not toy) and g1 == "pass" and (not projection_taint)

    go_evidence_ok = True
    if evaluate_go_thresholds:
        if not production_dims_ok(rep):
            reasons.append(
                f"{fname}: full GO requires REAL production/consensus dims "
                "(toy/medium / missing production_dims=true are insufficient)"
            )
            go_evidence_ok = False
        if tip_id(rep) is None:
            reasons.append(
                f"{fname}: missing same-tip provenance "
                "(source_revision/git_tip required; dirty tips refused)"
            )
            go_evidence_ok = False
        if not device_residency_ok(rep):
            reasons.append(
                f"{fname}: missing device-residency proof "
                "(device_resident=true / residency_proof.ok)"
            )
            go_evidence_ok = False
        if not native_path_ok(rep):
            reasons.append(
                f"{fname}: missing native-path evidence "
                "(native_path_eligible or native_*_qualified)"
            )
            go_evidence_ok = False
        # Wall-clock must be measured, not MAC-projected.
        wprov = _norm_token(rep.get("wall_clock_provenance") or rep.get("evidence_kind"))
        if wprov and _token_is_projection(wprov):
            reasons.append(
                f"{fname}: wall_clock_provenance={rep.get('wall_clock_provenance')!r} "
                "is projection — REFUSED"
            )
            go_evidence_ok = False
        elif wprov and not _token_is_measured(wprov):
            reasons.append(
                f"{fname}: wall_clock_provenance={rep.get('wall_clock_provenance')!r} "
                "is not a measured chrono provenance"
            )
            go_evidence_ok = False
        elif not wprov:
            reasons.append(
                f"{fname}: missing wall_clock_provenance "
                "(need chrono/device measured; MAC estimates refused)"
            )
            go_evidence_ok = False

    g2 = g2_threshold_pass(rep, reasons, for_go=evaluate_go_thresholds)
    g3 = g3_threshold_pass(rep, reasons, for_go=evaluate_go_thresholds)
    g4 = g4_threshold_pass(rep, reasons, for_go=evaluate_go_thresholds)

    # Allocation caps: toy skips are OK for PARTIAL; full GO needs pass.
    caps = rep.get("allocation_cap_verdicts")
    cap_ok_full = False
    if not isinstance(caps, dict):
        reasons.append(f"{fname}: missing allocation_cap_verdicts")
    else:
        cap_vals = [caps.get(k) for k in ("512MiB", "2GiB", "8GiB")]
        if toy:
            if any(v in (None, "not_run", "fail") for v in cap_vals):
                reasons.append(
                    f"{fname}: toy allocation_cap_verdicts incomplete/fail: {cap_vals}"
                )
        else:
            cap_ok_full = all(v == "pass" for v in cap_vals)
            if not cap_ok_full:
                for key in ("512MiB", "2GiB", "8GiB"):
                    v = caps.get(key)
                    if v != "pass":
                        reasons.append(
                            f"{fname}: allocation_cap_verdicts[{key}]={v!r} "
                            "(need 'pass' for full GO)"
                        )

    full_pass = (
        g1 == "pass"
        and g2 == "pass"
        and g3 == "pass"
        and g4 == "pass"
        and not toy
        and not projection_taint
        and go_evidence_ok
        and cap_ok_full
        and production_dims_ok(rep)
        and tip_id(rep) is not None
        and device_residency_ok(rep)
        and native_path_ok(rep)
    )
    # Absolute hard-fail: projections never GO.
    if projection_taint:
        full_pass = False

    # Stage G: NEVER GO without measured walls + variance + residency fields.
    if full_pass and not require_measured_walls_variance_residency(rep, reasons):
        full_pass = False
    # Missing/omitted/False GPU / NVLink campaigns can never produce GO.
    # Only explicit True counts (assessment #6: omitted ≠ pass).
    if full_pass and (
        rep.get("gpu_campaign_present") is not True
        or rep.get("nvlink_campaign_present") is not True
    ):
        full_pass = False
        reasons.append(
            f"{fname}: HARD-FAIL — Stage G GO requires gpu_campaign_present=true "
            "AND nvlink_campaign_present=true (missing/empty/False≠pass)"
        )
    sim = rep.get("interconnect_sim")
    if full_pass and isinstance(sim, dict) and sim.get("simulated") is True:
        full_pass = False
        reasons.append(
            f"{fname}: HARD-FAIL — SIMULATED interconnect is NOT Stage-I gate 4 evidence"
        )

    # Stage G / final-form: nonempty reports never count as PASS without
    # numeric §8 thresholds actually applied (G2 cliff, G3 k@24GB, G4 walls).
    if full_pass and not evaluate_go_thresholds:
        full_pass = False
        reasons.append(
            f"{fname}: HARD-FAIL — nonempty report cannot PASS without "
            "numeric G2/G3/G4 threshold evaluation"
        )
    if g2 == "pass" and not evaluate_go_thresholds:
        g2 = "fail"
        reasons.append(
            f"{fname}: G2 status demoted — 'pass' requires numeric thresholds"
        )
        full_pass = False
    if g3 == "pass" and not evaluate_go_thresholds:
        g3 = "fail"
        reasons.append(
            f"{fname}: G3 status demoted — 'pass' requires numeric thresholds"
        )
        full_pass = False
    if g4 == "pass" and not evaluate_go_thresholds:
        g4 = "fail"
        reasons.append(
            f"{fname}: G4 status demoted — 'pass' requires numeric thresholds"
        )
        full_pass = False

    toy_partial = (
        g1 == "pass"
        and g2 == "toy-pass"
        and g3 == "toy-pass"
        and g4 == "toy-pass"
        and toy
        and stub is False
        and not projection_taint
    )
    if toy_partial:
        reasons.append(
            f"{fname}: toy chrono G2–G4 present — PARTIAL only; never GO; "
            "projections/MAC estimates remain NOT EVIDENCE; verifier-floor "
            "must be measured at production dims before GO"
        )

    return {
        "g1": g1,
        "g2": g2,
        "g3": g3,
        "g4": g4,
        "full_pass": full_pass,
        "toy_partial": toy_partial,
        "projection_taint": projection_taint,
        "reasons": reasons,
        "toy": toy,
        "stub": stub,
        "tip": tip_id(rep),
    }


def same_tip_blockers(reports: list[dict[str, Any]], per: list[dict[str, Any]]) -> list[str]:
    tips = {p.get("tip") for p in per if p.get("tip")}
    missing = [p["file"] for p in per if not p.get("tip") and not p.get("toy")]
    blockers: list[str] = []
    if missing:
        blockers.append(
            "same-tip provenance incomplete for non-toy reports: " + ", ".join(missing)
        )
    if len(tips) > 1:
        blockers.append(
            f"same-tip provenance mismatch across reports: {sorted(tips)} "
            "(GO requires a single source_revision/git_tip)"
        )
    return blockers


def aggregate(reports: list[dict[str, Any]]) -> dict[str, Any]:
    blockers: list[str] = []
    per: list[dict[str, Any]] = []
    any_full = True
    any_partial = True
    any_projection = False

    for rep in reports:
        g = gate_report(rep)
        blockers.extend(g["reasons"])
        any_projection = any_projection or bool(g["projection_taint"])
        per.append(
            {
                "file": rep["_file"],
                "device_id": rep.get("device_id"),
                "backend": rep.get("backend"),
                "profile": rep.get("profile"),
                "stub": rep.get("stub"),
                "toy": rep.get("toy"),
                "tip": g.get("tip"),
                "evidence_kind": rep.get("evidence_kind"),
                "wall_clock_provenance": rep.get("wall_clock_provenance"),
                "extractmx_self_qual_status": (
                    (rep.get("extractmx_self_qual") or {}).get("status")
                ),
                "G1": g["g1"],
                "G2": g["g2"],
                "G3": g["g3"],
                "G4": g["g4"],
                "projection_taint": g["projection_taint"],
            }
        )
        if not g["full_pass"]:
            any_full = False
        if not g["toy_partial"]:
            any_partial = False

    if not reports:
        any_full = False
        any_partial = False

    blockers.extend(same_tip_blockers(reports, per))
    # Multi-tip or projection taint can never be GO.
    if any_projection:
        any_full = False
    tip_set = {p.get("tip") for p in per if p.get("tip")}
    if len(tip_set) > 1:
        any_full = False

    if any_full:
        verdict = "GO"
        go = True
    elif any_partial and all(
        (r.get("G1") == "pass" and r.get("toy")) for r in per
    ):
        verdict = "PARTIAL"
        go = False
        # Soften empty-field G2/G3/G4 noise for the toy PARTIAL path.
        blockers = [
            b
            for b in blockers
            if "G2 residency_sweep empty" not in b
            and "G3 k_curve empty" not in b
            and "G4 phase_wall_s unset" not in b
        ]
        if not any("PARTIAL:" in b or "PARTIAL only" in b for b in blockers):
            blockers.append(
                "PARTIAL: toy G2–G4 present (toy-pass); full GO requires non-toy "
                "consensus-dim G2–G4 with measured verifier-floor, same-tip "
                "provenance, device-residency, variance bounds, and native-path "
                "evidence — never projections/MAC estimates"
            )
    else:
        verdict = "NO-GO"
        go = False

    # Absolute: projections never flip GO.
    if go and any_projection:
        verdict = "NO-GO"
        go = False
        blockers.append(
            "HARD-FAIL: projection/MAC-estimate/structural evidence present — never GO"
        )

    summary = {
        "tool": "rc-gate",
        "schema_version": 2,
        "verdict": verdict,
        "go": go,
        "n_reports": len(reports),
        "reports": per,
        "blocking_reasons": blockers,
        "decision_matrix": DECISION_MATRIX,
        "consensus_note": (
            "nMatMulRCHeight remains INT32_MAX; ENC_RC activation is NO-GO. "
            "Offline tally never wires consensus and never recommends raising "
            "height from toy measurements or §R.7 projections (doc §8 / §9 / §R.7). "
            "Verifier-floor MUST be measured; MAC/heuristic curves are NOT EVIDENCE."
        ),
    }
    return summary


DECISION_MATRIX = {
    "curve_only_projections": "NO-GO (PROVISIONAL / NOT EVIDENCE; never raise height)",
    "stub_or_g1_fail": "NO-GO",
    "toy_g1_pass_plus_toy_g2g3g4": "PARTIAL (never GO; never raise height)",
    "projection_mac_structural_as_evidence": "NO-GO hard-fail (never GO)",
    "non_toy_missing_tip_residency_variance_native_or_measured_verifier_floor": "NO-GO",
    "production_dims_measured_g1g4_thresholds_met": (
        "GO offline tally only; nMatMulRCHeight stays INT32_MAX"
    ),
    "nonempty_report_without_numeric_thresholds": (
        "NO-GO (nonempty reports never PASS without G2/G3/G4 numeric thresholds)"
    ),
    "stage_g_missing_walls_variance_residency": (
        "NO-GO (Stage G never GO without measured numeric walls + variance + "
        "residency=true; nonempty string≠pass; missing≠pass)"
    ),
    "stage_g_missing_gpu_or_nvlink_campaign": (
        "NO-GO / blocker (gpu_campaign_present=true AND "
        "nvlink_campaign_present=true required; omitted/False≠pass; "
        "B200/MI355X/5090 + NVLink-vs-PCIe ≥7× still required)"
    ),
    "stage_g_simulated_interconnect": (
        "NOT EVIDENCE for Stage-I gate 4 (SIMULATED factor must not flip GO)"
    ),
    "stage_e_decision": (
        "DECIDED winner-only GKR/sumcheck — unlocks magnitude *direction* toward "
        "full HBM IF verify ≤ fraction of block interval; still need Stage G silicon. "
        "Decision alone does NOT raise nMatMulRCHeight (stays INT32_MAX)."
    ),
}


def print_human(summary: dict[str, Any]) -> None:
    print("MatMul ENC_RC — GO/NO-GO aggregate verdict")
    print(f"  reports:  {summary['n_reports']}")
    for r in summary["reports"]:
        print(
            f"    - {r['file']}: device={r.get('device_id')} "
            f"backend={r.get('backend')} profile={r.get('profile')} "
            f"stub={r.get('stub')} toy={r.get('toy')} tip={r.get('tip')} "
            f"evidence={r.get('evidence_kind')} "
            f"G1={r.get('G1')} G2={r.get('G2')} G3={r.get('G3')} G4={r.get('G4')}"
            f"{' [PROJECTION-TAINTED]' if r.get('projection_taint') else ''}"
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
        print("VERDICT: GO — G1–G4 measured criteria satisfied in this offline tally.")
        print("  (Activation height still NO-GO — see consensus_note.)")
    elif v == "PARTIAL":
        print(
            "VERDICT: PARTIAL — G1 pass + toy G2–G4 present. "
            "nMatMulRCHeight stays INT32_MAX; not a raise-height signal. "
            "Projections/MAC estimates remain NOT EVIDENCE."
        )
    else:
        print(
            "VERDICT: NO-GO — see blocking reasons. "
            "nMatMulRCHeight stays INT32_MAX."
        )


# --- §R.7 projected scale curve (PROVISIONAL; never a raise-height signal) ---

# Mirrors Consensus::FillDefaultRCGrowthTables / RCScaleForHeight (Q16).
_K_RC_W0_RES = 192 * 1024 * 1024
_K_RC_W0_CAP = 2 * 1024 * 1024 * 1024
_K_RC_HEAD = 128
_K_RC_LAYERS = 16
_K_RC_MODEL = 4096
_K_RC_ROUNDS = 4
_HARD_CAP_RES = 1 << 32
_HARD_CAP_CAP = 1 << 34
_RES_Q16 = (71287, 71031, 70773, 70511)
_CAP_Q16 = (69296, 69017, 68735, 68449)


def _round32_bytes(x: int) -> int:
    if x <= 0:
        return 0
    return ((x + 16) // 32) * 32


def _mul_q16_round32(w: int, g_q16: int) -> int:
    if g_q16 <= 0:
        return w
    scaled = (w * g_q16 + (1 << 15)) >> 16
    return _round32_bytes(scaled)


def _growth_q16(epoch: int) -> tuple[int, int]:
    band = min(epoch // 12, 3)
    return _RES_Q16[band], _CAP_Q16[band]


def total_rc_episode_macs(n_q: int, n_ctx: int, d_head: int, L: int, d_model: int, b_seq: int,
                          rounds: int = _K_RC_ROUNDS) -> int:
    """Mirror matmul::v4::rc::TotalRCEpisodeMacs."""
    p1 = 2 * n_q * n_ctx * d_head
    p2 = 3 * L * b_seq * d_model * d_model
    return rounds * (p1 + p2)


def project_scale_curve(n_epochs: int = 40) -> list[dict[str, Any]]:
    """Projected W_res/W_cap (PROVISIONAL / NOT EVIDENCE).

    replay_s_heuristic is a MAC/1e9 model only — never a verifier-floor
    measurement and never a raise-height signal.
    """
    w_res, w_cap = _K_RC_W0_RES, _K_RC_W0_CAP
    rows: list[dict[str, Any]] = []
    for e in range(n_epochs):
        n_ctx = ((w_res // (2 * _K_RC_HEAD) + 16) // 32) * 32
        b_seq = ((w_cap // (2 * _K_RC_MODEL * _K_RC_LAYERS) + 16) // 32) * 32
        n_q = 4 * _K_RC_HEAD
        macs = total_rc_episode_macs(n_q, n_ctx, _K_RC_HEAD, _K_RC_LAYERS, _K_RC_MODEL, b_seq)
        # Heuristic ONLY — labeled NOT EVIDENCE. Do not invent silicon rates.
        replay_s = macs / 1e9
        rows.append(
            {
                "epoch": e,
                "W_res": w_res,
                "W_cap": w_cap,
                "n_ctx": n_ctx,
                "b_seq": b_seq,
                "MACs": macs,
                "replay_s_heuristic": replay_s,
                "evidence_class": "PROVISIONAL_NOT_EVIDENCE",
            }
        )
        if e + 1 < n_epochs:
            g_res, g_cap = _growth_q16(e)
            w_res = min(_mul_q16_round32(w_res, g_res), _HARD_CAP_RES)
            w_cap = min(_mul_q16_round32(w_cap, g_cap), _HARD_CAP_CAP)
    return rows


def print_scale_curve(n_epochs: int, constants: dict[str, Any] | None = None) -> None:
    print("=" * 72)
    print("ENC_RC §R.7 projected W_res/W_cap curve")
    print("  *** PROVISIONAL / NOT EVIDENCE / NEVER A RAISE-HEIGHT SIGNAL ***")
    print("  nMatMulRCHeight stays INT32_MAX. Do not invent silicon rates.")
    print("  Verifier-floor is BINDING and MUST be MEASURED — this curve is not it.")
    print("=" * 72)
    if constants:
        print(f"  harness constants: {sorted(constants.keys())}")
    rows = project_scale_curve(n_epochs)
    print(
        f"  {'epoch':>5}  {'W_res':>14}  {'W_cap':>14}  {'n_ctx':>10}  "
        f"{'b_seq':>8}  {'MACs':>16}  {'replay_s~':>10}"
    )
    for r in rows:
        print(
            f"  {r['epoch']:5d}  {r['W_res']:14d}  {r['W_cap']:14d}  "
            f"{r['n_ctx']:10d}  {r['b_seq']:8d}  {r['MACs']:16d}  "
            f"{r['replay_s_heuristic']:10.2f}"
        )
    print(
        "  replay_s~ = MACs / 1e9 (single-thread HEURISTIC model) — NOT EVIDENCE.\n"
        "  Human curve-fit review + measured full-episode/full-verify walls remain\n"
        "  the load-bearing verifier-floor check (doc §R.7.6). Status: NO-GO for GO."
    )


def _load_curve_constants(reports: list[dict[str, Any]]) -> dict[str, Any] | None:
    for rep in reports:
        c = rep.get("rc_scale_constants") or rep.get("scale_constants")
        if isinstance(c, dict) and c:
            return c
    return None


def curve_only_summary(n_epochs: int) -> dict[str, Any]:
    """Projections-only path: always NO-GO / never GO."""
    return {
        "tool": "rc-gate",
        "schema_version": 2,
        "verdict": "NO-GO",
        "go": False,
        "n_reports": 0,
        "reports": [],
        "blocking_reasons": [
            "PROVISIONAL / NOT EVIDENCE: --curve-only emits the §R.7 projected "
            "W_res/W_cap / MAC heuristic curve only. Projections never satisfy "
            "G2/G3/G4. Verifier-floor MUST be measured. Never raise nMatMulRCHeight.",
        ],
        "decision_matrix": DECISION_MATRIX,
        "scale_curve": project_scale_curve(n_epochs),
        "scale_curve_evidence_class": "PROVISIONAL_NOT_EVIDENCE",
        "consensus_note": (
            "nMatMulRCHeight remains INT32_MAX; ENC_RC activation is NO-GO. "
            "§R.7 projected curve is PROVISIONAL / NOT EVIDENCE and must never "
            "be treated as a raise-height signal."
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Aggregate ENC_RC rc-episode-harness JSONs into a fail-closed "
            "GO/PARTIAL/NO-GO verdict (doc §8 / §R). Refuses projections, "
            "MAC-count estimates, and modeled verifier-floors as GO evidence. "
            "Optionally prints the §R.7 projected W_res/W_cap curve labeled "
            "PROVISIONAL / NOT EVIDENCE (never a raise-height signal)."
        ),
    )
    ap.add_argument(
        "inputs",
        nargs="*",
        metavar="PATH",
        help="JSON file(s) and/or directories containing *.json reports",
    )
    ap.add_argument(
        "--out",
        default="summary.json",
        metavar="PATH",
        help="Write machine-readable summary JSON (default: summary.json)",
    )
    ap.add_argument(
        "--curve-epochs",
        type=int,
        default=16,
        metavar="N",
        help=(
            "Print PROVISIONAL §R.7 W_res/W_cap for epochs 0..N-1 "
            "(default: 16). NOT EVIDENCE; never raises height."
        ),
    )
    ap.add_argument(
        "--curve-only",
        action="store_true",
        help=(
            "Only print the PROVISIONAL / NOT EVIDENCE scale curve "
            "(no JSON reports). Verdict is NO-GO — never GO."
        ),
    )
    ap.add_argument(
        "--print-decision-matrix",
        action="store_true",
        help="Print the gate decision matrix and exit",
    )
    args = ap.parse_args()

    if args.print_decision_matrix:
        print("ENC_RC rc-gate decision matrix (fail-closed):")
        for k, v in DECISION_MATRIX.items():
            print(f"  {k}: {v}")
        return 0

    if args.curve_only:
        print_scale_curve(max(1, args.curve_epochs))
        summary = curve_only_summary(max(1, args.curve_epochs))
        print(
            "VERDICT: NO-GO — projections-only (--curve-only). "
            "PROVISIONAL / NOT EVIDENCE. nMatMulRCHeight stays INT32_MAX."
        )
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"  wrote:    {out_path}")
        return 1  # NO-GO

    if not args.inputs:
        die("no JSON reports found (pass paths, or use --curve-only)")

    reports = load_reports(args.inputs)
    summary = aggregate(reports)
    print_human(summary)
    print_scale_curve(max(1, args.curve_epochs), _load_curve_constants(reports))
    summary["scale_curve"] = project_scale_curve(max(1, args.curve_epochs))
    summary["scale_curve_evidence_class"] = "PROVISIONAL_NOT_EVIDENCE"
    summary["consensus_note"] = (
        "nMatMulRCHeight remains INT32_MAX; ENC_RC activation is NO-GO. "
        "Offline tally never wires consensus and never recommends raising "
        "height from toy measurements or §R.7 projections (doc §8 / §9 / §R.7). "
        "Verifier-floor MUST be measured; MAC/heuristic curves are NOT EVIDENCE."
    )

    # Belt-and-suspenders: never emit go=true if scale curve is the only signal.
    if summary.get("go") and summary.get("n_reports", 0) == 0:
        summary["go"] = False
        summary["verdict"] = "NO-GO"

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote:    {out_path}")

    # Exit 0 for GO or PARTIAL (measurement path succeeded); 1 for NO-GO; 2 usage.
    return 0 if summary["verdict"] in ("GO", "PARTIAL") else 1


if __name__ == "__main__":
    raise SystemExit(main())
