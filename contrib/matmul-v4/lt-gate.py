#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
"""Rank-1 ENC-DR-LT GO/NO-GO checklist + device-JSON aggregator.

Mirrors contrib/matmul-v4/k2b-gate.py for schema_version 3 / profile bmx4c-lt
reports produced by `measure-hardware.sh <backend> --profile bmx4c-lt`.

HARD RULE: invent nothing. Missing fields, missing labels, missing device
rates, or missing review acknowledgements => NO-GO (fail closed). This tool
never raises nMatMulDRLTHeight and never claims the campaign is closed.

Usage:
  contrib/matmul-v4/lt-gate.py --check-inert
  contrib/matmul-v4/lt-gate.py --list-gates
  contrib/matmul-v4/lt-gate.py results/ --manifest parts.tsv
  contrib/matmul-v4/lt-gate.py results/ --label b200=nvidia:datacenter:B200 \\
      --label 5090=nvidia:consumer:RTX5090 --json
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import re
import sys
from math import gcd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

VALID_CLASSES = {"datacenter", "consumer", "apple", "other", "cpu-ref"}
FRONTIER_CLASSES = {"datacenter", "consumer", "other"}
LT_PRODUCTION_N = 4096


def die(msg: str, code: int = 2) -> None:
    sys.stderr.write("lt-gate: " + msg + "\n")
    sys.exit(code)


def _has_def(path: Path, name: str) -> bool:
    text = path.read_text(encoding="utf-8")
    return bool(re.search(rf"\b{re.escape(name)}\s*\(", text))


def check_inert() -> list[str]:
    errors: list[str] = []
    params = (ROOT / "src/consensus/params.h").read_text(encoding="utf-8")
    if "nMatMulDRLTHeight" not in params:
        errors.append("missing nMatMulDRLTHeight in consensus/params.h")
    if "ENC_BMX4C_LT" not in params:
        errors.append("missing ENC_BMX4C_LT profile enum")
    chain = (ROOT / "src/kernel/chainparams.cpp").read_text(encoding="utf-8")
    if "nMatMulDRLTHeight" not in chain:
        errors.append("chainparams missing nMatMulDRLTHeight assignment")
    if "assert_profile_dimension_pin" not in chain or "nMatMulDRLTHeight" not in chain:
        errors.append("chainparams missing DRLT dimension-pin wiring")
    if not re.search(
        r"nMatMulDRLTHeight\s*!=\s*std::numeric_limits<int32_t>::max\(\)[\s\S]*?"
        r"assert_profile_dimension_pin\s*\(\s*lt_profile\s*\)",
        chain,
    ):
        errors.append("live DRLT block must call assert_profile_dimension_pin(lt_profile)")

    lt_h = ROOT / "src/matmul/matmul_v4_lt.h"
    lt_c = ROOT / "src/matmul/matmul_v4_lt.cpp"
    if not lt_h.is_file() or not lt_c.is_file():
        errors.append("missing matmul_v4_lt reference sources")
    else:
        for sym in ("MixMatExpandEntry", "ExtractDequantMatExpand", "DeriveMatExpandPrfKey",
                    "ExtractDequantMatExpandSplitMix", "PlanLTAccel"):
            if not _has_def(lt_h, sym) and f"{sym}" not in lt_h.read_text(encoding="utf-8"):
                errors.append(f"missing declaration of {sym} in matmul_v4_lt.h")
            if not _has_def(lt_c, sym):
                errors.append(f"missing definition of {sym} in matmul_v4_lt.cpp")
        lt_body = lt_c.read_text(encoding="utf-8")
        if "ExtractDequantMatExpand" not in lt_body or "MatExpandCore" not in lt_body:
            errors.append("MatExpandCore must use ExtractDequantMatExpand")
        if "ChaCha20" not in lt_body and "chacha20" not in lt_body:
            errors.append("normative MatExpand Extract must use in-tree ChaCha20 PRF")
        if "BTX_MATEXPAND_PRF_V44LT" not in lt_body:
            errors.append("missing MatExpand PRF domain tag BTX_MATEXPAND_PRF_V44LT")
        # Restrict legacy-call checks to MatExpandCore's definition. Searching
        # from its name through the whole file falsely matched the intentionally
        # retained differential-only SplitMix definition later in the source.
        core = re.search(r"MatExpandCore\s*\([\s\S]*?\n\}\s*\n", lt_body)
        if core and "FoldInt32ToEmax48" in core.group(0):
            errors.append("MatExpandCore still uses FoldInt32ToEmax48 (affine fold)")
        if core and re.search(r"\bExtractDequantMatExpandSplitMix\s*\(", core.group(0)):
            errors.append("MatExpandCore must not call legacy SplitMix Extract")

    accel = (ROOT / "src/matmul/accel_v4.cpp").read_text(encoding="utf-8")
    if "ComputeDigestsBMX4CLTDispatched" not in accel:
        errors.append("accel_v4 missing ComputeDigestsBMX4CLTDispatched")
    pow_cpp = (ROOT / "src/pow.cpp").read_text(encoding="utf-8")
    if "ComputeDigestsBMX4CLTDispatched" not in pow_cpp:
        errors.append("pow.cpp EncDr path must call ComputeDigestsBMX4CLTDispatched")

    if _has_def(lt_h, "SealWindowCommit") and not _has_def(lt_c, "SealWindowCommit"):
        errors.append("SealWindowCommit declared without definition")

    spec = ROOT / "doc/btx-matmul-v4.4-lt-normative-spec.md"
    if not spec.is_file():
        errors.append("missing LT normative spec")
    adv = ROOT / "doc/btx-matmul-v4.4-lt-adversarial-analysis.md"
    if not adv.is_file():
        errors.append("missing LT adversarial analysis doc")
    packet = ROOT / "doc/btx-matmul-v4.4-lt-external-c15-packet.md"
    if not packet.is_file():
        errors.append("missing external C-15 review packet")
    return errors


def print_gates() -> None:
    gates = [
        "G1 Native tensor execution majority on B200+5090 from device timing/counters",
        "G2 B200/5090 silicon nonce/s >= ~4x from resident consensus-Q* batches",
        "G3 Nonce/$ proxies from silicon-eligible rates: B200 >= 5090 — operator costs only",
        "G4 MI350 FER / OCP MX exactness PASS",
        "G5 MatExpand adversarial review (ChaCha20-PRF+M11 candidate; external C-15 OPEN — not closed; orthogonal to FMM/ASERT)",
        "G6 Tip verify budget with sketch-cache within policy",
        "G7 Header-PoW + authenticated chainwork blockers still required (bit-26 wire withdrawn)",
        "G8 Phase B seal-as-PoW only if Rank-1 launch requires consensus-bound windows",
    ]
    print("Rank-1 ENC-DR-LT GO/NO-GO gates (silicon / review — not auto-pass):")
    for g in gates:
        print(f"  [ ] {g}")


def load_reports(paths: list[str]) -> list[dict]:
    files: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "*.json"))))
        else:
            files.append(p)
    if not files:
        die("no JSON reports found in the given path(s)")
    reports: list[dict] = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as e:
            die("cannot parse %s: %s" % (f, e))
        if data.get("tool") != "matmul-v4-report":
            die("%s is not a matmul-v4-report JSON (tool=%r)" % (f, data.get("tool")))
        data["_file"] = os.path.basename(f)
        reports.append(data)
    return reports


def parse_labels(manifest_path: str | None, label_args: list[str] | None) -> dict:
    labels: dict[str, tuple[str, str, str]] = {}
    if manifest_path:
        try:
            with open(manifest_path, "r", encoding="utf-8") as fh:
                for lineno, raw in enumerate(fh, 1):
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    cols = line.split("\t")
                    if len(cols) < 3:
                        die(
                            "manifest %s line %d: need >=3 tab-separated columns "
                            "(host, vendor, class[, part])" % (manifest_path, lineno)
                        )
                    key, vendor, cls = cols[0].strip(), cols[1].strip(), cols[2].strip().lower()
                    part = cols[3].strip() if len(cols) > 3 else ""
                    labels[key] = (vendor, cls, part)
        except OSError as e:
            die("cannot read manifest %s: %s" % (manifest_path, e))
    for lab in label_args or []:
        if "=" not in lab:
            die("--label must be host=vendor:class[:part], got %r" % lab)
        key, spec = lab.split("=", 1)
        bits = spec.split(":")
        if len(bits) < 2:
            die("--label value must be vendor:class[:part], got %r" % spec)
        vendor, cls = bits[0].strip(), bits[1].strip().lower()
        part = bits[2].strip() if len(bits) > 2 else ""
        labels[key.strip()] = (vendor, cls, part)
    for _, (_, cls, _) in labels.items():
        if cls not in VALID_CLASSES:
            die(
                "label class %r invalid; use one of %s"
                % (cls, ", ".join(sorted(VALID_CLASSES)))
            )
    return labels


def label_for(rep: dict, labels: dict) -> tuple[str | None, str | None, str | None]:
    backend = rep.get("backend", "")
    host = rep.get("host", "")
    if backend == "cpu":
        return ("reference", "cpu-ref", "CPU")
    for key in (
        rep["_file"],
        rep["_file"].replace(".json", ""),
        host,
        "%s/%s" % (host, backend),
        backend,
    ):
        if key in labels:
            return labels[key]
    for key, val in labels.items():
        if key and (key in rep["_file"] or key in host):
            return val
    return (None, None, None)


def stage_bit_exact(rep: dict) -> bool:
    st = rep.get("stages") or {}
    return bool(st.get("bit_exact", False))


def finite_number(value: object) -> float | None:
    """Return a finite JSON number, rejecting bools and numeric strings."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def report_metric(rep: dict, key: str) -> float | None:
    """Read a finite top-level metric, falling back to the stages object."""
    v = rep.get(key)
    if v is None:
        st = rep.get("stages") or {}
        v = st.get(key)
    return finite_number(v)


def tensor_share(rep: dict) -> float | None:
    """CPU-reference stage composition; never device execution evidence."""
    value = report_metric(rep, "cpu_reference_tensor_share_pct")
    if value is None:
        # Legacy schema-3 reports used this ambiguous name. Preserve it only as
        # a diagnostic CPU composition value; it can never satisfy G1.
        value = report_metric(rep, "tensor_share_pct")
    return value


def device_tensor_share(rep: dict) -> float | None:
    """Counter/timer-backed native device tensor share, when certified."""
    value = report_metric(rep, "device_tensor_share_pct")
    if value is None or value < 0 or value > 100:
        return None
    return value


def device_tensor_majority_verified(rep: dict) -> bool:
    """Require native capability plus independent device timing/counters.

    A CPU stage timer can say that GEMM-shaped reference work dominates the
    reference composition.  It cannot say that a device executed tensor
    instructions or spent a majority of its time there.  Keep G1 fail-closed
    until the backend publishes both facts explicitly.
    """
    share = device_tensor_share(rep)
    return (
        rep.get("backend") != "cpu"
        and rep.get("native_path_eligible") is True
        and rep.get("device_tensor_timing_valid") is True
        and rep.get("device_tensor_counters_valid") is True
        and rep.get("device_tensor_timing_domain") == "device-kernel-timing-and-counters"
        and share is not None
        and share > 50.0
    )


def tensor_util(rep: dict) -> float | None:
    value = report_metric(rep, "tensor_util_pct")
    if value is None or value < 0:
        return None
    return value


def positive_number(value: object) -> float | None:
    result = finite_number(value)
    return result if result is not None and result > 0 else None


def asert_suggestion(rep: dict) -> str | None:
    """Return a well-formed, reduced positive Num/Den suggestion, if present."""
    value = rep.get("asert_rescale_num_den_suggestion")
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"([1-9][0-9]*)/([1-9][0-9]*)", value.strip())
    if not match:
        return None
    num, den = int(match.group(1)), int(match.group(2))
    if gcd(num, den) != 1:
        return None
    return "%d/%d" % (num, den)


def expected_asert_suggestion(rep: dict) -> str | None:
    """Mirror matmul-v4-report's positive-value ReducedRatio arithmetic."""
    v3 = positive_number(rep.get("v3_hashrate"))
    nps = device_nps(rep)
    if v3 is None or nps is None:
        return None
    # C++ std::llround rounds positive half values away from zero.
    num, den = int(v3 + 0.5), int(nps + 0.5)
    if num <= 0 or den <= 0:
        return None
    divisor = gcd(num, den)
    return "%d/%d" % (num // divisor, den // divisor)


def silicon_rate_provenance(rep: dict) -> bool:
    """Require a consensus-Q* device-resident batch before ranking silicon.

    Exact device participation is not sufficient: the former raw report loop
    issued one seed-complete call per nonce and was dominated by host W
    expansion, launches, copies, synchronization, and host digesting.
    """
    lt = rep.get("lt") or {}
    return (
        lt.get("qstar_is_consensus") is True
        and lt.get("qstar_device_batched") is True
        and lt.get("device_w_generation") is True
        and lt.get("device_digest") is True
        and lt.get("per_nonce_sync_absent") is True
        and lt.get("rate_provenance") == "device-resident-qstar-batched"
    )


def device_measured(rep: dict) -> bool:
    """True only for a silicon-comparable batched DEVICE nonce/s."""
    if rep.get("backend") == "cpu":
        return False
    lt = rep.get("lt") or {}
    # This exact tuple is deliberately separate from native tensor-instruction
    # certification, but it must prove resident Q* scheduling rather than mere
    # device participation in a host-orchestrated per-nonce loop.
    if rep.get("backend_used_device") is not True:
        return False
    if rep.get("device_rate_valid") is not True:
        return False
    if rep.get("silicon_rate_valid") is not True:
        return False
    if rep.get("execution_path") != "device-resident-qstar-batched":
        return False
    if lt.get("device_assisted_path_exact") is not True:
        return False
    if not silicon_rate_provenance(rep):
        return False
    # Null/missing/zero/negative/non-finite values and CPU-reference fields do
    # not count. A measured device rate is necessarily finite and positive.
    return positive_number(rep.get("device_nonce_per_s")) is not None


def device_nps(rep: dict) -> float | None:
    if not device_measured(rep):
        return None
    return positive_number(rep.get("device_nonce_per_s"))


def g2_comparison_config(rep: dict) -> tuple[int, int, int, str, str] | None:
    """Return the exact workload/build identity required for a G2 comparison."""
    dimensions: list[int] = []
    for field in ("n", "window", "rounds"):
        value = rep.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return None
        dimensions.append(value)
    measurement_mode = rep.get("measurement_mode")
    source_revision = rep.get("source_revision")
    if not isinstance(measurement_mode, str) or not measurement_mode:
        return None
    if (
        not isinstance(source_revision, str)
        or not source_revision
        or source_revision.endswith("-dirty")
    ):
        return None
    return (*dimensions, measurement_mode, source_revision)


def g2_part_matches(row: dict, expected: str) -> bool:
    """Require the explicitly labeled silicon named by the B200/5090 gate."""
    part = re.sub(r"[^a-z0-9]", "", (row.get("part") or "").lower())
    return expected in part


def host_orchestrated_nps(rep: dict) -> float | None:
    """Diagnostic wall rate; never usable by G2/G3 or ASERT."""
    return positive_number(rep.get("host_orchestrated_nonce_per_s"))


def parse_cost_args(cost_args: list[str] | None) -> dict[str, float]:
    """Optional operator-supplied $/hour (or purchase-normalized) keyed like labels."""
    out: dict[str, float] = {}
    for c in cost_args or []:
        if "=" not in c:
            die("--cost must be host=dollars_per_unit, got %r" % c)
        key, val = c.split("=", 1)
        try:
            out[key.strip()] = float(val.strip())
        except ValueError:
            die("--cost value must be a number, got %r" % val)
    return out


def cost_for(row: dict, costs: dict[str, float]) -> float | None:
    for key in (row.get("part") or "", row.get("host") or "", row.get("file") or ""):
        if key and key in costs:
            return costs[key]
    for key, val in costs.items():
        if key and (key in (row.get("file") or "") or key in (row.get("host") or "")):
            return val
    return None


def evaluate(
    reports: list[dict],
    labels: dict,
    costs: dict[str, float],
    ack_external_c15: bool,
) -> tuple[bool, dict, list, list[str], list[str], dict]:
    rows: list[dict] = []
    reasons: list[str] = []
    notes: list[str] = []
    frontier: list[dict] = []

    for rep in reports:
        vendor, cls, part = label_for(rep, labels)
        is_lt = rep.get("schema_version") == 3 and rep.get("profile") == "bmx4c-lt"
        be = bool(rep.get("bit_exact", False)) and stage_bit_exact(rep)
        tsp = tensor_share(rep)
        device_tsp = device_tensor_share(rep)
        device_tensor_verified = device_tensor_majority_verified(rep)
        tup = tensor_util(rep)
        npe = bool(rep.get("native_path_eligible", False))
        measured_nps = device_nps(rep)
        comparison_config = g2_comparison_config(rep)
        reported_asert = asert_suggestion(rep)
        expected_asert = expected_asert_suggestion(rep)
        row = {
            "file": rep["_file"],
            "host": rep.get("host", ""),
            "backend": rep.get("backend", ""),
            "vendor": vendor,
            "class": cls,
            "part": part or "",
            "bmx4c_lt": is_lt,
            "bit_exact": be,
            "native_path_eligible": npe,
            "tensor_share_pct": tsp,
            "cpu_reference_tensor_share_pct": tsp,
            "device_tensor_share_pct": device_tsp,
            "device_tensor_majority_verified": device_tensor_verified,
            "device_tensor_timing_valid": rep.get("device_tensor_timing_valid") is True,
            "device_tensor_counters_valid": rep.get("device_tensor_counters_valid") is True,
            "device_tensor_timing_domain": rep.get("device_tensor_timing_domain"),
            "tensor_util_pct": tup,
            "backend_used_device": rep.get("backend_used_device") is True,
            "device_rate_valid": rep.get("device_rate_valid") is True,
            "silicon_rate_valid": rep.get("silicon_rate_valid") is True,
            "execution_path": rep.get("execution_path"),
            "device_assisted_path_exact": (rep.get("lt") or {}).get("device_assisted_path_exact") is True,
            "silicon_rate_provenance": silicon_rate_provenance(rep),
            "device_measured": device_measured(rep),
            "nps": measured_nps,
            "g2_comparison_config": comparison_config,
            "host_orchestrated_nps": host_orchestrated_nps(rep),
            "cpu_nps": None,
            "v3_hashrate": positive_number(rep.get("v3_hashrate")),
            "asert_suggestion": reported_asert,
            "asert_expected": expected_asert,
            "asert_consistent": (
                reported_asert == expected_asert
                if reported_asert is not None and expected_asert is not None
                else None
            ),
        }
        try:
            cn = rep.get("cpu_reference_nonce_per_s")
            if cn is not None:
                row["cpu_nps"] = float(cn)
        except (TypeError, ValueError):
            row["cpu_nps"] = None
        rows.append(row)

        if row["host_orchestrated_nps"] is not None and measured_nps is None:
            notes.append(
                "%s reports %.3g host-orchestrated nonce/s; diagnostic only — excluded "
                "from G2, G3, tensor utilization, and ASERT calibration."
                % (rep["_file"], row["host_orchestrated_nps"])
            )

        if reported_asert is not None and measured_nps is None:
            notes.append(
                "%s carries an ASERT suggestion without a silicon-eligible batched Q* rate; "
                "exclude it from calibration." % rep["_file"]
            )

        if is_lt and measured_nps is not None and row["v3_hashrate"] is not None:
            if reported_asert is None:
                notes.append(
                    "%s has measured LT device nonce/s + v3_hashrate but no valid reduced "
                    "asert_rescale_num_den_suggestion; expected %s (calibration evidence only; "
                    "not a G2 substitute)." % (rep["_file"], expected_asert or "n/a")
                )
            elif expected_asert is not None and reported_asert != expected_asert:
                notes.append(
                    "%s ASERT suggestion %s does not match measured v3/device ratio %s; "
                    "exclude that suggestion from calibration (G2 still uses measured device "
                    "nonce/s only)." % (rep["_file"], reported_asert, expected_asert)
                )

        if not be:
            reasons.append(
                "G1 bit-exactness FAIL on %s (%s/%s) — consensus-split signal; NO-GO."
                % (rep["_file"], vendor or "?", rep.get("backend", "?"))
            )
        if not is_lt:
            if rep.get("profile") == "bmx4c":
                notes.append(
                    "%s is an ENC-BMX4C report — use contrib/matmul-v4/k2b-gate.py; "
                    "excluded from the LT aggregator." % rep["_file"]
                )
            else:
                notes.append(
                    "%s is not an ENC-DR-LT report (schema_version=%r profile=%r) — excluded."
                    % (rep["_file"], rep.get("schema_version"), rep.get("profile"))
                )
            continue
        if rep.get("backend") == "cpu":
            notes.append(
                "%s is a CPU-reference run — certifies the harness, never frontier silicon."
                % rep["_file"]
            )
            continue
        if cls is None:
            notes.append(
                "%s (host=%s backend=%s) is UNLABELED — excluded from silicon gates. "
                "Add --label %s=vendor:class."
                % (
                    rep["_file"],
                    rep.get("host", "?"),
                    rep.get("backend", "?"),
                    rep.get("host") or rep["_file"],
                )
            )
            continue
        if cls not in FRONTIER_CLASSES:
            notes.append("%s class=%s excluded from frontier silicon set." % (rep["_file"], cls))
            continue
        frontier.append(row)

    # G1 — native tensor execution must be a measured majority on every labeled
    # frontier part. CPU-reference stage composition is diagnostic only.
    g1_fail = [r for r in frontier if not r["device_tensor_majority_verified"]]
    # Also require at least one datacenter and one consumer frontier report present.
    has_b200ish = any(r["class"] == "datacenter" for r in frontier)
    has_5090ish = any(r["class"] == "consumer" for r in frontier)
    g1 = (
        len(frontier) > 0
        and not g1_fail
        and has_b200ish
        and has_5090ish
        and all(r["bit_exact"] for r in frontier)
    )
    for r in g1_fail:
        reasons.append(
            "G1 native tensor-majority FAIL on %s: device share=%s; require >50%% "
            "from device-side timing/counters plus native_path_eligible=true. "
            "cpu_reference_tensor_share_pct=%s does not count."
            % (
                r["file"],
                "unknown" if r["device_tensor_share_pct"] is None
                else "%.1f%%" % r["device_tensor_share_pct"],
                "unknown" if r["cpu_reference_tensor_share_pct"] is None
                else "%.1f%%" % r["cpu_reference_tensor_share_pct"],
            )
        )
    if frontier and not has_b200ish:
        reasons.append(
            "G1: no labeled datacenter-class LT report in the set (need B200-class)."
        )
    if frontier and not has_5090ish:
        reasons.append(
            "G1: no labeled consumer-class LT report in the set (need 5090-class)."
        )
    if not frontier:
        reasons.append(
            "G1: no labeled frontier ENC-DR-LT reports — fail closed (collect "
            "`measure-hardware.sh <cuda|metal|hip> --profile bmx4c-lt` JSON)."
        )

    # G2 — B200/5090 silicon nonce/s ratio >= ~4x. Fail closed unless each rate
    # is a consensus-Q* device-resident batch with W generation and digest on
    # device and no per-nonce synchronization. Reports are comparable only
    # when workload, measurement mode, and source revision match exactly.
    dc = [
        r
        for r in frontier
        if r["class"] == "datacenter"
        and g2_part_matches(r, "b200")
        and r["nps"] is not None
    ]
    cons = [
        r
        for r in frontier
        if r["class"] == "consumer"
        and g2_part_matches(r, "5090")
        and r["nps"] is not None
    ]
    g2 = False
    g2_evidence = {
        "datacenter_file": None,
        "consumer_file": None,
        "datacenter_nonce_per_s": None,
        "consumer_nonce_per_s": None,
        "ratio": None,
        "comparison_config": None,
    }
    if not dc or not cons:
        reasons.append(
            "G2 B200/5090 ratio: UNVERIFIED — need explicitly labeled B200 and RTX 5090 "
            "reports with finite positive device_nonce_per_s from resident consensus-Q* "
            "batches (device W generation + digest; no per-nonce sync). Other parts, CPU "
            "rates, and host-orchestrated rates do not count."
        )
    else:
        comparable: list[tuple[dict, dict]] = []
        for dc_row in dc:
            config = dc_row["g2_comparison_config"]
            if config is None or config[0] != LT_PRODUCTION_N:
                continue
            for consumer_row in cons:
                if consumer_row["g2_comparison_config"] == config:
                    comparable.append((dc_row, consumer_row))

        if not comparable:
            reasons.append(
                "G2 B200/5090 ratio: UNVERIFIED — no comparable datacenter/consumer "
                "production report pair. Both reports must use n=4096 and have identical "
                "positive integer window and rounds plus identical non-empty "
                "measurement_mode and identical clean source_revision (-dirty builds are rejected)."
            )
        else:
            configs = {dc_row["g2_comparison_config"] for dc_row, _ in comparable}
            if len(configs) != 1:
                reasons.append(
                    "G2 B200/5090 ratio: UNVERIFIED — multiple comparable production "
                    "campaign configurations were supplied; filter inputs to one exact "
                    "n/window/rounds/measurement_mode/source_revision campaign."
                )
            else:
                config = next(iter(configs))
                matching_dc = [r for r in dc if r["g2_comparison_config"] == config]
                matching_consumers = [r for r in cons if r["g2_comparison_config"] == config]
                best_dc = max(matching_dc, key=lambda r: r["nps"])
                best_c = max(matching_consumers, key=lambda r: r["nps"])
                ratio = best_dc["nps"] / best_c["nps"]
                n, window, rounds, measurement_mode, source_revision = config
                g2_evidence = {
                    "datacenter_file": best_dc["file"],
                    "consumer_file": best_c["file"],
                    "datacenter_nonce_per_s": best_dc["nps"],
                    "consumer_nonce_per_s": best_c["nps"],
                    "ratio": ratio,
                    "comparison_config": {
                        "n": n,
                        "window": window,
                        "rounds": rounds,
                        "measurement_mode": measurement_mode,
                        "source_revision": source_revision,
                    },
                }
                g2 = ratio >= 4.0
                if not g2:
                    reasons.append(
                        "G2 B200/5090 ratio FAIL: %.3g / %.3g = %.2fx < 4x "
                        "(n=%d window=%d rounds=%d mode=%s revision=%s)."
                        % (
                            best_dc["nps"],
                            best_c["nps"],
                            ratio,
                            n,
                            window,
                            rounds,
                            measurement_mode,
                            source_revision,
                        )
                    )

    # G3 — nonce/$ ordering from operator-supplied costs only (never invent $/hr).
    # Use the same exact workload/build campaign selected for G2. Comparing the
    # best cost-normalized reports independently would recreate the old G2 bug:
    # a cheap/small/old consumer run could be ranked against an unrelated
    # production/new datacenter run even though both rates are individually
    # silicon-eligible.
    g3 = False
    if not costs:
        reasons.append(
            "G3 nonce/$: UNVERIFIED — supply --cost host=dollars_per_unit for labeled "
            "parts (this tool invents no rental/purchase prices)."
        )
    elif g2_evidence["comparison_config"] is None:
        reasons.append(
            "G3 nonce/$: UNVERIFIED — no exact workload/build-matched "
            "datacenter/consumer campaign is available for cost comparison."
        )
    else:
        selected = g2_evidence["comparison_config"]
        selected_config = (
            selected["n"],
            selected["window"],
            selected["rounds"],
            selected["measurement_mode"],
            selected["source_revision"],
        )
        measured = [
            r
            for r in frontier
            if r["nps"] is not None and r["g2_comparison_config"] == selected_config
        ]
        scored = []
        for r in measured:
            c = cost_for(r, costs)
            if c is None or c <= 0:
                continue
            scored.append((r, r["nps"] / c))
        dc_s = [s for s in scored if s[0]["class"] == "datacenter"]
        c_s = [s for s in scored if s[0]["class"] == "consumer"]
        costed_configs = {
            dc_score[0]["g2_comparison_config"]
            for dc_score in dc_s
            for consumer_score in c_s
            if dc_score[0]["g2_comparison_config"] is not None
            and dc_score[0]["g2_comparison_config"][0] == LT_PRODUCTION_N
            and dc_score[0]["g2_comparison_config"]
            == consumer_score[0]["g2_comparison_config"]
        }
        if not costed_configs:
            reasons.append(
                "G3 nonce/$: UNVERIFIED — need --cost for a comparable datacenter/consumer "
                "n=4096 pair with identical window, rounds, measurement_mode, and "
                "clean source_revision that also carries silicon-eligible device_nonce_per_s."
            )
        elif len(costed_configs) != 1:
            reasons.append(
                "G3 nonce/$: UNVERIFIED — multiple costed production campaign "
                "configurations were supplied; filter inputs to one exact campaign."
            )
        else:
            config = next(iter(costed_configs))
            best_dc_s = max(
                (score for score in dc_s if score[0]["g2_comparison_config"] == config),
                key=lambda x: x[1],
            )
            best_c_s = max(
                (score for score in c_s if score[0]["g2_comparison_config"] == config),
                key=lambda x: x[1],
            )
            g3 = best_dc_s[1] >= best_c_s[1]
            if not g3:
                reasons.append(
                    "G3 REWARD INVERSION (nonce/$): datacenter %.3g < consumer %.3g."
                    % (best_dc_s[1], best_c_s[1])
                )

    # G4 — MI350 / AMD datacenter native_path_eligible (exactness claim).
    amd_dc = [
        r
        for r in frontier
        if r["class"] == "datacenter"
        and (r["vendor"] or "").lower() in ("amd", "mi350", "amdgpu")
    ]
    g4 = bool(amd_dc) and all(r["native_path_eligible"] for r in amd_dc)
    if not amd_dc:
        reasons.append(
            "G4 MI350/OCP MX: UNVERIFIED — no labeled amd:datacenter LT report with "
            "native_path_eligible (fail closed)."
        )
    else:
        for r in amd_dc:
            if not r["native_path_eligible"]:
                reasons.append(
                    "G4 MI350 exactness FAIL on %s: native_path_eligible=false." % r["file"]
                )

    # G5 — external C-15: never auto-pass from JSON; require explicit ack.
    # Orthogonal to FMM / ASERT calibration (tournament = fastest known exact;
    # G1–G4 consume measured silicon JSON only — invent no rates). C-15 OPEN.
    g5 = bool(ack_external_c15)
    if not g5:
        reasons.append(
            "G5 external C-15: NOT acknowledged — pass --ack-external-c15 only after an "
            "independent cryptanalyst completes doc/btx-matmul-v4.4-lt-external-c15-packet.md "
            "(internal ChaCha20-PRF + non-affinity witnesses are not sufficient; "
            "C-15 remains OPEN until independent review; G5 is orthogonal to FMM/"
            "ASERT tournament baselines — see lt-c15-asert-fmm-calibration note)."
        )

    # G6/G7/G8 — measurement/review blockers; this aggregator cannot invent them.
    g6 = False
    g7 = False
    g8 = False
    reasons.append(
        "G6 tip-verify budget: UNVERIFIED by this aggregator (no tip-soak JSON schema yet)."
    )
    reasons.append(
        "G7 Header-PoW + chainwork blockers: UNVERIFIED by this aggregator (separate gates)."
    )
    reasons.append(
        "G8 Phase B seal-as-PoW review: UNVERIFIED by this aggregator (code inert; review still required)."
    )

    gates = {
        "G1_tensor_majority": g1,
        "G2_b200_5090_ratio": g2,
        "G3_nonce_per_dollar": g3,
        "G4_mi350_exactness": g4,
        "G5_external_c15": g5,
        "G6_tip_verify_budget": g6,
        "G7_header_chainwork": g7,
        "G8_seal_as_pow_review": g8,
    }
    go = all(gates.values())
    return go, gates, rows, reasons, notes, {
        "frontier_count": len(frontier),
        "has_datacenter": has_b200ish,
        "has_consumer": has_5090ish,
        "g2_evidence": g2_evidence,
        "asert_calibration": [
            {
                "file": r["file"],
                "v3_hashrate": r["v3_hashrate"],
                "device_nonce_per_s": r["nps"],
                "silicon_rate_eligible": r["device_measured"],
                "reported_suggestion": r["asert_suggestion"],
                "expected_suggestion": r["asert_expected"],
                "consistent": r["asert_consistent"],
            }
            for r in rows
            if r["v3_hashrate"] is not None or r["asert_suggestion"] is not None
        ],
    }


def print_human(go: bool, gates: dict, rows: list, reasons: list[str], notes: list[str], extra: dict) -> None:
    W = 145
    print("=" * W)
    print("MatMul ENC-DR-LT — Rank-1 GO/NO-GO aggregate verdict")
    print("=" * W)
    hdr = "%-22s %-8s %-9s %-11s %-6s %-7s %-9s %-9s %-7s %-10s %-10s %s" % (
        "file",
        "backend",
        "vendor",
        "class",
        "bitex",
        "npe",
        "cpuShare%",
        "devShare%",
        "util%",
        "dev n/s",
        "diag n/s",
        "ASERT",
    )
    print(hdr)
    print("-" * W)
    for r in rows:
        tsp = "%.1f" % r["cpu_reference_tensor_share_pct"] if r["cpu_reference_tensor_share_pct"] is not None else "-"
        device_tsp = "%.1f" % r["device_tensor_share_pct"] if r["device_tensor_share_pct"] is not None else "-"
        tup = "%.1f" % r["tensor_util_pct"] if r["tensor_util_pct"] is not None else "-"
        nps = ("%.3g" % r["nps"]) if r["nps"] is not None else "-"
        diag_nps = ("%.3g" % r["host_orchestrated_nps"]) if r["host_orchestrated_nps"] is not None else "-"
        asert = r["asert_suggestion"] or "-"
        print(
            "%-22s %-8s %-9s %-11s %-6s %-7s %-9s %-9s %-7s %-10s %-10s %s"
            % (
                r["file"][:22],
                r["backend"],
                (r["vendor"] or "UNLABELED")[:9],
                (r["class"] or "-")[:11],
                "YES" if r["bit_exact"] else "NO",
                "YES" if r["native_path_eligible"] else "no",
                tsp,
                device_tsp,
                tup,
                nps,
                diag_nps,
                asert,
            )
        )
    print("-" * W)
    print("  (dev n/s requires a device-resident consensus-Q* batch, device W/digest, no per-nonce sync, and a finite positive rate)")
    print("  (diag n/s is host-orchestrated wall rate and never counts for G2/G3, tensor utilization, or ASERT)")
    print("  (cpuShare% is reference composition only; G1 requires devShare% > 50 from device timing/counters and a native tensor path)")
    print()
    print("Gate results:")
    labels = {
        "G1_tensor_majority": "G1 native tensor majority from device timing/counters on B200+5090",
        "G2_b200_5090_ratio": "G2 datacenter/consumer device nonce/s >= ~4x",
        "G3_nonce_per_dollar": "G3 nonce/$ (operator --cost only; no invented prices)",
        "G4_mi350_exactness": "G4 MI350/AMD datacenter native_path_eligible",
        "G5_external_c15": "G5 external C-15 packet acknowledged",
        "G6_tip_verify_budget": "G6 tip-verify budget",
        "G7_header_chainwork": "G7 Header-PoW + chainwork blockers",
        "G8_seal_as_pow_review": "G8 Phase B seal-as-PoW review",
    }
    for k in labels:
        print("  [%s] %s" % ("PASS" if gates[k] else "FAIL", labels[k]))
    if notes:
        print("\nNotes:")
        for n in notes:
            print("  - " + n)
    if reasons:
        print("\nBlocking reasons:")
        for r in reasons:
            print("  - " + r)
    print()
    print("=" * W)
    if go:
        print("VERDICT: GO — all Rank-1 gates satisfied in this offline tally.")
        print("         Humans may now consider ratification. This tool does NOT")
        print("         raise nMatMulDRLTHeight and does NOT close the campaign by itself.")
    else:
        print("VERDICT: NO-GO — see blocking reasons. nMatMulDRLTHeight stays INT32_MAX.")
        print("         Missing silicon JSON / costs / external C-15 ack fail closed.")
        print("         This is the correct honest state; no numbers were invented.")
    print("=" * W)


def check_g4(reports_dir: str | None) -> int:
    """G4 MI350/OCP MX readiness: never invent PASS.

    Without reports: PENDING (exit 0) unless BTX_REQUIRE_GPU_GOLDEN=1 (exit 1).
    With reports: require at least one schema_version=3 / profile=bmx4c-lt JSON
    labeled or carrying native_path_eligible for an AMD datacenter class — else
    PENDING/FAIL under the same env gate. This helper does not invent labels.
    """
    require = os.environ.get("BTX_REQUIRE_GPU_GOLDEN", "").strip() in ("1", "true", "yes")
    if not reports_dir:
        msg = "G4 MI350/OCP MX: PENDING (no --reports dir; no invented PASS)"
        print(msg)
        if require:
            print("FAIL: BTX_REQUIRE_GPU_GOLDEN=1 but no reports directory", file=sys.stderr)
            return 1
        return 0

    files = sorted(glob.glob(os.path.join(reports_dir, "*.json")))
    if not files:
        print("G4 MI350/OCP MX: PENDING (empty reports dir %s)" % reports_dir)
        if require:
            print("FAIL: BTX_REQUIRE_GPU_GOLDEN=1 and no JSON in %s" % reports_dir, file=sys.stderr)
            return 1
        return 0

    eligible = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as e:
            die("cannot parse %s: %s" % (f, e))
        if data.get("tool") != "matmul-v4-report":
            continue
        if data.get("schema_version") != 3 or data.get("profile") != "bmx4c-lt":
            continue
        if bool(data.get("native_path_eligible", False)):
            eligible.append(os.path.basename(f))

    if not eligible:
        print(
            "G4 MI350/OCP MX: PENDING — no bmx4c-lt report with native_path_eligible=true "
            "in %s (fail closed; no invented PASS)" % reports_dir
        )
        if require:
            print("FAIL: BTX_REQUIRE_GPU_GOLDEN=1 and no eligible LT report", file=sys.stderr)
            return 1
        return 0

    print("G4 MI350/OCP MX: candidate reports with native_path_eligible=true:")
    for e in eligible:
        print("  - " + e)
    print(
        "NOTE: labeling (amd:datacenter) is still required via lt-gate.py aggregate; "
        "this check only confirms eligible JSON exists — not Rank-1 GO."
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "paths",
        nargs="*",
        help="JSON report files and/or directories (schema_version 3 / profile bmx4c-lt)",
    )
    ap.add_argument("--check-inert", action="store_true", help="Verify LT scaffolding stays inert-ready")
    ap.add_argument("--list-gates", action="store_true", help="Print GO/NO-GO gates")
    ap.add_argument(
        "--check-g4",
        action="store_true",
        help="MI350/OCP MX readiness probe (PENDING unless eligible JSON; never invent PASS)",
    )
    ap.add_argument(
        "--reports",
        help="Directory of matmul-v4-report JSON for --check-g4 / aggregation",
    )
    ap.add_argument("--manifest", help="TSV: <host-or-file>\\t<vendor>\\t<class>[\\t<part>]")
    ap.add_argument(
        "--label",
        action="append",
        default=[],
        help="host=vendor:class[:part] (repeatable; overrides manifest)",
    )
    ap.add_argument(
        "--cost",
        action="append",
        default=[],
        help="host=dollars_per_unit for G3 nonce/$ (repeatable; never invented)",
    )
    ap.add_argument(
        "--ack-external-c15",
        action="store_true",
        help=(
            "Operator asserts independent completion of the external C-15 packet (G5). "
            "Orthogonal to FMM/ASERT; does not invent silicon; C-15 remains OPEN until "
            "that review (see doc/btx-matmul-v4.4-lt-c15-asert-fmm-calibration-2026-07-19.md)."
        ),
    )
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    if args.list_gates:
        print_gates()

    if args.check_g4:
        code = check_g4(args.reports)
        if code != 0:
            return code
        if not args.check_inert and not args.paths:
            return 0

    if args.check_inert:
        errs = check_inert()
        if errs:
            for e in errs:
                print(f"FAIL: {e}", file=sys.stderr)
            return 1
        print("LT inert scaffolding: OK")
        text = (ROOT / "src/consensus/params.h").read_text(encoding="utf-8")
        if not re.search(r"nMatMulDRLTHeight\{std::numeric_limits<int32_t>::max\(\)\}", text):
            print("FAIL: nMatMulDRLTHeight default is not INT32_MAX", file=sys.stderr)
            return 1
        print("nMatMulDRLTHeight default INT32_MAX: OK")
        if not args.paths and not args.list_gates:
            return 0

    if args.list_gates and not args.paths and not args.check_inert:
        return 0

    paths = list(args.paths)
    if args.reports and not paths:
        paths = [args.reports]
    if not paths:
        if args.check_g4 or args.check_inert or args.list_gates:
            return 0
        die("provide JSON path(s), or use --check-inert / --list-gates / --check-g4")

    reports = load_reports(paths)
    labels = parse_labels(args.manifest, args.label)
    costs = parse_cost_args(args.cost)
    go, gates, rows, reasons, notes, extra = evaluate(
        reports, labels, costs, args.ack_external_c15
    )

    if args.json:
        print(
            json.dumps(
                {
                    "verdict": "GO" if go else "NO-GO",
                    "gates": gates,
                    "rows": rows,
                    "blocking_reasons": reasons,
                    "notes": notes,
                    "summary": extra,
                },
                indent=2,
            )
        )
    else:
        print_human(go, gates, rows, reasons, notes, extra)
    return 0 if go else 1


if __name__ == "__main__":
    sys.exit(main())
