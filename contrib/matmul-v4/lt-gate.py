#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
"""Rank-1 ENC-DR-LT GO/NO-GO checklist (mirrors k2b-gate style)."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


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
    # Dimension pin must be invoked inside the live-DRLT block.
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
        for sym in ("MixMatExpandEntry", "ExtractDequantMatExpand", "PlanLTAccel"):
            if not _has_def(lt_h, sym) and f"{sym}" not in lt_h.read_text(encoding="utf-8"):
                errors.append(f"missing declaration of {sym} in matmul_v4_lt.h")
            if not _has_def(lt_c, sym):
                errors.append(f"missing definition of {sym} in matmul_v4_lt.cpp")
        # Normative MatExpand must not fold via the legacy affine map alone.
        lt_body = lt_c.read_text(encoding="utf-8")
        if "ExtractDequantMatExpand" not in lt_body or "MatExpandCore" not in lt_body:
            errors.append("MatExpandCore must use ExtractDequantMatExpand")
        if re.search(r"MatExpandCore[\s\S]*?FoldInt32ToEmax48\s*\(", lt_body):
            # Fold may still appear elsewhere; forbid it as the MatExpandCore body path.
            core = re.search(r"MatExpandCore\s*\([\s\S]*?\n\}\s*\n", lt_body)
            if core and "FoldInt32ToEmax48" in core.group(0):
                errors.append("MatExpandCore still uses FoldInt32ToEmax48 (affine fold)")

    accel = (ROOT / "src/matmul/accel_v4.cpp").read_text(encoding="utf-8")
    if "ComputeDigestsBMX4CLTDispatched" not in accel:
        errors.append("accel_v4 missing ComputeDigestsBMX4CLTDispatched")
    pow_cpp = (ROOT / "src/pow.cpp").read_text(encoding="utf-8")
    if "ComputeDigestsBMX4CLTDispatched" not in pow_cpp:
        errors.append("pow.cpp EncDr path must call ComputeDigestsBMX4CLTDispatched")

    # Seal helpers are Phase-A harness / Phase-B prep: may be unused by pow/validation.
    # Fail only if declared without a definition.
    if _has_def(lt_h, "SealWindowCommit") and not _has_def(lt_c, "SealWindowCommit"):
        errors.append("SealWindowCommit declared without definition")

    spec = ROOT / "doc/btx-matmul-v4.4-lt-normative-spec.md"
    if not spec.is_file():
        errors.append("missing LT normative spec")
    adv = ROOT / "doc/btx-matmul-v4.4-lt-adversarial-analysis.md"
    if not adv.is_file():
        errors.append("missing LT adversarial analysis doc")
    return errors


def print_gates() -> None:
    gates = [
        "G1 Tensor wall-time majority on B200 and 5090 at Rank-1 unit",
        "G2 B200/5090 nonce/s >= ~4x on fat MatExpand+Q* miner schedule",
        "G3 Nonce/$ proxies: B200 >= 5090 (rental + purchase)",
        "G4 MI350 FER / OCP MX exactness PASS",
        "G5 MatExpand adversarial review (Mix+M11 Extract; external C-15 still required)",
        "G6 Tip verify budget with sketch-cache within policy",
        "G7 Header-PoW + authenticated chainwork blockers still required",
        "G8 Phase B seal-as-PoW only if Rank-1 launch requires consensus-bound windows",
    ]
    print("Rank-1 ENC-DR-LT GO/NO-GO gates (silicon / review — not auto-pass):")
    for g in gates:
        print(f"  [ ] {g}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check-inert", action="store_true",
                    help="Verify LT scaffolding exists and stays inert-ready")
    ap.add_argument("--list-gates", action="store_true", help="Print GO/NO-GO gates")
    args = ap.parse_args()

    if args.list_gates or not args.check_inert:
        print_gates()

    if args.check_inert:
        errs = check_inert()
        if errs:
            for e in errs:
                print(f"FAIL: {e}", file=sys.stderr)
            return 1
        print("LT inert scaffolding: OK")
        # Spot-check default height still max in params default initializer
        text = (ROOT / "src/consensus/params.h").read_text(encoding="utf-8")
        if not re.search(r"nMatMulDRLTHeight\{std::numeric_limits<int32_t>::max\(\)\}", text):
            print("FAIL: nMatMulDRLTHeight default is not INT32_MAX", file=sys.stderr)
            return 1
        print("nMatMulDRLTHeight default INT32_MAX: OK")

    return 0


if __name__ == "__main__":
    sys.exit(main())
