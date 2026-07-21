#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
"""ENC_RC golden-diff CI gate (FINAL-FORM Stage A1 / Stage H).

FAILS if a frozen V1 episode digest changes without an explicit transcript
version bump (`kRCTranscriptVersion` / `ENC_RC_V1` in matmul_v4_rc.h).

Policy (do not weaken):
  - Silent golden replacement is FORBIDDEN.
  - ENC_RC_V1 toy golden (V1 stream, segment leaves OFF) is pinned below.
  - A V2 transition MUST introduce new domain tags (BTX_RC_*_V2) and KEEP
    BOTH V1 and V2 goldens in tests / this gate.

Usage:
  contrib/matmul-v4/rc-golden-gate.py
  contrib/matmul-v4/rc-golden-gate.py --expect b339d0ff...
  contrib/matmul-v4/rc-golden-gate.py --json

Exit: 0 = OK, 1 = golden/version mismatch, 2 = usage/parse error.
Stdlib only. Never raises nMatMulRCHeight.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_CPP = REPO_ROOT / "src" / "test" / "matmul_v4_rc_tests.cpp"
COUPLED_TEST_CPP = REPO_ROOT / "src" / "test" / "matmul_v4_rc_coupled_tests.cpp"
RC_H = REPO_ROOT / "src" / "matmul" / "matmul_v4_rc.h"
SCALE_AXES_H = REPO_ROOT / "src" / "matmul" / "matmul_v4_rc_scale_axes.h"
PARAMS_H = REPO_ROOT / "src" / "consensus" / "params.h"

# Frozen V1 toy golden (MakeToyRCEpisodeParams + MakeRCHeader(42)).
# V1 stream; kRCSegmentLeavesEnabled = false.
FROZEN_V1_HEX = "b339d0ff1b02871208df10d9553760c93a8cebe63b6201b3264f57ec4e8be43a"
FROZEN_VERSION = 1  # ENC_RC_V1

# Separate frozen digest for Stage C coupled toy (MakeCoupHeader(42) @ height 0).
# Not an episode transcript version — listed so silent replacement is caught.
FROZEN_COUPLED_TOY_HEX = "71c40b7b28bf12926282912bf694b3ac699ec728fcb5fe2123b43af7346e731b"

def die(msg: str, code: int = 1) -> None:
    sys.stderr.write("rc-golden-gate: FAIL — " + msg + "\n")
    sys.exit(code)


def parse_uint_constexpr(text: str, name: str) -> int | None:
    m = re.search(
        rf"inline\s+constexpr\s+uint32_t\s+{re.escape(name)}\s*=\s*(\d+)\s*;",
        text,
    )
    return int(m.group(1)) if m else None


def extract_goldens(text: str) -> list[str]:
    return re.findall(
        r'GetHex\(\),\s*\n?\s*"(?P<hex>[0-9a-f]{64})"',
        text,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--expect",
        default=FROZEN_V1_HEX,
        help="Expected V1 toy golden hex (default: frozen V1)",
    )
    ap.add_argument("--json", action="store_true", help="machine-readable summary")
    args = ap.parse_args()
    expect = args.expect.strip().lower()
    if len(expect) != 64 or any(c not in "0123456789abcdef" for c in expect):
        die(f"invalid --expect hex: {expect!r}", code=2)

    if not TEST_CPP.is_file():
        die(f"missing {TEST_CPP}", code=2)
    if not RC_H.is_file():
        die(f"missing {RC_H}", code=2)

    hdr = RC_H.read_text(encoding="utf-8")
    text = TEST_CPP.read_text(encoding="utf-8")
    errors: list[str] = []

    ver = parse_uint_constexpr(hdr, "kRCTranscriptVersion")
    enc_v1 = parse_uint_constexpr(hdr, "ENC_RC_V1")
    if ver is None:
        errors.append("missing kRCTranscriptVersion in matmul_v4_rc.h")
    if enc_v1 is None:
        errors.append("missing ENC_RC_V1 in matmul_v4_rc.h")
    if ver is not None and enc_v1 is not None and ver == 1 and enc_v1 != 1:
        errors.append(f"ENC_RC_V1={enc_v1} must be 1 while kRCTranscriptVersion==1")
    if "BTX_RC_ROUND_V1" not in hdr or "BTX_RC_EPISODE_V1" not in hdr:
        errors.append("ENC_RC_V1 domain tags BTX_RC_ROUND_V1 / BTX_RC_EPISODE_V1 missing")
    if ver == 1 and not re.search(
        r"inline\s+constexpr\s+bool\s+kRCSegmentLeavesEnabled\s*=\s*false\s*;",
        hdr,
    ):
        errors.append(
            "kRCSegmentLeavesEnabled must be false while ENC_RC_V1 is active "
            "(enabling segment leaves changes the stream and the toy golden)"
        )

    # Stage F / 4.3: three-axis schedule must stay inert; ratios PROVISIONAL.
    if SCALE_AXES_H.is_file():
        axes = SCALE_AXES_H.read_text(encoding="utf-8")
        if not re.search(
            r"inline\s+constexpr\s+bool\s+kRCThreeAxisScheduleEnabled\s*=\s*false\s*;",
            axes,
        ):
            errors.append(
                "kRCThreeAxisScheduleEnabled must remain false until Stage I "
                "(ratios PROVISIONAL; epoch-0 golden must stay inert)"
            )
    else:
        errors.append(f"missing {SCALE_AXES_H}")

    # Activation sentinel: nMatMulRCHeight stays INT32_MAX on the Params default.
    if PARAMS_H.is_file():
        params = PARAMS_H.read_text(encoding="utf-8")
        if not re.search(
            r"int32_t\s+nMatMulRCHeight\s*\{\s*std::numeric_limits<int32_t>::max\(\)\s*\}",
            params,
        ):
            errors.append(
                "nMatMulRCHeight must default to std::numeric_limits<int32_t>::max() "
                "(activation NO-GO)"
            )
    else:
        errors.append(f"missing {PARAMS_H}")

    goldens = extract_goldens(text)
    if not goldens:
        errors.append(f"no GetHex() golden literals found in {TEST_CPP.name}")

    v1_hits = [g for g in goldens if g.lower() == expect]
    other = sorted({g.lower() for g in goldens if g.lower() != expect})

    toy_pin = re.search(
        r"rc_t1_golden_episode_digest_stable[\s\S]*?"
        r'BOOST_CHECK_EQUAL\s*\(\s*d1\.GetHex\(\)\s*,\s*"([0-9a-f]{64})"\s*\)',
        text,
    )

    if ver == FROZEN_VERSION:
        if not v1_hits:
            errors.append(
                f"frozen V1 golden {expect} not found in {TEST_CPP.name}. "
                "Silent golden replacement is forbidden — bump kRCTranscriptVersion "
                "and keep BOTH V1 and V2 goldens."
            )
        if toy_pin and toy_pin.group(1).lower() != expect:
            errors.append(
                f"rc_t1 toy golden changed to {toy_pin.group(1)} without version bump "
                f"(kRCTranscriptVersion still {ver})"
            )
        elif not toy_pin:
            errors.append("could not locate rc_t1_golden_episode_digest_stable pin")
    else:
        if not v1_hits:
            errors.append(
                f"transcript version bumped to {ver} but V1 golden {expect} is gone — "
                "KEEP BOTH goldens (Stage H)"
            )
        if not other:
            errors.append(
                f"kRCTranscriptVersion={ver} but no additional V2 golden hex in tests"
            )
        if "BTX_RC_ROUND_V2" not in hdr and "BTX_RC_EPISODE_V2" not in hdr:
            errors.append(
                "version bump requires new domain tags BTX_RC_ROUND_V2 / "
                "BTX_RC_EPISODE_V2 (or equivalent V2 tags)"
            )

    summary = {
        "ok": not errors,
        "kRCTranscriptVersion": ver,
        "ENC_RC_V1": enc_v1,
        "frozen_toy_golden_v1": expect,
        "v1_golden_hits": len(v1_hits),
        "other_goldens": other,
        "frozen_coupled_toy_golden": FROZEN_COUPLED_TOY_HEX,
        "coupled_toy_golden_hits": 0,
        "errors": errors,
        "kRCThreeAxisScheduleEnabled": False,
        "policy": (
            "Silent golden replacement forbidden. V2 requires new domain tags "
            "+ BOTH goldens kept. Coupled toy golden is a separate frozen digest. "
            "kRCThreeAxisScheduleEnabled=false (ratios PROVISIONAL). "
            "nMatMulRCHeight stays INT32_MAX."
        ),
    }

    # Optional section: Stage C coupled toy golden (separate from V1 episode).
    coupled_hits = 0
    if COUPLED_TEST_CPP.is_file():
        coup_text = COUPLED_TEST_CPP.read_text(encoding="utf-8")
        coup_pin = re.search(
            r"rc_coup_golden_digest_stable[\s\S]*?"
            r'BOOST_CHECK_EQUAL\s*\(\s*d1\.GetHex\(\)\s*,\s*"([0-9a-f]{64})"\s*\)',
            coup_text,
        )
        coup_goldens = extract_goldens(coup_text)
        coupled_hits = sum(
            1 for g in coup_goldens if g.lower() == FROZEN_COUPLED_TOY_HEX
        )
        summary["coupled_toy_golden_hits"] = coupled_hits
        if coupled_hits == 0:
            errors.append(
                f"frozen coupled toy golden {FROZEN_COUPLED_TOY_HEX} not found in "
                f"{COUPLED_TEST_CPP.name}"
            )
        if coup_pin and coup_pin.group(1).lower() != FROZEN_COUPLED_TOY_HEX:
            errors.append(
                f"rc_coup toy golden changed to {coup_pin.group(1)} "
                f"(expected {FROZEN_COUPLED_TOY_HEX})"
            )
        elif not coup_pin:
            errors.append("could not locate rc_coup_golden_digest_stable pin")
        summary["ok"] = not errors
        summary["errors"] = errors
    else:
        summary["coupled_toy_golden_note"] = "coupled test file absent — skip"

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        if errors:
            for e in errors:
                sys.stderr.write(f"rc-golden-gate: FAIL — {e}\n")
            return 1
        print("rc-golden-gate: PASS")
        print(f"  kRCTranscriptVersion = {ver} (ENC_RC_V1={enc_v1})")
        print(f"  V1 golden: {expect} ({len(v1_hits)} occurrence(s) in {TEST_CPP.name})")
        if other:
            print(f"  other GetHex goldens present: {len(other)} (ok if V2+)")
        print(
            f"  coupled toy golden: {FROZEN_COUPLED_TOY_HEX} "
            f"({summary.get('coupled_toy_golden_hits', 0)} occurrence(s))"
        )
        print("  rule: silent golden replacement forbidden; V2 needs new tags + BOTH goldens")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
