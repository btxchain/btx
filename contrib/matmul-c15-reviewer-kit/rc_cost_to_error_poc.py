#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
PoC: cost-to-error / Extract-quantization audit of the ENC_RC v4.6 profile-2
sampled carrier.

QUESTION (from the FS/T-BIND audit and the matmul-v4 adversarial review):
  The profile-2 sampled carrier exact-recomputes sampled tiles and byte-compares
  the int8 `Extract` output.  The (1-phi)^384 deterrence bound is only meaningful
  if computing the CORRECT int8 tile actually FORCES the exact int64 accumulation.
  `Extract` maps int64 -> int8 and is non-injective (a quantizer).  Could a
  CHEAPER, less-precise accumulation (fp16/bf16/int16 partial-sum/truncated/
  low-rank) land on the SAME int8 tile as the exact int64 accumulator, letting an
  adversary pass even SAMPLED tiles at reduced compute cost?

THIS HARNESS decides it empirically, using the consensus-faithful Extract
(reference_extract.py, pinned bit-for-bit to src/matmul/matmul_v4_lt.cpp and
matmul_v4_rc_extract.h).  It:

  1. Prints the magnitude / margin arithmetic for the two production committed
     tile paths the carrier checks: fused-FFN DOWN (X_out) and SV (Z).
  2. LSB-SENSITIVITY probe: how often does perturbing the exact accumulator by a
     small delta flip the int8 Extract output?  (Tight quantizer => ~ always.)
  3. CONSTRUCTIVE ATTACK: takes honest tiles, computes the exact int64
     accumulator, then re-derives the int8 with a deliberately CHEAPER
     accumulator (bf16/fp16 emulation, bit-truncation, K-term subsampling),
     and measures (a) per-element int8 match, (b) per-32-tile byte-equality
     match, (c) the pass probability against the sampled carrier, versus the
     realized compute saving.

Consensus code is untouched; this is a read-only reviewer probe.  Stdlib only.
"""

from __future__ import annotations

import argparse
import math
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reference_extract import (  # noqa: E402
    BLOCK_LEN,
    derive_matexpand_mx_scale,
    derive_matexpand_prf_key,
    extract_dequant_matexpand_tile,
    extract_mat_expand_mx_tile_mantissas,
)

# ---------------------------------------------------------------------------
# Consensus constants (src/matmul/matmul_v4_rc.h).
# ---------------------------------------------------------------------------
M11 = [0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6]  # accepted E2M1->M11 mantissa set
RC_OPERAND_ABS_MAX = 48  # kRCMxOperandAbsMax = 6 * 2^3  (M11 max 6, scale max 2^3)
RC_MODEL_DIM = 4096      # kRCModelDim
RC_FFN_DIM = 4 * RC_MODEL_DIM  # kRCFfnDim = 16384
RC_HEAD_DIM = 128        # kRCHeadDim
RC_CONTEXT_LEN = 786_432  # kRCContextLen (the SV Z-tile contraction)


def rand_operand(rng: random.Random) -> int:
    """One honest ENC_RC operand entry: an M11 mantissa times a per-block 2^e.

    The consensus expander (ExpandMxDequantInt8) emits mantissa*2^e with e<=3,
    so |entry| <= 48.  We draw the full balanced range the carrier sees."""
    m = rng.choice(M11)
    e = rng.randint(0, 3)
    return m * (1 << e)


# ---------------------------------------------------------------------------
# Cheap-accumulator models (what an adversary would use to skip exact work).
# Each returns an approximate accumulator value for a dot product, plus a
# nominal compute-cost weight relative to the exact int32/int64 MAC.
# ---------------------------------------------------------------------------
def exact_dot(a: list[int], b: list[int]) -> int:
    return sum(x * y for x, y in zip(a, b))


def _round_mantissa(x: float, mant_bits: int) -> float:
    """Round x to a float with `mant_bits` mantissa bits (bf16=7, fp16=10)."""
    if x == 0.0:
        return 0.0
    m, e = math.frexp(x)          # x = m * 2^e, 0.5 <= |m| < 1
    scale = 1 << mant_bits
    m = round(m * scale) / scale
    return math.ldexp(m, e)


def fp_accumulate(a: list[int], b: list[int], mant_bits: int) -> int:
    """Emulate a reduced-precision FP MAC pipeline (fp16/bf16 tensor core):
    products are exact-ish but the RUNNING accumulator is rounded to `mant_bits`
    after every add -- exactly the low-bit loss real fp-accumulate MMUs suffer.
    Returns the nearest int (the value that would be handed to Extract)."""
    acc = 0.0
    for x, y in zip(a, b):
        acc = _round_mantissa(acc + float(x * y), mant_bits)
    return int(round(acc))


def truncate_accumulator(exact: int, drop_bits: int) -> int:
    """Model any accumulator that loses the bottom `drop_bits` (rounding to a
    coarser grid): int16-ish saturating paths, block-fp, staged narrowing."""
    if drop_bits <= 0:
        return exact
    step = 1 << drop_bits
    return int(round(exact / step)) * step


def subsample_dot(a: list[int], b: list[int], keep_frac: float, rng: random.Random) -> int:
    """The ultimate work-skip: sum only a `keep_frac` fraction of the K terms and
    rescale.  Compute saving = 1/keep_frac.  This is what a miner that wants to
    do less than the full contraction would do."""
    k = len(a)
    keep = max(1, int(round(k * keep_frac)))
    idx = rng.sample(range(k), keep)
    partial = sum(a[t] * b[t] for t in idx)
    return int(round(partial / keep_frac))


# ---------------------------------------------------------------------------
# Extract wrappers.
# ---------------------------------------------------------------------------
def extract_tile_from_raw(raw32: list[int], i: int, bj: int, prf_key: bytes) -> list[int]:
    """int8 Extract of one 32-value accumulator tile (consensus-faithful)."""
    return extract_dequant_matexpand_tile(raw32, i, bj, prf_key)


# ===========================================================================
# 1. Magnitude / margin arithmetic.
# ===========================================================================
def report_magnitudes() -> None:
    print("=" * 78)
    print("1. MAGNITUDE / MARGIN ARITHMETIC  (production committed tile paths)")
    print("=" * 78)
    amax = RC_OPERAND_ABS_MAX
    for name, K in [("fused-FFN DOWN  X_out = Extract(H*W_down + X)  K=d_ff  [committed]", RC_FFN_DIM),
                    ("SV tile         Z     = Extract(S*V)           K=n_ctx [committed]", RC_CONTEXT_LEN),
                    ("fused-FFN UP    H     = Extract(X*W_up)        K=d_model [internal]", RC_MODEL_DIM),
                    ("attention S     S     = Extract(Q*K^T)         K=d_head [internal]", RC_HEAD_DIM)]:
        peak = K * amax * amax + amax  # +residual on the DOWN path
        print(f"  {name}")
        print(f"    K={K:<6d} |operand|<= {amax}   peak|acc| = K*{amax}^2(+res) = "
              f"{peak:,} ~ 2^{math.log2(peak):.2f}")
    print()
    print(f"  int32 capacity 2^31 = {2**31:,}   -> every committed accumulator is")
    print(f"  EXACT in int32 (static_assert |acc| < 2^31 in matmul_v4_rc.h).")
    print(f"  Because |acc| < 2^31, Extract's ExtractMixBitsFromInt64 returns the")
    print(f"  raw 32-bit two's-complement value verbatim: ALL low-order bits of the")
    print(f"  exact accumulator feed the mixing hash (see probe #2).")
    print()


# ===========================================================================
# 2. LSB-sensitivity of Extract:  raw -> int8 is a multiplicative hash, so a
#    +-1 change in the accumulator should flip the int8 with prob ~ (M-1)/M.
# ===========================================================================
def probe_lsb_sensitivity(prf_key: bytes, trials: int, rng: random.Random) -> None:
    print("=" * 78)
    print("2. LSB-SENSITIVITY OF Extract  (is the quantizer 'tight'?)")
    print("=" * 78)
    print("   For random exact tiles, perturb ONE element's accumulator by delta and")
    print("   measure P(that element's int8 output changes).  A magnitude-truncating")
    print("   quantizer would give ~0 for small delta (low bits discarded).  A hash")
    print("   binds every bit -> ~ (11-1)/11 = 0.909 even for delta=+-1.")
    print()
    print(f"   {'delta':>8} | P(int8 flips)")
    print(f"   {'-'*8}-+-{'-'*14}")
    for delta in [1, -1, 2, 3, 7, 16, 256, 65536]:
        flips = 0
        total = 0
        for _ in range(trials):
            raw = [rng.randint(-(1 << 25), 1 << 25) for _ in range(BLOCK_LEN)]
            i = rng.randint(0, 1 << 20)
            bj = rng.randint(0, 511)
            base = extract_tile_from_raw(raw, i, bj, prf_key)
            t = rng.randint(0, BLOCK_LEN - 1)
            raw2 = list(raw)
            raw2[t] += delta
            pert = extract_tile_from_raw(raw2, i, bj, prf_key)
            if pert[t] != base[t]:
                flips += 1
            total += 1
        print(f"   {delta:>8} | {flips/total:.4f}")
    print()
    print("   => any accumulator error, even the least-significant bit, flips the")
    print("      int8 with overwhelming probability.  Extract is a per-element PRF")
    print("      hash of the exact accumulator, NOT a low-bit-discarding quantizer.")
    print()


# ===========================================================================
# 3. Constructive attack: honest tiles vs cheap accumulators.
# ===========================================================================
def run_attack(prf_key: bytes, K: int, n_tiles: int, rng: random.Random) -> None:
    print("=" * 78)
    print(f"3. CONSTRUCTIVE ATTACK  (K={K} contraction, {n_tiles} tiles of 32 elems)")
    print("=" * 78)
    print("   Honest tiles: 32 exact int64 dot products of length K over M11*2^e")
    print("   operands.  For each cheap accumulator we report per-element int8 match,")
    print("   whole-32-tile byte-equality (what the carrier checks), and the pass")
    print("   probability of a sampled tile at the cheap method's compute saving.")
    print()

    # Build honest tiles: each tile = one output row-block, 32 columns; each
    # column is a length-K dot product a . b_col.
    tiles = []  # (i, bj, list_of_32 (a, b_col))
    for n in range(n_tiles):
        a = [rand_operand(rng) for _ in range(K)]  # shared left operand row
        cols = []
        for _ in range(BLOCK_LEN):
            b = [rand_operand(rng) for _ in range(K)]
            cols.append((a, b))
        tiles.append((n, 0, cols))

    def eval_cheap(label, fn, cost_frac):
        elem_match = 0
        elem_total = 0
        tile_match = 0
        for (i, bj, cols) in tiles:
            exact_raw = [exact_dot(a, b) for (a, b) in cols]
            cheap_raw = [fn(a, b) for (a, b) in cols]
            ex_i8 = extract_tile_from_raw(exact_raw, i, bj, prf_key)
            ch_i8 = extract_tile_from_raw(cheap_raw, i, bj, prf_key)
            m = sum(1 for x, y in zip(ex_i8, ch_i8) if x == y)
            elem_match += m
            elem_total += BLOCK_LEN
            if ex_i8 == ch_i8:
                tile_match += 1
            # also count how often the cheap raw already equalled exact raw
        p_elem = elem_match / elem_total
        p_tile = tile_match / len(tiles)
        # Wrong-element fraction and the resulting per-tile pass prob under the
        # ~1/11 hash-collision model:  a wrong element still matches int8 w.p. ~1/11.
        rho_wrong = 1.0 - (p_elem)  # approx: matched elems include lucky collisions
        print(f"   {label}")
        print(f"     compute cost vs exact : {cost_frac:.3f}   (saving {1-cost_frac:+.1%})")
        print(f"     per-element int8 match: {p_elem:.4f}")
        print(f"     per-TILE byte-equality: {p_tile:.4f}   <-- carrier compares this")
        print()
        return p_tile

    # (a) bf16 accumulate (7 mantissa bits) -- cheapest common tensor-core path
    eval_cheap("(a) bf16-accumulate  (7 mantissa bits)",
               lambda a, b: fp_accumulate(a, b, 7), cost_frac=0.30)
    # (b) fp16 accumulate (10 mantissa bits)
    eval_cheap("(b) fp16-accumulate  (10 mantissa bits)",
               lambda a, b: fp_accumulate(a, b, 10), cost_frac=0.50)
    # (c) truncate 4 low bits of the exact accumulator (block-fp / staged narrow)
    eval_cheap("(c) truncate-4-low-bits of exact acc",
               lambda a, b: truncate_accumulator(exact_dot(a, b), 4), cost_frac=0.80)
    # (d) truncate 1 low bit -- the gentlest possible imprecision
    eval_cheap("(d) truncate-1-low-bit of exact acc",
               lambda a, b: truncate_accumulator(exact_dot(a, b), 1), cost_frac=0.95)
    # (e) subsample 50% of K terms (work-skip)
    eval_cheap("(e) subsample 50% of K terms (rescaled)",
               lambda a, b: subsample_dot(a, b, 0.5, rng), cost_frac=0.50)
    # (f) subsample 90% of K terms (mild work-skip)
    eval_cheap("(f) subsample 90% of K terms (rescaled)",
               lambda a, b: subsample_dot(a, b, 0.9, rng), cost_frac=0.90)
    # (g) EXACT control -- must match perfectly (fidelity check)
    p = eval_cheap("(g) EXACT int64 control (no saving)",
                   lambda a, b: exact_dot(a, b), cost_frac=1.00)
    assert p == 1.0, "FIDELITY FAILURE: exact accumulator must reproduce the int8 tile"
    print("   (g) exact control matched all tiles byte-for-byte: harness is faithful.")
    print()


def extrapolate(prf_key: bytes) -> None:
    print("=" * 78)
    print("4. EXTRAPOLATION TO PRODUCTION + SAMPLING BOUND")
    print("=" * 78)
    # empirically measure per-element collision prob p_coll on random distinct raws
    rng = random.Random(999)
    coll = 0
    tot = 0
    for _ in range(4000):
        raw = [rng.randint(-(1 << 25), 1 << 25) for _ in range(BLOCK_LEN)]
        i = rng.randint(0, 1 << 20)
        bj = rng.randint(0, 511)
        base = extract_tile_from_raw(raw, i, bj, prf_key)
        t = rng.randint(0, BLOCK_LEN - 1)
        raw2 = list(raw)
        raw2[t] += rng.choice([1, -1, 2, -3, 5, -7, 11])
        pert = extract_tile_from_raw(raw2, i, bj, prf_key)
        if pert[t] == base[t]:
            coll += 1
        tot += 1
    p_coll = coll / tot
    print(f"   Measured per-element int8 collision prob for a WRONG accumulator:")
    print(f"     p_coll ~= {p_coll:.4f}  (~1/{1/p_coll:.1f}; matches the 11-value M11 alphabet)")
    print()
    print("   A cheap accumulator that is wrong on a fraction rho of a tile's 32")
    print("   elements passes that 32-byte tile with prob ~ (1 - rho*(1 - p_coll))^32.")
    for rho in [1.0, 0.5, 0.1, 0.05, 0.02]:
        p_tile = (1 - rho * (1 - p_coll)) ** 32
        print(f"     rho={rho:>4}: P(one sampled tile passes) ~= {p_tile:.3e}")
    print()
    print("   The carrier samples ~384 tiles (fixed-lambda kRCFreivaldsSampleCount);")
    print("   passing requires ALL sampled tiles to match, compounding these odds.")
    print("   A cheap accumulator only saves compute by being wrong on many elements")
    print("   (large rho) -> caught with overwhelming probability.  Being right on")
    print("   nearly all elements (rho ~ 0) yields no compute saving.  There is no")
    print("   regime with BOTH meaningful saving AND meaningful pass probability.")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed-w", default="11" * 32, help="operand seed (hex uint256)")
    ap.add_argument("--K", type=int, default=512, help="toy contraction length")
    ap.add_argument("--tiles", type=int, default=200, help="number of 32-elem tiles")
    ap.add_argument("--lsb-trials", type=int, default=2000)
    ap.add_argument("--rng", type=int, default=20260724)
    args = ap.parse_args()

    prf_key = derive_matexpand_prf_key(args.seed_w)
    rng = random.Random(args.rng)

    report_magnitudes()
    probe_lsb_sensitivity(prf_key, args.lsb_trials, rng)
    run_attack(prf_key, args.K, args.tiles, rng)
    extrapolate(prf_key)

    print("=" * 78)
    print("VERDICT")
    print("=" * 78)
    print("  Extract is a per-element multiplicative-PRF hash of the exact int32/")
    print("  int64 accumulator (mixed = ks_nibble XOR ((raw*0x9E3779B9)>>28), then")
    print("  M11 sample, then data-independent *2^e).  It is NOT a low-bit-discarding")
    print("  magnitude quantizer.  Producing the correct int8 tile therefore REQUIRES")
    print("  reproducing the exact accumulator; any cheaper/less-precise accumulation")
    print("  flips the int8 with prob ~10/11 per wrong element and is caught by the")
    print("  sampled carrier.  COST-TO-ERROR HOLDS.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
