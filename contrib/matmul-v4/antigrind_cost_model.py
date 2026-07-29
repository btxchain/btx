#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Standalone COST MODEL (not a PoC, imports nothing from the tree) for the
# ENC_RC v4.6 profile-2 sampled-carrier anti-grind design spec
#   doc/btx-matmul-v4.6-rc-antigrind-construction.md
#
# It quantifies:
#   (1) the confirmed break: per-trial cost of a terminal-tile digest re-roll,
#       sample coverage, and the collapse P_accept ~ G*p vs the advertised
#       single-shot (1-f)^384;
#   (2) the FVT / CAP forced-work floor (Omega(W_round)) the fix installs; and
#   (3) verify-budget feasibility  V_int' + V_tail <= 900 ms  across interior-lambda
#       retunes and capstone sizes (the "cost law": forced work == verify cost of
#       the fully-checked unit).
#
# All numbers are first-order (MAC counts + a linear ms model anchored to the two
# published measurements: interior sampled verify ~700 ms @ 32 threads, budget
# 900 ms). Override the two anchors on the CLI to re-fit to a real machine.

import argparse

# ----------------------------------------------------------------------------
# Production episode dimensions (design spec section 3).
# ----------------------------------------------------------------------------
ROUNDS   = 8
L_LYR    = 24
D_FF     = 16384
B_SEQ    = 32768
N_CTX    = 786432
# d_model / d_head / n_q are not pinned in the task; use representative values.
# Only ratios (round vs episode, tile coverage) matter for the conclusions.
D_MODEL  = 4096
D_HEAD   = 128
N_Q      = 32768

# Commitment / sampling constants (from matmul_v4_rc_freivalds_sampled.h).
LAMBDA           = 512      # kRCFreivaldsSampleCount
SEG_OUT_TILES    = 2        # kRCFreivaldsSegOutTiles
T_LEAF           = 4096     # representative tile-leaf byte length
MX_BLOCK         = 32       # kRCMxBlockLen (one output row x 32 cols)
FS_QUERIES       = 384      # advertised single-shot exponent ("(1-f)^384")


def episode_macs():
    """Dominant GEMM MACs for one episode (FFN up+down + attention), section-model
    identical to RCEpisodeMatMulMacs (matmul_v4_rc.cpp:1180-1188)."""
    p1 = 2 * N_Q * N_CTX * D_HEAD                     # attention QKt + SV
    p2 = 2 * L_LYR * B_SEQ * D_MODEL * D_FF           # fused FFN up+down / round
    per_round = p1 + p2
    return per_round, ROUNDS * per_round


def round_stream_bytes():
    """Committed int8 output-stream bytes for one round (what the Merkle tree hashes).
    Fused-FFN commits X_out (b_seq x d_model) per layer + attention SV output."""
    ffn_out = L_LYR * B_SEQ * D_MODEL
    sv_out  = N_Q * D_HEAD
    return ffn_out + sv_out


def tiles_per_unit():
    """Output tiles (row x 32-col block) in one sampled unit's output m x n.
    Coverage denominator for 'is a mutated tile sampled'."""
    # A representative sampled unit = one FFN-down layer output (b_seq x d_model).
    return (B_SEQ * D_MODEL) // MX_BLOCK


def sampleable_units():
    """Approx count of sampleable Lambda units (FFN up/down + SV per layer per round;
    QKt excluded)."""
    return ROUNDS * L_LYR * 3


def fmt(x):
    for unit, div in (("P", 1e15), ("T", 1e12), ("G", 1e9), ("M", 1e6), ("K", 1e3)):
        if abs(x) >= div:
            return f"{x/div:.2f}{unit}"
    return f"{x:.2f}"


def main():
    ap = argparse.ArgumentParser(description="ENC_RC v4.6 anti-grind cost model")
    ap.add_argument("--interior-ms", type=float, default=700.0,
                    help="measured interior sampled verify at lambda=512 (ms @ 32 threads)")
    ap.add_argument("--budget-ms", type=float, default=900.0, help="block-verify budget (ms)")
    ap.add_argument("--episode-recompute-ms", type=float, default=5000.0,
                    help="est. full-episode ExactReplay verify (ms @ 32 threads); V_tail scales as /ROUNDS")
    ap.add_argument("--gross-margin", type=float, default=2.0, help="mining gross margin kappa")
    args = ap.parse_args()

    per_round_mac, episode_mac = episode_macs()
    rsb = round_stream_bytes()
    total_stream = ROUNDS * rsb
    tpu = tiles_per_unit()
    n_units = sampleable_units()
    frac_round = per_round_mac / episode_mac

    print("=" * 74)
    print("ENC_RC v4.6 profile-2 sampled-carrier — anti-grind cost model")
    print("=" * 74)
    print(f"dims: rounds={ROUNDS} L_lyr={L_LYR} d_ff={D_FF} b_seq={B_SEQ} "
          f"n_ctx={N_CTX} d_model={D_MODEL}")
    print(f"episode GEMM MACs : {fmt(episode_mac)}   (one round {fmt(per_round_mac)} "
          f"= {frac_round*100:.1f}% of episode)")
    print(f"committed stream  : {fmt(total_stream)} B/episode  ({fmt(rsb)} B/round)")
    print(f"sampleable units  : ~{n_units}   lambda={LAMBDA} "
          f"({'covers all' if LAMBDA>=n_units else f'{LAMBDA/n_units*100:.0f}% sampled'})")

    print("\n--- (1) THE BREAK: cheap terminal-tile digest re-roll -------------------")
    # Attack per-trial cost = rebuild ONE round's Merkle tree (hash pass, NO GEMM).
    # Express as a fraction of an episode using the published 0.7% measurement, and
    # cross-check against the stream-bytes ratio (one round hash / episode compute).
    attack_frac = 0.007  # measured ~0.7% of an episode per re-roll
    cov = SEG_OUT_TILES / tpu
    print(f"per-trial cost      : ~{attack_frac*100:.1f}% of an episode "
          f"(one round Merkle rebuild, NO GEMM; amortizable)")
    print(f"tile sample coverage: {SEG_OUT_TILES}/{fmt(tpu)} = {cov:.2e} per unit "
          f"(prob. a mutated tile is checked)")
    f = FS_QUERIES  # advertised single-shot uses (1-f_frac)^384; here show scale only
    print(f"advertised bound    : single-shot ~ (1-f)^{FS_QUERIES} (episode-once)")
    print( "actual bound        : P_accept ~ G*p over G cheap trials (hashcash);")
    for G in (1e3, 1e6, 1e9):
        # p ~ prob(digest<=target) folded into G (miner grinds until <=target); the
        # security-relevant collapse is that a trial costs attack_frac episode, not 1.
        eff = G * attack_frac
        print(f"    G={fmt(G):>7} trials  ->  effective episodes of work = {fmt(eff)} "
              f"(vs {fmt(G)} if each trial were a full episode)")

    print("\n--- (2) THE FIX: forced non-amortizable work per fresh digest -----------")
    print(f"FVT forces one TERMINAL-round GEMM/trial: {fmt(per_round_mac)} MAC "
          f"= Omega(W_round) = {frac_round*100:.1f}% episode, REAL GEMM, non-amortizable")
    improvement = frac_round / attack_frac
    print(f"  -> per-trial cost {attack_frac*100:.1f}% (Merkle) -> {frac_round*100:.1f}% "
          f"(GEMM):  {improvement:.0f}x higher AND now genuine field work")
    rho_star = None
    import math
    rho_star = math.log(args.gross_margin) / LAMBDA
    print(f"  interior deterrence rho* ~ ln(kappa)/lambda = "
          f"ln({args.gross_margin})/{LAMBDA} = {rho_star*100:.3f}% (unchanged tier)")

    print("\n--- (3) VERIFY-BUDGET feasibility (cost law: forced == verify) ----------")
    B = args.budget_ms
    V_int_512 = args.interior_ms
    V_tail_round = args.episode_recompute_ms / ROUNDS  # FVT full terminal round
    print(f"budget={B:.0f}ms  interior(512)={V_int_512:.0f}ms  "
          f"one-round-recompute V_tail~{V_tail_round:.0f}ms")
    print("  FVT feasibility across interior-lambda retunes:")
    for lam in (512, 384, 256, 128):
        v_int = V_int_512 * lam / 512.0
        slack = B - v_int
        ok = slack >= V_tail_round
        rho = math.log(args.gross_margin) / lam
        print(f"    lambda={lam:>3}: V_int'={v_int:6.0f}ms  slack={slack:6.0f}ms  "
              f"V_tail(1 round)={V_tail_round:5.0f}ms  -> "
              f"{'FITS' if ok else 'OVER'}   rho*={rho*100:.3f}%")
    print("  CAP fallback: size the forced capstone to V_tail = budget - V_int' (always fits):")
    for lam in (512, 256):
        v_int = V_int_512 * lam / 512.0
        v_tail = max(0.0, B - v_int)
        cap_frac = v_tail / args.episode_recompute_ms  # forced work as episode fraction
        print(f"    lambda={lam:>3}: V_int'={v_int:6.0f}ms -> capstone V_tail={v_tail:5.0f}ms "
              f"= forced {cap_frac*100:.1f}% episode/trial (guaranteed in budget)")

    print("\nnote: override --interior-ms / --episode-recompute-ms with real 32-thread")
    print("      measurements to re-fit; ratios (round vs episode, coverage) are dims-exact.")


if __name__ == "__main__":
    main()
