#!/usr/bin/env python3
# Step-5 global-composition recomputation for PR-89 relation-local-sharding recursion.
# Mirrors the COMMITTED log-sum-exp in RCGkrComposedSeparation (matmul_v4_rc_gkr.cpp:2673)
# and extends it with the arity-4 recursion union-over-nodes penalty.
# Cross-checks against committed per-term screens + the relay host's newest stage3 FRI screens.
import math

def lse_bits(terms):
    """composed = -log2( sum_i 2^-term_i ).  Stable log-sum-exp in bits."""
    lo = min(terms)
    s = sum(2.0 ** (-(t - lo)) for t in terms)
    return lo - math.log2(s)

# ---- COMMITTED per-term separation screens (matmul_v4_rc_gkr.cpp) ----
FS_FP3      = 135.5   # kRCGkrFsSubtotalSepBits, Fp3 challenge cutover
COMP_II     = 144.0   # kRCGkrCompositionSepBits
COMP_III    = 256.0   # kRCGkrLookupSepBits (LogUp/lookup)  <- CTL terminals live here
COMP_IV     = 147.19  # min(wiring equality, permutation dual)
SHA         = 88.0    # kRCGkrShaSepBits (SHA256d computational, 2^40-query adv.)
FRI_FP2_EP  = 76.80   # committed episode FRI floor: 128*log2(32/17) - 40  (Q=128, rho=1/16)

# ---- the relay host stage3 FRI screens (relayed; post-grind conservative diagnostic) ----
FRI_S3_1LANE = 92.5983   # single-lane Fp3 saturation (21,672,707,874-site diagnostic)
FRI_S3_Q192  = 92.0279   # Q192 additive known-term screen ("increasing Q cannot solve")
OLDER_TOPO   = 100.3767  # canonical older topology conditional screen

TARGET = 64.0
POLICY_MARGIN = 7.0      # eps_global <= 2^-71 required for consensus adequacy

# Recursion shape (from the synthesis): 244 shards -> 256 leaves (4^4) + 85 internal = 341 nodes
N_LEAVES = 256
N_INTERNAL = 85
N_NODES = N_LEAVES + N_INTERNAL   # 341
print(f"recursion nodes N = {N_NODES}  (log2 = {math.log2(N_NODES):.2f})")
print("="*72)

def report(label, fri_term):
    # SHA256d Merkle/transcript binding (88 = 128-40) is a GLOBAL collision-resistance
    # term (one collision anywhere breaks it) -> FLAT, does NOT union per node.
    # The per-node STATISTICAL terms (FS, comp, LogUp, wiring, FRI) DO union over the tree.
    stat_terms = [FS_FP3, COMP_II, COMP_III, COMP_IV, fri_term]
    composed_stat = lse_bits(stat_terms)              # per-node statistical composed
    binding = min(stat_terms)
    which = {FS_FP3:'FS', COMP_II:'comp_ii', COMP_III:'LogUp',
             COMP_IV:'wiring', fri_term:'FRI'}[binding]
    for Nunion, ulabel in [(N_NODES, "341 nodes"), (512, "2^9 envelope"),
                           (4096, "2^12 (large Lambda)")]:
        stat_union = composed_stat - math.log2(Nunion)      # statistical union over tree
        g = -math.log2(2.0**(-stat_union) + 2.0**(-SHA))    # combine with flat SHA
        clears = "GO " if g >= TARGET else "NO-GO"
        pol = "PASS" if g >= TARGET + POLICY_MARGIN else "fail"
        dom = "SHA-flat" if stat_union > SHA else f"{which}-union"
        print(f"  union/{ulabel:<18} global = {g:6.2f} b  [{clears} vs64, 7-bit {pol}, {dom}]")
    print(f"{label}: per-node stat composed = {composed_stat:.2f} b (floor: {which} @ {binding}); SHA flat @ {SHA}")

print("[A] COMMITTED episode floor (Fp2-era FRI 76.8) -- what the workflow used:")
report("  committed-episode", FRI_FP2_EP)
print()
print("[B] the relay host stage3 single-lane Fp3 FRI screen (92.60):")
report("  stage3-1lane", FRI_S3_1LANE)
print()
print("[C] the relay host Q192 additive known-term screen (92.03):")
report("  stage3-q192", FRI_S3_Q192)
print("="*72)

# Min per-child NET target to clear 64 with 7-bit margin, given union count u = log2(#events)
print("Min per-NODE NET floor for eps_global <= 2^-71 (7-bit margin):")
for u_terms in [N_NODES, 512, 4096]:
    need = 71.0 + math.log2(u_terms)
    print(f"  #events={u_terms:<6} -> per-node NET >= {need:.2f} bits")
print("="*72)
# Historical Fp2 FS-dominated cross-check (the superseded workflow number)
print("cross-check (SUPERSEDED Fp2 FS-dominated 71.9 per node, union/341):",
      f"{71.9 - math.log2(N_NODES):.2f} b  -> reproduces workflow's ~2^-63.5 NO-GO")

# ============================================================================
# WAVE-2 LANE FLOORS (the real binding floor is H2c, not FRI)
# ============================================================================
print("LANE FLOORS (wave-2 adversarial hunt):")
FP2 = 128.0; g = 40.0; node_union = math.log2(N_NODES)  # 8.41
def h2c(logN, c):
    # child-proof-cell 14-span Fp2 SZ equality, c challenges (single-a c=1, dual-a c=2)
    return c*(FP2 - logN) - (g + node_union)
for logN,lab in [(12,"receipt N=2^12"),(8,"small N=2^8"),(4,"tiny N=2^4")]:
    s1=h2c(logN,1); s2=h2c(logN,2)
    print(f"  H2c {lab:14} single-a={s1:6.2f} [{'GO' if s1>=71 else 'POLICY-BREACH'}]  dual-a={s2:7.2f} [{'GO' if s2>=71 else 'BREACH'}]")
# H1 internal-node FRI: 92.6 (known-term retained) vs 76.8 (fallback), union/341, +SHA flat
for fri,lab in [(92.6,"known-term retained"),(76.8,"fallback unique-dec")]:
    su=fri-node_union; gl=-math.log2(2**-su+2**-SHA)
    print(f"  H1 internal {lab:22} -> global {gl:6.2f} [{'GO+policy' if gl>=71 else ('GO-vs64' if gl>=64 else 'NO-GO')}]")
print(f"\n  BINDING FLOOR = min(H2c single-a receipt {h2c(12,1):.1f}, H1 fallback 70.4, FRI-union 84.1)"
      f" = {min(h2c(12,1),70.39,84.09):.1f} b  (H2c single-a Fp2 dominates -> CONDITIONAL GO)")
