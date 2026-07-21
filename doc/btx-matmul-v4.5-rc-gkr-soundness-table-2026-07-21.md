# ENC_RC winner-GKR — companion soundness table — 2026-07-21

*Companion to `doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md`. All bit
counts are −log2 of acceptance probability. "Post-grind" subtracts the repo grinding
convention g = 40 bits (adversary RO budget 2^40, matching `FriSoundnessBoundBits()`).
Field sizes: |Fp| ≈ 2^64 (Goldilocks), |Fp2| ≈ 2^128, |Fp3| ≈ 2^192. Consensus dims:
200 layers, N_Y ≈ 2^33.39 trace cells, N_T ≈ 2^28.39 Extract tiles, Σν_k = 2540 sumcheck
rounds, N_L ≤ 2^43 LogUp rows (full PRF AIR), κ = 2^28 max column coefficients.*

## Per-relation soundness terms

| Relation | Term | Formula | Pre-grind bits | Post-grind bits | Status |
|---|---|---|---|---|---|
| PCS (§2) | batched FRI queries, unique decoding | (17/32)^116 | 105.85 | **65.85** | dominant term |
| PCS (§2) | RLC batching λ/μ/γ/weights | ≤ 2^12/\|Fp2\| | 116 | 76 | ok |
| PCS (§2) | dual-OOD DEEP | (2κ/\|Fp2\|)² | 196 | 156 | ok |
| PCS (§2) | single-OOD DEEP (rejected variant) | 2κ/\|Fp2\| | 99.6 | **59.6 — FAILS** | must use dual |
| PCS (§2) | 7 separate FRI instances (v6 layout) | 7·2^-65.85 | — | **63.05 — FAILS** | must batch |
| R1 (§3) | per-layer product sumcheck (round-by-round) | 2/\|Fp2\| | 127 | 87 | ok |
| R1 (§3) | all sumcheck rounds union | 2·2540/\|Fp2\| | 115.7 | 75.7 | ok |
| R1 (§3) | final_eval vs opened a·b | algebraic identity | ∞ (det.) | ∞ | ok |
| R2 (§4) | claim binding at (r_i,r_j) | (ν_i+ν_j)/\|Fp2\| | ≥ 122.4 | ≥ 82.4 | ok |
| R2 (§4) | padding suffix-zero checks | 3ν/\|Fp2\| per col | ≥ 121 | ≥ 81 | ok |
| R2/R4 (§4) | layout/order/dims/count forgeries | verifier-driven Λ | ∞ (det.) | ∞ | ok |
| R3 (§5) | LogUp single α over Fp2 | N_L/\|Fp2\| = 2^43/2^128 | 85 | **45 — FAILS** | forbidden |
| R3 (§5) | LogUp single α over Fp2, bare tile keys only | 2^28.4/2^128 | 99.6 | **59.6 — FAILS** | forbidden |
| R3 (§5) | **LogUp dual α over Fp2 (chosen)** | (2N_L/\|Fp2\|)² | 168 | **128** | ok |
| R3 (§5) | LogUp single α over Fp3 (alternative) | N_L/\|Fp3\| | 149 | 109 | ok (Fp3 unbuilt) |
| R3 (§5) | tuple-compression γ | w_max·n_inst/\|Fp2\| | ≥ 120 | ≥ 80 | ok |
| R3 (§5) | multiplicity wraparound | requires m ≥ char = p > N_L | ∞ | ∞ | ok |
| R5 (§7) | lobe sumchecks + mix line-restrictions | ≤ 2^9·3/\|Fp2\| | ≥ 117 | ≥ 77 | ok |
| R5 (§7) | int64-vs-mod-p wraparound | range constraints (det. given PCS) | — | shared | ok |
| Hash | SHA256d bindings (roots, digest, pow_bind) | 2^40 queries vs 2^-128 | — | 88 | computational |

## Single-challenge ceilings (the forcing arithmetic)

Requirement per FS round: pre-grind bits ≥ 64 + 40 = 104.

| Challenge | Max tolerable count over Fp2 | Actual | Verdict |
|---|---|---|---|
| LogUp α (single) | N ≤ 2^(128−104) = 2^24 | N_L ≈ 2^43 (≥ 2^28.4 minimum) | **Fp2 single-α impossible → dual-α or Fp3** |
| DEEP z (single) | deg ≤ 2^24 | κ = 2^28 | **dual-OOD required (or κ ≤ 2^24)** |
| Sumcheck round | d ≤ 2^24 | d = 2 | fine |

## Composed bound (Theorem 8.1)

| Component | Value |
|---|---|
| FS subtotal (all rounds, pre-grind) | ≤ 2^-112 |
| FS subtotal × 2^40 grinding | ≤ 2^-72 |
| Batched FRI (post-grind) | 2^-65.85 |
| SHA256d computational | ≤ 2^-88 |
| **Total ε** | **≤ 2^-65.7 (≈ 65.7 bits)** |
| Target | 2^-64 — **CLEARED**, margin < 1 bit |
| Hardening recommendation | Q: 116 → 128 ⇒ FRI 2^-76.8, total ≈ 2^-71.9 |

Preconditions for the bound (each individually necessary):
1. single batched FRI instance (union over 7 instances = 2^-63.05: fails);
2. dual-OOD DEEP points (single: 2^-59.6 worst column: fails);
3. dual-α LogUp over Fp2 (single: 2^-45: fails) — or Fp3 single-α (2^-109).

## v6 scaffold acceptance probabilities for the §9 forgery list (for contrast)

F0 fabricate-everything: 1. F4 free final_eval: 1. F5 free claim: 1.
F6 Extract witness: 1 (Theorem 5.1). F10 omitted coupled barrier: 1 (toy stand-in).
All others: see §9 table of the construction document.

*Nothing in this table changes consensus: arbiter OFF, heights INT32_MAX, int64
ExactReplay remains the sole authority.*
