# Stage-3 global composition — reconciliation & machine-checked recompute — 2026-07-25

> **Status: ANALYSIS ONLY. Not CLOSED, not audited, not activated.** Consensus
> authority remains ExactReplay; `kRCGkrFormalSoundnessReady = false`; heights
> `nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`. This is the independent
> (local-box) soundness reconciliation for PR-89 step 5, built on the relay host's Stage-3
> findings. External cryptographic audit remains a hard precondition for any claim.

## 0. What this resolves

The Stage-3 wave left step 5 (global composition theorem) at **"certified soundness
0 bits"** and posed the arity-4 recursion as requiring **≥109 bits per child unless a
tighter composition theorem avoids a ~9-bit union loss**. An adversarial derive→verify
pass (6 independent derivations, opus verification, 11/12 claims refuted/corrected)
plus a machine-checked recompute against the **committed** per-term screens resolves the
*arithmetic* side and sharply relocates the *real* blocker.

Two prior positions were both wrong:

- **Over-optimistic (an earlier local hand-wave):** "every screen ≥ 64, so bits are not
  the blocker." — Ignored that every one of the ~341 recursion nodes re-incurs its own
  floor, and the union costs ~8.4 bits.
- **Over-pessimistic (the derive/verify synthesis headline NO-GO at `2^-63.5`):** used the
  **superseded Fp2** FS-dominated per-node floor of **71.9**. The shipped config is **Fp3**
  (`matmul_v4_rc_gkr.cpp:2723`): FS subtotal **135.5**, composed FRI-dominated at **76.8**.

## 1. Machine-checked recompute

`RCGkrComposedSeparation` (`matmul_v4_rc_gkr.cpp:2673`) composes as a log-sum-exp,
`composed = −log2(Σ_i 2^−termᵢ)`, over the committed per-term separation screens:

| term | bits | source |
|---|---:|---|
| FS subtotal (Fp3) | 135.5 | `kRCGkrFsSubtotalSepBits` |
| composition (II) | 144 | `kRCGkrCompositionSepBits` |
| LogUp / lookup (III) — **CTL terminals live here** | 256 | `kRCGkrLookupSepBits` |
| wiring (IV) | 147.19 | min(equality, permutation-dual) |
| FRI proximity | 76.8 (episode) / **92.6** (stage3 screen) | `FriSoundnessBoundBits()` / the relay host |
| SHA256d computational | **88** | `kRCGkrShaSepBits` |

Recursion shape (from the synthesis): 244 shards → 256 leaves (`4⁴`) + 85 internal =
**341 nodes** (`2^8.41`). Each node is itself a STARK+FRI proof; global failure is the
OR over all nodes (union). **Two composition classes, treated correctly:**

- **Statistical terms** (FS 135.5, composition 144, LogUp 256, wiring 147.19, FRI proximity)
  are per-node and **union** over the tree: `stat_union = composed_stat − log2(N)`.
- **SHA256d (88 = 128 − 40)** is a **global collision-binding** term (`gkr.h:889` — "Merkle/
  transcript bindings vs a 2^40-query adversary; computational, field-independent"): one
  collision anywhere breaks it, so it is **FLAT** and does *not* union per node.

`global = −log2( 2^−stat_union + 2^−88 )`.

Recompute (`scratchpad/step5_compose.py`, reproduces committed 76.80 and the workflow's
63.49 as validation). **Machine-validated 2026-07-25:** a fresh `test_btx` build passes
`fri_constants_and_soundness_bits`, `gkr_soundness_and_height_inert`, and the exact pin
`gkr_integration_composed_separation_bound` (asserts compiled `RCGkrComposedSeparationBits()
∈ (76.7, 76.81)`, FRI-dominated, heights `INT32_MAX`) — so the single-instance base of this
recompute matches compiled code; the 341-node union + flat-SHA extension is layered on that
validated base.)

| per-node FRI screen | floor after union | per-node stat composed | **global (union/341)** | vs 64 | 7-bit policy |
|---|---|---:|---:|:--:|:--:|
| committed episode **76.8** (Fp2-era) | FRI-union | 76.80 | **68.39** | GO | **fail** |
| stage3 single-lane Fp3 **92.60** | FRI-union (SHA flat 88) | 92.60 | **84.09** | GO | **PASS** (+20.1) |
| stage3 Q192 **92.03** | FRI-union (SHA flat 88) | 92.03 | **83.55** | GO | **PASS** (+19.6) |
| *superseded Fp2 FS-dominated 71.9* | FS | 71.90 | 63.49 | NO-GO | fail |

Even at a `2^12` (large cross-link census Λ) union envelope, the stage3 rows hold at
**80.6 bits** (still passes the 7-bit policy) — so Λ is **not** a threat at the stage3
floor. Min per-**node** NET floor for a 7-bit margin is **79.4–83 bits** across
`341…4096` events — comfortably met by the stage3 FRI screen (92.6), **not** met by the
bare episode floor (76.8, → 68.4).

## 2. Reconciled verdict (arithmetic) — two reductions from 84.1

**84.1 is not the shipped number, and not the binding floor.** Two independent reductions apply:

1. **84.1 is contingent on an unverified input.** It requires the stage3 FRI screen **92.6**,
   which **appears nowhere in the committed code** — `RCGkrComposedSeparationBits()` pins to
   **76.80** (machine-validated by `gkr_integration_composed_separation_bound`). 92.6 is
   the relay host's measurement on the *uncommitted* stage3 tree. Under the **shipped** floor 76.80,
   the 341-node union is **76.80 − log₂341 = 68.4 bits** (clears 64, **fails** the 71 policy).
2. **Even granting 92.6, the binding floor is lower.** An adversarial lane hunt (wave 2) found
   the **Fp2 child-proof-cell transport (H2c) caps at ~67.6 bits** — below FRI, below policy.

So the **currently-provable bound is ≈ 2⁻⁶⁷·⁶** (H2c), with the shipped-parameter FRI-union at
≈ 2⁻⁶⁸·⁴. The 84.1 figure is a *conditional target* requiring both the unverified 92.6 screen
(inherited by internal nodes) **and** dual-α/Fp3 at the H2c cell. And cross-shard equality (P2)
has **no closure mechanism in the committed recursion** — see the companion roadmap
(`...composition-theorem-roadmap-2026-07-25.md`), §0 and §2/P2. §3 below gives the
CONDITIONAL-GO checklist; it supersedes any bare "84.1 GO" reading.

The `~9-bit` union loss is **real and paid**, not avoided. It is *affordable* only because
the per-node floor is high (88, SHA). This matters because:

- **The correlated-agreement "tightening" (Theorem B) is architecturally unavailable** to
  the shipped **sealed T-BIND receipt** tree (`9a45b1f`): sealed receipts have already
  committed and FRI-folded their codewords and live on **heterogeneous domains** (≤512-col
  leaf shards vs aggregating nodes), violating the common-domain / not-yet-folded
  preconditions of batched correlated agreement. Pursuing it would require an
  accumulation / deferred-proximity re-architecture that conflicts with T-BIND sealing and
  the FVT terminal-round verify gate. **Recommendation: do not pursue the batched tightening;
  the union loss is affordable at the SHA floor.**
- **"≥109 bits per child" is a mis-framing** — neither necessary nor sufficient. The binding
  floor is SHA (88) / FRI (92.6); ~80-bit NET nodes suffice. Requiring 109 buys nothing the
  SHA floor doesn't already cap.

## 3. CONDITIONAL-GO checklist (wave-2 adversarial lane hunt)

Certified soundness is **0 bits** not because a number is below 64, but because the
**composition theorem binding all 341 node receipts + `2Λ` CTL link terminals + SHA
Fiat–Shamir replay + parent-proof verification into a single certified statement is unproven**.
An adversarial hunt over the four un-constrained lanes (5 derivations → opus verification)
found **no unconditional NO-GO** (nothing below 64 under shipped/plausible params) but **two
lanes that breach the 71-bit policy** on parameters only measurable in the stage3 code. Ranked
worst cases (post-verification):

| # | Lane | worst-case bits | <84? | <71? | <64? | real? | measure in stage3 |
|---|---|---:|:--:|:--:|:--:|:--:|---|
| 1 | **H2c** child-proof-cell 14-span transport (Fp2 SZ equality) | **67.6** | Y | **Y** | no | **YES** | challenge field (Fp2 vs Fp3) + multiplicity c (single vs **dual-α**) at the cell; N=Σ span lengths |
| 2 | **H1** internal aggregating-node FRI screen | **70.4** | Y | **Y** (fallback) | no | **YES** | do internal nodes retain the additive **known-term** decomposition, or drop to the 76.8 unique-decoding floor; do ≤4 child instances batch into one query term |
| 3 | H2a SHA Fiat–Shamir replay | 81.2 | Y | no | no | no | digest→field reduction remainder (rejection vs mod, width w) |
| 4 | H2b proof/terminal digest lanes | 88 | no | no | no | no* | confirm no lane truncates below 4 Goldilocks lanes / 256-bit |
| 5 | H3 SHA binding-class | 88 | no | no | no | no | every SHA site is recompute-and-compare, not digest-set membership |

**The binding floor is H2c, not FRI.** The succinct scaffold / child-transport lives on **Fp2**
(the Fp3 cutover shipped only on the episode-v7 FRI path). A **single-α Fp2** 14-span equality
caps at `128 − 48.41 − log2 N = 79.59 − log2 N` — already below the 84.1 FRI floor for any N,
and ~**67.6** at a receipt-sized cell (`N≈2^12`), ~3.6 bits above the 64 NO-GO. The rescue is
the **standing dual-α mandate** (`c=2`): `2·(128 − log2 N) − 48.41 ≥ 84` for N up to `2^61`.
So the whole verdict hinges on whether dual-α (or Fp3) amplification actually reaches *this
specific cell*.

**Correction to §3 of the prior draft (H3):** the multi-target attack against a *fixed honest*
digest is **second-preimage** (SHA256d base ≈ 256), **not** collision (128). The earlier
`88 − log2 t` figures (71.0 / 53.7) were mis-based by ~128 bits; the real second-preimage branch
is ≥ ~182 bits at any realistic `t`. The SHA term is `min(collision 88 flat, 2nd-preimage
216 − log2 t) = ` **flat 88**. SHA never becomes the floor via multi-target `t`; the *only* SHA
sub-84 path is **digest truncation** (a width invariant), covered by H2b.

### GO conditions (all must hold; each safe-iff is a stage3 measurement)

1. **H2c**: transport-challenge amplification `≥ dual-α (c≥2)` at Fp2, **or** field = Fp3. (If
   single-α Fp2 is found: policy-safe only iff `N ≤ 384` total span elements.)
2. **H1**: internal nodes retain the additive known-term decomposition (`b_int ≥ 77.41` for the
   71 policy; `≥ 92.26` to hold the 84 floor) **and** the ≤4 child proximity instances batch
   into a single query term.
3. **H1/H2c** FRI instances use the committed `Q ≥ 128`, `g = 40` (`kRCFriNumQueries=128`).
4. **H2a**: digest→field reduction is rejection-sampled or wide (`w ≥ log2 p + 8`).
5. **H2b**: no digest lane truncated below full width (256-bit / 4 Goldilocks lanes) at any
   binding point — 14-span cell, parent-proof-verify, FS-replay.
6. **H3**: every SHA comparison is recompute-and-compare against a transcript-bound value; no
   content-addressed / digest-set-membership acceptance in the parent path.

If all six hold, the global floor is **84.1 bits** (FRI-union, SHA flat 88 above) — GO with the
7-bit margin. If H2c is single-α Fp2 at a receipt-sized cell, the floor is **~67.6** (policy
breach, still GO vs 64). No configuration examined produces an outright NO-GO on bits.

## 4. Recommended next actions (production critical path, corrected)

1. **H2c is now the top lever** (it is the binding floor at ~67.6, not FRI). Measure the
   child-proof-cell 14-span transport: is its equality challenge **dual-α** (or Fp3) at the cell,
   or single-α Fp2? Single-α Fp2 at a receipt-sized cell breaches the 71 policy. If the standing
   dual-α mandate does not already cover this cell, **make it do so** — cheapest fix in the set.
2. **H1** — confirm internal aggregating nodes retain the additive known-term decomposition
   (not the 76.8 fallback) and that ≤4 child instances batch into one query term.
3. **H2a/H2b/H3 hygiene** — rejection-sample (or wide-reduce) digest→field maps; forbid any
   sub-256-bit digest lane; keep every SHA site recompute-and-compare (no digest-set membership).
4. **Do not** invest in the batched correlated-agreement tightening for the sealed-receipt tree;
   it is architecturally unavailable, and the union loss is affordable at the FRI floor.
5. The composition *theorem* (binding all nodes+links+replay into one certified statement) is the
   remaining certified-soundness deliverable; the arithmetic clears at ≈ 84.1 bits **iff** the
   six §3 conditions hold — with H2c the only one at real risk of a policy breach.

## Cross-links
- Committed composed bound: `src/matmul/matmul_v4_rc_gkr.cpp:2673` (`RCGkrComposedSeparation`).
- Committed FRI floor: `src/matmul/matmul_v4_rc_fri.h:56` (`FriSoundnessBoundBits() = 76.80`).
- v7 composed bound (superseded Fp2 figures): `doc/btx-matmul-v4.5-v7-composed-soundness-bound-2026-07-22.md`.
- Recompute script: `scratchpad/step5_compose.py` (reproduces 76.80 and the 63.49 cross-check).
