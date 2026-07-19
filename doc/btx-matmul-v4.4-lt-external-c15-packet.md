# BTX MatMul v4.4-LT — External C-15 adversarial review packet

*Status: **DRAFT for independent cryptanalyst** — not closed. ChaCha20-PRF
MatExpand Extract candidate is implemented with frozen goldens; this packet is
the external review brief.*
*Companions: `doc/btx-matmul-v4.4-lt-normative-spec.md`,
`doc/btx-matmul-v4.4-lt-adversarial-analysis.md`.*
*Do not treat completion of this packet as automatic GO for Rank-1 activation.*
*Do not claim C-15 cryptographically closed.*

## 0. Scope and non-goals

**In scope (ask the reviewer to break):**

1. **MatExpand non-collapse** — can an adversary replace the dense `G·W·H`
   MatExpand GEMMs with a cheaper Freivalds-linear / affine shortcut that still
   produces accepting digests with non-negligible probability?
2. **Invariant I1′ amortization** — does template-scoped MatExpand-A / `U` /
   `V` / `P=U·Â` create a reusable algebraic identity that collapses per-nonce
   MatExpand-B work?
3. **Batch algebra** — does optimal factoring `Ĉ=(U·Â)(B̂·V)` interact with
   MatExpand Extract to re-open a linear association attack?
4. **Seal-binding (Phase B)** — if Rank-1 launches with `fMatMulLTSealAsPoW`,
   does `SealWindowCommit(σ, Merkle(slot digests), Q*)` bind the window tightly
   enough that skinny single-nonce or cross-anchor amortization fails?

**Out of scope for this packet:** silicon nonce/s campaigns, ASERT calibration,
Header-PoW / chainwork (separate gates), tip-verify soak budgets.

**Hard rule for reviewers and operators:** invent no silicon numbers; do not
raise `nMatMulDRLTHeight`; do not claim GO/NO-GO closed from this draft alone.

## 1. Normative objects (short)

Domain tags (V44LT) and map (see normative spec for full text):

```
Y = G · W          # s8×s8→s32, n×w, w=128
B32 = Y · H        # s32×s8→s32, n×n
prf_key = SHA256("BTX_MATEXPAND_PRF_V44LT" ‖ seed_W)
B̂[i,j] = ExtractDequantMatExpand(B32[i,j], i, j, prf_key)
# ChaCha20 PRF (RFC8439 in-tree crypto/chacha20.h) over (key, raw, i, j, remix)
# → M11 rejection nibbles → e∈{0..3}; μ<<e ∈ [-48,48]
```

- Operand A: MatExpand with template-scoped `W_A` (I1′ amortized).
- Operand B: MatExpand with nonce-fresh `W_B` (marginal work).
- Sketch: `Ĉ = (U·Â)(B̂·V)` over `q=2⁶¹−1`, tile `b=2`, digest `H(σ‖Ĉ)`.
- Phase B seal (optional mode): `matmul_digest := SealWindowCommit(σ_anchor,
  Merkle(slot digests), Q*)` with `Q*∈{64,128}` and parent-MTP-threaded slot seeds.

Legacy `FoldInt32ToEmax48` (`y % 97`) and SplitMix
`ExtractDequantMatExpandSplitMix` are **non-normative** (differential tests
only). A review that only breaks Fold/SplitMix does not break consensus MatExpand.

**Candidate status:** ChaCha20-PRF Extract is selected for `ENC_BMX4C_LT`;
**external review still required before activation.** Not closed.

## 2. Attack class LT-C15 (Freivalds reassociation)

**Claim under review:** there is no efficient adversary that, given template
panels and Freivalds probes linear in `B̂`, recovers accepting sketches without
paying for the dense MatExpand GEMMs (up to negligible Freivalds soundness).

**Why implementers believe ChaCha20-PRF+M11 blocks the linear class:**

- Extract is not an affine function of the GEMM accumulator `B32[i,j]`.
- Position salts `(i,j)` and full `seed_W`-derived PRF key kill translation /
  panel-reuse collapses.
- M11 rejection + discrete scale `e∈{0..3}` destroy homomorphism useful to
  Freivalds reassociation through `fold(GWH)`.
- Mixer is a reviewed in-tree primitive (ChaCha20), not SplitMix64.

**Reviewer deliverables:**

| ID | Question | Expected artifact |
|---|---|---|
| C15-A | Exhibit (or rule out) an affine / low-degree surrogate `f(B32)` that matches Extract on a dense sample with advantage ≫ Freivalds ε | Proof sketch or concrete counterexample vectors |
| C15-B | Show whether Freivalds probes on `Ĉ` can be rewritten as probes on `G,W,H` alone | Reduction or impossibility argument |
| C15-C | Quantify any leftover structure (e.g. scale-lane bias, nibble remix cycles, ChaCha nonce packing) usable as a distinguisher | Notes + optional machine-checkable vectors |

Internal witnesses (not a substitute for external review):
`matexpand_not_affine_in_raw`, `matexpand_position_salt_differential`,
`matexpand_additivity_noncollapse`, `matexpand_chacha_prf_golden_vectors`
in `src/test/matmul_v4_lt_tests.cpp`.

## 3. Invariant I1′ (template amortization)

**Claim under review:** amortizing MatExpand-A / `U` / `V` / `P` once per
template does not create a cheaper-than-MatExpand-B path for fresh nonces.

**Reviewer deliverables:**

| ID | Question | Expected artifact |
|---|---|---|
| I1-A | Can an adversary reuse a single MatExpand-B across many templates that share `P`? | Attack or binding argument via `DeriveSigma` / header hash |
| I1-B | Does fixing `Â` allow solving for `B̂` from sketch equations cheaper than GEMM? | Algebraic degree / MAC lower-bound discussion |
| I1-C | Confirm marginal priced work remains `{MatExpand-B, B̂·V, combine, digest}` | Stage-boundary checklist vs `matmul-v4-report --profile bmx4c-lt` |

## 4. Batch algebra

**Claim under review:** integer-matrix associativity
`U·(Â·B̂)·V = (U·Â)·(B̂·V)` remains exact after MatExpand, and does **not**
reintroduce a linear fold of `G,W,H` into Freivalds.

**Reviewer deliverables:**

| ID | Question | Expected artifact |
|---|---|---|
| BA-A | Verify optimal factoring equals full-product sketch on MatExpand operands | Cross-check against `ComputeSketch` / `ComputeCombineModQ` |
| BA-B | Argue that associativity of exact int GEMMs does not commute past Extract | Short write-up |
| BA-C | Any batching / windowing (`Q*`) that accidentally linearizes Extract? | Yes/no with construction |

Internal witness: `matexpand_batch_algebra_optimal_equals_full` in
`src/test/matmul_v4_lt_tests.cpp`.

## 5. Seal-binding (Phase B)

**Claim under review:** when seal-as-PoW is active, the lottery object binds a
full `Q*` window of MTP-threaded sibling digests; skinny launches and
cross-anchor amortization fail.

**Reviewer deliverables:**

| ID | Question | Expected artifact |
|---|---|---|
| SB-A | Can two anchors share useful slot digests? | Binding via full `DeriveWindowSlotId(σ_anchor, j)` into seeds + Merkle leaf (`CommitWindowSlotLeaf`); `nNonce64` is only `ReadLE64(slot_id)` |
| SB-B | Does mutating one leaf / payload break `SealWindowCommit` and seal-auth? | Reduction to Merkle + tagged commit |
| SB-C | Parent-MTP omission / swap attack surface | Fail-closed checklist vs EncDr recompute |
| SB-D | Interaction with Phase-A sketch-cache auth (`H(σ‖Ĉ)==digest`) | Confirm Phase-A auth is correctly skipped in seal mode |

Internal witnesses: `phase_b_seal_round_trip_and_auth`,
`phase_b_seal_parent_mtp_slot_seeds_and_encdr`,
`seal_binding_sigma_and_merkle_leaf` in `src/test/matmul_v4_lt_tests.cpp`.

## 6. Suggested review procedure

1. Read normative + adversarial docs; skim `src/matmul/matmul_v4_lt.{h,cpp}`.
2. Run internal vectors: `test_btx --run_test=matmul_v4_lt_tests`.
3. Attempt C15-A/B with a small `n` (e.g. 64) and dense accumulator samples.
4. Attempt I1 / batch-algebra rewrite against the optimal sketch path.
5. If Phase B is in the launch package, work SB-A..D against seal helpers.
6. Return a short signed note: **PASS / FAIL / INCONCLUSIVE** per table ID,
   with any concrete vectors attached. Do **not** fill silicon nonce/s.

## 7. How this plugs into the silicon campaign

```
measure-hardware.sh <cuda|metal|hip> --profile bmx4c-lt
        │
        ▼
matmul-v4-report-*.json   (schema_version 3, profile bmx4c-lt)
        │
        ▼
lt-gate.py <dir> --manifest parts.tsv [--cost ...] [--ack-external-c15]
```

- Silicon gates G1–G4 consume **measured** JSON only; missing
  `device_nonce_per_s` / labels / costs ⇒ **NO-GO** (fail closed).
- G5 (`--ack-external-c15`) is the operator attestation that **this packet**
  was completed by an independent cryptanalyst. Ack without that work is a
  process failure, not a math proof.
- G6–G8 remain separate (tip soak, Header-PoW/chainwork, seal-mode review).
- Nothing in this packet raises `nMatMulDRLTHeight`.

## 8. Explicitly not claimed

- External C-15 **closed** (candidate selected; review still required)
- Rank-1 GO/NO-GO **closed**
- Finite public `nMatMulDRLTHeight`
- Any B200/5090 nonce/s or nonce/$ figure
- Cryptographic proof that ChaCha20-PRF Extract has no cheaper algebraic shortcut
