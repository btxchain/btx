# BTX matmul-v4 — MY end-to-end succinct-proof FINISH PLAN — 2026-07-25

> My own construction roadmap (fable+opus fleet; Codex mirror used read-only for study/comparison).
> HONEST STATUS: every drafted closure FAILED adversarial verify — this plan lists the exact
> corrections each needs. Nothing is CLOSED. certified_bits=0. Not activated (heights INT32_MAX).
> This is a complete DESIGN + ordered integration path, NOT a working/certified proof.

# BTX matmul-v4 Parallel Succinct-Proof — FINISH PLAN

**Branch context:** `claude/matmul-v4-design-spec-af23sj` · stage3 sources live in the read-only source mirror; local edits land there. **Status of every closure below reflects the adversarial verdicts — no gate is marked CLOSED where a verdict found a hole.**

---

## 0. Executive summary

Five closures were drafted; **all five failed adversarial verify** (`sound=false`) even where the author self-rated `closes_it=true`. The good news: two of the failures are *quantitative-accounting* errors over a *structurally correct* construction (registry migration, cross-hash), and one soundness number (dual-lane FRI 110.18b) is *arithmetically verified* — it is simply **misattributed** to closing a min-composed union it does not bind. The finish path is therefore real but has a hard ordering: **nothing produces a verifiable root until roles migrate (gap 4) and the self-similar fixed point closes (gap 9)**, and **soundness at the multi-billion-site envelope is gated by hash-binding, not FRI** — so `SoundnessTargetNotMet` is entangled with `cross_hash_collision_binding` and cannot be closed independently.

---

## 1. Ordered integration steps to a WORKING recursion

Dependencies are strict top-to-bottom. Each step lists the concrete artifact and the file it lands in.

### Step 1 — Role-bytecode migration (unblocks *everything*; nothing can be proved until this)
**Goal:** `ResolveCurrentRCStage3RelationConstraintSystem` returns a complete AIR for all 14 roles so `constraints_resolved` flips true.

| Artifact | File |
|---|---|
| `BuildRCStage3RoleProgramTable(role)` — one canonical pin-independent ProgramTable/role, dual-committed (SHA256d + AlgHash) vs 14 compiled-in `RCStage3RoleTablePin` constants | `matmul_v4_rc_stage3_constraint_bytecode.{h,cpp}` |
| H/C/S gadget families over the unchanged opcode set (SHA-256/ChaCha bit tables; LogUp/product lanes; preprocessed schedules via `preprocessed_pin_ood`) | same + `matmul_v4_rc_stage3_hash_air.cpp` |
| `AttachRCStage3RoleParameterColumns(role,pin)`; resolver: build → dual-commit check (fail-closed) → width/rows check → `BuildAirConstraintSystemFromProgramTable` | resolver in `matmul_v4_rc_stage3_relation_local_sharding.cpp` |
| `VerifyAllRegisteredRoleBytecodeMigrated()` + flip `kAllRegisteredRoleBytecodeMigrated` static_assert, with mandatory unit + differential-equivalence test | `matmul_v4_rc_stage3_recursive.cpp` |

**MANDATORY corrections before flipping the static_assert (from verdict):**
1. **Degree fix:** every running-product / LogUp *transition* lane stacked as a sub-section (roles 3, 5, 6, 12, 13, 14) must be gated `SEL_Gk(cur)·SEL_Gk(next)` for boundary completeness → **alg_degree = 5, not 4**. Update §4 "max gated deg" to 5 for those roles. *(Alternative: give each product/LogUp lane a whole-H shard at deg 3, changing the per-role width table.)*
2. **Row-cap re-derivation:** delete the false `4(N−1) ≤ 2^20` chain. Use the real FRI-validity bound `deg(quotient)=5N−5 < blowup·N = 2^22`; `N ≤ 2^18` survives against the 2^24 LDE cap even at deg 5. State explicitly whether you keep `kRCStage3RoleMaxShardRows=2^18` (drop the self-imposed 2^20 budget) or lower to 2^17.
3. **Delete "0 FRI soundness loss":** recompute `maximum_single_lane_fri_bcs_bits` at `dmax=5` (longer quotient → higher tested rate → worse `(17/32)^Q`) and fold the delta into the ledger.
4. **Fix the verify-cost claim:** replace "ms-scale untouched" with the true `O(#params·N)` barycentric dual-OOD cost per shard (~2.6e8 Fp3 ops/shard) and carry it into the 900 ms budget (§3).

> Structural outcome (verdict-confirmed): the resolver *does* meet the readiness contract (`n_rows==child_n_rows`, `n_columns==child_w`, non-empty) and the gadgets are individually correct → **`ConstraintRegistryUnavailable` genuinely disappears once the four edits land.**

### Step 2 — Self-similar fixed point (gap 9): make V_CS verify its own proof
**Goal:** `self_similar_fixed_point_closed` (`recursive.cpp:819`) legitimately flips.

| Layer | Artifact | File |
|---|---|---|
| 1 · Shape | Assert `parent_cs shape == child_cs shape` **only for internal nodes (level ≥ 2)**; add the explicit **leaf→S adapter level** where `episode_air` shape ≠ S | `matmul_v4_rc_stage3_recursive_fixedpoint.cpp` (BuildLevel/NextShape) |
| 2 · In-circuit FS | SHA256d transcript shards + Fp3/query decoders wired, digest-bit ↔ decoder-word equalities | `recursive_parent_air.cpp` (BuildOneSlotNormalizedFriParentV1 ~2450–2606); `fs_selection_air.cpp`; `hash_air.cpp` |
| 3 · Result closure | Bind the **already-present** `quotient_identity` constraint (`fixedpoint.cpp:17012`) to the child's authenticated DEEP/query openings via the dual-logup terminals → makes `result_zero_constrained` non-vacuous | `recursive_fixedpoint.cpp` (result ~17032; join ~15792) |
| 4 · Induction | `family_child_roots_sourced_from_verifier_outputs`: parent output-bus root → next-level child root | `recursive_parent_air.cpp:~2995, 3142` |

**MANDATORY corrections (from verdict):**
- **Decouple soundness from this closure.** The 4-lane packing does **not** "carry the 100-bit target," and FS-replay adds **zero** FRI proximity bits. Delete both claims; soundness is Step 4 + the hash-binding rework.
- **Rewrite item (D):** the recursive child ABI is **field-native** (`complete_proof_cell_decoder_in_air = field_abi_is_recursive_consensus_codec`), so a recursive Fp3 byte-decoder is *not* the open item. The real residual is the **trusted outer `transport_root → receipt_root` conversion** — specify an in-parent equality (`outer_transport_to_field_root_in_parent`).
- **Reorder (E) under (F):** the `Σλ^k C_k = q·Z_H` identity already exists but is **unbound**; it delivers nothing until (F)'s memory-bus join sources `constraint_accumulator`/`Value(3)` from authenticated openings. Validate on an adversarial mutated-quotient witness (`CountHashOpeningViolations==0`) before trusting it.
- **Ground the base case** in the separately-sound episode AIR; numerically reverify the `trace_rows` contraction by iterating BuildLevel/NextShape to a stable power of two.

### Step 3 — Child Fiat-Shamir replay (gap: ChildFiatShamirReplayNotClosed)
**Goal:** prove each pinned child scalar equals FS of the sealed transcript; `child_fiat_shamir_replay_closed` (`recursive.cpp:818`) flips.

New file: **`matmul_v4_rc_stage3_fs_replay_air.{h,cpp}`** — a 7th V_CS family composing SHA256d shards (A) + decoders (B) + glue constraints C1–C7, CTL-linked. Copy seam to close: `ExtractChildPublicInputs` (`air_recurse.cpp:1424–1462`).

**MANDATORY corrections — the drafted decoders target the WRONG primitive (fatal per verdict):**
- The recursed children ride `kFri3AlgQ192V3Config` with `uniform_challenges=FALSE`, `independent_batching_coefficients=FALSE`. So:
  - **Replace** the unbiased `fs_selection_air` decoder with a **biased `FromChallengeBytes3` decoder** (24 bytes, per-8-byte-LE limb `value = raw − q·p`, `q` bounded, result `< p`) for λ/z/w/β/final.
  - **Replace** the power-of-two mask with a query decoder = low `log2(n_lde)` bits of `((Canonical(c1)<<64)|Canonical(c0)) % n_lde`.
- **Arithmetize the variable-length z-rejection loop** (`Fri3AlgBatchSampleZ`): in-circuit `HasExtCoord((c1,c2)≠0)` + distinctness on each candidate, prove first-accepting `ctr`, pin every rejected-draw compression.
- **Fix C1 seed prefix:** `buf0` must include the full `Fri3AlgBatchFsInit` prefix — `LE32(proof_version)`, `LE32(column_len.size())`, `column_len[]`, and the init `AbsorbAlgRoot(row_commit)` — and CTL-equate `column_len` to the DEEP-consumed shift lengths.
- **Add a second replay family** over the AIR-quotient transcript (`aq::AirChallengeDigest → air_lambda`) so the quotient-RLC is pinned, not just FRI challenges.
- Re-derive the FS-replay false-accept contribution as a union of ~200 biased mod-p draws ≈ `2^-24.4` (**still ≈ 0 bits**) — not the uniform-zero-bias story.
- Discharge the **NIROP/oracle-domain-separation** half of the ledger `FiatShamirReplayAndNirop` term before flipping `fiat_shamir_replay_complete`.

> Topology note: ~200+ SHA256d compressions/child × ≤4 children **cannot inline** (exceeds `kFixedProgramRecursiveWidthCap=1092`); vertically pack (hash_air 63-instance) and fold as their own CTL layer — this widens V_CS and therefore must close **jointly** with Step 2.

### Step 4 — Multi-lane FRI (SoundnessTargetNotMet, numeric FRI half)
**Goal:** raise the FriBcs sub-term above 100 at the conservative envelope.

| Artifact | File |
|---|---|
| `kRCFri3AlgLanes=2`; 2 fully **domain-separated** Fp3 FRI lanes, each Q=192, `IndependentCoefficients` batching | `matmul_v4_rc_air_quotient_alg.h` |
| **Separate dual-lane assessor** (do **not** mutate the shared `assess_q` lanes arg — it corrupts the single-lane saturation diagnostics) | `matmul_v4_rc_stage3_global_soundness_ledger.cpp` (assess_q ~64–76) |

**Verified arithmetic (verdict-confirmed against code):** `field_rbr = 126.93`, lane pinned at Q=192; **FriBcs L1 = 93.42 → L2 = 110.18** at `kConservativeProductSites`. This number is correct. **But it does not close the union** — see §2.

### Step 5 — Certification (flip the top gate)
Only after Steps 1–4 land *and their corrections are in*: assemble the unified-root path, then flip `kRCStage3RecursiveAggregationReady` / `cryptographic_verification_ready`. **Precondition:** every load-bearing flag verified false today is true *and* backed by an executable test:
`result_zero_constrained`, `role_semantic_root_terminal_equality`, `deep_per_point_transition_join`, `family_child_roots_sourced_from_verifier_outputs`, `self_similar_arity4_shape`, `child_fiat_shamir_replay_closed`, `fiat_shamir_replay_complete`.

---

## 2. Certified soundness once done — bits and the path to 100

The ledger target is **`known_false_accept_union_bits = ComposeBits({FriBcs, TraceBatching, ConstraintBatching, CtlRationalIdentity, HashBinding})`**, a **min-composition dominated by its smallest term**. The dual-lane FRI closure moved the *wrong* term.

**At the conservative envelope `S = 1.222e10` (site_log2 = 33.51):**

| Term | Single-lane | After dual-lane FRI | Notes |
|---|---|---|---|
| FriBcs | 93.42 | **110.18** | verified; the only term Step 4 changes |
| TraceBatching | 101.49 | 101.49 | margin 1.49 b; untouched |
| ConstraintBatching | 101.49 | 101.49 | untouched |
| CtlRationalIdentity | 246.79 | 246.79 | non-binding |
| **HashBinding** | **94.49** | **94.49** | `128 − log2(S)`; **independent of FRI lanes** |
| **Union** | 92.85 | **≈ 94.47** | **still < 100 — binding term is HashBinding** |

**Conclusion: dual-lane FRI alone leaves the union at ~94.5 b, short of 100 by ~5.5 b, gated by hash-binding.** `SoundnessTargetNotMet` is **NOT** closed by Step 4 and is **entangled** with the hash-collision blocker.

**The two legitimate paths to 100:**

- **Path A — certify the site count (cleanest).** At `kCanonicalProductionSites = 3.75e7` (site_log2 = 25.16) the union is **already ≥ 100 with a single lane** (FriBcs 101.77, HashBinding 102.84). If `exact_selected_topology_manifest_derived` is proved (i.e. the true site union is ~2^25, not ~2^34), **single-lane closes and dual-lane FRI is redundant.**
- **Path B — the multi-billion-site envelope.** Requires **jointly**: (a) dual-lane FRI **+ a proven lane-independence / oracle-domain-separation reduction** (`transcript_domains_proven_disjoint`, currently hardcoded true only for `lanes==1`; `IndependenceReductionReady=false`), **and** (b) rework the per-site hash charge — the transcript-wide **SHA↔AlgHash first-collision hybrid charged once (site-independent 127 b)** instead of `128 − log2(S)` per site — **and** (c) confirm trace/constraint-batching margins (≈100.7 b at S=2.16e10). Path B cannot succeed without closing the *global* cross-hash hybrid, not just the per-pair node.

**Per-child FRI number (legitimate, take as given):** `Fri3AlgSoundnessBoundBits = 192·log2(32/17) − 40 = 135.21` per proof; `107.21` after the 2^28-site union. FS-replay converts these from honest-prover-conditional to **any-prover-unconditional (ROM)** — its own false-accept mass ≈ 0 bits.

---

## 3. 900 ms verify projection (corrected)

The drafted model is **not a measurement** and used the wrong parent query count. Corrections from the verdict:

- **Parent rides `AirFriBackendAlg<Fp3>` → `NumQueries = kRCFri3AlgNumQueries = 192` per lane** (128 is the *child* count). Dual-lane parent = **384 queries, not 256** — a **1.5× under-count** of the dominant row-leaf-sponge term.

**Corrected op-count (W=2184, D=24, F=20, Q_total=384):**

| Quantity | Corrected value |
|---|---|
| perms/query | 2,822 (unchanged) |
| **perms/root** | **1,083,648** (was 722,432) |
| row-leaf sponges | 944,640 (≈ 87%) |
| Fp3 algebra | 384 × 8,896 ≈ **3.42M muls** (~61 ms) |
| serialized root | **~67 MB ⇒ ~33.6 MiB/lane** (>2× the 16 MiB codec cap) |

**Corrected single-thread projection:**

| Scenario | Total | % of 900 ms |
|---|---|---|
| Nominal (0.50 µs/perm, SHA-NI) | **~785 ms** | ~87% — **holds, thin** |
| Conservative (1.0 µs/perm, no SHA-NI) | **~1,463 ms** | **~163% — breaches** |
| Conservative, 4-core query-parallel | ~478 ms* | *only under near-linear parallelism, uncredited serial floor* |

\* Serial floor (topology screen ~65 ms + up to 14 CTL AIRs ~84 ms + SHA FS replay + composition ≈ 130–220 ms) erodes the 4-core recovery on a commodity relay node.

**Verdict:** nominal single-thread **barely holds (~87%)**; commodity-relay conservative **blows the budget by well over half**. The architecture-forcing negative result stands and is useful: **natively verifying the 341-node arity-4 tree costs ~42 s (≈47× budget), so the single-root recursion is the only within-budget path** — which makes this projection **conditional on gap 9**. Also unreconciled: the **>16 MiB/lane codec cap breach** (re-serialize without the separate trace-row opening → ~13.4 MiB/lane, or reduce parent width). **A model with static_asserts over its own arithmetic does not discharge `ProductionPerformanceUnmeasured` — a wall-clock run on the produced proof is required.**

---

## 4. Blockers: genuinely CLOSED vs still OPEN

**No blocker is marked CLOSED where a verdict found a hole.** Every drafted closure failed `sound`.

| Blocker | Status | Basis |
|---|---|---|
| `ConstraintRegistryUnavailable` (registry migration) | **OPEN — closable.** Construction is *structurally* correct and does close the gap, but **only after the 4 mandatory corrections** (deg 5, N-bound re-derivation, delete "0 FRI loss", real verify cost). Do **not** flip `kAllRegisteredRoleBytecodeMigrated` until they land. | Verdict: `sound=false`; "structurally the design DOES close it" with required corrections. |
| `SelfSimilarFixedPointNotClosed` | **OPEN.** `self_similar_fixed_point_closed` hardcoded false; layers 2–4 are unwritten glue; `result_zero_constrained`/join/induction flags all false. | Verdict: `closes_it=false` confirmed, `sound=false`. |
| `ChildFiatShamirReplayNotClosed` | **OPEN.** Drafted decoders target the wrong FS primitive (uniform vs the actual biased V3 config); unbounded z-loop, seed prefix, and `air_lambda` uncovered. Unbuilt/untested. | Verdict: `closes_it=false`, `sound=false`, primitive mismatch "completeness-fatal". |
| `cross_hash_collision_binding_proved` | **OPEN.** Bit arithmetic (127 b) is right in isolation, but the binding is **vacuous**: it ties the two *commitments* to common bytes while the **operative table (adapter.program) is never hashed** and the interpreter result is unwired (`registry_program_result_bound_to_quotient_identity=false`). The proposed load-time recheck is a **tautology**. Per-pair flag must **not** be flipped. | Verdict: `closes_it=true` **overclaimed → sound=false**. |
| `SoundnessTargetNotMet` (100 vs 92.6) | **OPEN.** Dual-lane FRI raises FriBcs to 110.18 (verified) but the min-composed union stays ~94.5, **bound by HashBinding**, at the conservative envelope. Closed **only** via Path A (certify ~2^25 sites) or Path B (dual-lane + proven independence + reworked once-charged hash hybrid). | Verdict: `closes_it=false`; FRI arithmetic verified, misattributed. |
| `ProductionPerformanceUnmeasured` (900 ms) | **OPEN.** Corrected model: nominal ~785 ms, conservative breaches; and a model is not a measurement. Conditional on gaps 4 + 9; no proof is producible today. | Verdict: `closes_it=false`, `sound=false`, category error. |

**Net:** **0 of 6 blockers are CLOSED today.** Registry migration and the cross-hash *per-pair* node are the two nearest to closable, both contingent on concrete corrections above.

---

## 5. Remaining external-audit items

These require review beyond in-tree implementation and testing:

1. **AlgHash (Poseidon2-Goldilocks t=12, d=7) 128-bit collision floor** — heuristic/cryptanalytic, no ROM or standard-model proof. Needs external Gröbner-basis / interpolation cryptanalysis sign-off. The 127-bit cross-hash term inherits this unproven premise.
2. **Lane-independence / oracle-domain-separation reduction** for dual-lane FRI (`e_rep = e_bcs^L`) — the parallel-repetition argument requires a formal transcript-disjointness proof; `IndependenceReductionReady=false`, `FormalSoundnessReady=false`. External soundness review.
3. **Global first-collision hybrid** over *all* hash sites (Merkle nodes, transcripts, envelope roots) — scanner/total-order/extractor not executable; FS-extraction loss unproved. This is the load-bearing piece for Path B soundness and for `hash_first_collision_hybrid_complete`. The `FirstCollisionObservation` harness also needs a **byte/uint256 ↔ Fp-vector/Goldilocks-digest adapter** (AlgHash events don't fit the current type).
4. **NIROP / BCS-composition theorem + oracle separation** (ledger `FiatShamirReplayAndNirop` non-FRI half) — replay-equality alone cannot flip `fiat_shamir_replay_complete`.
5. **Exact selected-topology site-count manifest** (`exact_selected_topology_manifest_derived`) — if certified at ~2^25, Path A closes soundness single-lane and de-risks everything downstream. High-value external verification.
6. **Wall-clock relay-hardware measurement** of single-root verify (the ~0.30–1.0 µs/perm Poseidon2-GL t=12 microbenchmark collapses most of the 3× spread) — the only thing that discharges gap 10. Include codec-cap reconciliation (>16 MiB/lane) in the measured artifact.
7. **Consensus / economic review** that flipping structural gates (registry, per-pair cross-hash) grants **no consensus authority** until `kRCStage3RecursiveAggregationReady` is true — confirm the intermediate flips cannot be mistaken for production readiness.
