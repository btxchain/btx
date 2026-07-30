# BTX matmul-v4 Stage-3 — MY production candidate (all-Fp3 arity-4 recursive succinct proof) — 2026-07-25

> **MatMul v4.7 transition status:** despite the historical title, this is not
> the current production candidate. It is proof R&D for possible Epochs B–D.
> Epoch A is Profile-1 ExactReplay; Epoch B requires durable proof plus replay;
> Epoch C retains Profile 1 under proof authority; Profile 2 is Epoch D only.
> See `doc/btx-matmul-v4.7-transition-roadmap.md`.
>
> Produced by my own fable(math)+opus(crypto) fleet, grounded read-only in Codex's stage3 mirror as
> source material. ANALYSIS/DESIGN ONLY — not activated (heights INT32_MAX), certified_bits=0 today.
> Companion: reconciliation + theorem-roadmap docs (same date). Never claims CLOSED.

# BTX matmul-v4 Stage-3 — Production Candidate (all-Fp3 arity-4 recursive succinct proof)

**Date:** 2026-07-25 · **Historical branch:** `claude/matmul-v4-design-spec`
**Status:** design candidate — **UNVERIFIED** (build/tests not run in this environment). `certified_bits = 0` today; this document specifies the exact delta to lift it to a machine-defensible **per-node** floor.

> Honesty contract for this document: I never write "CLOSED." Every soundness reduction that is not machine-checked is listed as OPEN. The word "certified" is used only for the arithmetized, machine-checkable per-node floor once its two WIP gaps land; the end-to-end global proof remains uncertified.

---

## 1. Construction overview

### 1.1 Shape

An all-Fp3 (Goldilocks cubic extension, |K| = 2^191.99999) arity-4 recursive relation-local sharding proof for the matmul-v4 tensor-PoW round:

- **Leaf layer:** per-shard AIR (trace + constraint) with a v5 half-domain Fp3 FRI (`Fri3Alg`), dual-OOD DEEP, IndependentCoefficients correlated-agreement column batching.
- **Cross-shard glue:** dual-alpha Fp3 CTL (LogUp) linking the 52 buses, `alpha1/alpha2/gamma1/gamma2` sampled post-commitment.
- **Recursion:** arity-4 normalized parent AIR consuming four child receipts per node, over ~37.5 M canonical sites (or the 12.2 B conservative-product diagnostic topology).
- **Outer binding:** a `program_consensus_pin` (recursive_alg_hash_root + external SHA256d audit root + registry binding) carried through the CompositionLink envelope.
- **Grinding:** a verifier-enforced 40-bit Fiat–Shamir grinding nonce (`kRCFriGrindingBits == 40`), applied only to the proof-internal FS/FRI query surface.

### 1.2 What is MINE vs referenced from Codex

| Component | Provenance |
|---|---|
| Two-tier certification predicate (`CertifyExecutableGlobalSoundnessLedgerV1`) + composed-bound formula | **MINE** (C1) — new routine |
| Multi-lane FRI accounting flip (L=2/Q136 executable) + lane-tagged transcript spec | **MINE** (C2), built on Codex's already-coded `kRCFri3AlgDualQ136*` backend |
| End-to-end composed-soundness statement, corrected grinding justification | **MINE** (C3) |
| family_fold codec contract + f/g-pin hardening + test sequencing fix | **MINE** (M1), codec ported from Codex mirror |
| Outer-statement binding: native SHA path (A/B) + arithmetized PIN-BIND roadmap (C/D) | **MINE** (M2) |
| Corrected `eps_mlink` bit term (per-bus cap 2^29, not 2^24) + F1/F3 CTL fixes | **MINE** (M3) |
| Merged arity-4 parent completeness constraints (G1–G5) | **MINE** (M4) |
| `Fri3Alg` / `Fri3AlgDualQ136` codecs, AuthenticatedVerticalSpongeLayoutV1, CTL engine, ledger math | **Referenced** from `the read-only source mirror/src/matmul/…` (read-only) |

The *candidate and its certification are mine*; Codex is the reference implementation I audit against and reuse verbatim where sound.

---

## 2. Certified soundness statement (corrected accounting)

**Field:** Fp3, |K| = 191.99999 b. Child-cell transport ~131 b; CTL links dual-alpha ~183 b. **No sub-64 field-width hazard exists.** The retired Fp2 transport floor is inapplicable.

### 2.1 Term ledger (bits = −log₂ conditional false-accept prob)

`−log₂(S)` is subtracted **inside** every term, so each row is already the global union over all recursion nodes. Two topologies are priced:
- **S_exact = 37,488,397** (log₂ = 25.160) — canonical manifest topology.
- **S_loose = 12,221,217,422** (log₂ = 33.509) — conservative width-product diagnostic (needs no exact-topology theorem; safe fallback).

| Term | Formula | S_exact | S_loose |
|---|---|--:|--:|
| T1 FRI BCS (single-lane Q192, IndependentCoefficients) | all-Q crossover, lane_rbr=min(126.933, 175.2)=126.933 | 101.77 | 93.43 |
| T2 Trace batching | 189 − logS − 40 − log₂(w+2), w=16384 | 109.84 | 101.49 |
| T3 Constraint batching | 189 − logS − 40 − log₂(2¹⁴) | 109.84 | 101.49 |
| T4 CTL dual-alpha (**corrected**) | 378 − logS − log₂(52) − 2·log₂(4(2²⁹−1)) − 40 | **245.14** | **236.79** |
| T5 Hash-binding | 128 − logS (no −40) | 102.84 | 94.49 |
| **Composed union** | −log₂(Σ 2^−Tᵢ) (log-sum-exp) | **101.20** | **92.85** |
| Binding term | | FRI | FRI |

**Corrections applied vs Codex's printed ledger:**
- **T4 is 245.14 / 236.79, not 255.14 / 246.79.** Codex's static envelope hard-codes the per-bus event cap at 2²⁴, but the code enforces 2²⁴ **per participant** with up to `kRCStage3MaxRelationSections = 32` participants ⇒ true per-bus max E_b ≤ 32·2²⁴ = 2²⁹. Codex's term is 10.0 b optimistic. (The runtime assessor already computes 4·(Σevent_counts − 1) correctly; only the static ledger envelope is wrong.) T4 remains > 136 b above target — not binding.

**Excluded from the union (correctly):**
- FS-sampler exhaustion (111.50 / 103.15): honest-prover **liveness**, not a false-accept event.
- Field-width / child transport (~131 b), CTL links (~183 b): both ≫ 100, never bind.

### 2.2 Composition rule

Independent algebraic false-accept events T1..T5 compose by **log-sum-exp** (additive union of 2^−Tᵢ), not by min or product. The union sits ~0.57 b below the binding FRI term at both topologies. Adversary picks the cheapest attack ⇒ the union is the floor.

### 2.3 Grinding — CORRECTED justification (this is the most important correction)

The −40 (`kConservativeGrindingBits`) inside T2/T3/T4 is the **proof-internal FS/FRI transcript grind**, and it is safe because it is **verifier-enforced at 40 bits** (`grinding_parameter_executable = kRCFriGrindingBits == 40`), i.e. a conventional hash-based Fiat–Shamir grinding nonce.

> **Retraction of the earlier FVT framing.** An earlier draft priced the −40 as an FVT tensor-PoW Ω(W_round)/trial work-bound enforced by a T-BIND carrier. **That is contradicted by the source and is withdrawn.** `ledger.h:140-141` states the −40 is the proof-internal FS/FRI query grind, kept *separate* from mining a fresh tensor-PoW statement. `sampled_terminal_round_fvt_executable = false` and `external_pow_work_composition_complete = false`: the FVT terminal-round recompute is design-only and is **not in the ~900 ms verify path** (pre-activation gate per MEMORY). No in-verifier mechanism forces a regrind to cost W_round GEMM. The correct and *sufficient* justification for g = 40 is the verifier-enforced FS grinding nonce alone.

**Sensitivity (load-bearing for the shipped single-lane floor, not just the 2-lane path):** at S_loose single-lane, T2 = T3 = 189 − 33.509 − g − 14. If the enforced cap were bypassed to g ≈ 80, T2/T3 → 61.49 and the union → 60.49 < 64. So the **verifier-enforced 40-bit FS-grinding cap is load-bearing**. The `pow_composition_theorem` that certifies "40 covers every adaptive FS/algebraic attempt without double-counting oracle work" remains **OPEN**.

### 2.4 Final bits and margin

| Quantity | Value | Reading |
|---|--:|---|
| Numeric composed floor (S_loose, single-lane Q192, enforced g=40) | **92.85 b** | numeric/conditional, +28.85 over 64 |
| Numeric composed floor (S_exact) | **101.20 b** | numeric, meets 100 — conditional additionally on exact-topology theorem |
| Per-node Construction-I floor (field-independent, tier-64 anchor) | **76 b** | eps_node ≤ 2^−138.4 + 2^−76.8 + 2^−88 < 2^−76; binding = batched-FRI query 76.8 = Q128·log₂(32/17)−40 |
| **Certified bits (code, today)** | **0** | `theorem_complete = false`, `authority_eligible = false` |

**Path to a certified ≥64:** flip `certified_bits` from 0 to **76** (per-node Construction-I floor) the moment the two WIP gaps land (§3.1, §3.2). This is a **per-node primitive** floor — it certifies each recursion node's primitives at 76 b, **NOT** end-to-end global aggregation. `authority_eligible` stays false.

**Path to 100 (multi-lane FRI):** the single-lane FRI term (93.43 at S_loose) is the only sub-100 term. L=2/Q136 lifts it to 111.53 (canonical) / 107.35 (conservative), so **FRI stops gating** and the union becomes hash-limited at 102.84 / 94.49. Numeric 100 is met at S_exact today (101.20); at S_loose it needs either the exact-topology manifest or the 2-lane FRI plus a tightened hash site-union. **A machine-certified 100** additionally requires the composition-theorem flags in §5 — none are machine-checked.

---

## 3. Concrete delta to a passing + certified candidate

### 3.1 family_fold codec fix (M1) — closes WIP gap #1

**Root cause:** the codec is **not** broken. `SerializeAuthenticatedLinearFamilyFoldProofV1` already implements clear-then-append-return-total. The failing test has indeterminate argument sequencing:

```cpp
BOOST_REQUIRE_EQUAL(ff::SerializeAuthenticatedLinearFamilyFoldProofV1(proved.proof, bytes),
                    bytes.size());   // RHS captured as 0 before Serialize runs -> [296456 != 0]
```

**Fix (test only):**
```cpp
std::vector<unsigned char> bytes;
const size_t written = ff::SerializeAuthenticatedLinearFamilyFoldProofV1(proved.proof, bytes);
BOOST_REQUIRE_GT(written, 0U);
BOOST_REQUIRE_EQUAL(written, bytes.size());
```
Audit every `BOOST_*EQUAL(Serialize*(x,buf), buf.size())` with `grep -rn 'BOOST_[A-Z_]*EQUAL(.*Serialize.*bytes.size' src/test/`.

**Codec contract (ALF1, 72-byte fixed header + exact-length inner FMR2 payload):** magic `0x31464C41`, version 1, reserved 0 (malleability guard), evaluation (Fp3, canonical limbs < p), eval-arg version, sigma (Fp3), `f_column`, `g_column`, `batch_len == bytes.size() − 72`. Return-0 paths leave `out` empty (`ret==0 ? out.empty() : ret==out.size()`).

**Hardening delta:** pin `f_column == 2` and `g_column == 3` at both serialize and decode (the verifier already rejects other values, so honest proofs are never affected). Add the reject-leaves-empty and outer decode∘encode==id regression checks.

**Size note (do not confuse):** 296,456 B is the **mirror** fixture at Q=192. The **candidate** ships `kRCFri3AlgNumQueries = 148` ⇒ 228,696 B for the n_coeffs=4 shape. The codec is Q-parametric; whichever Q the soundness worker certifies flows through unchanged. Both are orders of magnitude under the 16 MiB hard cap.

**Files:** port `matmul_v4_rc_stage3_family_fold.{h,cpp}` + `Fri3AlgMultiRowBatchProof` codec from the mirror into `btx/src/matmul/`; apply the sequencing fix + f/g-pin + postcondition checks to `src/test/matmul_v4_rc_stage3_family_fold_tests.cpp`.

### 3.2 Outer-statement binding (M2) — closes WIP gap #2

**Parts A + B (ACCEPTED — lands the failing test with a sound native binding):**

Root cause: the fixture `Statement()` leaves `program_consensus_pin` defaulted (null `recursive_alg_hash_root`); `IsCanonicalProgramAlgHashRoot()` rejects it inside `VerifyRCStage3CompositionLink`.

**Fix** (in `Statement()`, **before** `ComputeRCStage3TranscriptCommitment`):
```cpp
p.program_consensus_pin.recursive_alg_hash_root   = H(9);
p.program_consensus_pin.external_sha256d_audit_root = H(10);
p.program_consensus_pin.registry_binding          = H(11);
```
Canonicity: `H(v)` gives limbs `v·0x0101010101010101 < p` for v ∈ [1,254]; 0xFF would be rejected.

**Substitution-gap regression** (must fail-verify even after the attacker recomputes a consistent transcript):
```cpp
auto changed_pin = statement;
changed_pin.public_inputs.program_consensus_pin.recursive_alg_hash_root = H(0x0c);
changed_pin.public_inputs.transcript_commitment = rc::ComputeRCStage3TranscriptCommitment(changed_pin);
BOOST_CHECK(!rc::VerifyRCStage3BoundedSemanticBinding(changed_pin, composition, &why));
```
This holds natively: the pin flows `program_pin → RCStage3EpisodeStatementCommitment (SHA256d) → manifest.statement_commitment → manifest_commitment → CompositionLink root → transcript_commitment`. Native binding sub-claim is **128-bit under SHA256d collision resistance**. No production-code change is needed for the test to pass.

**Parts C + D (RE-SCOPED as an uncertified roadmap — do NOT claim certifiable):**

The proposed in-circuit PIN-BIND used an **alg_hash Goldilocks sponge** StatementRoot, but the consensus `statement_commitment` is **SHA256d**. A 4-limb Goldilocks digest can never equal a 256-bit SHA256d value, and the payload encodings differ ⇒ the arithmetized root is a *different object* consensus never checks. **The in-circuit PIN-BIND does not yet certify the native consensus binding.** Two coherent closures, both OPEN:
- (a) add an in-circuit SHA256d chip and set `expected_root` = the native SHA256d statement_commitment (expensive; the parent AIR computes Poseidon/Merkle, not SHA256d); or
- (b) migrate the consensus `statement_commitment` from SHA256d to the alg_hash sponge (breaking change to `episode.cpp:284-310` and all callers) so native and in-circuit roots coincide.

Keep `kRCStage3ProductionProgramRegistryReady = false`. The type-consistent equalities P1/P3 (`recursive_alg_hash_root` vs `selected_registry_program_key`, both 4 canonical Fp limbs, degree-1, 0 slack) and P2 (CTL dual-alpha Fp3 ~183 b) are correct and preserved as the *arithmetized target*, not a shipped claim.

**Files:** `src/test/matmul_v4_rc_stage3_bounded_semantic_binding_tests.cpp` (A/B, test-only). PIN-BIND band + P1–P4 into `matmul_v4_rc_stage3_recursive_parent_air.{h,cpp}` and `fs_selection_air.*` — tracked OPEN.

### 3.3 Certification predicate (C1) — moves `certified_bits` 0 → 76 (per-node)

Add `CertifyExecutableGlobalSoundnessLedgerV1(ExecutableGlobalSoundnessLedgerV1&)` as the last statement of `AssessExecutableGlobalSoundnessLedgerV1` (replacing the hard-coded `certified_bits=0` block, ledger.cpp:476-478).

**Union formula (in-code guards):** recompute `ComposeBits` over the 5 union terms and assert `== canonical.known_false_accept_union_bits`; assert `known_union_numeric_target_met == (union ≥ 100.0)`; `static_assert(RCGkrConstructionISeparationBits() >= kRCFriTargetSoundnessBits + 10)`; require `FriSoundnessBoundBits() (=76) >= kRCFriTargetSoundnessBits`.

**Two-tier predicate:**
```
P_exec  = single_fp3_backend_executable && q192_multirow_v2_executable && q192_split_rap_integrated
       && ctl_dual_lane_arithmetic_executable && recursive_child_transport_fp3_only
       && legacy_fp2_transport_bound_inapplicable && hash_primitives_executable
       && grinding_parameter_executable && internal_fri_grinding_charged
       && deprecated_width_product_rejected && universal_program_registry_binding_defined
P_wip   = family_fold_proof_codec_executable        // §3.1 green codec roundtrip
       && semantic_relation_closure_complete         // §3.2 native binding passes

P64  = P_exec && P_wip
    && RCGkrConstructionISeparationBits() >= kRCFriTargetSoundnessBits   // 76 >= 64
    && FriSoundnessBoundBits()            >= kRCFriTargetSoundnessBits    // 76 >= 64

P100 = P64 && P_topology && P_numeric && P_reduce                        // §5 flags, all OPEN

if      (!P64)  certified_bits = 0;
else if (!P100) certified_bits = RCGkrConstructionISeparationBits();     // 76  (per-node floor)
else            certified_bits = (uint32_t)floor(known_false_accept_union_bits);  // 101 (OPEN)
```

**Semantics that MUST be documented in the header:** `certified_bits = 76` is a **per-node Construction-I primitive floor** (field-independent, needs no global reduction). It is **NOT** an end-to-end global soundness certificate; global aggregation over the ~37.5 M sites is uncertified and `authority_eligible` correctly stays false. The routine reads only fields the ledger already populates plus the two constexpr FRI/GKR helpers — buildable with no new proof machinery. It **correctly returns 0 today** because both WIP tests are red; it auto-certifies to 76 the moment §3.1 and §3.2 land, with zero further change here.

**Files:** `matmul_v4_rc_stage3_global_soundness_ledger.{h,cpp}`; include `matmul_v4_rc_gkr_eval.h`, `matmul_v4_rc_fri.h`.

### 3.4 Multi-lane FRI (C2) — the 100-bit path

**Construction:** L domain-separated FRI lanes over **one shared** row-Merkle column commitment. Each lane l independently: IndependentCoefficients correlated-agreement RLC (fresh a_{l,i} per column from a **lane-tagged** transcript), its own v5 fold betas, dual-OOD DEEP, and its own Q index set. Verifier accepts iff **all L lanes** accept ⇒ e_rep ≤ e_bcs(Q)^L.

**Batching residual = 0** under IndependentCoefficients (single-power γ batching would cost log₂(W−1) ≈ 14 b and is **forbidden**).

**Accounting (verified):**

| L | Q/lane | totalQ | FRI @canonical | FRI @conservative |
|--:|--:|--:|--:|--:|
| 1 | 192 | 192 | 101.77 | 93.43 (single-lane saturation) |
| **2** | **136** | **272** | **111.53 ← EXEC** | **107.35** |
| 3 | 136 | 408 | 115.72 | 112.94 |
| 4 | 136 | 544 | 117.82 | 115.73 |

**Correction:** Q136 is **proximity-limited**, not field-limited: `lane_rbr = min(field 126.933, proximity 124.105) = 124.105`. Proximity does not reach the field cap until Q≈139, so Q136 leaves ~2.8 b of proximity headroom; more queries/lane help only up to ~139, past which **lanes are the sole lever**.

Minimal executable config = **L=2 @ Q136** (272 openings, ≈1.42× single-lane Q192), the already-coded `kRCFri3AlgDualQ136*` backend. Codec bound `kRCFri3AlgDualQ136MaxProofBytesHard = 2·single + 128` already reserved.

**Integration:** in `BuildScenario()` flip the `assess_q` lambda from `lanes=1` to `lanes=2, queries=136`, keep IndependentCoefficients — `AssessFriScenario` already implements `e_bcs(Q)^L` and `AllQueryCrossoverBits`, so this is an **accounting flip, not new math**. Add `fri_lanes` to `ExecutableGlobalSiteScenarioV1`. Swap `OneSlotNormalizedFriParentV1::ChildProof` to the `Fri3AlgDualQ136Proof` codec; the recursive parent replays both lane transcripts (Lane0/Lane1 tags) and requires both to verify.

**Note:** with `lanes > 1`, `transcript_domains_proven_disjoint` and `common_commitment_hybrid_complete` go **false**, correctly holding `certified_bits = 0` until the three lane obligations (§5) close.

### 3.5 Merged arity-4 parent (M4) + CTL fixes (M3)

The two disjoint parent builders must be **merged into one `parent_cs`** that runs the V_CS Merkle/fold/DEEP/quotient chips *and* the family-slot/A_c composition. Then add, for the active slot (word 0..7):
- **G1:** extend `BuildFieldNativeProofAbi` with `alpha1_sum/alpha2_sum` lanes; `active_slot·(family.terminal{1,2} − childAc{1,2}_source) = 0` — binds CTL terminal A_c to the sponge-authenticated child statement.
- **G2:** `active_slot·(family.ChildRoot(word) − vcs_root_output[word]) = 0` — child roots recomputed, not host-decoded.
- **G3:** `(1 − active)·family.ChildRoot(word) = 0` — no smuggled child in a padding slot.
- **G4:** preprocessed `level` + `canonical_node_index` absorbed into the statement sponge, boolean/range pins, and (once self-similar) `child.level + 1 == parent.level`.
- **G5:** `kFirstRow slot_index=0`, `kTransition next[slot_index] = row[slot_index] + 1`.

**CTL fixes (M3):** add `ValidateRCStage3CtlBusSchedules` (bus-wide `(namespace, stage, address, sign)` uniqueness, cross-participant) called from `VerifyRCStage3CtlBusAirProofs` — closes the value-swap-between-receivers gap (**F1**). Enforce the per-bus event cap or set the ledger envelope to `kRCStage3MaxRelationSections·kRCStage3CtlMaxEvents = 2²⁹` and record T4 = 245.14 / 236.79 (**E1** — prefer the semantics-neutral envelope fix; option (i) is a real 32× capacity cut). Add bus_id uniqueness on the verify path (**F2**).

Verify the merged parent with `va::CountVerifierScalarViolations == 0` and `air_recurse::CountWitnessViolationsOnH == 0`.

---

## 4. Acceptance tests the candidate must pass

| # | Test | Maps to | Assertion |
|---|---|---|---|
| A1 | family_fold codec roundtrip | `matmul_v4_rc_stage3_family_fold_tests` | `written > 0 && written == bytes.size()`; reject-leaves-empty; outer decode∘encode == id |
| A2 | bounded_semantic_binding | `matmul_v4_rc_stage3_bounded_semantic_binding_tests::proof_owned_envelope_binds_every_typed_identity` | passes with canonical pin; `changed_pin` fail-verifies via `outer_manifest_root` |
| A3 | Certification predicate | new `global_soundness_ledger` test | after A1+A2 green: `CertifyExecutableGlobalSoundnessLedgerV1` sets `certified_bits == 76`, `authority_eligible == false`, `theorem_complete == false` |
| A4 | `certified_bits ≥ 64` gate | new assertion | `BOOST_REQUIRE(ledger.certified_bits >= 64)` — **fails today (0), passes once A1/A2 land → 76** |
| A5 | Union arithmetic guard | ledger test | recomputed `ComposeBits{T1..T5} == known_false_accept_union_bits`; `known_union_numeric_target_met == (union ≥ 100)` |
| A6 | Multi-lane FRI numeric | soundness_scenarios test | L=2/Q136 `q192_fri_bcs_bits ≥ 100` at both site counts |
| A7 | CTL T4 corrected term | ledger test | `ctl_rational_identity_bits == 245.14` (canonical) after E1 fix |
| A8 | Merged parent completeness | new AIR test | `CountVerifierScalarViolations == 0 && CountWitnessViolationsOnH == 0`; G1–G5 constraints present |
| A9 | **900 ms verify budget** | new perf test | end-to-end recursive verify (excluding FVT full-round recompute, which is pre-activation-gated) within the ~900 ms relay window; record actual on `the relay host` RTX 5060 Ti (sm_120) and CPU-only |

A9 note: per MEMORY, an FVT full-round recompute likely breaks the 900 ms relay budget except on datacenter accelerators, so the sampled-carrier full recompute is **deliberately excluded** from the relay verify path and gated pre-activation. The budget test covers only the succinct-proof verify.

---

## 5. Honest OPEN items requiring completion of remaining verification (never CLOSED)

**Blocking `certified_bits > 0` today:**
1. **WIP gap #1** — family_fold codec roundtrip not yet built/run in the candidate tree (fix is static-analysis-verified only). §3.1.
2. **WIP gap #2 (native)** — bounded_semantic_binding fix not yet run. §3.2 A/B.

**Blocking the per-node 76 → 100 lift (all currently `false` in the ledger; none machine-checked):**
3. `normalized_recursive_verifier_executable`
4. `exact_selected_topology_manifest_derived` (needed to claim S_exact/101.20 rather than S_loose/92.85)
5. `universal_program_registry_consumed_in_recursion`
6. `ali_degree_and_constraint_manifest_complete` (undermines T2/T3 until proven)
7. `ctl_export_and_terminal_reduction_complete` (T4 is "numeric envelope only"; **F3** — recursive terminal consumption + in-circuit dual-lane Σterminal==0 + per-role VALUE-column equality)
8. `hash_first_collision_hybrid_complete` (T5)
9. `fiat_shamir_replay_complete`
10. `nirop_oracle_separation_complete`
11. `pow_composition_theorem_complete` — the theorem that the verifier-enforced 40-bit FS-grinding cap covers every adaptive FS/algebraic attempt without double-counting oracle work. **Load-bearing** (§2.3 sensitivity: g→80 breaks 64).
12. `global_additive_theorem_complete`

**Multi-lane FRI lane obligations (block the 100-bit path; all `false`):**
13. `kRCFri3AlgDualQ136FullOracleDomainSeparated` — per-lane oracle domain separation.
14. `kRCFri3AlgDualQ136IndependenceReductionReady` — common-commitment hybrid licensing e_rep ≤ e_bcs^L on a shared column root.
15. `kRCFri3AlgDualQ136FormalSoundnessReady` — NIROP repetition theorem machine-checked. Plus: enforce IndependentCoefficients (not single-power) so the batching residual stays 0.

**Outer-binding arithmetization (M2 Parts C/D — uncertified roadmap):**
16. **Cross-hash bridge** — the arithmetized alg_hash StatementRoot is a *different object* than the SHA256d consensus commitment. Either add an in-circuit SHA256d chip or migrate the consensus commitment to alg_hash. Until then, C/D do **not** certify the in-circuit binding.
17. `complete_splitrap_verifier_in_air`, `complete_sha_fiat_shamir_replay_in_air`, `registry_program_interpreter_executes_in_parent`, `host_preprocessed_replay_eliminated`, `canonical_program_key_bound_in_air` — EXPECTED operands are host-replayed today; keep fail-closed.

**Parent completeness (M4 — reach NOT met):**
18. Merge the two disjoint parent builders; G1–G5 are live missing-constraint holes (A_c unbound, active-slot child roots host-sourced, padding child roots not zeroed, no level/node-index, unconstrained slot ordering). Requires the merged-`parent_cs` integration work (§3.5).

**CTL (M3):**
19. **F1** bus-wide send/receive key uniqueness (value-swap gap). **F3** recursive terminal consumption + VALUE-column equality (`relation_witness_equality_pending`). **E1** per-bus cap/envelope fix. **F2** bus_id uniqueness on the verify path.

**Grinding premise:**
20. `sampled_terminal_round_fvt_executable = false` / `external_pow_work_composition_complete = false` — the FVT terminal-round recompute is design-only and outside the relay verify path. The 40-bit grinding charge stands on the **verifier-enforced FS nonce**, not on any FVT tensor-work bound (the earlier FVT-work justification is withdrawn, §2.3).

**Bottom line:** the ledger arithmetic is correct and the numeric composed floor is **92.85 b (loose) / 101.20 b (exact)**, comfortably above 64 under the conventional verifier-enforced 40-bit FS-grinding model. But `certified_bits = 0` today; this is a numeric floor, not a certified one. The candidate reaches a **machine-defensible per-node 76-b certified floor** the moment WIP gaps #1 and #2 land, with `authority_eligible` correctly staying false until the ~18 global/lane/binding reductions above are externally audited and machine-checked.
