# BTX CTV + CSFS Implementation Plan (Revision 7d)

> **Status**: Execution-ready
> **Scope**: Add `OP_CHECKTEMPLATEVERIFY` (CTV) and `OP_CHECKSIGFROMSTACK` (CSFS)
> to the P2MR script environment. PQ-only, minimal bloat, hostile-to-DoS.
> **Assumption**: BTX is a pre-launch hard fork. Breaking changes are free.

---

## Revision History

| Rev | Key Changes |
|-----|-------------|
| 2 | Initial actionable draft. |
| 3 | Fixed CSFS flag/activation inconsistency (genesis-active). Corrected CTV preimage sizes (116/84, not 144/112). Added P2MR DoS hardening prerequisite. |
| 4 | **Six blocking fixes**: (1) CTV stack semantics changed to no-pop/BIP-119-style to satisfy cleanstack. (2) CTV opcode moved from 0xbd to 0xb3 (OP_NOP4) to avoid OP_SUCCESS range and match BIP-119. (3) CSFS message hashing restored to `TaggedHash("CSFS/btx")` for domain separation. (4) Concrete P2MR policy template matcher changes added (`policy.cpp`). (5) Sigops scaling corrected: raw count without `WITNESS_SCALE_FACTOR`, matching witness v0 convention. (6) Factual corrections: the 1650 limit is `DEFAULT_SCRIPT_SIZE_POLICY_LIMIT` applied to leaf script size, not a per-witness-item cap; SLH-DSA-128s already relays via `IsPolicyP2MRSignatureSize`. Also: validation weight uses algorithm-specific decrements instead of flat 50. |
| 4a | **Three refinements**: (1) Added delegation/oracle leaf pattern (`CSFS_VERIFY_CHECKSIG_*`) to policy template matcher for 5-item witness standardness. (2) Removed P2MR `WitnessSigOps()` counting: validation weight is the primary DoS defense; sigops adds consensus parsing surface for marginal benefit. Deferred to future work if an independent block-level cap is still needed. (3) Locked in CTV strict-fail for non-32-byte arguments with explicit test requirements. |
| 4b | **Five execution-blocking fixes**: (1) CTV transaction-context hook: `EvalScript()` only has `BaseSignatureChecker&`; added `CheckCTVHash()` virtual to `BaseSignatureChecker`, implementation in `GenericTransactionSignatureChecker` (has `txTo`/`nIn`/`txdata`), forwarding in `DeferringSignatureChecker`. (2) CSFS tagged hash must hash raw bytes via `hasher.write(MakeByteSpan(msg))`, NOT `hasher << msg` (which serializes with CompactSize length prefix). (3) CSFS policy signature sizing: exact size only (no +1 hashtype byte), distinct from CHECKSIG which allows +1. (4) New flag names added to `transaction_tests.cpp:mapFlagNames`. (5) Python/functional test harness opcode definitions added to `test/functional/test_framework/script.py`. |
| 4c | **Three build/safety fixes**: (1) Build system: `src/script/ctv.cpp` must be added to `bitcoin_consensus` source list in `src/CMakeLists.txt`, and any new C++ test files to their respective CMake targets. (2) Null-safety: `CheckCTVHash()` replaced `assert(txdata)` with `HandleMissingData(m_mdb)` to match the established `CheckPQSignature()` pattern — avoids null-deref crash in release builds if CTV is ever evaluated without precomputed data. (3) Cache deduplication: CTV sequences hash and outputs hash reuse existing BIP-341 fields (`m_sequences_single_hash`, `m_outputs_single_hash`) instead of adding duplicate fields — both are single-SHA256 of the same serialized data. Only scriptSig-specific fields added. |
| 5 | **Six fixes**: (1) Delegation/oracle example leaf used two ML-DSA pubkeys (~2633 bytes), exceeding `g_script_size_policy_limit` (1650). Fixed: standard delegation uses SLH-DSA oracle (32-byte pubkey) + ML-DSA spender, producing ~1351-byte leaf. Two-ML-DSA noted as consensus-valid but non-standard. (2) `SCRIPT_ERR_*` insertion rule: append-only before `SCRIPT_ERR_ERROR_COUNT`; `script_error.cpp` (ScriptErrorString) must also be updated. (3) `ComputeCTVHash()` readiness check added. (4) CSFS handler must check `stack.size() < 3` before popping 3 items. (5) P2MRLeafType delegation patterns clarified: which algorithm combinations are standard (≤1650 bytes) vs consensus-only. (6) Deep code scan verified: P2MR dispatch, Init() flow, EvalScript signature, OP_CHECKSIG_MLDSA handler pattern all consistent with plan. |
| 5a | **Two fixes**: (1) CTV readiness condition: `ComputeCTVHash()` must check `m_bip143_segwit_ready \|\| m_bip341_taproot_ready` (not just `m_bip341_taproot_ready`). `Init()` computes `m_sequences_single_hash` / `m_outputs_single_hash` for either precompute path; checking only the taproot flag is fragile for test harnesses. (2) Flag-gating vs sigversion-gating decision made explicit: CTV is **flag-gated** (redefines OP_NOP4, needs NOP fallback when flag unset, matching CLTV/CSV pattern); CSFS is **sigversion-gated** (P2MR-only opcode in OP_SUCCESS range, matching OP_CHECKSIG_MLDSA pattern). `pq_consensus_tests.cpp` `P2MR_SCRIPT_FLAGS` must include `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` for CTV tests. |
| 5b | **Two specification clarifications**: (1) CSFS verification call path: CSFS must NOT call `checker.CheckPQSignature()` (which always computes a transaction sighash via `SignatureHashSchnorr()`). Instead: compute `hash = TaggedHash("CSFS/btx", msg)` via `HASHER_CSFS` + `write()`, then verify via `CPQPubKey{algo, pubkey}.Verify(hash, sig)` directly. (2) CTV scriptSigs hash serialization: each scriptSig is serialized using Bitcoin's standard `CScript` serialization (CompactSize length prefix + script bytes) via `ss << tx.vin[i].scriptSig`. New Section 2.2.1 spells out the exact serialization for all three sub-hashes (scriptSigs, sequences, outputs), including code patterns. |
| 5c | **Three consistency fixes**: (1) Design Principle #1: changed "CSFS reuses the existing `CheckPQSignature` path" to "CSFS reuses the existing PQ verification primitives (`CPQPubKey::Verify`)" to match the Rev 5b specification that CSFS must NOT call `checker.CheckPQSignature()`. (2) Section 2.5: removed stale "requires `m_bip341_taproot_ready`" sentence that contradicted the later-corrected readiness guard; only the correct `m_bip143_segwit_ready \|\| m_bip341_taproot_ready` guard remains. (3) CTV cache fields `m_ctv_*` are explicitly computed inside `PrecomputedTransactionData::Init()`, not lazily. Added concrete `Init()` code block showing the CTV computation block. Lazy init would require `mutable` fields or non-const references, adding unnecessary complexity. |
| 6b | **Comprehensive test matrix**: New Section 9 with 99 tests across 8 categories: prerequisite validation weight (6), CTV consensus (21), CSFS consensus (23), CSFS validation weight (5), delegation/oracle (5), policy (18), cross-context/regression (10), functional/integration (11). Every test has unique ID (e.g., C-CTV-3, C-CSFS-14, P-CSFS-9), expected result, and back-reference to the specification section it validates. Phase 2 and Phase 3 test lists expanded from bullet summaries to fully enumerated test plans. Covers happy paths, edge cases (empty stack, empty sig, 0-byte msg, boundary sizes), flag-gating, sigversion-gating, cross-context behavior, Init() correctness, sub-hash equivalence, and end-to-end functional flows including vault CPFP and package relay. |
| 7 | **Three hardening fixes + two execution-readiness tightenings**: (1) **Execution-readiness blocker resolved — P2MR consensus element size cap (Section 1.4)**: P2MR bypasses `MAX_SCRIPT_ELEMENT_SIZE` for both script pushes (`interpreter.cpp:457`) and execution-stack elements (`interpreter.cpp:1940-1946`). With stack-copying opcodes (`OP_DUP`, `OP_2DUP`) and `MAX_STACK_SIZE = 1000`, a miner can duplicate large witness items many times, causing OOM/CPU spikes unbounded by the validation-weight model. Fix: enforce `MAX_P2MR_ELEMENT_SIZE` (10,000 bytes) at both sites. Scope clarified: leaf_script and control_block are popped before Site 2 runs; the cap applies to execution-stack elements (witness args) and script push values. Memory analysis accounts for parallel script validation (`par_script_checks`): ~threads × 10 MB peak. (2) **Appendix B wording tightened**: `MANDATORY_SCRIPT_VERIFY_FLAGS` is explicitly policy-only (`policy.h:138-145`); the activation-flag invariant is phrased as "for genesis-active features, ensure `GetBlockScriptFlags()` includes the new flags at all heights," not as a universal truth about `MANDATORY_*`. (3) **CSFS consensus signature-size semantics made explicit (Section 3.2.1)**: If a CSFS signature is non-empty and not the exact algorithm size, consensus hard-fails with `SCRIPT_ERR_SIG_MLDSA` / `SCRIPT_ERR_SIG_SLHDSA`, matching the `OP_CHECKSIG_MLDSA`/`OP_CHECKSIG_SLHDSA` pattern (`interpreter.cpp:1135-1144`). Written down so implementers don't guess. |
| 7a | **Two execution-readiness tightenings**: (1) Phase 4 made concrete (initial): descriptor grammar, signing plan, PSBT fields specified. (2) Appendix D enforcement points made concrete for `tr()` ban. |
| 7b | **Full Phase 4 execution-readiness pass + flag infrastructure fix**: (1) `SCRIPT_VERIFY_END_MARKER` bump requirement added (Section 3.3): new flags must be inserted before the sentinel in the enum (`interpreter.h:149`); the marker is used by `txvalidationcache_tests.cpp:137` to generate random flag combinations for exhaustive testing. (2) Phase 4 (Sections 4.0-4.4) rewritten with full reconciliation against actual codebase: `mr()` descriptor grammar reconciled with existing `MRLeafSpec`/`BuildP2MRScript()` (`descriptor.cpp`), `SignP2MR()`/`ExtractP2MRLeafPubKey()`/`CreatePQSig()` (`sign.cpp:96-471`), and PSBT infrastructure (`psbt.h:34-62`). Concrete changes: `MRLeafSpec` struct extension with `MRLeafType` enum; `ExtractP2MRLeafPubKey()` → `ExtractP2MRLeafInfo()` returning full leaf metadata; per-leaf-type `SignP2MR()` dispatch; PSBT key type numbers assigned (`0x19`-`0x1F` input, `0x08`-`0x09` output) with serialization formats; CSFS multi-party signing workflow (creator → oracle → spender → finalizer). 28 new Phase 4 tests (T-DESC-*, T-SIGN-*, T-PSBT-*, T-INT-*). Verification checklist 6.13 added. Total tests: 136. |
| 7c | **Residual CPU-DoS hardening — P2MR consensus leaf-script size cap (Section 1.5)**: `MAX_P2MR_ELEMENT_SIZE` (Section 1.4) fixed memory amplification but not CPU amplification: with no consensus leaf-script size limit, `OP_DUP OP_SHA256 OP_DROP` loops on 10 KB elements drive worst-case block validation to ~10.4x tapscript baseline (hash opcodes on P2MR's 10 KB elements are ~19x more expensive per invocation than tapscript's 520-byte elements). Fix: `MAX_P2MR_SCRIPT_SIZE` (10,000 bytes) — re-imposes legacy `MAX_SCRIPT_SIZE` that BIP-342 removed for tapscript. Enforced in P2MR dispatch path immediately after `SpanPopBack()` and before `ComputeP2MRLeafHash()`, reusing existing `SCRIPT_ERR_SCRIPT_SIZE`. Reduces worst-case ratio to ~5.2x at consensus (10,000-byte scripts) and ~2.0x at policy (`g_script_size_policy_limit` = 1,650 bytes). Strict 1.2x parity for hash-maximizing workloads would require validation-weight charging for non-sig opcodes (deferred). Design Principle #5 updated. 4 new tests (S-PQ-1..4). Total tests: 140. |
| 7d | **Six execution-readiness fixes**: (1) **Section 1.5 enforcement point moved before `ComputeP2MRLeafHash()`**: oversized scripts now rejected immediately after `SpanPopBack()` (line 2085), before any hashing or copying. (2) **Design Principle #5 internal inconsistency resolved**: split into "signature-dominated blocks ≤ 1.2x" (what validation weight controls) and "hash-dominated blocks ~5.2x at consensus / ~2.0x at policy" (accepted trade-off with documented future mitigation). Appendix C.2 updated with separate sig-dominated and hash-dominated tables. (3) **Phase 4 signing architecture blocker fixed (Section 4.2)**: `SignP2MR()` now accepts `SignatureData&` (mirroring `SignTaproot()`), new `CreateP2MRScriptSig()` helper checks sigdata for existing PQ sigs before falling back to `CreatePQSig()`, `SignatureData` extended with P2MR fields (`p2mr_script_sigs`, `p2mr_csfs_sigs`, `p2mr_csfs_msgs`), `FillSignatureData()`/`FromSignatureData()` extended for bidirectional PSBT↔sigdata flow. (4) **PSBT key format collisions fixed (Section 4.3)**: `PSBT_IN_P2MR_LEAF_SCRIPT` now keyed by `{control_block_bytes}` (matching BIP-371 pattern); `PSBT_IN_P2MR_PQ_SIG` keyed by `{leaf_hash\|\|pubkey}`; CSFS keys include `leaf_hash` disambiguator; `PSBT_IN_P2MR_CONTROL` (0x1A) removed (control block is in leaf_script key). Single-selected-leaf constraint explicitly documented. (5) **`g_script_size_policy_limit` location corrected**: declared in `policy/settings.h` (not `policy/policy.h`); descriptor.cpp must `#include <policy/settings.h>`. (6) **Minor spec cleanups**: 5-key multisig example corrected to "5-of-5 sequential CHECKSIG" (P2MR rejects OP_CHECKMULTISIG at line 1163); ML-DSA performance numbers unified to defer exact ratios to Appendix C benchmarks. 5 new tests (T-SIGN-9..12, T-PSBT-8). Total tests: 144. |
| 6a | **Hardening pass**: (1) Design Principle #5 added: Mining-load neutral — CTV/CSFS must not increase worst-case block validation beyond 1.2x tapscript baseline; no new per-block scanning or data structures. (2) Appendix C rewritten: two-tier benchmark model — Tier 1 CI smoke tests (GitHub-hosted, regression detection, no hard threshold) and Tier 2 release-gating benchmarks (self-hosted reference machine or manual pre-release sign-off). Specific reference hardware documented. New Section C.4 on mining load constraint. (3) Appendix D hardened: explicit `--allow-op-success` per-invocation override for intentional OP_SUCCESS testing; hard-error by default (not warning); L2 catastrophic risk callout added; negative test requirement for L2 script compilers. |
| 6 | **Six completeness additions**: (1) Appendix C: PQ Benchmark Gate — formal release criteria with per-algorithm verification time targets, worst-case block validation thresholds, CI integration requirements, and fail-closed rule. (2) Appendix D: CSFS OP_SUCCESS Range Safety Policy — wallet/compiler ban for P2MR opcodes in tapscript, descriptor validation, CI lint, rationale for not using alternative opcode. (3) Appendix E: L2/Lightning Integration Profile — supported constructions (CTV vaults, payment trees, delegated closes, factory trees), unsupported (eltoo/APO, recursive covenants), fee-bumping/CPFP/package-relay requirements. (4) Appendix F: Mempool Policy Extensibility Roadmap — three-phase graduation from strict templates to resource-bounded acceptance. (5) Appendix G: Operator Guidance for non-standard transactions — miner submission paths, `-maxscriptsize` configuration, propagation impact. (6) Appendix H: ScriptError Compatibility Governance — stability rules, numeric value assignment, downstream consumer guidance. |

---

## 0. Design Principles

| # | Principle | Constraint |
|---|-----------|-----------|
| 1 | **Post-quantum only** | CTV is SHA-256 only (no new crypto). CSFS reuses the existing PQ verification primitives (`CPQPubKey::Verify`, ML-DSA-44 / SLH-DSA-128s) but computes its own tagged hash — it does NOT call `checker.CheckPQSignature()` (see 3.2). No classical ECDSA or Schnorr path for CSFS. |
| 2 | **Minimal bloat** | Leaf script size bounded by `g_script_size_policy_limit` (default 1650). P2MR execution-stack elements and script push values capped at `MAX_P2MR_ELEMENT_SIZE` (10,000 bytes) at consensus (1.4). CSFS message capped at 520 bytes by policy. Witness stack items capped at 5 by policy. CTV adds zero witness overhead (introspection only). |
| 3 | **Hostile-to-DoS** | Every PQ signature verification in P2MR must decrement the validation weight budget using algorithm-specific costs. Validation weight is the sole per-input DoS defense, matching tapscript's model. P2MR sigops counting is deliberately **not added**: validation weight is sufficient and adding sigops introduces extra consensus parsing surface with marginal benefit. |
| 4 | **From genesis** | Both opcodes are consensus-active at height 0 on all networks. No height-gating, no BIP-9 deployment. Static policy flags are safe because consensus and policy agree from block 0. |
| 5 | **Mining-load neutral** | **Signature-dominated blocks**: worst-case P2MR block validation ≤ 1.2x tapscript baseline (Appendix C.2). This is what the validation weight budget controls — CTV adds zero new crypto (single SHA-256, negligible); CSFS reuses `CPQPubKey::Verify()` already executed for P2MR checksig. No new per-block scanning, no additional block data structures, no mining-specific indices. **Hash-dominated blocks** (non-sig opcodes on large P2MR elements): bounded by `MAX_P2MR_SCRIPT_SIZE` (10,000 bytes, Section 1.5) to ~5.2x tapscript at consensus, ~2.0x at policy. This is an inherent consequence of P2MR's larger element sizes (10 KB vs 520 bytes). Achieving strict 1.2x for hash workloads would require validation-weight charging for non-sig opcodes (deferred; see 1.5). |

---

## 1. Prerequisite: P2MR Consensus DoS Hardening

> **Why this comes first**: P2MR today has no `MAX_OPS_PER_SCRIPT`, no script-
> size limit, no sigops accounting for witness v2 spends (`WitnessSigOps()`
> returns 0 for non-v0), and no validation weight budget consumption for PQ
> checks. The budget IS initialized (`interpreter.cpp:2100-2101`) but never
> decremented: `EvalChecksigTapscript()` asserts `sigversion ==
> SigVersion::TAPSCRIPT` (`interpreter.cpp:356`). An attacker can put one PQ
> signature in the witness and use `OP_2DUP <pq_checksig> OP_DROP` thousands
> of times. This is "policy-safe but miner-malicious unsafe." CSFS would
> inherit this same surface. **Fix it first.**

### 1.1 Validation Weight Budget for PQ Signature Checks

**Problem**: `m_validation_weight_left` is initialized for P2MR but never
decremented. Using the tapscript constant `VALIDATION_WEIGHT_PER_SIGOP_PASSED
= 50` (`src/script/script.h:61`) is too permissive for PQ algorithms because
PQ verification is orders of magnitude slower than Schnorr.

Consider the attack: one ML-DSA sig (2420 bytes), a leaf script repeating
`OP_2DUP OP_CHECKSIG_MLDSA OP_DROP` (~4 bytes per iteration), 10,000-byte
script = ~2,500 iterations. Witness = ~12,453 bytes. Budget = 12,503. At
cost=50, that permits ~250 ML-DSA verifications per input. ML-DSA verification
is significantly slower than Schnorr (exact ratio depends on implementation
and hardware — see Appendix C for calibration methodology), so the CPU cost
of this input would be proportionally worse than the equivalent tapscript
input with Schnorr.

**Fix**: Decrement `execdata.m_validation_weight_left` inside the
`OP_CHECKSIG_MLDSA` / `OP_CHECKSIG_SLHDSA` handler (and later the CSFS
handler) on every non-empty signature, using **algorithm-specific** costs.

**File**: `src/script/script.h` (new constants), `src/script/interpreter.cpp`
(inside `case OP_CHECKSIG_MLDSA: case OP_CHECKSIG_SLHDSA:` block, before the
call to `checker.CheckPQSignature(...)`).

**New constants** (`src/script/script.h`):

```cpp
// Validation weight cost per passing ML-DSA-44 signature check.
// Calibrated so worst-case P2MR block validation time is comparable to
// worst-case tapscript block validation time.  Initial value = 10x Schnorr.
// Must be tuned via benchmarking before shipping.
static constexpr int64_t VALIDATION_WEIGHT_PER_MLDSA_SIGOP{500};

// Validation weight cost per passing SLH-DSA-128s signature check.
// SLH-DSA verification is ~50-100x slower than ML-DSA.
// Must be tuned via benchmarking before shipping.
static constexpr int64_t VALIDATION_WEIGHT_PER_SLHDSA_SIGOP{5000};
```

**Change** (in the `OP_CHECKSIG_MLDSA` / `OP_CHECKSIG_SLHDSA` handler,
`interpreter.cpp:1146`, before `checker.CheckPQSignature`):

```cpp
if (!sig.empty()) {
    assert(execdata.m_validation_weight_left_init);
    const int64_t weight_cost = is_mldsa
        ? VALIDATION_WEIGHT_PER_MLDSA_SIGOP
        : VALIDATION_WEIGHT_PER_SLHDSA_SIGOP;
    execdata.m_validation_weight_left -= weight_cost;
    if (execdata.m_validation_weight_left < 0) {
        return set_error(serror, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
    }
}
```

**Worst-case analysis with tuned constants**: Same 12,453-byte witness, budget
= 12,503. At cost=500 per ML-DSA check, that permits ~25 verifications per
input (vs ~250 Schnorr at cost=50 for the same budget). The 10x cost ratio
(500 / 50) is a conservative starting point; the exact ratio must be
determined by benchmarking (see Appendix C). If ML-DSA is 10x slower than
Schnorr, this permits roughly comparable wall-clock cost. At cost=5000 per
SLH-DSA check, a 7856-byte-sig witness (budget ~8000) permits ~1 verification,
which is the intended behavior for the emergency backup algorithm.

**Calibration requirement**: The exact constants must be determined by
benchmarking ML-DSA-44 and SLH-DSA-128s verify times on target hardware,
relative to Schnorr, before shipping. The values above (500, 5000) are
conservative starting points. See **Appendix C** for formal acceptance
thresholds, CI integration, and fail-closed rule.

### 1.2 P2MR Sigops Accounting: Not Added (Design Decision)

`WitnessSigOps()` (`src/script/interpreter.cpp:2236-2250`) returns 0 for all
non-v0 witness versions. P2MR PQ signature checks do not count toward
`MAX_BLOCK_SIGOPS_COST`. This is **unchanged** in this plan.

**Rationale**: Tapscript also has no sigops counting -- it relies entirely on
validation weight. Adding sigops counting for P2MR would be a **stricter model
than tapscript** and introduces additional consensus parsing surface (scanning
leaf scripts for opcode patterns at the `GetTransactionSigOpCost` call site,
which runs for every transaction in both mempool acceptance and block
validation).

With algorithm-specific validation weight costs (Section 1.1), per-input
verification cost is already bounded. The block-level cost is bounded
transitively: each input's PQ verification time is proportional to its witness
weight, and total witness weight is bounded by `MAX_BLOCK_WEIGHT = 24000000`.
This is the same transitive argument that justifies tapscript's lack of sigops
counting.

**No code changes to `WitnessSigOps()` in this plan.**

### 1.3 Summary of Pre-Existing P2MR Limits

| Limit | P2MR Status | Notes |
|-------|-------------|-------|
| `MAX_SCRIPT_SIZE` (10000) | **Not enforced** for tapscript (BIP-342). **Re-imposed for P2MR** via `MAX_P2MR_SCRIPT_SIZE` (1.5). | Tapscript: bounded indirectly by block weight. P2MR: bounded at consensus to 10,000 bytes to limit CPU amplification from hash opcodes on large elements. |
| `MAX_OPS_PER_SCRIPT` (201) | **Not enforced** (same as tapscript) | Replaced by validation weight budget (1.1). |
| `MAX_SCRIPT_ELEMENT_SIZE` (520) | **Not enforced** for pushes (`interpreter.cpp:457`) | PQ pubkeys (1312 bytes for ML-DSA-44) require larger pushes. |
| Leaf script size | Bounded by `g_script_size_policy_limit` (default 1650) at relay (`policy.cpp:537`). No consensus limit. | **Fixed in 1.5**: `MAX_P2MR_SCRIPT_SIZE` (10,000 bytes) enforced at consensus in the P2MR dispatch path. |
| PQ signature size | Checked by `IsPolicyP2MRSignatureSize()` at relay (`policy.cpp:533`). Accepts both ML-DSA (2420/2421 bytes) and SLH-DSA (7856/7857 bytes). | SLH-DSA already relays. |
| Validation weight budget | **Initialized** (`interpreter.cpp:2100`) but not consumed | **Fixed in 1.1**: now consumed per PQ sigop with algorithm-specific costs. |
| Block sigops accounting | **Returns 0** | **Deferred** (1.2): not changed in this plan. Validation weight is the primary defense. Sigops counting may be added later if block-level cap is needed. |
| Witness/push element size | **Not enforced** for P2MR (`interpreter.cpp:457`, `interpreter.cpp:1940-1946`) | **Fixed in 1.4**: `MAX_P2MR_ELEMENT_SIZE` (10,000 bytes) enforced for P2MR execution-stack elements and script push values. |

### 1.4 P2MR Consensus Element Size Cap

**Problem**: P2MR explicitly bypasses the `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes)
limit at two sites:

1. **Script push values** (`interpreter.cpp:457-458`): inside `EvalScript()`,
   checks every data-push opcode's payload size.
   ```cpp
   if (sigversion != SigVersion::P2MR && vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
       return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
   ```

2. **Initial execution stack elements** (`interpreter.cpp:1940-1946`): inside
   `ExecuteWitnessScript()`, loops over the `stack` parameter — which is the
   **execution stack** passed into script evaluation.
   ```cpp
   for (const valtype& elem : stack) {
       if (sigversion != SigVersion::P2MR && elem.size() > MAX_SCRIPT_ELEMENT_SIZE) {
           return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
       }
   }
   ```

> **Important scope clarification**: In the P2MR dispatch path
> (`interpreter.cpp:2084-2102`), the `leaf_script` and `control_block` witness
> items are popped from `stack` via `SpanPopBack()` **before**
> `ExecuteWitnessScript()` is called. The loop at line 1942 therefore only
> sees the **remaining execution-stack elements** (signature, message, etc.),
> not the popped leaf script or control block. The `leaf_script` size is
> already bounded indirectly by `P2MR_CONTROL_MAX_SIZE` (4097 bytes for the
> control block, line 2086) and `g_script_size_policy_limit` (1650 bytes for
> the leaf script, policy layer). The `control_block` is bounded by
> `P2MR_CONTROL_MAX_SIZE` at consensus (line 2086). Neither is affected by
> `MAX_P2MR_ELEMENT_SIZE`.
>
> **What `MAX_P2MR_ELEMENT_SIZE` actually caps**:
> - Site 1: Any data-push operand within the leaf script during execution
>   (e.g., a pubkey literal like `OP_PUSHDATA2 <1312-byte-mldsa-pubkey>`).
> - Site 2: Witness arguments that become the initial execution stack (e.g.,
>   signatures, CSFS messages) — the elements that remain after leaf_script
>   and control_block are popped.

This bypass is necessary: ML-DSA-44 pubkeys are 1312 bytes, ML-DSA-44
signatures are 2420 bytes, and SLH-DSA-128s signatures are 7856 bytes — all
exceed 520 bytes. However, without **any** upper bound, the combination of
large execution-stack elements and stack-copying opcodes (`OP_DUP`, `OP_2DUP`,
`OP_OVER`, `OP_PICK`, etc.) creates a memory amplification vector that the
validation weight model does not cover.

**Attack vector**: A miner constructs a P2MR spend with a single ~10 KB witness
argument (consensus-valid — no size limit) and a leaf script that uses
`OP_DUP` to duplicate it on every iteration. With `MAX_STACK_SIZE = 1000`, the
attacker can hold up to 1000 copies of the element on the stack — ~10 MB of
memory allocated per script evaluation. The validation weight budget only
constrains signature-verification CPU cost; it does not account for memory
allocation from stack-copying non-signature data. This is "validation-weight-
safe but memory-unsafe."

**Fix**: Enforce a consensus maximum element size for P2MR at both bypass sites.

**New constant** (`src/script/script.h`):

```cpp
// Maximum size of a single execution-stack element or push value in P2MR
// scripts.  Sized to accommodate the largest PQ primitive (SLH-DSA-128s
// signature = 7856 bytes) with generous headroom for future algorithms.
// All current PQ elements fit well within this limit:
//   ML-DSA-44 pubkey:  1312 bytes
//   ML-DSA-44 sig:     2420 bytes (+1 hashtype = 2421)
//   SLH-DSA-128s sig:  7856 bytes (+1 hashtype = 7857)
static constexpr unsigned int MAX_P2MR_ELEMENT_SIZE = 10000;
```

**Rationale for 10,000 bytes**: This is ~1.27x the largest current element
(SLH-DSA-128s sig at 7857 bytes with hashtype). It provides headroom for
potential future PQ algorithms while bounding the memory amplification attack.

**Changes** (`src/script/interpreter.cpp`):

Site 1 — script push values (line 457):
```cpp
// Before:
if (sigversion != SigVersion::P2MR && vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
    return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

// After:
if (vchPushValue.size() > (sigversion == SigVersion::P2MR
        ? MAX_P2MR_ELEMENT_SIZE : MAX_SCRIPT_ELEMENT_SIZE))
    return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
```

Site 2 — initial execution stack elements (lines 1940-1946):
```cpp
// Before:
for (const valtype& elem : stack) {
    if (sigversion != SigVersion::P2MR && elem.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
    }
}

// After:
for (const valtype& elem : stack) {
    const size_t max_elem = (sigversion == SigVersion::P2MR)
        ? MAX_P2MR_ELEMENT_SIZE : MAX_SCRIPT_ELEMENT_SIZE;
    if (elem.size() > max_elem) {
        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
    }
}
```

**Worst-case memory analysis**:

*Per-script-evaluation*: 1000 stack entries × 10,000 bytes = ~10 MB.

*Per-process with parallel validation*: `ConnectBlock()`
(`validation.cpp:2702`) uses `CCheckQueue` for parallel script checks. The
default thread pool size is `par_script_checks` (typically equal to the number
of available cores). Each thread evaluates one input's script independently,
with its own stack allocation. Peak process memory from script stacks is
therefore:

```
peak_script_memory ≈ par_threads × 10 MB
```

With a typical 8-core machine: ~80 MB. With a 32-core machine: ~320 MB. This
is well within validator memory budgets (typical Bitcoin Core / BTX validators
use 1–4 GB total). The previous unbounded case allowed `par_threads ×
(MAX_STACK_SIZE × unbounded_element_size)`, which had no theoretical upper
bound.

> **Note**: Each thread's stack memory is freed when the input's script
> evaluation completes, so this is a transient peak, not a sustained
> allocation. In practice, not all parallel inputs will simultaneously hit
> the worst case — the adversarial composition requires all inputs in the
> batch to contain maximum-size elements with maximum stack duplication.

**No impact on existing P2MR transactions**: All current P2MR execution-stack
elements (signatures ≤ 7857 bytes, pubkeys ≤ 1312 bytes) and script push
values (pubkeys ≤ 1312 bytes) fit well within the 10,000-byte limit. The cap
only blocks the construction of artificially large elements for amplification
purposes.

### 1.5 P2MR Consensus Leaf-Script Size Cap

**Problem**: Section 1.4 caps individual element sizes at 10,000 bytes,
eliminating the **memory** amplification vector. However, with no consensus
limit on **leaf-script size** (Section 1.3: `MAX_SCRIPT_SIZE` is not enforced
for P2MR, same as tapscript under BIP-342), a miner can construct P2MR leaf
scripts of arbitrary length containing `OP_DUP OP_SHA256 OP_DROP` loops that
hash 10,000-byte elements on every iteration. The validation weight budget
does not cover non-signature opcodes — it only constrains PQ signature
verification CPU cost. This is "validation-weight-safe but CPU-unsafe" for
hash-intensive workloads on large elements.

**Why tapscript gets away with no script size limit**: Tapscript (BIP-342)
intentionally removed the legacy `MAX_SCRIPT_SIZE` (10,000 bytes) limit. This
is safe because tapscript's `MAX_SCRIPT_ELEMENT_SIZE` is 520 bytes — hash
opcodes process at most 520 bytes per invocation (~9 SHA-256 blocks, ~54 ns
on modern hardware). P2MR's `MAX_P2MR_ELEMENT_SIZE` of 10,000 bytes means
hash opcodes process up to 10,000 bytes per invocation (~157 SHA-256 blocks,
~942 ns) — approximately **19x more CPU per hash operation**.

**Quantitative worst-case analysis** (unbounded script, `MAX_BLOCK_WEIGHT =
24,000,000`):

The worst-case script is `OP_DUP OP_SHA256 OP_DROP` repeated (3 bytes per
iteration). Each iteration hashes the top-of-stack element and replaces it
with a 32-byte digest, then drops the digest, leaving the original element
for the next iteration.

*Tapscript* (520-byte element, unbounded script):
```
per_iteration_cost     = ~94 ns   (SHA-256 of 520B + 3 opcode dispatches)
max_iterations_per_blk ≈ 24M / 3  = 8,000,000  (script dominates weight)
worst_case_block_time  ≈ 8M × 94 ns ≈ 752 ms
```

*P2MR without script size cap* (10,000-byte element, unbounded script):
```
per_iteration_cost     = ~982 ns  (SHA-256 of 10KB + 3 opcode dispatches)
max_iterations_per_blk ≈ 24M / 3  = 8,000,000
worst_case_block_time  ≈ 8M × 982 ns ≈ 7.86 s
```

Ratio: **~10.4x** tapscript baseline — well above the 1.2x target in Design
Principle #5 and Appendix C.2.

**Fix**: Enforce a consensus maximum leaf-script size for P2MR, re-imposing
the legacy `MAX_SCRIPT_SIZE` limit that BIP-342 removed. This is justified
because P2MR's larger element sizes change the risk calculus that motivated
the removal.

**New constant** (`src/script/script.h`):

```cpp
// Maximum leaf-script size for P2MR (witness v2) spends.
// Re-imposes the legacy MAX_SCRIPT_SIZE limit that BIP-342 removed for
// tapscript.  Justified because P2MR's MAX_P2MR_ELEMENT_SIZE (10,000 bytes)
// makes hash opcodes ~19x more expensive per invocation than tapscript's
// 520-byte elements.  Without this cap, unbounded P2MR leaf scripts create
// a CPU amplification vector that the validation-weight model does not cover
// (validation weight only constrains signature-verification cost).
//
// The policy layer already enforces g_script_size_policy_limit (default 1650),
// so this cap only binds miner-constructed (non-relayed) transactions.
// All current standard P2MR leaves (checksig, CTV, CSFS, delegation) are
// well under 1650 bytes.
static constexpr unsigned int MAX_P2MR_SCRIPT_SIZE = 10000;
```

**Rationale for 10,000 bytes**: This matches the legacy `MAX_SCRIPT_SIZE`
value — a well-understood, battle-tested limit from Bitcoin's original script
system. It provides ~6x headroom above the policy limit (1,650 bytes),
allowing future policy relaxation without consensus changes. All current
standard P2MR leaf patterns fit easily:

| Leaf pattern | Typical size | Headroom |
|---|---|---|
| CHECKSIG (ML-DSA-44) | ~1,316 bytes | 8,684 |
| CHECKSIG (SLH-DSA-128s) | ~35 bytes | 9,965 |
| CTV-only | ~34 bytes | 9,966 |
| CTV + CHECKSIG | ~1,351 bytes | 8,649 |
| CSFS + VERIFY + CHECKSIG (delegation) | ~1,351 bytes | 8,649 |
| 5-of-5 ML-DSA threshold (sequential CHECKSIG) | ~6,585 bytes | 3,415 |

> **Note**: P2MR rejects `OP_CHECKMULTISIG` (`interpreter.cpp:1163`). A
> multi-key threshold in P2MR is implemented as sequential
> `<pk> OP_CHECKSIG_MLDSA OP_VERIFY` instructions, not `OP_CHECKMULTISIG`.
> The size estimate above reflects 5 × (3 + 1312 + 1 + 1) = 6,585 bytes
> for five `OP_PUSHDATA2 <1312B> OP_CHECKSIG_MLDSA [OP_VERIFY]` sequences.

**Enforcement point** (`src/script/interpreter.cpp`, P2MR dispatch path,
immediately after `const valtype& script = SpanPopBack(stack);` at line 2085
and **before** `ComputeP2MRLeafHash()` at line 2093):

```cpp
const valtype& control = SpanPopBack(stack);
const valtype& script = SpanPopBack(stack);

// P2MR consensus leaf-script size limit (Section 1.5).
// Check BEFORE hashing or copying the script to avoid spending CPU on
// oversized scripts.  Re-imposes MAX_SCRIPT_SIZE for P2MR to bound CPU
// cost of hash opcodes on large elements (up to MAX_P2MR_ELEMENT_SIZE).
if (script.size() > MAX_P2MR_SCRIPT_SIZE) {
    return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
}

if (control.size() < P2MR_CONTROL_BASE_SIZE || control.size() > P2MR_CONTROL_MAX_SIZE || ...) {
```

> **Why before the leaf hash**: The existing code computes
> `ComputeP2MRLeafHash(control[0] & P2MR_LEAF_MASK, script)` at line 2093
> and then constructs `exec_script = CScript(script.begin(), script.end())`
> at line 2099. Both hash and copy an oversized script, spending CPU and
> memory on data that will be rejected anyway. Placing the size check
> immediately after `SpanPopBack()` rejects oversized scripts with a single
> comparison — zero wasted work.

> **Note**: This reuses the existing `SCRIPT_ERR_SCRIPT_SIZE` error code
> (already defined in `script_error.h` for the legacy `MAX_SCRIPT_SIZE`
> check). No new error code is needed.

**Worst-case analysis with cap** (`MAX_P2MR_SCRIPT_SIZE = 10,000`):

```
iterations_per_input    = 10,000 / 3 ≈ 3,333
cpu_per_input           = 3,333 × 982 ns ≈ 3.27 ms
witness_per_input       ≈ 10,000 (script) + 10,000 (element) + 65 (control)
                        = 20,065 bytes
inputs_per_block        ≈ 24,000,000 / 20,065 ≈ 1,196
worst_case_block_time   ≈ 1,196 × 3.27 ms ≈ 3.91 s
```

Versus tapscript worst case (unbounded script): ~752 ms.
Ratio with cap: **~5.2x** (down from ~10.4x without cap).

This does not achieve strict 1.2x parity with tapscript for hash-maximizing
workloads. Achieving 1.2x would require capping scripts at ~650 bytes — too
small for a single ML-DSA pubkey push (1,315 bytes). The remaining gap is a
consequence of P2MR's larger element sizes, which are inherent to post-quantum
cryptography.

**Effective mitigation at policy level**: For relayed transactions (the
non-miner case), the effective limit is `g_script_size_policy_limit` (1,650
bytes):

```
iterations_per_input    = 1,650 / 3 ≈ 550
cpu_per_input           = 550 × 982 ns ≈ 540 µs
witness_per_input       ≈ 1,650 + 10,000 + 65 = 11,715 bytes
inputs_per_block        ≈ 24,000,000 / 11,715 ≈ 2,049
worst_case_block_time   ≈ 2,049 × 540 µs ≈ 1.11 s
```

Versus tapscript at policy level (also 1,650): ~558 ms.
Ratio at policy: **~2.0x** — comparable to existing inter-version differences
that Bitcoin Core validators already tolerate.

> **Future hardening option**: If the ~5.2x consensus-level ratio is deemed
> unacceptable, the validation-weight model can be extended to charge
> non-signature opcodes (hash opcodes, arithmetic) proportional to the
> operand size. This would allow unlimited script sizes while bounding total
> CPU cost per input, matching tapscript's model. This is a more complex
> change and is deferred to a future revision if benchmarking reveals the
> consensus-level ratio causes problems in practice.

**No impact on existing P2MR transactions**: All current standard P2MR leaf
scripts are under 1,650 bytes (policy limit). The 10,000-byte consensus cap
only blocks the construction of artificially large scripts for CPU
amplification by miners.

---

## 2. CTV: `OP_CHECKTEMPLATEVERIFY`

### 2.1 Opcode Assignment

| Field | Value |
|-------|-------|
| Opcode | `OP_CHECKTEMPLATEVERIFY = 0xb3` (redefines `OP_NOP4`) |
| Script context | P2MR: CTV verify semantics. All other sigversions: NOP (policy-discouraged). |

> **Correction from Revision 3**: Rev 3 assigned CTV to 0xbd. This is wrong:
> 0xbd falls in the `IsOpSuccess` range (`script.cpp:442`: opcodes 187-254 /
> 0xbb-0xfe). In tapscript, `ExecuteWitnessScript` pre-scans for OP_SUCCESS
> (`interpreter.cpp:1918-1933`) and returns immediate success before
> `EvalScript` runs. So 0xbd in a tapscript leaf makes the output trivially
> spendable. Using 0xb3 (OP_NOP4) avoids this entirely:
>
> - 0xb3 is NOT in the OP_SUCCESS range.
> - In tapscript/legacy/v0: OP_NOP4 is a NOP. With
>   `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS` (set in `STANDARD_SCRIPT_
>   VERIFY_FLAGS`), it is policy-rejected but not consensus-invalid.
> - In P2MR with CTV flag set: verify semantics.
> - Matches BIP-119 opcode assignment.
>
> BTX is defining a new covenant opcode that uses the same opcode byte and
> compatible preimage format as BIP-119, but with P2MR-specific execution
> semantics (strict 32-byte requirement, no NOP fallback for non-32-byte
> arguments). This is NOT a soft-fork NOP upgrade; BTX is a hard fork and
> enforces CTV strictly in P2MR from genesis.

**File**: `src/script/script.h` -- rename `OP_NOP4` to `OP_CHECKTEMPLATEVERIFY`
(keep `OP_NOP4 = OP_CHECKTEMPLATEVERIFY` alias for backward compatibility in
non-P2MR contexts).

**Interpreter change** (`src/script/interpreter.cpp:605-611`): Remove `OP_NOP4`
from the NOP case list and add a dedicated CTV handler:

```cpp
// Before (line 605):
case OP_NOP1: case OP_NOP4: case OP_NOP5: ...

// After:
case OP_NOP1: case OP_NOP5: ...  // OP_NOP4 removed

// New dedicated handler (flag-gated, see Section 3.3.1):
case OP_CHECKTEMPLATEVERIFY:
{
    if (!(flags & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY)) {
        // Flag unset: behave as OP_NOP4.
        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
        break;
    }
    if (sigversion == SigVersion::P2MR) {
        // CTV verify semantics (see Section 2.3)
        // ...
        break;
    }
    // Non-P2MR with flag set: still NOP (flag is mandatory,
    // but CTV verify only applies in P2MR).
    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}
break;
```

### 2.2 CTV Template Hash Preimage

The CTV template hash commits to the spending transaction's structure without
committing to input prevouts or witnesses, enabling pre-signed covenant trees.

**Preimage construction** (BIP-119):

```
SHA-256 of the serialization of:
  1. version              (4 bytes, int32_t little-endian)
  2. nLockTime            (4 bytes, uint32_t little-endian)
  3. scriptSigs hash      (32 bytes, SHA-256 of serialized scriptSigs)
     -- only if any scriptSig is non-empty
  4. input count          (4 bytes, uint32_t little-endian)
  5. sequences hash       (32 bytes, SHA-256 of serialized sequences)
  6. output count         (4 bytes, uint32_t little-endian)
  7. outputs hash         (32 bytes, SHA-256 of serialized outputs)
  8. input index          (4 bytes, uint32_t little-endian)

Total: 116 bytes (with scriptSigs hash) or 84 bytes (without)
```

#### 2.2.1 Sub-Hash Serialization Details

Each sub-hash (fields 3, 5, 7) is a single-SHA256 of the concatenation of
serialized per-input or per-output data. The exact serialization format for
each:

**Field 3 — scriptSigs hash** (CTV-specific, not cached by BIP-341):

```
scriptSigs_hash = SHA256( ser(scriptSig_0) || ser(scriptSig_1) || ... )

where ser(scriptSig_i) is Bitcoin's standard script serialization:
  [CompactSize(len)] [scriptSig_bytes]

CScript inherits from prevector and serializes via READWRITE(AsBase<>()),
which writes CompactSize length prefix + raw bytes. Using operator<<:

  HashWriter ss{};
  for (size_t i = 0; i < tx.vin.size(); ++i) {
      ss << tx.vin[i].scriptSig;
  }
  m_ctv_scriptsigs_hash = ss.GetSHA256();
```

The `m_ctv_has_scriptsigs` boolean is true if any `tx.vin[i].scriptSig` is
non-empty. When false, the scriptSigs hash is omitted from the preimage
entirely (84-byte preimage instead of 116-byte).

> **Note**: Using `ss << scriptSig` (with CompactSize prefix) is **correct**
> here, unlike CSFS message hashing (Section 3.2) where raw bytes via
> `write()` are required. CTV's scriptSigs hash follows BIP-119, which uses
> standard Bitcoin serialization. Each scriptSig's length prefix ensures
> unambiguous boundary detection between consecutive entries.

**Field 5 — sequences hash** (reuses BIP-341 `m_sequences_single_hash`):

```
sequences_hash = SHA256( nSequence_0 || nSequence_1 || ... )

Each nSequence is a uint32_t serialized as 4 bytes little-endian.
Implemented identically by GetSequencesSHA256() (interpreter.cpp:1410-1416):

  HashWriter ss{};
  for (const auto& txin : tx.vin) {
      ss << txin.nSequence;
  }
  return ss.GetSHA256();
```

**Field 7 — outputs hash** (reuses BIP-341 `m_outputs_single_hash`):

```
outputs_hash = SHA256( ser(txout_0) || ser(txout_1) || ... )

Each txout serializes as [int64_t nValue][CScript scriptPubKey].
Implemented identically by GetOutputsSHA256() (interpreter.cpp:1421-1426):

  HashWriter ss{};
  for (const auto& txout : tx.vout) {
      ss << txout;
  }
  return ss.GetSHA256();
```

**Caching**: Fields 5 and 7 (sequences hash, outputs hash) are already cached
in `PrecomputedTransactionData` as `m_sequences_single_hash` and
`m_outputs_single_hash` (BIP-341, single-SHA256, same serialization as BIP-119).
These are reused directly — no new fields needed. Field 3 (scriptSigs hash) is
CTV-specific and requires new cache fields. Field 8 (input index) is per-input,
so the final CTV hash must be computed per-input.

**Implementation**: Add `ComputeCTVHash()` in `src/script/ctv.cpp` /
`src/script/ctv.h`.

### 2.3 CTV Opcode Semantics (P2MR)

> **Correction from Revision 3**: Rev 3 used "pop" semantics, which breaks
> cleanstack. `ExecuteWitnessScript` enforces `stack.size() == 1`
> (`interpreter.cpp:1952`). A CTV-only leaf `<hash> OP_CTV` would pop the hash,
> leaving an empty stack, and fail cleanstack. BIP-119-style "no-pop" semantics
> are used instead: the 32-byte hash remains on stack as the truthy cleanstack
> element.

```
OP_CHECKTEMPLATEVERIFY (in P2MR):
  Peek at top stack element (do NOT pop).
  If top element is not exactly 32 bytes: fail with SCRIPT_ERR_CTV_HASH_SIZE.
  Delegate to checker.CheckCTVHash(top_element):
    - GenericTransactionSignatureChecker has txTo, nIn, txdata.
    - It calls ComputeCTVHash(*txTo, nIn, *txdata) and compares.
    - Returns true if top_element == computed hash.
  If checker.CheckCTVHash() returns false: fail with SCRIPT_ERR_CTV_HASH_MISMATCH.
  Otherwise: continue execution. Hash remains on stack.
```

> **Why the checker indirection**: `EvalScript()` receives only a
> `const BaseSignatureChecker& checker`. It has no direct access to `txTo`,
> `nIn`, or `PrecomputedTransactionData`. This is the same pattern used by
> `OP_CHECKLOCKTIMEVERIFY` (`checker.CheckLockTime()`) and
> `OP_CHECKSEQUENCEVERIFY` (`checker.CheckSequence()`). See Section 2.5 for
> the full virtual method specification.

**Non-32-byte arguments**: BIP-119 treats non-32-byte top elements as NOP (for
soft-fork forward compatibility). Since BTX is a hard fork with CTV genesis-
active, we use **strict semantics**: non-32-byte arguments are a consensus
failure. This prevents accidental misuse and simplifies reasoning.

**Validation cost**: CTV is a single SHA-256 computation over 84-116 bytes.
Negligible. No validation weight decrement required.

### 2.4 CTV Implementation Files

| File | Change |
|------|--------|
| `src/script/script.h` | Rename `OP_NOP4` to `OP_CHECKTEMPLATEVERIFY`. Add alias `OP_NOP4 = OP_CHECKTEMPLATEVERIFY`. |
| `src/script/ctv.h` | Declare `ComputeCTVHash()`. |
| `src/script/ctv.cpp` | Implement `ComputeCTVHash()`. |
| `src/CMakeLists.txt` | Add `script/ctv.cpp` to `bitcoin_consensus` source list (after `script/pqm.cpp`, line ~141). |
| `src/script/interpreter.cpp` | Split `OP_NOP4` out of NOP handler. Add **flag-gated** `case OP_CHECKTEMPLATEVERIFY:` (checks `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY`, NOP when unset; P2MR verify semantics when set, see 3.3.1). Implement `GenericTransactionSignatureChecker::CheckCTVHash()`. In `PrecomputedTransactionData::Init()`: add CTV block that computes `m_ctv_scriptsigs_hash`, `m_ctv_has_scriptsigs`, and sets `m_ctv_ready = true` (see 2.5). |
| `src/script/interpreter.h` | Add `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` flag. Add `CheckCTVHash()` virtual to `BaseSignatureChecker`, override in `GenericTransactionSignatureChecker`, forward in `DeferringSignatureChecker`. Add CTV-specific cache fields to `PrecomputedTransactionData` (`m_ctv_ready`, `m_ctv_scriptsigs_hash`, `m_ctv_has_scriptsigs`); sequences/outputs hashes reuse existing BIP-341 fields. |
| `src/script/script.cpp` | Update `GetOpName()` for `OP_CHECKTEMPLATEVERIFY`. |
| `src/script/script_error.h` | Add `SCRIPT_ERR_CTV_HASH_SIZE`, `SCRIPT_ERR_CTV_HASH_MISMATCH`. **Append-only**: insert new values immediately before `SCRIPT_ERR_ERROR_COUNT` (line 90). Do NOT reorder or renumber existing values. |
| `src/script/script_error.cpp` | Add corresponding case strings to `ScriptErrorString()` for each new `SCRIPT_ERR_*` value. |
| `src/policy/policy.h` | Add flag to `MANDATORY_SCRIPT_VERIFY_FLAGS`. |
| `src/policy/policy.cpp` | Add CTV leaf pattern to `ParsePolicyP2MRLeafScript()`. Update stack size check. |
| `src/validation.cpp` | Add flag to `GetBlockScriptFlags()` static set. |
| `src/test/pq_consensus_tests.cpp` | Add `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` to `P2MR_SCRIPT_FLAGS` (or define `P2MR_CTV_SCRIPT_FLAGS`). CTV is flag-gated; tests without the flag will silently get NOP behavior. |
| `src/test/` | Unit tests (see Phase 2 tests). |

### 2.5 CTV Transaction-Context Hook

`EvalScript()` receives only `const BaseSignatureChecker& checker`
(`interpreter.cpp:430`). The CTV handler needs access to the spending
transaction (`txTo`), input index (`nIn`), and precomputed data (`txdata`) to
compute the template hash. This is solved by adding a virtual method to the
signature checker hierarchy, following the same pattern as `CheckLockTime()`
and `CheckSequence()`.

**BaseSignatureChecker** (`src/script/interpreter.h`):

```cpp
virtual bool CheckCTVHash(Span<const unsigned char> hash_from_stack) const
{
    return false;
}
```

**GenericTransactionSignatureChecker** (`src/script/interpreter.h` +
`src/script/interpreter.cpp`):

```cpp
// In class declaration (interpreter.h):
bool CheckCTVHash(Span<const unsigned char> hash_from_stack) const override;

// Implementation (interpreter.cpp):
template <class T>
bool GenericTransactionSignatureChecker<T>::CheckCTVHash(
    Span<const unsigned char> hash_from_stack) const
{
    assert(hash_from_stack.size() == 32);
    // Match CheckPQSignature() pattern: use HandleMissingData instead of
    // raw assert to avoid null-deref crash in release builds.
    if (!this->txdata) return HandleMissingData(m_mdb);
    uint256 computed = ComputeCTVHash(*txTo, nIn, *txdata);
    return std::memcmp(hash_from_stack.data(), computed.data(), 32) == 0;
}
```

> **Safety note**: Using `assert(txdata)` would be a null-deref in release
> builds (assertions compiled out). `HandleMissingData(m_mdb)` follows the
> same pattern as `CheckPQSignature()` (`interpreter.cpp:1816`) and
> `CheckSchnorrSignature()` (`interpreter.cpp:1801`): in consensus mode
> (`MissingDataBehavior::ASSERT_FAIL`) it still asserts, but in non-consensus
> contexts (`MissingDataBehavior::FAIL`) it returns false safely.

**DeferringSignatureChecker** (`src/script/interpreter.h`):

```cpp
bool CheckCTVHash(Span<const unsigned char> hash_from_stack) const override
{
    return m_checker.CheckCTVHash(hash_from_stack);
}
```

**CTV sub-hash caching in PrecomputedTransactionData**
(`src/script/interpreter.h`):

The CTV preimage includes transaction-global sub-hashes (scriptSigs hash,
sequences hash, outputs hash) that are identical across all inputs.

**Reuse existing BIP-341 fields** — do NOT add duplicate hashes:

- `m_sequences_single_hash` (BIP-341, already exists): single-SHA256 of
  serialized `nSequence` values. Identical to the CTV sequences hash — both
  serialize the same data with the same hash function.
- `m_outputs_single_hash` (BIP-341, already exists): single-SHA256 of
  serialized outputs. Identical to the CTV outputs hash.

**New CTV-specific fields only** (for scriptSigs, which BIP-341 does not cache):

```cpp
// In struct PrecomputedTransactionData:
bool m_ctv_ready = false;
uint256 m_ctv_scriptsigs_hash;
bool m_ctv_has_scriptsigs = false;  // true if any scriptSig is non-empty
```

**Initialization**: The new `m_ctv_*` fields are computed inside
`PrecomputedTransactionData::Init()`, NOT lazily on first CTV evaluation.
`Init()` is the only method that mutates `PrecomputedTransactionData`; after
`Init()` returns, the struct is effectively const for the lifetime of
validation. Lazy computation would require either a `mutable` field (hiding
mutation behind a const interface) or passing a non-const reference through
the checker hierarchy, both of which add unnecessary complexity.

Add a CTV block to `Init()`, after the existing BIP-143/BIP-341 blocks:

```cpp
// In PrecomputedTransactionData::Init(), after the BIP-341 block:
{
    bool has_scriptsigs = false;
    HashWriter ss{};
    for (const auto& txin : txTo.vin) {
        ss << txin.scriptSig;
        if (!txin.scriptSig.empty()) has_scriptsigs = true;
    }
    m_ctv_scriptsigs_hash = ss.GetSHA256();
    m_ctv_has_scriptsigs = has_scriptsigs;
    m_ctv_ready = true;
}
```

**Readiness guard in `ComputeCTVHash()`**: The sequences and outputs hashes
(`m_sequences_single_hash`, `m_outputs_single_hash`) are computed inside
`Init()`'s `if (uses_bip143_segwit || uses_bip341_taproot)` block
(`interpreter.cpp:1487-1491`). These fields are initialized for **either**
precompute path, but guarded by separate ready flags:

- `m_bip143_segwit_ready` (`interpreter.cpp:1497`): set when
  `uses_bip143_segwit` is true.
- `m_bip341_taproot_ready` (`interpreter.cpp:1502`): set when BOTH
  `uses_bip341_taproot` AND `m_spent_outputs_ready` are true.

The correct readiness condition for reading `m_sequences_single_hash` and
`m_outputs_single_hash` is therefore **`m_bip143_segwit_ready ||
m_bip341_taproot_ready`** — not `m_bip341_taproot_ready` alone. In
practice, P2MR spends set `uses_bip341_taproot = true` (line 1470: OP_2
triggers the taproot path) and `m_spent_outputs_ready` is always true in
real validation, so `m_bip341_taproot_ready` will be set. But tying the
guard to a single flag is fragile (e.g., test harnesses that call
`Init(txTo, {})` without spent outputs would not set
`m_bip341_taproot_ready` even though the shared hashes were computed via
the segwit path).

```cpp
uint256 ComputeCTVHash(const CTransaction& tx, uint32_t nIn,
                       const PrecomputedTransactionData& txdata)
{
    // sequences/outputs hashes are valid if either precompute path ran.
    assert(txdata.m_bip143_segwit_ready || txdata.m_bip341_taproot_ready);
    assert(txdata.m_ctv_ready);  // scriptSigs hash valid
    // ... serialize preimage using txdata fields ...
}
```

In the `CheckCTVHash()` caller, the `HandleMissingData(m_mdb)` null-check
on `txdata` (Section 2.5 above) provides the first line of defense. The
asserts inside `ComputeCTVHash()` provide the second.

> **Why this is safe**: BIP-341 `m_sequences_single_hash` is defined as
> `SHA256(ser(nSequence_0 || nSequence_1 || ...))` — single SHA-256 of the
> concatenated little-endian uint32_t sequence values. BIP-119 CTV uses the
> identical construction. Same for outputs. Adding duplicate fields would
> increase the consensus-risk surface (two fields that must always agree) with
> no benefit.

---

## 3. CSFS: `OP_CHECKSIGFROMSTACK`

### 3.1 Opcode Assignment

| Field | Value |
|-------|-------|
| Opcode | `OP_CHECKSIGFROMSTACK = 0xbd` |
| Script context | P2MR only (`SigVersion::P2MR`) |
| Signature algorithms | ML-DSA-44 and SLH-DSA-128s only (PQ-only) |

0xbd is in the `IsOpSuccess` range (0xbb-0xfe). This means:
- In tapscript: OP_SUCCESS (anyone-can-spend, policy-discouraged via
  `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS`). Same behavior as OP_CHECKSIG_MLDSA
  (0xbb) and OP_CHECKSIG_SLHDSA (0xbc) in tapscript.
- In P2MR: no OP_SUCCESS pre-scan occurs (`ExecuteWitnessScript` only scans
  for OP_SUCCESS when `sigversion == SigVersion::TAPSCRIPT`,
  `interpreter.cpp:1918`). The opcode reaches `EvalScript` and is handled by
  the dedicated `case OP_CHECKSIGFROMSTACK:` handler.
- In legacy/v0: hits `default:` case -> `SCRIPT_ERR_BAD_OPCODE`.

This matches the existing convention for P2MR-only opcodes.

**File**: `src/script/script.h`, after `OP_CHECKSIG_SLHDSA`.

### 3.2 CSFS Opcode Semantics

```
OP_CHECKSIGFROMSTACK (P2MR only):
  Stack: <sig> <msg> <pubkey> (top)
  If stack.size() < 3: fail with SCRIPT_ERR_INVALID_STACK_OPERATION.
  Pop pubkey.
  Pop msg (arbitrary data, max 520 bytes by policy, no consensus limit).
  Pop sig (PQ signature).
  Algorithm detection by pubkey size:
    - 1312 bytes -> ML-DSA-44  (algo = PQAlgorithm::ML_DSA_44)
    - 32 bytes   -> SLH-DSA-128s (algo = PQAlgorithm::SLH_DSA_128S)
    - Other      -> SCRIPT_ERR_PQ_PUBKEY_SIZE
  Compute hash = TaggedHash("CSFS/btx", msg).
  Verify: CPQPubKey{algo, pubkey}.Verify(hash, sig).
  Push OP_TRUE on success, OP_FALSE on failure.
  If NULLFAIL flag set and sig is non-empty and verification fails:
    fail with SCRIPT_ERR_SIG_MLDSA or SCRIPT_ERR_SIG_SLHDSA.
```

> **CSFS must NOT call `checker.CheckPQSignature()`**.
> `GenericTransactionSignatureChecker::CheckPQSignature()`
> (`interpreter.cpp:1810-1824`) always computes a transaction sighash via
> `SignatureHashSchnorr()`. CSFS is verifying a signature over an arbitrary
> stack message, not a transaction. The correct call path is:
>
> ```cpp
> // CORRECT: CSFS computes its own tagged hash, then verifies directly.
> HashWriter hasher = HASHER_CSFS;
> hasher.write(MakeByteSpan(msg));
> uint256 hash = hasher.GetSHA256();
> const CPQPubKey pq_pubkey{algo, pubkey};
> bool success = pq_pubkey.Verify(hash, sig);
>
> // WRONG: checker.CheckPQSignature() computes a transaction sighash
> // via SignatureHashSchnorr(), which is the wrong hash for CSFS.
> // bool success = checker.CheckPQSignature(sig, pubkey, algo, ...);
> ```
>
> `CPQPubKey` is declared in `src/pqkey.h` (line 59). Its `Verify(hash, sig)`
> method (`pqkey.cpp`) takes a `uint256` hash and a signature span, and
> delegates to the algorithm-specific verification function (ML-DSA-44 or
> SLH-DSA-128s). This is the same `Verify` call that
> `CheckPQSignature()` uses internally (line 1823), but CSFS provides
> the CSFS-tagged hash instead of the transaction sighash.

**Key design choices**:

1. **Algorithm detection by pubkey size** (not by separate opcode): Keeps the
   opcode count minimal. ML-DSA-44 pubkeys are 1312 bytes; SLH-DSA-128s pubkeys
   are 32 bytes. These sizes are unambiguous.

2. **Domain-separated tagged hash**: CSFS verifies `sig` over
   `TaggedHash("CSFS/btx", msg)`, NOT plain `SHA-256(msg)`.

   > **Correction from Revision 3**: Rev 3 used plain `SHA-256(msg)`, losing
   > the domain separation that Rev 2 had. The existing PQ checksig path uses
   > `SignatureHashSchnorr()` which produces a tagged sighash via
   > `HASHER_TAPSIGHASH`. Without domain separation, a CSFS message hash could
   > theoretically collide with a transaction sighash (attacker would need a
   > preimage, but defense-in-depth says eliminate the possibility). BTX already
   > has `TaggedHash` infrastructure (`pqm.cpp:13-16`). Using
   > `TaggedHash("CSFS/btx")` ensures CSFS message hashes are in a separate
   > domain from transaction sighashes, P2MR leaf hashes, and all other tagged
   > hashes in the system.

   **Critical implementation detail**: The message bytes must be hashed raw,
   NOT serialized as a `std::vector`. `HashWriter::operator<<` calls
   `::Serialize()`, which prepends a CompactSize length prefix to vectors.
   This would produce the wrong hash. Use the raw `write()` method:

   ```cpp
   // CORRECT: raw bytes, no length prefix
   HashWriter hasher{TaggedHash("CSFS/btx")};
   hasher.write(MakeByteSpan(msg));
   uint256 hash = hasher.GetSHA256();

   // WRONG: operator<< serializes std::vector with CompactSize prefix
   // HashWriter hasher{TaggedHash("CSFS/btx")};
   // hasher << msg;  // BUG: hashes [varint_len][msg_bytes], not [msg_bytes]
   ```

   A static `HASHER_CSFS` can be pre-initialized (like `HASHER_TAPSIGHASH`)
   to avoid recomputing the tag hash on every invocation:

   ```cpp
   const HashWriter HASHER_CSFS{TaggedHash("CSFS/btx")};
   // Per invocation:
   HashWriter hasher = HASHER_CSFS;  // copy pre-initialized midstate
   hasher.write(MakeByteSpan(msg));
   uint256 hash = hasher.GetSHA256();
   ```

3. **No sighash flags**: CSFS is not signing a transaction. The `msg` is an
   opaque blob from the stack. Sighash type handling does not apply. CSFS
   signatures are **exact algorithm size** (2420 bytes for ML-DSA-44, 7856 bytes
   for SLH-DSA-128s) with no appended hashtype byte. This differs from
   `OP_CHECKSIG_MLDSA`/`OP_CHECKSIG_SLHDSA` which allow a +1 hashtype suffix.

#### 3.2.1 CSFS Consensus Signature-Size Behavior

This section makes the consensus-level signature size enforcement for CSFS
explicit, removing any ambiguity for implementers.

**Rule**: If a CSFS signature is non-empty and not the exact algorithm size,
the handler **hard-fails** with a script error — it does NOT treat the
signature as "verify = false" (which would allow the spend to continue with
OP_FALSE on the stack).

This matches the existing `OP_CHECKSIG_MLDSA` / `OP_CHECKSIG_SLHDSA` behavior
(`interpreter.cpp:1135-1144`), where a non-empty signature of incorrect size
returns `set_error(serror, sig_err)` — a hard script failure, not a soft
"push false."

**Exact semantics** (for CSFS handler in `interpreter.cpp`):

```cpp
// After popping sig, msg, pubkey from stack:
// algo is determined by pubkey size (1312 → ML-DSA, 32 → SLH-DSA).
const size_t expected_sig_size = is_mldsa ? MLDSA44_SIGNATURE_SIZE
                                          : SLHDSA128S_SIGNATURE_SIZE;
const ScriptError sig_err = is_mldsa ? SCRIPT_ERR_SIG_MLDSA
                                     : SCRIPT_ERR_SIG_SLHDSA;

// CSFS: no hashtype byte. Exact size only.
if (!sig.empty() && sig.size() != expected_sig_size) {
    return set_error(serror, sig_err);  // HARD FAIL — not "push false"
}

// Empty sig: push OP_FALSE, no verification, no weight decrement.
// Correctly-sized sig: verify and push result.
bool success = false;
if (!sig.empty()) {
    // ... compute tagged hash, verify, decrement weight ...
}
```

**Comparison with CHECKSIG**:

| Behavior | CHECKSIG (`OP_CHECKSIG_MLDSA`/`SLHDSA`) | CSFS (`OP_CHECKSIGFROMSTACK`) |
|----------|------------------------------------------|-------------------------------|
| Empty sig | Push OP_FALSE (no verify) | Push OP_FALSE (no verify) |
| Exact algo size | Verify, push result | Verify, push result |
| Exact algo size + 1 byte | Parse hashtype, verify | **Hard fail** (`SCRIPT_ERR_SIG_*`) — no hashtype in CSFS |
| Any other non-empty size | Hard fail (`SCRIPT_ERR_SIG_*`) | Hard fail (`SCRIPT_ERR_SIG_*`) |
| NULLFAIL: non-empty, verify fails | Hard fail (`SCRIPT_ERR_SIG_*`) | Hard fail (`SCRIPT_ERR_SIG_*`) |

**Rationale**: Hard-fail for incorrect sizes (rather than soft "push false")
provides early error detection and prevents accidental acceptance of malformed
signatures. This is defense-in-depth: a CSFS signature with an appended byte
is always a bug (CSFS has no hashtype concept), and hard-failing makes the
bug immediately visible rather than silently continuing with a false result.

### 3.3 Activation and Interpreter Gating

Both CTV and CSFS are consensus-active from height 0 on all networks (mainnet,
testnet, regtest). No `nCSFSActivationHeight` or `nCTVActivationHeight`.

**Implementation**:

1. Add `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY = (1U << 21)` and
   `SCRIPT_VERIFY_CHECKSIGFROMSTACK = (1U << 22)` to the flag enum in
   `src/script/interpreter.h`, **before** `SCRIPT_VERIFY_END_MARKER`.

   `SCRIPT_VERIFY_END_MARKER` (`interpreter.h:149`) is an implicit enum
   sentinel — it has no assigned value, so it equals the last explicit value
   plus one. It is used by tests and fuzzing
   (`txvalidationcache_tests.cpp:137`: `insecure_rand.randrange(
   (SCRIPT_VERIFY_END_MARKER - 1) << 1)`) to generate random flag
   combinations up to the highest defined bit. If new flags are added
   **after** END_MARKER (or END_MARKER is not bumped), tests will never
   exercise the new flag combinations.

   **Required ordering** in the enum:
   ```cpp
   SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = (1U << 20),

   // CTV / CSFS (P2MR, genesis-active)
   SCRIPT_VERIFY_CHECKTEMPLATEVERIFY = (1U << 21),
   SCRIPT_VERIFY_CHECKSIGFROMSTACK = (1U << 22),

   // Constants to point to the highest flag in use. Add new flags above this line.
   //
   SCRIPT_VERIFY_END_MARKER
   ```

   After this change, `SCRIPT_VERIFY_END_MARKER` implicitly becomes
   `(1U << 22) + 1 = 0x400001`. The `randrange((END_MARKER - 1) << 1)`
   expression in tests will generate flags up to bit 22, covering the new
   flags.

2. Add both to `MANDATORY_SCRIPT_VERIFY_FLAGS` in `src/policy/policy.h`.

3. Add both to the static flags in `GetBlockScriptFlags()`
   (`src/validation.cpp:2661`):
   ```cpp
   uint32_t flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
                  SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_CHECKTEMPLATEVERIFY |
                  SCRIPT_VERIFY_CHECKSIGFROMSTACK};
   ```

This ensures the activation flag consistency invariant holds (see Appendix B).

#### 3.3.1 Interpreter Gating: Flag-Check vs Sigversion-Check

The interpreter must decide how each new opcode behaves when its flag is unset
or when it appears in a non-P2MR context. The two existing patterns are:

- **Flag-gated NOP upgrade** (`OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY`):
  `if (!(flags & FLAG)) break;` — falls through as NOP when flag unset.
  Required because CLTV/CSV redefine NOP opcodes and must be inert in
  contexts that don't set the flag.

- **Sigversion-gated** (`OP_CHECKSIG_MLDSA`, `OP_CHECKSIG_SLHDSA`):
  `if (sigversion != SigVersion::P2MR) return set_error(serror, SCRIPT_ERR_BAD_OPCODE);`
  — no flag check. P2MR-only opcodes that have no NOP fallback.

**Decision for CTV**: **Flag-gated** (like CLTV/CSV). CTV redefines `OP_NOP4`
(0xb3), which is a NOP in legacy/v0/tapscript. The flag check provides the
NOP→verify transition:

```cpp
case OP_CHECKTEMPLATEVERIFY:
{
    if (!(flags & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY)) {
        // Flag unset: behave as OP_NOP4.
        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
        break;
    }
    // Flag set: verify semantics (P2MR or non-P2MR)
    if (sigversion == SigVersion::P2MR) {
        // CTV verify (Section 2.3)
        // ...
        break;
    }
    // Non-P2MR with flag set: still NOP (flag is always set via MANDATORY,
    // but no verify semantics outside P2MR).
    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}
break;
```

In practice, `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` is always set (MANDATORY), so
the flag check never falls through on the consensus path. But the flag must
exist for test harnesses that call `VerifyScript()` with custom flag sets.

**Decision for CSFS**: **Sigversion-gated** (like OP_CHECKSIG_MLDSA). CSFS
uses opcode 0xbd, which is in the `IsOpSuccess` range. It has no NOP fallback:

```cpp
case OP_CHECKSIGFROMSTACK:
{
    if (sigversion != SigVersion::P2MR)
        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
    // CSFS verify semantics (Section 3.2)
    // ...
}
break;
```

`SCRIPT_VERIFY_CHECKSIGFROMSTACK` exists for flag consistency (in MANDATORY and
`GetBlockScriptFlags()`), but the interpreter does **not** check it. This
matches the existing P2MR PQ checksig opcodes, which also don't check a flag.

> **Summary**:
> | Opcode | Gating | Why |
> |--------|--------|-----|
> | CTV (0xb3) | Flag-gated | Redefines OP_NOP4. Needs NOP fallback when flag unset. |
> | CSFS (0xbd) | Sigversion-gated | OP_SUCCESS range opcode. No NOP fallback. |

#### 3.3.2 Test Flag Implications

`P2MR_SCRIPT_FLAGS` in `src/test/pq_consensus_tests.cpp` (line 25) currently
includes `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_NULLFAIL`.
CTV tests using this flag set must add `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY`,
otherwise the flag check will fall through to NOP behavior:

```cpp
// For CTV tests:
constexpr unsigned int P2MR_CTV_SCRIPT_FLAGS =
    P2MR_SCRIPT_FLAGS | SCRIPT_VERIFY_CHECKTEMPLATEVERIFY;
```

CSFS tests do **not** need `SCRIPT_VERIFY_CHECKSIGFROMSTACK` in the flag set
(sigversion-gated, no flag check), but including it is harmless and
recommended for consistency:

```cpp
// For CSFS tests (flag is harmless but consistent):
constexpr unsigned int P2MR_CSFS_SCRIPT_FLAGS =
    P2MR_SCRIPT_FLAGS | SCRIPT_VERIFY_CHECKSIGFROMSTACK;
```

### 3.4 CSFS Validation Weight

CSFS performs the same class of PQ signature verification as
`OP_CHECKSIG_MLDSA` / `OP_CHECKSIG_SLHDSA`. It must **decrement
`m_validation_weight_left`** per non-empty signature check, using the same
algorithm-specific constants from Section 1.1:

- ML-DSA-44 pubkey detected: decrement by `VALIDATION_WEIGHT_PER_MLDSA_SIGOP`
- SLH-DSA-128s pubkey detected: decrement by `VALIDATION_WEIGHT_PER_SLHDSA_SIGOP`

If P2MR sigops counting is added in the future (Section 1.2), CSFS would also
need to be included in the opcode scan.

### 3.5 CSFS Policy Limits

| Limit | Value | Enforcement Location | Rationale |
|-------|-------|---------------------|-----------|
| Max message size | 520 bytes | `policy.cpp`, in `IsWitnessStandard()` P2MR block | Prevents relay of bloated messages. 520 = `MAX_SCRIPT_ELEMENT_SIZE`. Consensus does not limit. |
| Max witness stack items | 5 | `policy.cpp`, in `IsWitnessStandard()` P2MR block | CSFS needs 3 items (sig, msg) on execution stack + leaf script + control block = 4. Combined CTV+CSFS or multi-arg scripts may need 5. |
| Leaf script size | `g_script_size_policy_limit` (default 1650) | Already enforced (`policy.cpp:537`) | No change needed. |
| PQ signature size (CHECKSIG) | Accepted via `IsPolicyP2MRSignatureSize()` | Already enforced (`policy.cpp:533`) | ML-DSA (2420/2421) and SLH-DSA (7856/7857) both accepted. The +1 variant includes the hashtype byte. No change needed for CHECKSIG. |
| PQ signature size (CSFS) | **Exact size only** (no hashtype byte) | New check in `IsWitnessStandard()` P2MR block | CSFS: ML-DSA exactly 2420, SLH-DSA exactly 7856. The +1 hashtype byte is CHECKSIG-specific; CSFS has no sighash concept (see 3.2). |

> **Correction from Revision 3**: Rev 3 claimed a "1650-byte policy witness-
> item cap" that blocks SLH-DSA relay. This is factually wrong:
>
> - `DEFAULT_SCRIPT_SIZE_POLICY_LIMIT = 1650` (`policy.h:60`) controls **leaf
>   script** size (`policy.cpp:537`) and non-P2MR total witness serialized size
>   (`policy.cpp:441`, which explicitly skips P2MR: `if (!is_p2mr && ...)`).
> - P2MR signature size is checked by `IsPolicyP2MRSignatureSize()`
>   (`policy.cpp:104-112`), which explicitly accepts SLH-DSA signatures of
>   7856 or 7857 bytes.
> - There is **no per-witness-item 1650-byte cap** for P2MR.
> - SLH-DSA-128s transactions **already relay** under current P2MR policy.

### 3.6 CSFS Implementation Files

| File | Change |
|------|--------|
| `src/script/script.h` | Add `OP_CHECKSIGFROMSTACK = 0xbd`. Update `MAX_OPCODE`. |
| `src/script/interpreter.h` | Add `SCRIPT_VERIFY_CHECKSIGFROMSTACK` flag. |
| `src/policy/policy.h` | Add flag to `MANDATORY_SCRIPT_VERIFY_FLAGS`. |
| `src/validation.cpp` | Add flag to `GetBlockScriptFlags()` static set. |
| `src/script/interpreter.cpp` | Add **sigversion-gated** `case OP_CHECKSIGFROMSTACK:` in `EvalScript()` (checks `sigversion == P2MR`, no flag check, matching OP_CHECKSIG_MLDSA pattern; see 3.3.1). Compute hash via `HASHER_CSFS{TaggedHash("CSFS/btx")}` + `hasher.write(MakeByteSpan(msg))` (raw bytes, no length prefix). Verify via `CPQPubKey{algo, pubkey}.Verify(hash, sig)` — NOT `checker.CheckPQSignature()`. Wire validation weight decrement with algorithm-specific costs. |
| `src/script/script.cpp` | Add `OP_CHECKSIGFROMSTACK` to `GetOpName()`. |
| `src/policy/policy.cpp` | Add `IsPolicyCSFSSignatureSize()` (exact size, no hashtype byte). Add CSFS sig size check to `IsWitnessStandard()` P2MR block. |
| `src/script/script_error.h` | Add CSFS-specific error codes if needed (e.g., `SCRIPT_ERR_CSFS_PUBKEY_SIZE`). **Append-only**: insert immediately before `SCRIPT_ERR_ERROR_COUNT`. |
| `src/script/script_error.cpp` | Add corresponding case strings to `ScriptErrorString()` for each new CSFS `SCRIPT_ERR_*` value. |
| `src/test/` | Unit tests (see Phase 3 tests). |

---

## 4. P2MR Policy Template Matcher Updates

> **New section in Revision 4**: Rev 3 omitted this entirely. Without these
> changes, CTV and CSFS transactions are consensus-valid but will never relay
> through the mempool.

### 4.1 Current State

`IsWitnessStandard()` (`policy.cpp:505-541`) enforces for P2MR:
- `stack.size() == 3` (line 511): exactly `[sig, leaf_script, control_block]`
- `ParsePolicyP2MRLeafScript()` (line 529): only accepts two leaf patterns:
  - `OP_PUSHDATA2 <1312-byte-pubkey> OP_CHECKSIG_MLDSA`
  - `<32-byte-pubkey> OP_CHECKSIG_SLHDSA`
- `IsPolicyP2MRSignatureSize()` (line 533): checks signature size

### 4.2 Required Changes

#### 4.2.1 Witness Stack Size

Change `stack.size() != 3` to accept 2-5 items:

```cpp
// Before:
if (stack.size() != 3) {
    out_reason = reason_prefix + "p2mr-stack-size";
    return false;
}

// After:
if (stack.size() < 2 || stack.size() > 5) {
    out_reason = reason_prefix + "p2mr-stack-size";
    return false;
}
```

Stack size breakdown:
- **2**: CTV-only spend `[leaf_script, control_block]` (no witness args)
- **3**: Existing checksig spend `[sig, leaf_script, control_block]`
- **4**: CSFS spend `[sig, msg, leaf_script, control_block]`
- **5**: Combined or multi-witness-arg scripts

#### 4.2.2 Leaf Script Pattern Matcher

Extend `ParsePolicyP2MRLeafScript()` to accept new patterns. Change its
signature to return a leaf type enum:

```cpp
enum class P2MRLeafType {
    CHECKSIG_MLDSA,              // <pubkey> OP_CHECKSIG_MLDSA
    CHECKSIG_SLHDSA,             // <pubkey> OP_CHECKSIG_SLHDSA
    CTV_ONLY,                    // <32-byte-hash> OP_CHECKTEMPLATEVERIFY
    CTV_CHECKSIG_MLDSA,          // <hash> OP_CTV OP_DROP <pubkey> OP_CHECKSIG_MLDSA
    CTV_CHECKSIG_SLHDSA,         // <hash> OP_CTV OP_DROP <pubkey> OP_CHECKSIG_SLHDSA
    CSFS_MLDSA,                  // <pubkey_csfs> OP_CHECKSIGFROMSTACK
    CSFS_SLHDSA,                 // <pubkey_csfs> OP_CHECKSIGFROMSTACK
    CSFS_VERIFY_CHECKSIG_MLDSA,  // <pubkey_csfs> OP_CHECKSIGFROMSTACK OP_VERIFY
                                 //   <pubkey_checksig> OP_CHECKSIG_MLDSA
                                 // Standard when leaf ≤ 1650 bytes.
                                 // SLH-DSA oracle (32B) + ML-DSA spender (1312B) = 1351B ✓
                                 // ML-DSA oracle (1312B) + ML-DSA spender (1312B) = 2633B ✗ (non-standard)
    CSFS_VERIFY_CHECKSIG_SLHDSA, // <pubkey_csfs> OP_CHECKSIGFROMSTACK OP_VERIFY
                                 //   <pubkey_checksig> OP_CHECKSIG_SLHDSA
                                 // Standard when leaf ≤ 1650 bytes.
                                 // SLH-DSA oracle (32B) + SLH-DSA spender (32B) = 70B ✓
                                 // ML-DSA oracle (1312B) + SLH-DSA spender (32B) = 1351B ✓
    UNKNOWN
};

P2MRLeafType ParsePolicyP2MRLeafScript(Span<const unsigned char> leaf_script);
```

The `CSFS_VERIFY_CHECKSIG_*` patterns cover the **delegation/oracle** use case:
an oracle signs an arbitrary message via CSFS (e.g., a price attestation or
delegation token), and a separate on-chain PQ key authorizes the spend. Both
signatures are verified in the same leaf. This is the primary motivating
pattern for the 5-item witness.

For each leaf type, the policy matcher knows the expected witness layout:
- `CTV_ONLY`: stack.size() == 2 (no witness args needed)
- `CHECKSIG_*`: stack.size() == 3 (sig only)
- `CSFS_*`: stack.size() == 4 (sig_csfs + msg)
- `CTV_CHECKSIG_*`: stack.size() == 3 (sig only; CTV hash is in script)
- `CSFS_VERIFY_CHECKSIG_*`: stack.size() == 5 (sig_checksig + sig_csfs + msg)

#### 4.2.3 CSFS Message Size Check

For leaf types containing CSFS, validate the message witness item. The message
position depends on the leaf type:

```cpp
// Determine message index based on leaf type.
// CSFS-only: witness = [sig_csfs, msg, leaf_script, control_block]
//   -> msg at index 1
// CSFS_VERIFY_CHECKSIG: witness = [sig_checksig, sig_csfs, msg, leaf_script, control_block]
//   -> msg at index 2
int msg_idx = -1;
if (leaf_type == P2MRLeafType::CSFS_MLDSA || leaf_type == P2MRLeafType::CSFS_SLHDSA) {
    msg_idx = 1;
} else if (leaf_type == P2MRLeafType::CSFS_VERIFY_CHECKSIG_MLDSA ||
           leaf_type == P2MRLeafType::CSFS_VERIFY_CHECKSIG_SLHDSA) {
    msg_idx = 2;
}
if (msg_idx >= 0) {
    const std::vector<unsigned char>& msg = stack[msg_idx];
    if (msg.size() > MAX_SCRIPT_ELEMENT_SIZE) {  // 520 bytes
        out_reason = reason_prefix + "p2mr-csfs-msg-size";
        return false;
    }
}
```

#### 4.2.4 Signature Size Check

Update the signature size check to handle the variable position and count of
signature items based on leaf type. **Critical**: CHECKSIG and CSFS have
different size requirements because CSFS has no hashtype byte.

- `CHECKSIG_*`, `CTV_CHECKSIG_*`: one sig at `stack[0]`, checked via
  `IsPolicyP2MRSignatureSize()` (allows exact size or +1 for hashtype).
- `CSFS_*`: one sig at `stack[0]`, checked via **`IsPolicyCSFSSignatureSize()`**
  (exact algorithm size only, no +1).
- `CSFS_VERIFY_CHECKSIG_*`: two sigs -- `stack[0]` is the checksig sig
  (uses `IsPolicyP2MRSignatureSize()`, allows +1), `stack[1]` is the CSFS sig
  (uses `IsPolicyCSFSSignatureSize()`, exact size only). The algorithm for each
  is determined by the corresponding pubkey in the leaf script (the leaf
  contains two pubkeys; the parser extracts both).
- `CTV_ONLY`: no signature (skip check)

**New function** (`src/policy/policy.cpp`):

```cpp
bool IsPolicyCSFSSignatureSize(Span<const unsigned char> signature, bool is_mldsa)
{
    // CSFS signatures have no hashtype byte -- exact algorithm size only.
    const size_t expected_sig_size = is_mldsa ? MLDSA44_SIGNATURE_SIZE
                                              : SLHDSA128S_SIGNATURE_SIZE;
    return signature.size() == expected_sig_size;
}
```

The existing `IsPolicyP2MRSignatureSize()` is unchanged; it continues to accept
`expected_sig_size + 1` for the hashtype byte appended to CHECKSIG signatures.

---

## 5. Implementation Phases

### Phase 1: P2MR DoS Hardening (Prerequisite)

1. Define algorithm-specific validation weight constants in `script.h` (1.1).
2. Add validation weight decrement to `OP_CHECKSIG_MLDSA` / `OP_CHECKSIG_SLHDSA`
   handler (1.1).
3. Benchmark ML-DSA-44 and SLH-DSA-128s verify times to calibrate constants.
4. Define `MAX_P2MR_ELEMENT_SIZE` (10,000 bytes) in `script.h` (1.4).
5. Enforce `MAX_P2MR_ELEMENT_SIZE` at both P2MR element-size bypass sites:
   script push values (`interpreter.cpp:457`) and witness stack elements
   (`interpreter.cpp:1940-1946`) (1.4).
6. Add regression tests:
   - Script that exhausts validation weight budget with repeated PQ checksig
     (both ML-DSA and SLH-DSA).
   - `OP_2DUP OP_CHECKSIG_MLDSA OP_DROP` attack vector is bounded by
     algorithm-specific weight cost.
   - Worst-case P2MR block validation time is comparable to worst-case
     tapscript block (validates calibration).
   - P2MR execution-stack element (witness arg) > `MAX_P2MR_ELEMENT_SIZE` is
     rejected at consensus with `SCRIPT_ERR_PUSH_SIZE` (Site 2: line 1942).
   - P2MR script push value > `MAX_P2MR_ELEMENT_SIZE` in leaf script is
     rejected (Site 1: line 457).
   - All existing PQ execution-stack elements (ML-DSA sig/pubkey, SLH-DSA
     sig/pubkey) fit within `MAX_P2MR_ELEMENT_SIZE` (no regression).
7. Update `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT` name/message if desired
   (currently tapscript-specific wording, now shared with P2MR).
8. Define `MAX_P2MR_SCRIPT_SIZE` (10,000 bytes) in `script.h` (1.5).
9. Enforce `MAX_P2MR_SCRIPT_SIZE` in the P2MR dispatch path
   (`interpreter.cpp`), immediately after `SpanPopBack()` and before
   `ComputeP2MRLeafHash()`. Use existing `SCRIPT_ERR_SCRIPT_SIZE` (1.5).
10. Add regression tests for leaf-script size cap:
    - Leaf script > 10,000 bytes is consensus-rejected with
      `SCRIPT_ERR_SCRIPT_SIZE`.
    - Leaf script == 10,000 bytes is accepted.
    - All standard P2MR leaf patterns (checksig, CTV, CSFS, delegation) are
      well under the cap (no regression).
    - Hash-opcode CPU amplification (`OP_DUP OP_SHA256 OP_DROP` loop) is
      bounded by the script size cap.

### Phase 2: CTV

1. Rename `OP_NOP4` to `OP_CHECKTEMPLATEVERIFY` in `script.h` (2.1).
2. Add `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` flag, wire into MANDATORY and
   `GetBlockScriptFlags()` (3.3).
3. Add `CheckCTVHash()` virtual to `BaseSignatureChecker`, implement in
   `GenericTransactionSignatureChecker`, forward in
   `DeferringSignatureChecker` (2.5).
4. Add CTV-specific cache fields (`m_ctv_scriptsigs_hash`,
   `m_ctv_has_scriptsigs`, `m_ctv_ready`) to `PrecomputedTransactionData`.
   Compute them in `Init()` (not lazily). Reuse existing
   `m_sequences_single_hash` and `m_outputs_single_hash` from BIP-341 (2.5).
5. Add `script/ctv.cpp` to `bitcoin_consensus` source list in
   `src/CMakeLists.txt`.
6. Implement `ComputeCTVHash()` with correct 116/84-byte preimage (2.2).
7. Split `OP_NOP4` out of NOP handler, add CTV case with **flag-gated**
   handler: check `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` flag first (NOP
   fallback when unset), then sigversion for P2MR verify semantics (3.3.1).
8. Add CTV leaf patterns to `ParsePolicyP2MRLeafScript()` (4.2.2).
9. Update stack size check to accept 2-5 items (4.2.1).
10. Add `"CHECKTEMPLATEVERIFY"` to `mapFlagNames` in
    `src/test/transaction_tests.cpp` (see 5.5).
11. Add CTV opcode aliases to Python test framework
    `test/functional/test_framework/script.py` (see 5.5).
12. Update `P2MR_SCRIPT_FLAGS` in `pq_consensus_tests.cpp` to include
    `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` for CTV tests (3.3.2).
13. Add tests (see Section 9 for full test matrix):

   **CTV Consensus (unit tests, `src/test/`):**
   - C-CTV-1: Preimage byte-count: no scriptSigs → 84 bytes exactly.
   - C-CTV-2: Preimage byte-count: non-empty scriptSig → 116 bytes exactly.
   - C-CTV-3: Round-trip happy path: construct CTV-locked P2MR output, spend
     with matching transaction. Script succeeds, hash remains on stack.
   - C-CTV-4: Rejection: spend with non-matching transaction (different
     outputs). Fails with `SCRIPT_ERR_CTV_HASH_MISMATCH`.
   - C-CTV-5: Rejection: spend with non-matching transaction (different
     nLockTime). Fails with `SCRIPT_ERR_CTV_HASH_MISMATCH`.
   - C-CTV-6: Rejection: spend with non-matching transaction (different
     input index). Fails with `SCRIPT_ERR_CTV_HASH_MISMATCH`.
   - C-CTV-7: Cleanstack: `<hash> OP_CTV` leaf, stack.size() == 1 post-exec.
   - C-CTV-8: Non-32-byte argument (20 bytes) → `SCRIPT_ERR_CTV_HASH_SIZE`.
   - C-CTV-9: Non-32-byte argument (33 bytes) → `SCRIPT_ERR_CTV_HASH_SIZE`.
   - C-CTV-10: Non-32-byte argument (0 bytes/empty) → `SCRIPT_ERR_CTV_HASH_SIZE`.
   - C-CTV-11: Empty stack → `SCRIPT_ERR_INVALID_STACK_OPERATION`.
   - C-CTV-12: Multiple inputs: CTV hash at input index 0 differs from
     input index 1 (input index is part of preimage).
   - C-CTV-13: Flag-gating: CTV with `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY`
     unset → NOP behavior (value remains on stack, script succeeds).
   - C-CTV-14: Flag-gating: CTV with flag unset + DISCOURAGE_UPGRADABLE_NOPS
     → `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS`.
   - C-CTV-15: Flag-gating: CTV with flag set in non-P2MR context → NOP
     (flag is set via MANDATORY, but no verify semantics outside P2MR).
   - C-CTV-16: HandleMissingData: CheckCTVHash() with txdata=null in
     `MissingDataBehavior::FAIL` mode → returns false safely.
   - C-CTV-17: CTV sub-hash equivalence: `m_sequences_single_hash` matches
     hand-computed SHA256 of serialized nSequence values.
   - C-CTV-18: CTV sub-hash equivalence: `m_outputs_single_hash` matches
     hand-computed SHA256 of serialized outputs.
   - C-CTV-19: CTV scriptSigs hash: `m_ctv_scriptsigs_hash` matches
     hand-computed SHA256 of CompactSize-prefixed scriptSig concatenation.
   - C-CTV-20: Init() sets m_ctv_ready = true after completion.
   - C-CTV-21: CTV combined leaf: `<hash> OP_CTV OP_DROP <pubkey>
     OP_CHECKSIG_MLDSA` — both CTV and checksig pass in same script.

   **CTV Policy (unit tests, `src/test/`):**
   - P-CTV-1: CTV-only leaf (stack.size()==2) relays through mempool.
   - P-CTV-2: CTV combined leaf (stack.size()==3) relays through mempool.
   - P-CTV-3: ParsePolicyP2MRLeafScript() recognizes CTV_ONLY pattern.
   - P-CTV-4: ParsePolicyP2MRLeafScript() recognizes CTV_CHECKSIG_MLDSA.
   - P-CTV-5: ParsePolicyP2MRLeafScript() recognizes CTV_CHECKSIG_SLHDSA.

   **CTV Functional (Python, `test/functional/`):**
   - F-CTV-1: End-to-end: create CTV-locked UTXO, spend with correct tx,
     confirm in block.
   - F-CTV-2: End-to-end: attempt spend with wrong tx, verify rejection.
   - F-CTV-3: Mempool acceptance: CTV transaction relays between nodes.

### Phase 3: CSFS

1. Add `OP_CHECKSIGFROMSTACK = 0xbd` to `script.h`, update `MAX_OPCODE` (3.1).
2. Add `SCRIPT_VERIFY_CHECKSIGFROMSTACK` flag, wire into MANDATORY and
   `GetBlockScriptFlags()` (3.3).
3. Implement `OP_CHECKSIGFROMSTACK` handler using pre-initialized
   `HASHER_CSFS{TaggedHash("CSFS/btx")}` with `hasher.write(MakeByteSpan(msg))`
   for raw-bytes message hashing -- NOT `hasher << msg` (3.2). Enforce consensus
   signature-size hard-fail for non-empty sigs of incorrect size — no +1
   hashtype byte, unlike CHECKSIG (3.2.1).
4. Wire validation weight decrement with algorithm-specific costs (3.4).
5. Add CSFS leaf patterns (including `CSFS_VERIFY_CHECKSIG_*` delegation
   pattern) to `ParsePolicyP2MRLeafScript()` (4.2.2).
6. Add `IsPolicyCSFSSignatureSize()` to `policy.cpp`: exact algorithm size
   only, no +1 hashtype byte (4.2.4).
7. Add CSFS message size check to policy (4.2.3).
8. Add `"CHECKSIGFROMSTACK"` to `mapFlagNames` in
   `src/test/transaction_tests.cpp` (see 5.5).
9. Add CSFS opcode to Python test framework
   `test/functional/test_framework/script.py` (see 5.5).
10. Add tests (see Section 9 for full test matrix):

   **CSFS Consensus (unit tests, `src/test/`):**
   - C-CSFS-1: ML-DSA-44 happy path: sign message, push sig/msg/pubkey,
     CSFS succeeds, pushes OP_TRUE.
   - C-CSFS-2: SLH-DSA-128s happy path: same as C-CSFS-1 with SLH-DSA key.
   - C-CSFS-3: Wrong signature (corrupted): CSFS pushes OP_FALSE (no NULLFAIL
     with empty sig convention).
   - C-CSFS-4: Empty signature: CSFS pushes OP_FALSE (defined behavior,
     no verification attempted, no weight decrement).
   - C-CSFS-5: NULLFAIL: non-empty sig that fails verification + NULLFAIL
     flag → `SCRIPT_ERR_SIG_MLDSA` (or `_SLHDSA`).
   - C-CSFS-6: Stack underflow: stack.size() < 3 →
     `SCRIPT_ERR_INVALID_STACK_OPERATION`.
   - C-CSFS-7: Stack underflow: stack.size() == 2 (missing msg) →
     `SCRIPT_ERR_INVALID_STACK_OPERATION`.
   - C-CSFS-8: Pubkey size detection: 1312-byte pubkey → ML-DSA-44.
   - C-CSFS-9: Pubkey size detection: 32-byte pubkey → SLH-DSA-128s.
   - C-CSFS-10: Pubkey size rejection: 33-byte pubkey (not 32 or 1312) →
     `SCRIPT_ERR_PQ_PUBKEY_SIZE`.
   - C-CSFS-11: Pubkey size rejection: 0-byte pubkey → same error.
   - C-CSFS-12: Pubkey size rejection: 1311-byte pubkey → same error.
   - C-CSFS-13: Cross-algorithm: ML-DSA sig + SLH-DSA pubkey → verification
     fails (algorithm mismatch detected by pubkey size).
   - C-CSFS-14: TaggedHash domain separation: same message bytes produce
     different hash via `TaggedHash("CSFS/btx", msg)` vs plain `SHA256(msg)`
     vs `SignatureHashSchnorr(...)`.
   - C-CSFS-15: Raw-bytes hashing correctness: verify that
     `HASHER_CSFS.write(MakeByteSpan(msg))` and `HASHER_CSFS << msg`
     produce **different** hashes for non-empty messages (catches the
     CompactSize length prefix bug).
   - C-CSFS-16: Verification path: CSFS must NOT call
     `checker.CheckPQSignature()`. Construct a scenario where the tx sighash
     would match (contrived) but the CSFS tagged hash does not — verify CSFS
     correctly rejects (proves it uses TaggedHash, not sighash).
   - C-CSFS-17: Sigversion gating: CSFS in legacy context →
     `SCRIPT_ERR_BAD_OPCODE`.
   - C-CSFS-18: Sigversion gating: CSFS in witness v0 →
     `SCRIPT_ERR_BAD_OPCODE`.
   - C-CSFS-19: Tapscript context: 0xbd is OP_SUCCESS (script succeeds
     immediately regardless of stack).
   - C-CSFS-20: Tapscript + DISCOURAGE_OP_SUCCESS: policy-rejected.
   - C-CSFS-21: Message boundary: 520-byte message (max policy) succeeds.
   - C-CSFS-22: Message boundary: 0-byte message succeeds (empty message
     is valid, hashed as TaggedHash("CSFS/btx", "")).
   - C-CSFS-23: Message boundary: 521-byte message succeeds at consensus
     (no consensus limit on msg size).

   **CSFS Validation Weight (unit tests, `src/test/`):**
   - W-CSFS-1: Single ML-DSA CSFS decrements weight by 500.
   - W-CSFS-2: Single SLH-DSA CSFS decrements weight by 5000.
   - W-CSFS-3: Empty-sig CSFS does NOT decrement weight (no verification).
   - W-CSFS-4: Weight exhaustion: repeated CSFS in single script exceeds
     budget → `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT`.
   - W-CSFS-5: Weight budget boundary: exactly-at-limit CSFS succeeds;
     one-over-limit fails.
   - W-CSFS-6: Existing P2MR checksig weight decrement (prerequisite):
     OP_CHECKSIG_MLDSA decrements by 500, OP_CHECKSIG_SLHDSA by 5000.

   **CSFS Delegation/Oracle (unit tests, `src/test/`):**
   - D-CSFS-1: Standard delegation: SLH-DSA oracle (32B pubkey) + ML-DSA
     spender (1312B pubkey), 5-item witness. Both sigs valid → success.
   - D-CSFS-2: Standard delegation: oracle sig invalid → script fails after
     OP_VERIFY (CSFS pushes false, VERIFY aborts).
   - D-CSFS-3: Standard delegation: spender sig invalid → OP_CHECKSIG_MLDSA
     pushes false, cleanstack fails.
   - D-CSFS-4: Standard delegation leaf size: verify ≤ 1650 bytes.
   - D-CSFS-5: Two-ML-DSA delegation: leaf ~2633 bytes. Consensus-valid
     (test via direct VerifyScript, not mempool).

   **CSFS Policy (unit tests, `src/test/`):**
   - P-CSFS-1: CSFS-only leaf (stack.size()==4) relays through mempool.
   - P-CSFS-2: Delegation leaf (stack.size()==5) relays through mempool.
   - P-CSFS-3: Oversized message (> 520 bytes) rejected by policy (not by
     consensus).
   - P-CSFS-4: Exact-size sig: 2420-byte ML-DSA sig accepted by policy.
   - P-CSFS-5: Sig with hashtype byte: 2421-byte rejected by
     `IsPolicyCSFSSignatureSize()`.
   - P-CSFS-6: ParsePolicyP2MRLeafScript() recognizes CSFS_ONLY pattern.
   - P-CSFS-7: ParsePolicyP2MRLeafScript() recognizes
     CSFS_VERIFY_CHECKSIG_MLDSA pattern.
   - P-CSFS-8: ParsePolicyP2MRLeafScript() recognizes
     CSFS_VERIFY_CHECKSIG_SLHDSA pattern.
   - P-CSFS-9: Two-ML-DSA delegation leaf (~2633 bytes) rejected by policy
     (exceeds `g_script_size_policy_limit`).
   - P-CSFS-10: Stack.size()==6 rejected by policy.
   - P-CSFS-11: Stack.size()==1 rejected by policy (too few items).

   **CSFS Functional (Python, `test/functional/`):**
   - F-CSFS-1: End-to-end: create CSFS-locked UTXO, spend with valid
     sig/msg, confirm in block.
   - F-CSFS-2: End-to-end: delegation/oracle flow with SLH-DSA oracle +
     ML-DSA spender, confirm in block.
   - F-CSFS-3: Mempool acceptance: CSFS transaction relays between nodes.
   - F-CSFS-4: Mempool rejection: oversized message (> 520 bytes) does not
     relay.

### Phase 4: Integration and Tooling

> **Note**: Phase 4 is post-consensus — it requires no consensus or policy
> changes. The items below are tooling/wallet-level. They are gated on
> Phases 1-3 being complete but are fully specified here so that continuous
> development can begin immediately after consensus code lands.

#### 4.0 Current `mr()` Descriptor and Signer (Pre-CTV/CSFS)

**Descriptor grammar** (`descriptor.cpp:2170-2350`): The existing `mr()`
descriptor builds **CHECKSIG-style P2MR leaves only** via
`BuildP2MRScript()` (`pqm.cpp:74`):

```
mr(<mldsa_hex_or_xpub> [, pk_slh(<slhdsa_hex_or_xpub>)]
   [, {<backup_tree>}])
```

Each leaf is `<pubkey> OP_CHECKSIG_MLDSA` or `<pubkey> OP_CHECKSIG_SLHDSA`.
The `MRLeafSpec` struct (`descriptor.cpp`) stores `{PQAlgorithm algo,
int provider_index, std::vector<unsigned char> fixed_pubkey}` — it has no
concept of CTV hashes, CSFS oracle keys, or non-CHECKSIG leaf scripts.

**Signer** (`sign.cpp:423-471`): `SignP2MR()` iterates P2MR spend data and
delegates to `ExtractP2MRLeafPubKey()` (lines 423-442), which only recognizes
two leaf script formats:

```cpp
// ML-DSA: [OP_PUSHDATA2] [2-byte LE size] [1312-byte pubkey] [OP_CHECKSIG_MLDSA]
// SLH-DSA: [1-byte push size] [32-byte pubkey] [OP_CHECKSIG_SLHDSA]
```

It then calls `creator.CreatePQSig()` (lines 96-119) which computes a
sighash via `SignatureHashSchnorr()` and signs with the PQ key. The returned
witness is always `[sig, leaf_script, control_block]`.

**PSBT**: No P2MR-specific PSBT key types exist. The highest allocated
taproot input key is `PSBT_IN_TAP_MERKLE_ROOT = 0x18` (`psbt.h:52`).
P2MR keys start at `0x19`.

**What must change**: The descriptor must express new leaf types. The signer
must recognize new leaf scripts and produce the correct witness layout.
The PSBT must carry CSFS-specific data for multi-party signing.

#### 4.1 `mr()` Descriptor Grammar Extensions

New leaf expressions within `mr()`:

| Expression | Leaf Script Produced | Example |
|------------|---------------------|---------|
| `ctv(<32B-hash-hex>)` | `<hash> OP_CHECKTEMPLATEVERIFY` | `mr(<key>, ctv(abcd...ef))` |
| `ctv_pk(<32B-hash-hex>, <key>)` | `<hash> OP_CTV OP_DROP <pubkey> OP_CHECKSIG_MLDSA` | `mr(ctv_pk(abcd..ef, <xpub>))` |
| `ctv_pk(<32B-hash-hex>, pk_slh(<key>))` | `<hash> OP_CTV OP_DROP <pubkey> OP_CHECKSIG_SLHDSA` | `mr(ctv_pk(abcd..ef, pk_slh(<xpub>)))` |
| `csfs(<key>)` | `<pubkey> OP_CHECKSIGFROMSTACK` | `mr(<key>, csfs(<mldsa-hex>))` |
| `csfs(pk_slh(<key>))` | `<pubkey> OP_CHECKSIGFROMSTACK` | `mr(<key>, csfs(pk_slh(<slh-hex>)))` |
| `csfs_pk(pk_slh(<oracle>), <spender>)` | `<oracle-pk> OP_CSFS OP_VERIFY <spender-pk> OP_CHECKSIG_MLDSA` | `mr(csfs_pk(pk_slh(<oracle>), <xpub>))` |
| `csfs_pk(<oracle>, pk_slh(<spender>))` | `<oracle-pk> OP_CSFS OP_VERIFY <spender-pk> OP_CHECKSIG_SLHDSA` | `mr(csfs_pk(<mldsa>, pk_slh(<xpub>)))` |

Leaf expressions compose with the existing `mr()` backup-tree syntax:

```
mr(<primary_key>, {ctv(abcd...ef), csfs_pk(pk_slh(<oracle>), <spender>)})
```

This produces a P2MR output with three leaves: a CHECKSIG primary, a CTV
branch, and a delegation branch, arranged in the Merkle tree.

**`MRLeafSpec` extension** (`descriptor.cpp`):

```cpp
enum class MRLeafType {
    CHECKSIG,           // existing: <pubkey> OP_CHECKSIG_{MLDSA,SLHDSA}
    CTV_ONLY,           // <32-byte-hash> OP_CHECKTEMPLATEVERIFY
    CTV_CHECKSIG,       // <hash> OP_CTV OP_DROP <pubkey> OP_CHECKSIG_{MLDSA,SLHDSA}
    CSFS_ONLY,          // <pubkey> OP_CHECKSIGFROMSTACK
    CSFS_VERIFY_CHECKSIG, // <oracle-pk> OP_CSFS OP_VERIFY <spender-pk> OP_CHECKSIG_{algo}
};

struct MRLeafSpec {
    MRLeafType type = MRLeafType::CHECKSIG;
    PQAlgorithm algo;           // algorithm for the primary (CHECKSIG) key
    int provider_index = -1;    // xpub provider index for primary key
    std::vector<unsigned char> fixed_pubkey;  // raw hex pubkey if not xpub

    // CTV-specific fields (used when type == CTV_ONLY or CTV_CHECKSIG):
    uint256 ctv_hash;           // the 32-byte template hash

    // CSFS-specific fields (used when type == CSFS_ONLY or CSFS_VERIFY_CHECKSIG):
    PQAlgorithm csfs_algo;      // algorithm for the CSFS/oracle key
    int csfs_provider_index = -1;
    std::vector<unsigned char> csfs_fixed_pubkey;
};
```

**Leaf script construction**: Replace the single `BuildP2MRScript()` call
with a dispatch on `MRLeafSpec::type`:

```cpp
std::vector<unsigned char> BuildP2MRLeafScript(const MRLeafSpec& spec,
    Span<const unsigned char> primary_pubkey,
    Span<const unsigned char> csfs_pubkey /* empty if N/A */)
{
    switch (spec.type) {
    case MRLeafType::CHECKSIG:
        return BuildP2MRScript(spec.algo, primary_pubkey);  // existing
    case MRLeafType::CTV_ONLY:
        // <hash> OP_CHECKTEMPLATEVERIFY
        return BuildP2MRCTVScript(spec.ctv_hash);
    case MRLeafType::CTV_CHECKSIG:
        // <hash> OP_CTV OP_DROP <pubkey> OP_CHECKSIG_{algo}
        return BuildP2MRCTVChecksigScript(spec.ctv_hash, spec.algo, primary_pubkey);
    case MRLeafType::CSFS_ONLY:
        // <pubkey> OP_CHECKSIGFROMSTACK
        return BuildP2MRCSFSScript(spec.csfs_algo, csfs_pubkey);
    case MRLeafType::CSFS_VERIFY_CHECKSIG:
        // <oracle-pk> OP_CSFS OP_VERIFY <spender-pk> OP_CHECKSIG_{algo}
        return BuildP2MRDelegationScript(spec.csfs_algo, csfs_pubkey,
                                          spec.algo, primary_pubkey);
    }
}
```

**Parser changes** (`descriptor.cpp`): Extend the leaf-parsing lambdas
(`parse_primary_leaf`, `parse_backup_leaf`) to recognize `ctv(...)`,
`ctv_pk(...)`, `csfs(...)`, `csfs_pk(...)` as `Func()` calls. Each
populates the appropriate `MRLeafSpec` fields. Validation:
- `ctv()` argument must be exactly 64 hex chars (32 bytes).
- `ctv_pk()` first arg is 64 hex chars, second is a key expression.
- `csfs()` and `csfs_pk()` key arguments follow existing `pk_slh()` /
  xpub parsing rules.
- Leaf script size must be ≤ `g_script_size_policy_limit` (1650) — reject
  at descriptor parse time if the constructed leaf exceeds it.
  **Note**: `g_script_size_policy_limit` is declared in `policy/settings.h`
  (not `policy/policy.h`). `descriptor.cpp` must `#include <policy/settings.h>`
  to access this runtime-configurable limit.

#### 4.2 Signer Extensions

##### 4.2.0 Architectural Gap in Current `SignP2MR()`

The current `SignP2MR()` (`sign.cpp:444-471`) has three deficiencies that
prevent PSBT-based multi-party signing:

1. **No `SignatureData&` parameter**: Unlike `SignTaproot()` (`sign.cpp:361`)
   which takes `SignatureData& sigdata` and stores/retrieves partial
   signatures from it, `SignP2MR()` only takes `provider`, `creator`,
   `output`, and `result`. There is no way to feed pre-existing PSBT
   signatures into the signing path.

2. **Always creates fresh signatures**: `SignP2MR()` always calls
   `creator.CreatePQSig()` directly. A finalizer that has no keys (only
   PSBT fields) cannot assemble a witness — the call will fail because no
   key is available.

3. **No CSFS material handling**: CSFS signatures and messages must come from
   external sources (oracle via PSBT). The current signer has no fields to
   carry this data.

The PSBT signing flow is:
```
SignPSBTInput() → PSBTInput::FillSignatureData() → ProduceSignature()
  → SignStep() → SignP2MR()
```

`ProduceSignature()` already passes `SignatureData& sigdata` through
`SignStep()`. The fix is to thread `sigdata` into `SignP2MR()` and add
P2MR-specific fields to `SignatureData`.

##### 4.2.1 `SignatureData` Extensions (`sign.h`)

Add P2MR-specific fields to `SignatureData` (mirroring the taproot fields):

```cpp
struct SignatureData {
    // ... existing fields ...

    // P2MR spend data (populated from PSBT or provider).
    P2MRSpendData p2mr_spenddata;

    // P2MR CHECKSIG signatures, indexed by (leaf_hash, pubkey_bytes).
    // Analogous to taproot_script_sigs for Taproot.
    std::map<std::pair<uint256, std::vector<unsigned char>>,
             std::vector<unsigned char>> p2mr_script_sigs;

    // CSFS signatures, indexed by (leaf_hash, csfs_pubkey_bytes).
    std::map<std::pair<uint256, std::vector<unsigned char>>,
             std::vector<unsigned char>> p2mr_csfs_sigs;

    // CSFS messages, indexed by (leaf_hash, csfs_pubkey_bytes).
    std::map<std::pair<uint256, std::vector<unsigned char>>,
             std::vector<unsigned char>> p2mr_csfs_msgs;

    // Selected leaf script and control block for finalization.
    std::vector<unsigned char> p2mr_leaf_script;
    std::vector<unsigned char> p2mr_control_block;
};
```

##### 4.2.2 `CreateP2MRScriptSig()` Helper (`sign.cpp`)

Add a helper analogous to `CreateTaprootScriptSig()` (`sign.cpp:182`) that
checks `sigdata` for an existing PQ signature before falling back to
`creator.CreatePQSig()`:

```cpp
static bool CreateP2MRScriptSig(
    const BaseSignatureCreator& creator,
    SignatureData& sigdata,
    const SigningProvider& provider,
    std::vector<unsigned char>& sig_out,
    Span<const unsigned char> pubkey,
    PQAlgorithm algo,
    const uint256& leaf_hash,
    SigVersion sigversion)
{
    // First, check if a signature already exists in sigdata (from PSBT).
    auto key = std::make_pair(leaf_hash,
        std::vector<unsigned char>(pubkey.begin(), pubkey.end()));
    auto it = sigdata.p2mr_script_sigs.find(key);
    if (it != sigdata.p2mr_script_sigs.end()) {
        sig_out = it->second;
        return true;
    }
    // Fall back to creating a fresh signature.
    if (creator.CreatePQSig(provider, sig_out, pubkey, algo,
                             leaf_hash, sigversion)) {
        sigdata.p2mr_script_sigs[key] = sig_out;
        return true;
    }
    return false;
}
```

##### 4.2.3 `SignP2MR()` Signature Change

Change `SignP2MR()` to accept `SignatureData& sigdata` (mirroring
`SignTaproot()`):

```cpp
// Before:
static bool SignP2MR(const SigningProvider& provider,
    const BaseSignatureCreator& creator,
    const WitnessV2P2MR& output, std::vector<valtype>& result);

// After:
static bool SignP2MR(const SigningProvider& provider,
    const BaseSignatureCreator& creator,
    const WitnessV2P2MR& output,
    SignatureData& sigdata,
    std::vector<valtype>& result);
```

Update the call site in `SignStep()` (`sign.cpp:555` equivalent for P2MR)
to pass `sigdata` through.

##### 4.2.4 `ExtractP2MRLeafInfo()` (`sign.cpp`)

Replace `ExtractP2MRLeafPubKey()` with a broader function:

```cpp
struct P2MRLeafInfo {
    P2MRLeafType type;
    PQAlgorithm algo;                     // CHECKSIG algorithm (if present)
    Span<const unsigned char> pubkey;      // CHECKSIG pubkey (if present)
    PQAlgorithm csfs_algo;                // CSFS algorithm (if present)
    Span<const unsigned char> csfs_pubkey; // CSFS pubkey (if present)
    uint256 ctv_hash;                      // CTV hash (if present)
};

static bool ExtractP2MRLeafInfo(Span<const unsigned char> script, P2MRLeafInfo& info);
```

This mirrors the `ParsePolicyP2MRLeafScript()` pattern from Section 4.2.2
(policy), recognizing all leaf types in the `P2MRLeafType` enum.

##### 4.2.5 Per-Leaf-Type `SignP2MR()` Dispatch

| Leaf Type | Signing Action | Witness Layout |
|-----------|---------------|----------------|
| `CHECKSIG` | `CreateP2MRScriptSig()` (checks sigdata first, then `CreatePQSig()`) | `[sig, leaf_script, control_block]` |
| `CTV_ONLY` | No signature needed | `[leaf_script, control_block]` |
| `CTV_CHECKSIG` | `CreateP2MRScriptSig()` for the CHECKSIG key | `[sig, leaf_script, control_block]` |
| `CSFS_ONLY` | Look up CSFS sig + msg from `sigdata.p2mr_csfs_sigs` / `sigdata.p2mr_csfs_msgs` | `[sig_csfs, msg, leaf_script, control_block]` |
| `CSFS_VERIFY_CHECKSIG` | CSFS sig + msg from sigdata; CHECKSIG sig via `CreateP2MRScriptSig()` | `[sig_checksig, sig_csfs, msg, leaf_script, control_block]` |

**Key insight**: `CreatePQSig()` computes a transaction sighash via
`SignatureHashSchnorr()`. This is correct for CHECKSIG leaves. It is **not**
applicable to the CSFS portion (which signs a `TaggedHash("CSFS/btx", msg)`,
not a transaction sighash). CSFS signatures must be injected via PSBT →
`FillSignatureData()` → `sigdata.p2mr_csfs_sigs`.

**CTV_ONLY witness**: No signature needed — verify the spending transaction
matches the CTV hash (fail fast in wallet), then return:

```cpp
case P2MRLeafType::CTV_ONLY:
    result = Vector(
        std::vector<unsigned char>(script.begin(), script.end()),
        *controls.begin());
    return true;
```

##### 4.2.6 `PSBTInput::FillSignatureData()` / `FromSignatureData()` Extensions

**`FillSignatureData()`** (`psbt.cpp`): Populate `SignatureData` P2MR fields
from PSBT input fields:

```cpp
// In PSBTInput::FillSignatureData():
sigdata.p2mr_leaf_script = m_p2mr_leaf_script;
sigdata.p2mr_control_block = m_p2mr_control_block;
for (const auto& [key, sig] : m_p2mr_pq_sigs) {
    sigdata.p2mr_script_sigs[key] = sig;
}
for (const auto& [key, sig] : m_p2mr_csfs_sigs) {
    sigdata.p2mr_csfs_sigs[key] = sig;
}
for (const auto& [key, msg] : m_p2mr_csfs_msgs) {
    sigdata.p2mr_csfs_msgs[key] = msg;
}
```

**`FromSignatureData()`** (`psbt.cpp`): Move newly-created signatures back
into PSBT fields after signing:

```cpp
// In PSBTInput::FromSignatureData():
for (const auto& [key, sig] : sigdata.p2mr_script_sigs) {
    m_p2mr_pq_sigs[key] = sig;
}
// CSFS sigs/msgs written back similarly.
```

This bidirectional flow (PSBT → sigdata → signer → sigdata → PSBT) is
the same pattern used for Taproot (`taproot_script_sigs`).

#### 4.3 PSBT Extensions for P2MR

**New PSBT input key types** (`psbt.h`): Starting at `0x19` (next after
`PSBT_IN_TAP_MERKLE_ROOT = 0x18`).

```cpp
// P2MR-specific PSBT input types (0x1A reserved for future use)
static constexpr uint8_t PSBT_IN_P2MR_LEAF_SCRIPT         = 0x19;
static constexpr uint8_t PSBT_IN_P2MR_PQ_SIG              = 0x1B;
static constexpr uint8_t PSBT_IN_P2MR_BIP32_DERIVATION    = 0x1C;
static constexpr uint8_t PSBT_IN_P2MR_MERKLE_ROOT         = 0x1D;
static constexpr uint8_t PSBT_IN_CSFS_MESSAGE              = 0x1E;
static constexpr uint8_t PSBT_IN_CSFS_SIGNATURE            = 0x1F;
```

> **Change from Rev 7b**: `PSBT_IN_P2MR_CONTROL` (0x1A) is removed. The
> control block is now embedded in the key data of `PSBT_IN_P2MR_LEAF_SCRIPT`
> (keyed by `{control_block_bytes}`, matching BIP-371's
> `PSBT_IN_TAP_LEAF_SCRIPT` pattern). See key format table below.

**New PSBT output key types** (`psbt.h`):

```cpp
// P2MR-specific PSBT output types
static constexpr uint8_t PSBT_OUT_P2MR_TREE        = 0x08;
static constexpr uint8_t PSBT_OUT_P2MR_BIP32_DERIVATION = 0x09;
```

**Design constraint — single selected leaf per PSBT input**: Unlike BIP-371
(Taproot PSBT) which supports carrying the full script tree and multiple
candidate leaves per input, P2MR PSBTs carry **exactly one selected leaf
script and one control block per input**. This simplification is acceptable
because:

1. P2MR leaf selection is deterministic in the common case (the wallet knows
   which leaf to spend).
2. Multi-party workflows (CSFS delegation) require the creator to select
   the target leaf before passing the PSBT to the oracle.
3. Carrying the full tree is unnecessary complexity for Phase 4 — it can be
   added in a future revision if general "tree-carrying PSBT" behavior is
   needed.

**Enforcement mechanics**: Because `PSBT_IN_P2MR_LEAF_SCRIPT` is keyed by
`{control_block_bytes}` (matching BIP-371's `PSBT_IN_TAP_LEAF_SCRIPT`
pattern), the map type naturally allows multiple entries — one per distinct
control block. The "single selected leaf" invariant must be enforced
explicitly:

- **Deserialization** (`PSBTInput::Unserialize`): When deserializing
  `PSBT_IN_P2MR_LEAF_SCRIPT` entries, if a second entry with a different
  control block key is encountered, **hard-error** with
  `PSBTError::INVALID_P2MR_MULTIPLE_LEAVES`. Do not silently accept or
  use first-wins/last-wins — ambiguous leaf selection is a signing hazard
  that must be surfaced immediately.
- **`PSBTInput::Merge()`**: When merging two `PSBTInput` structs that both
  contain a `PSBT_IN_P2MR_LEAF_SCRIPT` entry, if the control block keys
  differ, **hard-error** (same error code). If the keys match, the entries
  are identical and merging is a no-op. Signatures (`PSBT_IN_P2MR_PQ_SIG`)
  and CSFS fields are merged normally since they are keyed by
  `(leaf_hash, pubkey)` and are unambiguous once the leaf is fixed.
- **`PSBTInput::Sanity()`** (if added): Assert that `m_p2mr_leaf_scripts`
  contains at most one entry.

This constraint makes the key formats safe: `PSBT_IN_P2MR_LEAF_SCRIPT`
stores exactly one entry per input. Signatures are
disambiguated by `(leaf_hash, pubkey)` pairs, preventing collision when the
same pubkey appears in multiple possible leaves.

**Key/value serialization**:

| Key Type | Key Data | Value Data | Modeled After |
|----------|----------|------------|---------------|
| `PSBT_IN_P2MR_LEAF_SCRIPT` | `{control_block_bytes}` | `{script_bytes \|\| leaf_version}` | `PSBT_IN_TAP_LEAF_SCRIPT` (keyed by control block, same pattern) |
| `PSBT_IN_P2MR_PQ_SIG` | `{leaf_hash \|\| pubkey_bytes}` | `{signature_bytes}` | `PSBT_IN_TAP_SCRIPT_SIG` (keyed by pubkey + leaf_hash) |
| `PSBT_IN_P2MR_BIP32_DERIVATION` | `{pq_pubkey_bytes}` | `{master_fingerprint \|\| derivation_path \|\| algo_byte \|\| leaf_hashes}` | `PSBT_IN_TAP_BIP32_DERIVATION` |
| `PSBT_IN_P2MR_MERKLE_ROOT` | (empty) | `{32-byte merkle root}` | `PSBT_IN_TAP_MERKLE_ROOT` |
| `PSBT_IN_CSFS_MESSAGE` | `{leaf_hash \|\| csfs_pubkey_bytes}` | `{message_bytes}` (≤ 520 bytes) | — |
| `PSBT_IN_CSFS_SIGNATURE` | `{leaf_hash \|\| csfs_pubkey_bytes}` | `{signature_bytes}` (exact algo size, no hashtype) | `PSBT_IN_P2MR_PQ_SIG` |
| `PSBT_OUT_P2MR_TREE` | (empty) | Serialized P2MR leaf tree (leaf versions + scripts) | `PSBT_OUT_TAP_TREE` |
| `PSBT_OUT_P2MR_BIP32_DERIVATION` | `{pq_pubkey_bytes}` | `{master_fingerprint \|\| derivation_path \|\| algo_byte}` | `PSBT_OUT_TAP_BIP32_DERIVATION` |

> **Key format changes from Rev 7b**: (1) `PSBT_IN_P2MR_LEAF_SCRIPT` is now
> keyed by `{control_block_bytes}` (not `{leaf_version}`), matching BIP-371's
> `PSBT_IN_TAP_LEAF_SCRIPT` pattern. The control block uniquely identifies
> the leaf position in the tree. (2) `PSBT_IN_P2MR_PQ_SIG` is keyed by
> `{leaf_hash || pubkey_bytes}` (not just `{pubkey_bytes}`), disambiguating
> signatures when the same pubkey appears in multiple leaves. (3)
> `PSBT_IN_CSFS_MESSAGE` and `PSBT_IN_CSFS_SIGNATURE` are keyed by
> `{leaf_hash || csfs_pubkey_bytes}` for the same reason. (4)
> `PSBT_IN_P2MR_CONTROL` (0x1A) is removed — the control block is now part
> of the `PSBT_IN_P2MR_LEAF_SCRIPT` key, so a separate field is redundant.

**Updated PSBT constants** (`psbt.h`):

```cpp
// P2MR-specific PSBT input types (0x1A removed — control is in leaf key)
static constexpr uint8_t PSBT_IN_P2MR_LEAF_SCRIPT         = 0x19;
static constexpr uint8_t PSBT_IN_P2MR_PQ_SIG              = 0x1B;
static constexpr uint8_t PSBT_IN_P2MR_BIP32_DERIVATION    = 0x1C;
static constexpr uint8_t PSBT_IN_P2MR_MERKLE_ROOT         = 0x1D;
static constexpr uint8_t PSBT_IN_CSFS_MESSAGE              = 0x1E;
static constexpr uint8_t PSBT_IN_CSFS_SIGNATURE            = 0x1F;
```

**CSFS multi-party signing workflow**:

1. **Creator** builds the PSBT with `PSBT_IN_P2MR_LEAF_SCRIPT` populated
   for the target leaf (keyed by control block, value = script + leaf_ver).
2. **Oracle** receives the PSBT, reads the delegation leaf script to identify
   its CSFS pubkey, computes `hash = TaggedHash("CSFS/btx", msg)`, signs
   with its PQ key, and populates `PSBT_IN_CSFS_MESSAGE` (keyed by
   leaf_hash + its pubkey, value = message bytes) and
   `PSBT_IN_CSFS_SIGNATURE` (keyed by leaf_hash + its pubkey, value = raw
   signature).
3. **Spender** receives the PSBT with the oracle's CSFS fields populated,
   signs the CHECKSIG portion via the PSBT signing flow
   (`FillSignatureData()` → `SignP2MR()` → `CreateP2MRScriptSig()`),
   populating `PSBT_IN_P2MR_PQ_SIG` (keyed by leaf_hash + pubkey) with
   the sighash-based signature.
4. **Finalizer** assembles the witness:
   `[sig_checksig, sig_csfs, msg, leaf_script, control_block]`.

**Implementation files**:

| File | Change |
|------|--------|
| `src/psbt.h` | Add new `PSBT_IN_P2MR_*`, `PSBT_IN_CSFS_*`, `PSBT_OUT_P2MR_*` constants. Add P2MR fields to `PSBTInput` and `PSBTOutput` structs. |
| `src/psbt.cpp` | Add serialization/deserialization cases for new key types. Extend `FillSignatureData()` / `FromSignatureData()` for P2MR fields (4.2.6). Extend `PSBTInput::Merge()` (lines 198-223) to merge new P2MR maps/fields (with single-leaf enforcement). Extend `PSBTOutput::Merge()` to merge `PSBT_OUT_P2MR_TREE` and `PSBT_OUT_P2MR_BIP32_DERIVATION` fields. |
| `src/script/sign.h` | Add P2MR fields to `SignatureData`: `p2mr_spenddata`, `p2mr_script_sigs`, `p2mr_csfs_sigs`, `p2mr_csfs_msgs`, `p2mr_leaf_script`, `p2mr_control_block` (4.2.1). |
| `src/script/sign.cpp` | Add `CreateP2MRScriptSig()` helper (4.2.2). Change `SignP2MR()` to accept `SignatureData&` (4.2.3). Replace `ExtractP2MRLeafPubKey()` with `ExtractP2MRLeafInfo()` (4.2.4). Extend `SignP2MR()` with per-leaf-type dispatch using sigdata lookup (4.2.5). Update `SignStep()` call site. Extend `SignatureData::MergeSignatureData()` (lines 769-784) to merge new P2MR fields (`p2mr_script_sigs`, `p2mr_csfs_sigs`, `p2mr_csfs_msgs`, `p2mr_leaf_script`, `p2mr_control_block`), ensuring partial-data combination paths don't drop them. |
| `src/script/descriptor.cpp` | Extend `MRLeafSpec`, add `ctv()`/`csfs()`/`ctv_pk()`/`csfs_pk()` parsing in `mr()` descriptor, add `BuildP2MRLeafScript()` dispatch. Must `#include <policy/settings.h>` for `g_script_size_policy_limit`. |
| `src/script/pqm.cpp` / `pqm.h` | Add `BuildP2MRCTVScript()`, `BuildP2MRCSFSScript()`, `BuildP2MRCTVChecksigScript()`, `BuildP2MRDelegationScript()` leaf constructors. |
| `src/wallet/spend.cpp` | Wire CTV/CSFS aware `SignP2MR()` into wallet transaction signing path. |

#### 4.4 Phase 4 Steps

1. Extend `MRLeafSpec` struct with `MRLeafType`, CTV hash, and CSFS key
   fields (4.1).
2. Add `BuildP2MRCTVScript()`, `BuildP2MRCSFSScript()`,
   `BuildP2MRCTVChecksigScript()`, `BuildP2MRDelegationScript()` leaf
   constructors to `pqm.cpp` (4.1).
3. Add `BuildP2MRLeafScript()` dispatch function (4.1).
4. Extend `mr()` descriptor parser to recognize `ctv()`, `ctv_pk()`,
   `csfs()`, `csfs_pk()` expressions. Validate CTV hash length, key
   sizes, and leaf size at parse time. `#include <policy/settings.h>` for
   `g_script_size_policy_limit` (4.1).
5. Add P2MR fields to `SignatureData` in `sign.h` (4.2.1).
6. Add `CreateP2MRScriptSig()` helper in `sign.cpp` (4.2.2).
7. Change `SignP2MR()` signature to accept `SignatureData&`. Update
   `SignStep()` call site (4.2.3).
8. Replace `ExtractP2MRLeafPubKey()` with `ExtractP2MRLeafInfo()` (4.2.4).
9. Implement per-leaf-type `SignP2MR()` dispatch using `sigdata` lookup
   for existing sigs and CSFS material (4.2.5).
10. Add PSBT key type constants and P2MR struct fields to `psbt.h` (4.3).
11. Add PSBT serialization/deserialization for new key types in `psbt.cpp`.
    Extend `FillSignatureData()` / `FromSignatureData()` for P2MR fields
    (4.2.6 / 4.3).
12. Extend `PSBTInput::Merge()` (`psbt.cpp`, lines 198-223) to merge
    new P2MR maps/fields. Enforce the single-selected-leaf invariant:
    hard-error if merging two inputs with different
    `PSBT_IN_P2MR_LEAF_SCRIPT` control block keys. Merge
    `PSBT_IN_P2MR_PQ_SIG`, `PSBT_IN_P2MR_BIP32_DERIVATION`,
    `PSBT_IN_P2MR_MERKLE_ROOT`, `PSBT_IN_CSFS_MESSAGE`, and
    `PSBT_IN_CSFS_SIGNATURE` using insert-if-absent semantics (4.3).
13. Extend `PSBTOutput::Merge()` to merge `PSBT_OUT_P2MR_TREE` and
    `PSBT_OUT_P2MR_BIP32_DERIVATION` fields (4.3).
14. Extend `SignatureData::MergeSignatureData()` (`sign.cpp`, lines 769-784)
    to merge new P2MR fields (`p2mr_script_sigs`, `p2mr_csfs_sigs`,
    `p2mr_csfs_msgs`, `p2mr_leaf_script`, `p2mr_control_block`). Without
    this, partial-data combination paths (e.g., `combinepsbt`) will silently
    drop P2MR signing material (4.2).
15. Wire the full PSBT → sigdata → signer → sigdata → PSBT flow for
    delegation signing (4.2/4.3).
16. Update `bitcoin-cli` / RPC to support CTV-locked address creation.
17. Add tests (see Section 9.10 for full Phase 4 test matrix).
18. Documentation: opcode specifications, example scripts, test vectors.

### 5.5 Test Infrastructure Updates

These changes are required for the C++ unit test framework and Python
functional test harness to recognize the new flags and opcodes.

#### 5.5.1 `src/test/transaction_tests.cpp`: `mapFlagNames`

The `mapFlagNames` map (line 52) maps string flag names to bit values for
JSON-driven script tests. New flags added to `STANDARD_SCRIPT_VERIFY_FLAGS`
(via `MANDATORY_SCRIPT_VERIFY_FLAGS`) must be registered here or
`ParseScriptFlags()` will fail to parse test vectors that use them.

```cpp
// Add after the DISCOURAGE_UPGRADABLE_TAPROOT_VERSION entry:
{std::string("CHECKTEMPLATEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKTEMPLATEVERIFY},
{std::string("CHECKSIGFROMSTACK"), (unsigned int)SCRIPT_VERIFY_CHECKSIGFROMSTACK},
```

#### 5.5.2 `test/functional/test_framework/script.py`: Python Opcodes

The Python test framework defines opcode constants used by functional tests.
The existing P2MR opcodes (`OP_CHECKSIG_MLDSA`, `OP_CHECKSIG_SLHDSA`) are
**missing** from this file and must also be added alongside the new opcodes.

```python
# After OP_CHECKSIGADD = CScriptOp(0xba):

# P2MR opcodes
OP_CHECKSIG_MLDSA = CScriptOp(0xbb)
OP_CHECKSIG_SLHDSA = CScriptOp(0xbc)
OP_CHECKSIGFROMSTACK = CScriptOp(0xbd)

# CTV alias (OP_NOP4 already defined as 0xb3)
OP_CHECKTEMPLATEVERIFY = CScriptOp(0xb3)
```

And in the `OPCODE_NAMES` dict:
```python
# After OP_CHECKSIGADD: 'OP_CHECKSIGADD':
OP_CHECKSIG_MLDSA: 'OP_CHECKSIG_MLDSA',
OP_CHECKSIG_SLHDSA: 'OP_CHECKSIG_SLHDSA',
OP_CHECKSIGFROMSTACK: 'OP_CHECKSIGFROMSTACK',
# Note: OP_CHECKTEMPLATEVERIFY shares 0xb3 with OP_NOP4.
# The OPCODE_NAMES entry remains 'OP_NOP4' for backward compatibility;
# tests should reference OP_CHECKTEMPLATEVERIFY by the Python symbol.
```

---

## 6. Verification Checklist

### 6.1 Correctness

- [ ] CTV uses no-pop semantics. `<hash> OP_CTV` leaves hash on stack.
      Cleanstack satisfied.
- [ ] CTV opcode is 0xb3 (OP_NOP4). Not in OP_SUCCESS range.
- [ ] CTV non-32-byte arguments fail strictly (not NOP).
- [ ] CSFS flag is in both `MANDATORY_SCRIPT_VERIFY_FLAGS` and
      `GetBlockScriptFlags()` static set. No height-gating.
- [ ] CTV flag follows the same pattern.
- [ ] No "passes policy, fails consensus" divergence is possible.
- [ ] CTV handler delegates to `checker.CheckCTVHash()`, not direct tx access.
      `BaseSignatureChecker::CheckCTVHash()` returns false (base case).
      `GenericTransactionSignatureChecker::CheckCTVHash()` calls
      `ComputeCTVHash()`. `DeferringSignatureChecker` forwards correctly.
- [ ] CTV sequences/outputs hashes reuse existing BIP-341 fields
      (`m_sequences_single_hash`, `m_outputs_single_hash`). No duplicate
      fields added. Only CTV-specific scriptSigs fields are new.
- [ ] `CheckCTVHash()` uses `HandleMissingData(m_mdb)` (not `assert`) when
      `txdata` is null, matching `CheckPQSignature()` pattern.
- [ ] CTV preimage is exactly 84 bytes (no scriptSigs hash) or 116 bytes
      (with scriptSigs hash). Test vectors confirm byte counts.
- [ ] CSFS uses `TaggedHash("CSFS/btx", msg)`, not plain SHA-256.
- [ ] CSFS message hashing uses `hasher.write(MakeByteSpan(msg))` (raw bytes),
      NOT `hasher << msg` (which would prepend a CompactSize length prefix).
- [ ] CSFS algorithm detection matches existing `OP_CHECKSIG_MLDSA` /
      `OP_CHECKSIG_SLHDSA` pubkey size expectations (1312 for ML-DSA-44,
      32 for SLH-DSA-128s).
- [ ] CSFS verifies via `CPQPubKey{algo, pubkey}.Verify(hash, sig)` directly.
      Does NOT call `checker.CheckPQSignature()` (which computes a transaction
      sighash via `SignatureHashSchnorr()`, the wrong hash for CSFS).

### 6.2 DoS Hardening

- [ ] `OP_CHECKSIG_MLDSA` decrements `m_validation_weight_left` by
      `VALIDATION_WEIGHT_PER_MLDSA_SIGOP`.
- [ ] `OP_CHECKSIG_SLHDSA` decrements `m_validation_weight_left` by
      `VALIDATION_WEIGHT_PER_SLHDSA_SIGOP`.
- [ ] `OP_CHECKSIGFROMSTACK` decrements by algorithm-appropriate cost.
- [ ] Validation weight constants are calibrated via benchmark before shipping.
- [ ] The `OP_2DUP <pq_checksig> OP_DROP` attack vector is bounded by
      validation weight budget.
- [ ] Test: worst-case P2MR block validation time is comparable to worst-case
      tapscript block validation time.
- [ ] `WitnessSigOps()` remains unchanged (returns 0 for P2MR). No sigops
      counting added. Revisit only if validation weight proves insufficient.
- [ ] `MAX_P2MR_ELEMENT_SIZE` (10,000 bytes) enforced for P2MR script push
      values (Site 1: `interpreter.cpp:457`).
- [ ] `MAX_P2MR_ELEMENT_SIZE` enforced for P2MR initial execution-stack
      elements (Site 2: `interpreter.cpp:1940-1946`). Note: the
      `leaf_script` and `control_block` witness items are already popped
      before this check runs (line 2084-2085); they are bounded separately
      by `P2MR_CONTROL_MAX_SIZE` and `g_script_size_policy_limit`.
- [ ] All current PQ execution-stack elements (ML-DSA sig 2420/2421,
      pubkey 1312; SLH-DSA sig 7856/7857, pubkey 32) fit within
      `MAX_P2MR_ELEMENT_SIZE`.
- [ ] Test: execution-stack element > 10,000 bytes is consensus-rejected.
- [ ] Test: `OP_DUP` amplification with element at cap limit stays within
      validator memory budget (~10 MB per evaluation, ~threads × 10 MB
      peak process memory with parallel script checks).
- [ ] `MAX_P2MR_SCRIPT_SIZE` (10,000 bytes) enforced in P2MR dispatch path
      (`interpreter.cpp`), immediately after `SpanPopBack()`, before
      `ComputeP2MRLeafHash()`. Reuses `SCRIPT_ERR_SCRIPT_SIZE`.
- [ ] No new `SCRIPT_ERR_*` needed (reuses existing `SCRIPT_ERR_SCRIPT_SIZE`).
- [ ] Leaf script at exactly 10,000 bytes is accepted; 10,001 is rejected.
- [ ] All standard P2MR leaf patterns (checksig, CTV, CSFS, delegation) are
      under the cap (no regression).
- [ ] Test: `OP_DUP OP_SHA256 OP_DROP` loop on 10 KB element is bounded by
      script size cap to ~3,333 iterations per input (Section 1.5 analysis).
- [ ] The `g_script_size_policy_limit` (1,650 bytes, policy layer) remains
      the effective limit for relayed transactions. `MAX_P2MR_SCRIPT_SIZE`
      only binds miner-constructed non-relayed transactions.

### 6.3 Policy / Relay

- [ ] `ParsePolicyP2MRLeafScript()` accepts CTV-only, CSFS, combined, and
      delegation/oracle (`CSFS_VERIFY_CHECKSIG_*`) leaf patterns.
- [ ] P2MR stack size check accepts 2-5 items.
- [ ] CSFS message size capped at 520 bytes by policy.
- [ ] CSFS signature sizes checked via `IsPolicyCSFSSignatureSize()` (exact
      algorithm size, no +1 hashtype byte). Distinct from CHECKSIG check.
- [ ] CHECKSIG signature sizes still use `IsPolicyP2MRSignatureSize()` (allows
      +1 for hashtype byte).
- [ ] CTV-only spends (stack.size()==2) relay through mempool.
- [ ] CSFS spends (stack.size()==4) relay through mempool.
- [ ] Delegation spends (stack.size()==5) relay through mempool.
- [ ] Existing checksig spends (stack.size()==3) still relay (no regression).

### 6.5 CTV Strict-Fail Semantics

- [ ] CTV with exactly 32-byte matching hash: succeeds, hash remains on stack.
- [ ] CTV with 32-byte non-matching hash: fails with
      `SCRIPT_ERR_CTV_HASH_MISMATCH`.
- [ ] CTV with non-32-byte top element (e.g., 20 bytes, 33 bytes, empty):
      fails with `SCRIPT_ERR_CTV_HASH_SIZE`.
- [ ] CTV with empty stack: fails with `SCRIPT_ERR_INVALID_STACK_OPERATION`.
- [ ] All strict-fail behaviors have dedicated test vectors.
- [ ] Non-P2MR context: CTV (0xb3) is NOP, not strict-fail. Passes with
      `DISCOURAGE_UPGRADABLE_NOPS` unset; fails policy (not consensus) with
      flag set.

### 6.6 Test Infrastructure

- [ ] `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` and `SCRIPT_VERIFY_CHECKSIGFROMSTACK`
      are inserted **before** `SCRIPT_VERIFY_END_MARKER` in the enum
      (`interpreter.h`). END_MARKER implicitly bumps to cover the new bits.
- [ ] `txvalidationcache_tests.cpp:137` `randrange((SCRIPT_VERIFY_END_MARKER - 1) << 1)`
      now generates flag combinations up to bit 22 (including new flags).
- [ ] `mapFlagNames` in `transaction_tests.cpp` includes
      `"CHECKTEMPLATEVERIFY"` and `"CHECKSIGFROMSTACK"` entries.
- [ ] Python `script.py` defines `OP_CHECKTEMPLATEVERIFY`,
      `OP_CHECKSIG_MLDSA`, `OP_CHECKSIG_SLHDSA`, `OP_CHECKSIGFROMSTACK`.
- [ ] Python `OPCODE_NAMES` dict includes entries for new P2MR opcodes.
- [ ] JSON-driven script tests can parse flag combinations including new flags.

### 6.7 Build System

- [ ] `src/script/ctv.cpp` added to `bitcoin_consensus` source list in
      `src/CMakeLists.txt`.
- [ ] Any new C++ test files added to their respective CMake test targets.
- [ ] Build completes successfully with new files.

### 6.8 Interpreter Gating

- [ ] CTV handler is **flag-gated**: checks
      `!(flags & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY)` and falls through as NOP
      when flag unset. Verify semantics only when flag set AND
      `sigversion == SigVersion::P2MR`.
- [ ] CSFS handler is **sigversion-gated**: checks
      `sigversion != SigVersion::P2MR` and returns `SCRIPT_ERR_BAD_OPCODE`.
      No flag check in the interpreter (matching OP_CHECKSIG_MLDSA pattern).
- [ ] `P2MR_SCRIPT_FLAGS` (or equivalent) in test files includes
      `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` for CTV tests. Without it, CTV
      falls through as NOP and tests silently pass for the wrong reason.
- [ ] CTV Test 6/7 (Section 8.5): non-P2MR context tests verify NOP behavior
      both with and without `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` flag set.

### 6.9 ScriptError Enum Safety

- [ ] New `SCRIPT_ERR_*` values are inserted immediately before
      `SCRIPT_ERR_ERROR_COUNT` (append-only). No existing values renumbered.
- [ ] `ScriptErrorString()` in `script_error.cpp` has a case for every new
      error code. No missing strings (would hit `default:` and return generic
      error message).

### 6.10 CTV Readiness Checks

- [ ] `ComputeCTVHash()` asserts
      `txdata.m_bip143_segwit_ready || txdata.m_bip341_taproot_ready`
      before reading `m_sequences_single_hash` and `m_outputs_single_hash`.
      (Both precompute paths compute these shared hashes; checking only
      `m_bip341_taproot_ready` is fragile.)
- [ ] `ComputeCTVHash()` asserts `txdata.m_ctv_ready` before reading
      `m_ctv_scriptsigs_hash`.
- [ ] `CheckCTVHash()` checks `!this->txdata` and calls
      `HandleMissingData(m_mdb)` before reaching `ComputeCTVHash()`.

### 6.11 CSFS Stack Safety and Signature-Size Enforcement

- [ ] CSFS handler checks `stack.size() < 3` before popping 3 items,
      matching the `stack.size() < 2` pattern in `OP_CHECKSIG_MLDSA`.
- [ ] CSFS exact-size signature check (`IsPolicyCSFSSignatureSize()`) rejects
      signatures with appended hashtype byte.
- [ ] CSFS **consensus** signature-size behavior: non-empty sig of incorrect
      size → hard fail with `SCRIPT_ERR_SIG_MLDSA` / `SCRIPT_ERR_SIG_SLHDSA`
      (not "push false"). Matches CHECKSIG pattern (Section 3.2.1).
- [ ] CSFS empty sig → push OP_FALSE (no verification, no weight decrement).
- [ ] CSFS sig of exact algo size + 1 byte → hard fail (no hashtype parsing,
      unlike CHECKSIG which accepts +1).

### 6.12 Delegation Leaf Standardness

- [ ] Standard delegation example uses SLH-DSA oracle (32-byte pubkey) +
      ML-DSA spender (1312-byte pubkey). Leaf size ≤ 1650 bytes.
- [ ] Two-ML-DSA delegation (~2633-byte leaf) documented as consensus-valid
      but non-standard.
- [ ] `ParsePolicyP2MRLeafScript()` correctly rejects leaves exceeding
      `g_script_size_policy_limit` regardless of pattern match.

### 6.13 Phase 4: Descriptor / Signer / PSBT

- [ ] `MRLeafSpec` extended with `MRLeafType`, `ctv_hash`, `csfs_algo`,
      `csfs_provider_index`, `csfs_fixed_pubkey` fields.
- [ ] `mr()` parser accepts `ctv(<64-hex>)`, `ctv_pk(<hash>, <key>)`,
      `csfs(<key>)`, `csfs(pk_slh(<key>))`, `csfs_pk(<oracle>, <spender>)`.
- [ ] `ctv()` rejects non-32-byte (non-64-hex-char) hashes at parse time.
- [ ] Leaf size validation: descriptor parser rejects leaves exceeding
      `g_script_size_policy_limit` at construction time. `descriptor.cpp`
      includes `<policy/settings.h>` (not `<policy/policy.h>`).
- [ ] `BuildP2MRLeafScript()` dispatch produces correct byte sequences for
      all `MRLeafType` variants.
- [ ] `ExtractP2MRLeafInfo()` recognizes CTV_ONLY, CTV_CHECKSIG, CSFS_ONLY,
      CSFS_VERIFY_CHECKSIG, and existing CHECKSIG leaves.
- [ ] `SignatureData` extended with P2MR fields: `p2mr_spenddata`,
      `p2mr_script_sigs`, `p2mr_csfs_sigs`, `p2mr_csfs_msgs`,
      `p2mr_leaf_script`, `p2mr_control_block` (4.2.1).
- [ ] `CreateP2MRScriptSig()` helper checks sigdata for existing sig before
      falling back to `creator.CreatePQSig()` (4.2.2).
- [ ] `SignP2MR()` accepts `SignatureData&` parameter (mirroring
      `SignTaproot()`). `SignStep()` call site updated (4.2.3).
- [ ] `SignP2MR()` CTV_ONLY: returns 2-item witness `[leaf_script, control]`.
- [ ] `SignP2MR()` CTV_CHECKSIG: returns 3-item witness with valid sighash sig.
- [ ] `SignP2MR()` CSFS_ONLY without sigdata CSFS fields: returns false.
- [ ] `SignP2MR()` CSFS_VERIFY_CHECKSIG with sigdata CSFS fields: returns
      5-item witness with both CSFS and CHECKSIG sigs.
- [ ] `FillSignatureData()` populates P2MR fields from PSBT input (4.2.6).
- [ ] `FromSignatureData()` writes P2MR sigs back to PSBT input (4.2.6).
- [ ] PSBT key format: `PSBT_IN_P2MR_LEAF_SCRIPT` keyed by
      `{control_block_bytes}` (not `{leaf_version}`). `PSBT_IN_P2MR_PQ_SIG`
      keyed by `{leaf_hash || pubkey_bytes}`. CSFS keys include `leaf_hash`
      disambiguator. `PSBT_IN_P2MR_CONTROL` (0x1A) not used.
- [ ] All new PSBT key types (`0x19`, `0x1B`-`0x1F` input, `0x08`-`0x09`
      output) round-trip serialize/deserialize correctly.
- [ ] Same pubkey in two different leaves: signatures disambiguated by
      `leaf_hash` in PSBT key — no collision.
- [ ] CSFS multi-party workflow: creator → oracle → spender → finalizer
      produces a valid finalized witness (full PSBT → sigdata → signer flow).
- [ ] Existing CHECKSIG `mr()` descriptors and `SignP2MR()` behavior are
      unchanged (no regression).
- [ ] `PSBTInput::Merge()` (`psbt.cpp`, lines 198-223) extended to merge
      all new P2MR input maps/fields (`PSBT_IN_P2MR_PQ_SIG`,
      `PSBT_IN_P2MR_BIP32_DERIVATION`, `PSBT_IN_P2MR_MERKLE_ROOT`,
      `PSBT_IN_CSFS_MESSAGE`, `PSBT_IN_CSFS_SIGNATURE`).
- [ ] `PSBTInput::Merge()` enforces single-selected-leaf invariant:
      hard-error if merging inputs with different `PSBT_IN_P2MR_LEAF_SCRIPT`
      control block keys.
- [ ] `PSBTOutput::Merge()` extended to merge `PSBT_OUT_P2MR_TREE` and
      `PSBT_OUT_P2MR_BIP32_DERIVATION` fields.
- [ ] `SignatureData::MergeSignatureData()` (`sign.cpp`, lines 769-784)
      extended to merge P2MR fields (`p2mr_script_sigs`, `p2mr_csfs_sigs`,
      `p2mr_csfs_msgs`, `p2mr_leaf_script`, `p2mr_control_block`).
- [ ] Test: `combinepsbt` with two PSBTs containing complementary P2MR
      signing material (e.g., oracle CSFS sig + spender CHECKSIG sig)
      produces a correctly merged PSBT with all fields intact.
- [ ] Test: `combinepsbt` with two PSBTs selecting different P2MR leaves
      for the same input hard-errors (single-leaf violation).

### 6.4 Post-Quantum Compliance

- [ ] CSFS uses only PQ algorithms (ML-DSA-44, SLH-DSA-128s). No Schnorr
      or ECDSA path.
- [ ] CTV uses only SHA-256. No new cryptographic assumptions.
- [ ] No classical key material is introduced.

---

## 7. Risk Register

| Risk | Severity | Mitigation |
|------|----------|------------|
| Validation weight constants may need re-tuning after benchmarks | Medium | Constants are defined as named constants, easily adjustable. Formal benchmark gate with fail-closed rule in Appendix C. |
| No block-level sigops cap for P2MR | Medium | Validation weight bounds per-input cost; block weight bounds input count. If worst-case block validation time is still too high, add `WitnessSigOps()` counting as a secondary cap. |
| Policy template matcher may be too restrictive for complex scripts | Medium | Start with enumerated safe patterns (checksig, CTV, CSFS, delegation/oracle). Three-phase extensibility roadmap in Appendix F. Non-standard scripts can be miner-submitted per Appendix G. |
| Future opcodes in P2MR need the same treatment | Medium | Document the pattern: any new sigop-class opcode must (a) decrement validation weight with algorithm-appropriate cost, (b) be added to MANDATORY flags if genesis-active, (c) be added to policy template matcher. |
| CSFS `HashWriter << msg` serialization bug | High | Using `operator<<` would prepend a CompactSize length prefix, producing wrong hashes that break all CSFS signatures. Mitigated by explicit code pattern in spec (`hasher.write(MakeByteSpan(msg))`), code review checklist item, and dedicated domain-separation test (same msg must produce same hash via both code paths). |
| CSFS/CHECKSIG signature size confusion | Medium | CSFS uses exact-size (no hashtype byte), CHECKSIG allows +1. Separate functions (`IsPolicyCSFSSignatureSize` vs `IsPolicyP2MRSignatureSize`) prevent accidental cross-use. Verify in review. |
| New source files not added to CMake targets | Medium | `ctv.cpp` must be in `bitcoin_consensus` or linker errors will occur. Mitigated by explicit build-system step in Phase 2 and verification checklist 6.7. |
| CSFS in tapscript is OP_SUCCESS (anyone-can-spend) | Medium | By design. 0xbd in tapscript is OP_SUCCESS, same as 0xbb/0xbc. Policy discourages via `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS`. Wallet/compiler ban and CI lint enforced per Appendix D. Note: Taproot v1 spends are consensus-valid on BTX (`interpreter.cpp:2045-2073`), only non-standard by policy (`policy.cpp:138-146`), so miner-constructed v1 outputs are a real (if unlikely) vector. |
| Delegation leaf exceeds policy limit with two ML-DSA keys | Medium | Two ML-DSA-44 pubkeys produce ~2633-byte leaf, exceeding `g_script_size_policy_limit` (1650). Standard delegation uses SLH-DSA oracle (32B) + ML-DSA spender (1312B) = 1351B. Two-ML-DSA is consensus-valid but non-standard. Operator guidance for submission in Appendix G. |
| `ComputeCTVHash()` accessing uninitialized shared hash fields | High | `m_sequences_single_hash` / `m_outputs_single_hash` are computed when either `uses_bip143_segwit` or `uses_bip341_taproot` is true, but guarded by two separate ready flags. Checking only `m_bip341_taproot_ready` is fragile (fails in test harnesses without spent outputs). Mitigated by `assert(txdata.m_bip143_segwit_ready \|\| txdata.m_bip341_taproot_ready)` in `ComputeCTVHash()` and `HandleMissingData` null-check in `CheckCTVHash()`. |
| CSFS accidentally calling `checker.CheckPQSignature()` | High | `CheckPQSignature()` always computes a transaction sighash via `SignatureHashSchnorr()`. Using it for CSFS would verify the signature against the wrong hash. CSFS must compute `TaggedHash("CSFS/btx", msg)` and call `CPQPubKey::Verify()` directly. Mitigated by explicit "must NOT" callout in Section 3.2, code review checklist item 6.1, and test that verifies CSFS-signed message fails if verified via transaction sighash path. |
| `SCRIPT_ERR_*` enum reordering breaks serialization | Medium | If new error values are inserted in the middle of the enum (not appended), existing error codes change numeric values, breaking any serialized/logged error values. Full governance rules in Appendix H. |
| Unbounded P2MR execution-stack element sizes enable memory amplification | **High** | P2MR bypasses `MAX_SCRIPT_ELEMENT_SIZE` at both push and execution-stack-init sites. With `OP_DUP` × 1000 stack slots, a single script evaluation can allocate unbounded memory. **Mitigated in 1.4**: `MAX_P2MR_ELEMENT_SIZE` (10,000 bytes) caps per-element size, bounding worst-case to ~10 MB per evaluation, ~threads × 10 MB peak process memory with `par_script_checks`. All existing PQ elements (≤ 7857 bytes) fit within the cap. Note: `leaf_script` and `control_block` witness items are popped before Site 2 runs and are bounded separately. |
| Unbounded P2MR leaf scripts enable CPU amplification via hash opcodes | **High** | With no consensus script size limit and `MAX_P2MR_ELEMENT_SIZE` = 10,000 bytes, `OP_DUP OP_SHA256 OP_DROP` loops hash 10 KB per iteration (~19x more CPU per hash than tapscript's 520-byte elements). Unbounded scripts drive worst-case block validation to ~10.4x tapscript baseline. **Mitigated in 1.5**: `MAX_P2MR_SCRIPT_SIZE` (10,000 bytes) caps leaf-script size, reducing worst case to ~5.2x at consensus level and ~2.0x at policy level (`g_script_size_policy_limit` = 1,650). Strict 1.2x parity for hash-maximizing workloads would require validation-weight charging for non-sig opcodes (deferred). |

---

## 8. Test Vector Notes

### 8.1 CTV Preimage Byte Count Verification

For a transaction with 1 input, 1 output, no non-empty scriptSigs,
`nLockTime = 0`, `version = 2`:

```
version:       4 bytes
nLockTime:     4 bytes
input count:   4 bytes
sequences:    32 bytes
output count:  4 bytes
outputs:      32 bytes
input index:   4 bytes
--------------------------
Total:        84 bytes
```

With non-empty scriptSigs:
```
+ scriptSigs: 32 bytes
--------------------------
Total:       116 bytes
```

### 8.2 CTV Cleanstack Verification

```
Locking script (P2MR leaf):  <32-byte-ctv-hash> OP_CHECKTEMPLATEVERIFY
Witness stack:               [leaf_script, control_block]

Execution:
  1. Witness items popped by P2MR dispatch: leaf_script, control_block.
  2. Execution stack is empty (no witness args).
  3. Script pushes 32-byte hash -> stack: [hash].
  4. OP_CHECKTEMPLATEVERIFY peeks at hash, verifies against tx. Does not pop.
  5. Stack: [hash]. stack.size() == 1. Cleanstack: PASS.
  6. CastToBool(hash): 32 non-zero bytes -> true. PASS.
```

### 8.3 CSFS Verification Flow

```
Locking script (P2MR leaf):  OP_PUSHDATA2 <1312-byte-pubkey> OP_CHECKSIGFROMSTACK
Witness stack:               [sig, msg, leaf_script, control_block]

Execution:
  1. Witness items popped by P2MR dispatch: leaf_script, control_block.
  2. Execution stack from remaining witness: [sig, msg].
  3. Script pushes pubkey -> stack: [sig, msg, pubkey].
  4. OP_CHECKSIGFROMSTACK:
     a. Pop pubkey (1312 bytes -> ML-DSA-44).
     b. Pop msg (arbitrary, <= 520 bytes by policy).
     c. Pop sig (2420 bytes for ML-DSA-44).
     d. Compute hash (NOT via checker.CheckPQSignature — that computes a tx sighash):
        HashWriter hasher = HASHER_CSFS;  // copy pre-initialized midstate
        hasher.write(MakeByteSpan(msg));  // raw bytes, NO length prefix
        uint256 hash = hasher.GetSHA256();
     e. Decrement m_validation_weight_left by VALIDATION_WEIGHT_PER_MLDSA_SIGOP (500).
     f. CPQPubKey{PQAlgorithm::ML_DSA_44, pubkey}.Verify(hash, sig).
     g. Push OP_TRUE.
  5. Stack: [true]. Cleanstack: PASS.
```

### 8.4 Delegation/Oracle Verification Flow (5-Item Witness)

> **Standard example**: Uses SLH-DSA-128s (32-byte pubkey) for the oracle and
> ML-DSA-44 (1312-byte pubkey) for the spender. This produces a leaf script of
> ~1351 bytes, which fits under `g_script_size_policy_limit` (1650) and relays
> through the mempool.
>
> **Leaf size calculation**:
> `push(1) + 32 + CSFS(1) + VERIFY(1) + OP_PUSHDATA2(3) + 1312 + CHECKSIG_MLDSA(1) = 1351 bytes`
>
> **Non-standard alternative**: Two ML-DSA-44 pubkeys would produce
> `OP_PUSHDATA2(3) + 1312 + CSFS(1) + VERIFY(1) + OP_PUSHDATA2(3) + 1312 + CHECKSIG_MLDSA(1) = 2633 bytes`,
> which exceeds the 1650-byte policy limit. Two-ML-DSA delegation is
> **consensus-valid** but **non-standard** — it will not relay through the
> default mempool and must be submitted directly to a miner (or the node
> operator must raise `-maxscriptsize`). The two-ML-DSA variant uses less
> total block space (7473 bytes total witness vs ~11627 for SLH-DSA oracle)
> but sacrifices relay standardness.

```
Locking script (P2MR leaf):
  <32-byte-oracle-pubkey> OP_CHECKSIGFROMSTACK OP_VERIFY
  OP_PUSHDATA2 <1312-byte-spender-pubkey> OP_CHECKSIG_MLDSA

  Leaf size: 1 + 32 + 1 + 1 + 3 + 1312 + 1 = 1351 bytes (< 1650, standard)

Witness stack: [sig_checksig, sig_csfs, msg, leaf_script, control_block]

Execution:
  1. P2MR dispatch pops leaf_script and control_block.
  2. Execution stack from remaining witness: [sig_checksig, sig_csfs, msg].
  3. Script pushes oracle-pubkey (32 bytes) -> stack: [sig_checksig, sig_csfs, msg, oracle-pubkey].
  4. OP_CHECKSIGFROMSTACK:
     a. Pop oracle-pubkey (32 bytes -> SLH-DSA-128s).
     b. Pop msg (<= 520 bytes by policy).
     c. Pop sig_csfs (7856 bytes for SLH-DSA-128s, exact size, no hashtype byte).
     d. Compute hash = TaggedHash("CSFS/btx", msg) via HASHER_CSFS + write().
     e. Decrement m_validation_weight_left by VALIDATION_WEIGHT_PER_SLHDSA_SIGOP (5000).
     f. CPQPubKey{PQAlgorithm::SLH_DSA_128S, oracle-pubkey}.Verify(hash, sig_csfs).
     g. Push OP_TRUE.
  5. Stack: [sig_checksig, true].
  6. OP_VERIFY: pop true, continue (would fail script if false).
  7. Stack: [sig_checksig].
  8. Script pushes spender-pubkey (1312 bytes) -> stack: [sig_checksig, spender-pubkey].
  9. OP_CHECKSIG_MLDSA:
     a. Pop spender-pubkey, pop sig_checksig.
     b. Decrement m_validation_weight_left by VALIDATION_WEIGHT_PER_MLDSA_SIGOP (500).
     c. Verify ML-DSA-44(spender-pubkey, sighash, sig_checksig).
     d. Push OP_TRUE.
  10. Stack: [true]. Cleanstack: PASS.
```

Use case: oracle attests to data (e.g., price feed, delegation authorization)
via CSFS. Spender proves possession of their own key via CHECKSIG. Both
verifications must pass for the spend to succeed.

> **Block space trade-off**: The SLH-DSA oracle variant uses more total witness
> bytes (~11627: 7856 sig_csfs + 2421 sig_checksig + 1351 leaf) compared to
> two-ML-DSA (~7473: 2420 sig_csfs + 2421 sig_checksig + 2633 leaf). However,
> the SLH-DSA oracle variant is the only delegation pattern that relays through
> the default mempool without raising `-maxscriptsize`. For cost-sensitive
> applications where both keys are ML-DSA, miners can include the non-standard
> variant directly.

### 8.5 CTV Strict-Fail Test Vectors

```
Test 1 (happy path):
  Script: <32-byte-correct-hash> OP_CHECKTEMPLATEVERIFY
  Result: PASS. Hash remains on stack, cleanstack satisfied.

Test 2 (wrong hash):
  Script: <32-byte-wrong-hash> OP_CHECKTEMPLATEVERIFY
  Result: FAIL with SCRIPT_ERR_CTV_HASH_MISMATCH.

Test 3 (20-byte argument):
  Script: <20-byte-value> OP_CHECKTEMPLATEVERIFY
  Result: FAIL with SCRIPT_ERR_CTV_HASH_SIZE.

Test 4 (33-byte argument):
  Script: <33-byte-value> OP_CHECKTEMPLATEVERIFY
  Result: FAIL with SCRIPT_ERR_CTV_HASH_SIZE.

Test 5 (empty stack):
  Script: OP_CHECKTEMPLATEVERIFY  (nothing pushed before)
  Result: FAIL with SCRIPT_ERR_INVALID_STACK_OPERATION.

Test 6 (non-P2MR, DISCOURAGE flag unset):
  Context: legacy/v0/tapscript, flags without DISCOURAGE_UPGRADABLE_NOPS
  Script: <32-byte-value> OP_NOP4
  Result: PASS (NOP behavior, value remains on stack).

Test 7 (non-P2MR, DISCOURAGE flag set):
  Context: legacy/v0, flags with DISCOURAGE_UPGRADABLE_NOPS
  Script: <32-byte-value> OP_NOP4
  Result: FAIL with SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS.
```

---

## 9. Comprehensive Test Matrix

This section consolidates all required tests from Phases 2-4 and the
verification checklists. Every test has a unique ID, category, expected
result, and the specification section it validates. Tests are organized by
subsystem.

### 9.1 Prerequisite Tests (Validation Weight — Phase 1)

| ID | Test | Expected Result | Validates |
|----|------|----------------|-----------|
| W-PQ-1 | OP_CHECKSIG_MLDSA with non-empty sig decrements weight by 500 | Weight reduced by exactly `VALIDATION_WEIGHT_PER_MLDSA_SIGOP` | 1.1 |
| W-PQ-2 | OP_CHECKSIG_SLHDSA with non-empty sig decrements weight by 5000 | Weight reduced by exactly `VALIDATION_WEIGHT_PER_SLHDSA_SIGOP` | 1.1 |
| W-PQ-3 | OP_CHECKSIG_MLDSA with empty sig does NOT decrement weight | Weight unchanged | 1.1 |
| W-PQ-4 | Repeated OP_2DUP+CHECKSIG_MLDSA exhausts budget | `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT` | 1.1 |
| W-PQ-5 | Budget boundary: exactly-at-limit succeeds, one-over fails | Pass/fail at boundary | 1.1 |
| W-PQ-6 | Existing CHECKSIG spends (no weight change) still work | No regression | 1.1 |
| E-PQ-1 | P2MR execution-stack element (witness arg) > 10,000 bytes rejected by Site 2 | `SCRIPT_ERR_PUSH_SIZE` | 1.4 |
| E-PQ-2 | P2MR script push value > 10,000 bytes in leaf script rejected by Site 1 | `SCRIPT_ERR_PUSH_SIZE` | 1.4 |
| E-PQ-3 | P2MR execution-stack element == 10,000 bytes accepted | PASS | 1.4 |
| E-PQ-4 | ML-DSA sig (2421 bytes) as execution-stack element fits within limit | PASS (no regression) | 1.4 |
| E-PQ-5 | SLH-DSA sig (7857 bytes) as execution-stack element fits within limit | PASS (no regression) | 1.4 |
| E-PQ-6 | Non-P2MR push > 520 bytes still rejected (limit unchanged) | `SCRIPT_ERR_PUSH_SIZE` | 1.4 |
| S-PQ-1 | P2MR leaf script > 10,000 bytes rejected in P2MR dispatch | `SCRIPT_ERR_SCRIPT_SIZE` | 1.5 |
| S-PQ-2 | P2MR leaf script == 10,000 bytes accepted | PASS | 1.5 |
| S-PQ-3 | Standard checksig leaf (~1,316 bytes) is well under cap | PASS (no regression) | 1.5 |
| S-PQ-4 | `OP_DUP OP_SHA256 OP_DROP` loop in 10,000-byte script bounded to ~3,333 iterations | Bounded CPU, completes within expected time | 1.5 |

### 9.2 CTV Consensus Tests (Phase 2)

| ID | Test | Expected Result | Validates |
|----|------|----------------|-----------|
| C-CTV-1 | Preimage: no scriptSigs → 84 bytes | Exact byte count | 2.2 |
| C-CTV-2 | Preimage: non-empty scriptSig → 116 bytes | Exact byte count | 2.2 |
| C-CTV-3 | Happy path: matching tx spends CTV output | PASS, hash on stack | 2.3 |
| C-CTV-4 | Wrong outputs → mismatch | `SCRIPT_ERR_CTV_HASH_MISMATCH` | 2.3 |
| C-CTV-5 | Wrong nLockTime → mismatch | `SCRIPT_ERR_CTV_HASH_MISMATCH` | 2.3 |
| C-CTV-6 | Wrong input index → mismatch | `SCRIPT_ERR_CTV_HASH_MISMATCH` | 2.3 |
| C-CTV-7 | Cleanstack: `<hash> OP_CTV`, stack==1 post-exec | PASS | 2.3 |
| C-CTV-8 | 20-byte argument | `SCRIPT_ERR_CTV_HASH_SIZE` | 2.3 |
| C-CTV-9 | 33-byte argument | `SCRIPT_ERR_CTV_HASH_SIZE` | 2.3 |
| C-CTV-10 | Empty argument (0 bytes) | `SCRIPT_ERR_CTV_HASH_SIZE` | 2.3 |
| C-CTV-11 | Empty stack | `SCRIPT_ERR_INVALID_STACK_OPERATION` | 2.3 |
| C-CTV-12 | Multi-input: hash at index 0 ≠ hash at index 1 | Different hashes | 2.2 |
| C-CTV-13 | Flag unset → NOP (value remains on stack) | PASS (NOP) | 3.3.1 |
| C-CTV-14 | Flag unset + DISCOURAGE_NOPS → error | `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS` | 3.3.1 |
| C-CTV-15 | Flag set, non-P2MR context → NOP | PASS (NOP) | 3.3.1 |
| C-CTV-16 | txdata=null, FAIL mode → false | Returns false, no crash | 2.5 |
| C-CTV-17 | m_sequences_single_hash matches hand-computed | Hash equality | 2.2.1 |
| C-CTV-18 | m_outputs_single_hash matches hand-computed | Hash equality | 2.2.1 |
| C-CTV-19 | m_ctv_scriptsigs_hash matches hand-computed | Hash equality | 2.2.1 |
| C-CTV-20 | Init() sets m_ctv_ready = true | Flag set after Init | 2.5 |
| C-CTV-21 | Combined leaf: CTV + CHECKSIG in same script | Both pass | 4.2.2 |

### 9.3 CSFS Consensus Tests (Phase 3)

| ID | Test | Expected Result | Validates |
|----|------|----------------|-----------|
| C-CSFS-1 | ML-DSA-44 happy path | PASS, pushes OP_TRUE | 3.2 |
| C-CSFS-2 | SLH-DSA-128s happy path | PASS, pushes OP_TRUE | 3.2 |
| C-CSFS-3 | Corrupted sig → false | Pushes OP_FALSE | 3.2 |
| C-CSFS-4 | Empty sig → false (no verify, no weight) | Pushes OP_FALSE | 3.2 |
| C-CSFS-5 | NULLFAIL: non-empty failed sig | `SCRIPT_ERR_SIG_MLDSA` | 3.2 |
| C-CSFS-6 | Stack < 3 items | `SCRIPT_ERR_INVALID_STACK_OPERATION` | 3.2 |
| C-CSFS-7 | Stack == 2 (missing msg) | `SCRIPT_ERR_INVALID_STACK_OPERATION` | 3.2 |
| C-CSFS-8 | 1312-byte pubkey → ML-DSA | Correct algo detection | 3.2 |
| C-CSFS-9 | 32-byte pubkey → SLH-DSA | Correct algo detection | 3.2 |
| C-CSFS-10 | 33-byte pubkey | `SCRIPT_ERR_PQ_PUBKEY_SIZE` | 3.2 |
| C-CSFS-11 | 0-byte pubkey | `SCRIPT_ERR_PQ_PUBKEY_SIZE` | 3.2 |
| C-CSFS-12 | 1311-byte pubkey | `SCRIPT_ERR_PQ_PUBKEY_SIZE` | 3.2 |
| C-CSFS-13 | ML-DSA sig + SLH-DSA pubkey | Verification fails | 3.2 |
| C-CSFS-14 | TaggedHash ≠ plain SHA256 ≠ sighash | Different hashes | 3.2 |
| C-CSFS-15 | write() vs operator<< produce different hashes | Different hashes | 3.2 |
| C-CSFS-16 | CSFS uses TaggedHash, not sighash | Rejects when sighash would match | 3.2 |
| C-CSFS-17 | Legacy context → BAD_OPCODE | `SCRIPT_ERR_BAD_OPCODE` | 3.3.1 |
| C-CSFS-18 | Witness v0 → BAD_OPCODE | `SCRIPT_ERR_BAD_OPCODE` | 3.3.1 |
| C-CSFS-19 | Tapscript → OP_SUCCESS | Script succeeds | 3.1 |
| C-CSFS-20 | Tapscript + DISCOURAGE_OP_SUCCESS | Policy-rejected | 3.1 |
| C-CSFS-21 | 520-byte message | PASS | 3.2 |
| C-CSFS-22 | 0-byte message | PASS (empty msg hashed) | 3.2 |
| C-CSFS-23 | 521-byte message (consensus-valid) | PASS | 3.2 |
| C-CSFS-24 | ML-DSA sig of exact size + 1 byte (2421) → hard fail | `SCRIPT_ERR_SIG_MLDSA` | 3.2.1 |
| C-CSFS-25 | SLH-DSA sig of exact size + 1 byte (7857) → hard fail | `SCRIPT_ERR_SIG_SLHDSA` | 3.2.1 |
| C-CSFS-26 | ML-DSA sig of wrong size (e.g., 100 bytes) → hard fail | `SCRIPT_ERR_SIG_MLDSA` | 3.2.1 |

### 9.4 CSFS Validation Weight Tests

| ID | Test | Expected Result | Validates |
|----|------|----------------|-----------|
| W-CSFS-1 | ML-DSA CSFS decrements by 500 | Weight reduced | 3.4 |
| W-CSFS-2 | SLH-DSA CSFS decrements by 5000 | Weight reduced | 3.4 |
| W-CSFS-3 | Empty-sig CSFS: no weight decrement | Weight unchanged | 3.4 |
| W-CSFS-4 | Repeated CSFS exhausts budget | `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT` | 3.4 |
| W-CSFS-5 | Budget boundary: at-limit pass, over-limit fail | Boundary behavior | 3.4 |

### 9.5 Delegation/Oracle Tests

| ID | Test | Expected Result | Validates |
|----|------|----------------|-----------|
| D-CSFS-1 | Standard: SLH-DSA oracle + ML-DSA spender, both valid | PASS | 8.4 |
| D-CSFS-2 | Oracle sig invalid → OP_VERIFY fails | Script aborts | 8.4 |
| D-CSFS-3 | Spender sig invalid → CHECKSIG_MLDSA false | Cleanstack fail | 8.4 |
| D-CSFS-4 | Leaf size ≤ 1650 bytes | Standard | 8.4 |
| D-CSFS-5 | Two-ML-DSA leaf (~2633 bytes) consensus-valid | PASS via VerifyScript | 8.4 |

### 9.6 Policy Tests

| ID | Test | Expected Result | Validates |
|----|------|----------------|-----------|
| P-CTV-1 | CTV-only (stack==2) relays | Mempool accepted | 4.2.1 |
| P-CTV-2 | CTV+CHECKSIG (stack==3) relays | Mempool accepted | 4.2.1 |
| P-CTV-3 | CTV_ONLY leaf pattern recognized | Template match | 4.2.2 |
| P-CTV-4 | CTV_CHECKSIG_MLDSA pattern recognized | Template match | 4.2.2 |
| P-CTV-5 | CTV_CHECKSIG_SLHDSA pattern recognized | Template match | 4.2.2 |
| P-CSFS-1 | CSFS-only (stack==4) relays | Mempool accepted | 4.2.1 |
| P-CSFS-2 | Delegation (stack==5) relays | Mempool accepted | 4.2.1 |
| P-CSFS-3 | Oversized msg (>520) policy-rejected | Rejected | 4.2.3 |
| P-CSFS-4 | Exact-size ML-DSA sig accepted | Policy passes | 4.2.4 |
| P-CSFS-5 | ML-DSA sig +1 (hashtype) rejected | Policy rejects | 4.2.4 |
| P-CSFS-6 | CSFS_ONLY pattern recognized | Template match | 4.2.2 |
| P-CSFS-7 | CSFS_VERIFY_CHECKSIG_MLDSA pattern | Template match | 4.2.2 |
| P-CSFS-8 | CSFS_VERIFY_CHECKSIG_SLHDSA pattern | Template match | 4.2.2 |
| P-CSFS-9 | Two-ML-DSA leaf policy-rejected (>1650) | Rejected | 4.2.2 |
| P-CSFS-10 | Stack==6 rejected | Policy rejects | 4.2.1 |
| P-CSFS-11 | Stack==1 rejected | Policy rejects | 4.2.1 |
| P-STD-1 | Existing checksig (stack==3) still relays | No regression | 4.2.1 |
| P-STD-2 | CHECKSIG sig +1 (hashtype) still accepted | No regression | 4.2.4 |

### 9.7 Cross-Context / Regression Tests

| ID | Test | Expected Result | Validates |
|----|------|----------------|-----------|
| X-1 | CTV opcode (0xb3) in tapscript: NOP behavior | PASS | 2.1 |
| X-2 | CSFS opcode (0xbd) in tapscript: OP_SUCCESS | Script succeeds | 3.1 |
| X-3 | P2MR opcodes (0xbb-0xbd) in legacy: BAD_OPCODE | Fails | 3.3.1 |
| X-4 | P2MR opcodes in witness v0: BAD_OPCODE | Fails | 3.3.1 |
| X-5 | Existing P2MR CHECKSIG spends unaffected | No regression | — |
| X-6 | Existing tapscript spends unaffected | No regression | — |
| X-7 | Existing legacy/v0 spends unaffected | No regression | — |
| X-8 | GetOpName("OP_CHECKTEMPLATEVERIFY") correct | String match | 2.1 |
| X-9 | GetOpName("OP_CHECKSIGFROMSTACK") correct | String match | 3.1 |
| X-10 | ScriptErrorString() for all new error codes | String match | H.2 |

### 9.8 Functional / Integration Tests (Python)

| ID | Test | Expected Result | Validates |
|----|------|----------------|-----------|
| F-CTV-1 | CTV end-to-end: lock, spend, confirm | Block accepted | 2.3 |
| F-CTV-2 | CTV rejection: wrong tx, verify error | Spend rejected | 2.3 |
| F-CTV-3 | CTV mempool relay between nodes | Propagates | 4 |
| F-CSFS-1 | CSFS end-to-end: lock, spend, confirm | Block accepted | 3.2 |
| F-CSFS-2 | Delegation end-to-end: oracle+spender confirm | Block accepted | 8.4 |
| F-CSFS-3 | CSFS mempool relay | Propagates | 4 |
| F-CSFS-4 | Oversized msg does not relay | Rejected | 4.2.3 |
| F-INT-1 | CTV vault: create, withdraw, confirm | End-to-end | E.1 |
| F-INT-2 | CTV vault with CPFP fee-bump | Fee-bumped tx confirms | E.3 |
| F-INT-3 | Package relay: zero-fee CTV + CPFP child | Package accepted | E.3 |

### 9.9 Phase 4 Tests (Descriptor / Signer / PSBT)

| ID | Test | Expected Result | Validates |
|----|------|----------------|-----------|
| T-DESC-1 | `mr(<key>, ctv(<64-hex>))` parses successfully | Descriptor created | 4.1 |
| T-DESC-2 | `mr(ctv_pk(<64-hex>, <xpub>))` parses successfully | Descriptor created | 4.1 |
| T-DESC-3 | `mr(<key>, csfs(<mldsa-hex>))` parses successfully | Descriptor created | 4.1 |
| T-DESC-4 | `mr(csfs_pk(pk_slh(<oracle>), <spender>))` parses successfully | Descriptor created | 4.1 |
| T-DESC-5 | `ctv()` with non-32-byte hash rejected at parse time | Parse error | 4.1 |
| T-DESC-6 | `csfs_pk()` producing leaf > 1650 bytes rejected at parse time | Parse error (leaf size) | 4.1 |
| T-DESC-7 | `BuildP2MRCTVScript()` produces correct `<hash> OP_CTV` bytes | Byte-exact match | 4.1 |
| T-DESC-8 | `BuildP2MRDelegationScript()` produces correct CSFS_VERIFY_CHECKSIG bytes | Byte-exact match | 4.1 |
| T-DESC-9 | Descriptor round-trip: parse → expand → serialize → parse matches | String equality | 4.1 |
| T-SIGN-1 | `ExtractP2MRLeafInfo()` recognizes CTV_ONLY leaf | Correct type returned | 4.2 |
| T-SIGN-2 | `ExtractP2MRLeafInfo()` recognizes CTV_CHECKSIG leaf | Correct type + pubkey | 4.2 |
| T-SIGN-3 | `ExtractP2MRLeafInfo()` recognizes CSFS_VERIFY_CHECKSIG leaf | Both keys extracted | 4.2 |
| T-SIGN-4 | `ExtractP2MRLeafInfo()` still recognizes existing CHECKSIG leaves | No regression | 4.2 |
| T-SIGN-5 | `SignP2MR()` for CTV_ONLY: witness = `[leaf_script, control_block]` (no sig) | 2-item witness | 4.2 |
| T-SIGN-6 | `SignP2MR()` for CTV_CHECKSIG: witness = `[sig, leaf_script, control_block]` | 3-item witness with valid sig | 4.2 |
| T-SIGN-7 | `SignP2MR()` for CSFS_ONLY without sigdata CSFS fields: signing fails gracefully | Returns false | 4.2.5 |
| T-SIGN-8 | `SignP2MR()` for CSFS_VERIFY_CHECKSIG with sigdata CSFS fields: assembles 5-item witness | `[sig_ck, sig_csfs, msg, leaf, ctrl]` | 4.2.5 |
| T-SIGN-9 | `CreateP2MRScriptSig()` uses existing sig from sigdata (no key needed) | Sig from sigdata returned | 4.2.2 |
| T-SIGN-10 | `CreateP2MRScriptSig()` falls back to `CreatePQSig()` when sigdata empty | Fresh sig created | 4.2.2 |
| T-SIGN-11 | `FillSignatureData()` populates P2MR fields from PSBTInput | Fields match | 4.2.6 |
| T-SIGN-12 | `FromSignatureData()` writes P2MR sigs back to PSBTInput | Round-trip match | 4.2.6 |
| T-PSBT-1 | `PSBT_IN_P2MR_LEAF_SCRIPT` (keyed by control_block) round-trip | Bytes match | 4.3 |
| T-PSBT-2 | `PSBT_IN_CSFS_MESSAGE` (keyed by leaf_hash+pubkey) round-trip | Bytes match | 4.3 |
| T-PSBT-3 | `PSBT_IN_CSFS_SIGNATURE` (keyed by leaf_hash+pubkey) round-trip | Bytes match | 4.3 |
| T-PSBT-4 | Unknown PSBT key types in P2MR range preserved in `unknown` map | Not silently dropped | 4.3 |
| T-PSBT-5 | Multi-party CSFS signing: creator → oracle → spender → finalizer (full PSBT flow) | Valid finalized witness | 4.2/4.3 |
| T-PSBT-6 | CSFS message > 520 bytes in PSBT accepted (PSBT is pre-policy) | Stored without error | 4.3 |
| T-PSBT-7 | `PSBT_IN_P2MR_PQ_SIG` keyed by leaf_hash+pubkey round-trips | Sig keying correct | 4.3 |
| T-PSBT-8 | Same pubkey in two leaves: `PSBT_IN_P2MR_PQ_SIG` disambiguated by leaf_hash | Both sigs stored/retrieved independently | 4.3 |
| T-INT-1 | End-to-end: create CTV descriptor → fund → spend → confirm | Block accepted | 4.1/4.2 |
| T-INT-2 | End-to-end: create delegation descriptor → oracle signs via PSBT → spender signs → broadcast | Block accepted | 4.1-4.3 |
| T-INT-3 | Existing CHECKSIG `mr()` descriptors and signing unchanged | No regression | 4.0 |

### 9.10 Test Count Summary

| Category | Count | Phase |
|----------|-------|-------|
| Prerequisite (weight) | 6 | 1 |
| Prerequisite (element size) | 6 | 1 |
| Prerequisite (script size) | 4 | 1 |
| CTV consensus | 21 | 2 |
| CSFS consensus | 26 | 3 |
| CSFS weight | 5 | 3 |
| Delegation | 5 | 3 |
| Policy | 18 | 2-3 |
| Cross-context/regression | 10 | 3-4 |
| Functional/integration | 11 | 2-4 |
| Descriptor/signer/PSBT (Phase 4) | 32 | 4 |
| **Total** | **144** | |

---

## Appendix A: Diff Summary

```
src/script/script.h
  ~ OP_NOP4 renamed to OP_CHECKTEMPLATEVERIFY (0xb3), alias kept
  + OP_CHECKSIGFROMSTACK = 0xbd
  ~ MAX_OPCODE = OP_CHECKSIGFROMSTACK
  + VALIDATION_WEIGHT_PER_MLDSA_SIGOP = 500
  + VALIDATION_WEIGHT_PER_SLHDSA_SIGOP = 5000
  + MAX_P2MR_ELEMENT_SIZE = 10000
  + MAX_P2MR_SCRIPT_SIZE = 10000

src/script/interpreter.h
  + SCRIPT_VERIFY_CHECKTEMPLATEVERIFY  = (1U << 21)
  + SCRIPT_VERIFY_CHECKSIGFROMSTACK    = (1U << 22)
  ~ SCRIPT_VERIFY_END_MARKER implicitly bumped (must remain after new flags)
  + BaseSignatureChecker::CheckCTVHash() virtual (returns false)
  + GenericTransactionSignatureChecker::CheckCTVHash() override
  + DeferringSignatureChecker::CheckCTVHash() forwarding
  + PrecomputedTransactionData: m_ctv_ready, m_ctv_scriptsigs_hash,
    m_ctv_has_scriptsigs (sequences/outputs reuse BIP-341 fields)

src/policy/policy.h
  ~ MANDATORY_SCRIPT_VERIFY_FLAGS |= SCRIPT_VERIFY_CHECKTEMPLATEVERIFY
                                   | SCRIPT_VERIFY_CHECKSIGFROMSTACK

src/policy/policy.cpp
  ~ ParsePolicyP2MRLeafScript(): add CTV, CSFS, combined, delegation patterns
  ~ IsWitnessStandard(): stack.size() 2-5, CSFS msg size check,
    CSFS exact-size sig check via IsPolicyCSFSSignatureSize()
  + IsPolicyCSFSSignatureSize() (exact algo size, no +1 hashtype byte)

src/validation.cpp (GetBlockScriptFlags)
  ~ static flags |= SCRIPT_VERIFY_CHECKTEMPLATEVERIFY
                   | SCRIPT_VERIFY_CHECKSIGFROMSTACK

src/script/interpreter.cpp (EvalScript / ExecuteWitnessScript / P2MR dispatch)
  ~ P2MR push-value size check: MAX_SCRIPT_ELEMENT_SIZE → MAX_P2MR_ELEMENT_SIZE (Site 1: line 457)
  ~ P2MR execution-stack element size check: MAX_SCRIPT_ELEMENT_SIZE → MAX_P2MR_ELEMENT_SIZE (Site 2: lines 1940-1946)
  + P2MR leaf-script size check: MAX_P2MR_SCRIPT_SIZE (P2MR dispatch, immediately after SpanPopBack(), before ComputeP2MRLeafHash())
  ~ case OP_CHECKSIG_MLDSA / OP_CHECKSIG_SLHDSA:
      + algorithm-specific validation weight decrement
  ~ OP_NOP4 removed from NOP handler
  + case OP_CHECKTEMPLATEVERIFY: flag-gated (checks SCRIPT_VERIFY_CHECKTEMPLATEVERIFY,
    falls through as NOP when unset; verify semantics in P2MR when set)
  + case OP_CHECKSIGFROMSTACK: sigversion-gated (checks sigversion == P2MR,
    BAD_OPCODE otherwise; no flag check in interpreter). Verifies via
    CPQPubKey::Verify(TaggedHash, sig), NOT checker.CheckPQSignature().
  + GenericTransactionSignatureChecker::CheckCTVHash() implementation
  + HASHER_CSFS{TaggedHash("CSFS/btx")} static initializer

src/script/interpreter.cpp (WitnessSigOps)
  (no changes -- sigops counting deferred)

src/script/ctv.h / ctv.cpp (new)
  + ComputeCTVHash()

src/CMakeLists.txt (bitcoin_consensus)
  + script/ctv.cpp

src/script/script.cpp (GetOpName)
  ~ "OP_CHECKTEMPLATEVERIFY" (was "OP_NOP4")
  + "OP_CHECKSIGFROMSTACK"

src/script/script_error.h
  + SCRIPT_ERR_CTV_HASH_SIZE, SCRIPT_ERR_CTV_HASH_MISMATCH
  + SCRIPT_ERR_CSFS_PUBKEY_SIZE (if needed)
  (append-only before SCRIPT_ERR_ERROR_COUNT)

src/script/script_error.cpp (ScriptErrorString)
  + case strings for all new SCRIPT_ERR_* values

src/test/pq_consensus_tests.cpp
  ~ P2MR_SCRIPT_FLAGS: CTV tests must include SCRIPT_VERIFY_CHECKTEMPLATEVERIFY
    (CSFS is sigversion-gated, flag optional but recommended for consistency)

src/test/transaction_tests.cpp (mapFlagNames)
  + {"CHECKTEMPLATEVERIFY", SCRIPT_VERIFY_CHECKTEMPLATEVERIFY}
  + {"CHECKSIGFROMSTACK", SCRIPT_VERIFY_CHECKSIGFROMSTACK}

test/functional/test_framework/script.py
  + OP_CHECKSIG_MLDSA = CScriptOp(0xbb)    (was missing)
  + OP_CHECKSIG_SLHDSA = CScriptOp(0xbc)   (was missing)
  + OP_CHECKSIGFROMSTACK = CScriptOp(0xbd)
  + OP_CHECKTEMPLATEVERIFY = CScriptOp(0xb3) (alias)
  + OPCODE_NAMES entries for new opcodes

(Phase 4 — descriptor/signer/PSBT, gated on Phases 1-3)

src/script/descriptor.cpp
  + #include <policy/settings.h> (for g_script_size_policy_limit)
  ~ MRLeafSpec: add MRLeafType enum, ctv_hash, csfs_algo, csfs fields
  + Parsing: ctv(), ctv_pk(), csfs(), csfs_pk() leaf expressions in mr()
  + BuildP2MRLeafScript() dispatch replacing single BuildP2MRScript() call

src/script/pqm.cpp / pqm.h
  + BuildP2MRCTVScript(), BuildP2MRCSFSScript(),
    BuildP2MRCTVChecksigScript(), BuildP2MRDelegationScript()

src/script/sign.h
  + SignatureData: p2mr_spenddata, p2mr_script_sigs (keyed by leaf_hash+pubkey),
    p2mr_csfs_sigs, p2mr_csfs_msgs, p2mr_leaf_script, p2mr_control_block

src/script/sign.cpp
  + CreateP2MRScriptSig(): check sigdata for existing sig, else CreatePQSig()
  ~ ExtractP2MRLeafPubKey() → ExtractP2MRLeafInfo() (returns P2MRLeafInfo)
  ~ SignP2MR(): accepts SignatureData& sigdata, per-leaf-type dispatch
    (CTV_ONLY, CTV_CHECKSIG, CSFS_ONLY, CSFS_VERIFY_CHECKSIG, CHECKSIG),
    uses CreateP2MRScriptSig() + sigdata lookup for CSFS material

src/psbt.h
  + PSBT_IN_P2MR_LEAF_SCRIPT  = 0x19 (keyed by control_block, value = script||leaf_ver)
  + PSBT_IN_P2MR_PQ_SIG       = 0x1B (keyed by leaf_hash||pubkey)
  + PSBT_IN_P2MR_BIP32_DERIVATION = 0x1C
  + PSBT_IN_P2MR_MERKLE_ROOT  = 0x1D
  + PSBT_IN_CSFS_MESSAGE       = 0x1E (keyed by leaf_hash||csfs_pubkey)
  + PSBT_IN_CSFS_SIGNATURE     = 0x1F (keyed by leaf_hash||csfs_pubkey)
  + PSBT_OUT_P2MR_TREE        = 0x08
  + PSBT_OUT_P2MR_BIP32_DERIVATION = 0x09
  (PSBT_IN_P2MR_CONTROL 0x1A removed — control is in leaf_script key)

src/psbt.cpp
  + Serialize/Unserialize cases for all new PSBT key types
  ~ FillSignatureData(): populate SignatureData P2MR fields from PSBT input
  ~ FromSignatureData(): write back P2MR signatures to PSBT input
```

---

## Appendix B: Activation Flag Consistency Proof

> **Clarification**: `MANDATORY_SCRIPT_VERIFY_FLAGS` (`policy.h:138-152`) is
> explicitly **policy-only** — it controls mempool acceptance and DoS-ban
> thresholds. Its doc comment states: *"Note that this does not affect
> consensus validity; see GetBlockScriptFlags() for that."*
>
> The safety invariant below is therefore **not** a universal truth about
> `MANDATORY_SCRIPT_VERIFY_FLAGS`. It holds for BTX's genesis-active features
> because we independently ensure that `GetBlockScriptFlags()` includes the
> same flags at all heights. For features that activate at a specific height
> (BIP-9/BIP-8 deployments), `MANDATORY_*` inclusion alone would be
> insufficient — you would need `GetBlockScriptFlags()` to gate the flag on
> the activation height. BTX avoids this complexity by activating all features
> from genesis.

The following invariant must hold for genesis-active features:

```
For any genesis-active flag F:
  1. F is in GetBlockScriptFlags(block_index) for ALL valid block_index.
     (This is the consensus-level requirement.)
  2. F is in MANDATORY_SCRIPT_VERIFY_FLAGS.
     (This ensures policy is at least as strict as consensus — no
     "passes policy, fails consensus" divergence.)
```

**Proof for CSFS and CTV flags**:

1. `SCRIPT_VERIFY_CHECKSIGFROMSTACK` and `SCRIPT_VERIFY_CHECKTEMPLATEVERIFY`
   are added to the static initializer of `GetBlockScriptFlags()` (line 2661):
   ```cpp
   uint32_t flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
                  SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_CHECKTEMPLATEVERIFY |
                  SCRIPT_VERIFY_CHECKSIGFROMSTACK};
   ```
   This satisfies invariant (1): the flags are in the static initializer,
   so they are present for every block regardless of height.

2. The only code path that can remove flags is the `script_flag_exceptions` map
   (line 2662-2665). BTX has no historical blocks that violate these rules
   (the chain has not launched), so this map will not contain entries that
   clear CSFS or CTV flags.

3. Therefore `GetBlockScriptFlags(block_index) & F == F` for all blocks,
   satisfying invariant (1).

4. Both flags are added to `MANDATORY_SCRIPT_VERIFY_FLAGS` (`policy.h`),
   satisfying invariant (2). Policy checks use `STANDARD_SCRIPT_VERIFY_FLAGS`,
   which includes `MANDATORY_SCRIPT_VERIFY_FLAGS`, which includes both flags.
   Policy is a superset of consensus. No "passes policy, fails consensus"
   path exists.

**QED**.

> **Implementation checklist for future genesis-active features**: When adding
> a new flag F that is active from height 0:
> 1. Add F to the `GetBlockScriptFlags()` static initializer (consensus).
> 2. Add F to `MANDATORY_SCRIPT_VERIFY_FLAGS` (policy).
> 3. Verify that (1) is not conditional on height or deployment state.
> Do NOT rely on `MANDATORY_*` inclusion alone — it does not affect consensus.

---

## Appendix C: PQ Benchmark Gate — Release Criteria

The validation weight constants (`VALIDATION_WEIGHT_PER_MLDSA_SIGOP = 500`,
`VALIDATION_WEIGHT_PER_SLHDSA_SIGOP = 5000`) are conservative starting points.
They **must** be calibrated via benchmarking before shipping. This appendix
formalizes the acceptance criteria.

### C.1 Per-Algorithm Verification Time Targets

| Algorithm | Max single-verify wall time | Target hardware |
|-----------|-----------------------------|-----------------|
| ML-DSA-44 | ≤ 1.0 ms | Mid-range x86-64 (e.g., Xeon E-2300, Ryzen 5) |
| SLH-DSA-128s | ≤ 50 ms | Same |
| Schnorr (baseline) | ≤ 0.05 ms | Same |

These targets bound the per-input cost. The validation weight constant for
each algorithm is then:

```
WEIGHT_PER_ALGO = ceil(algo_verify_ms / schnorr_verify_ms) * VALIDATION_WEIGHT_PER_SIGOP_PASSED
```

If benchmarked ML-DSA verify time is 0.5 ms and Schnorr is 0.05 ms, the
ratio is 10x, giving `10 * 50 = 500` (matches current constant). If
benchmarked time is 1.0 ms, the ratio is 20x, giving `20 * 50 = 1000`.

### C.2 Worst-Case Block Validation Time

**Signature-verification-dominated blocks** (primary DoS vector):

| Metric | Acceptance threshold |
|--------|---------------------|
| Worst-case sigop-maximizing P2MR block | ≤ 1.2x worst-case tapscript block |
| Worst-case mixed block (P2MR + tapscript) | ≤ 1.5x worst-case tapscript-only block |

**Adversarial composition**: construct a block that maximizes PQ verification
cost — fill `MAX_BLOCK_WEIGHT` with P2MR inputs, each containing the maximum
number of PQ sigops permitted by the validation weight budget. Measure total
wall-clock time. Compare against an equivalent tapscript block filled with
Schnorr sigops.

**Hash-opcode-dominated blocks** (secondary concern):

| Metric | Bound | Notes |
|--------|-------|-------|
| Consensus worst case (10,000-byte scripts) | ~5.2x tapscript | Bounded by `MAX_P2MR_SCRIPT_SIZE` (Section 1.5). Inherent to P2MR's larger element sizes (10 KB vs 520 bytes). |
| Policy worst case (1,650-byte scripts) | ~2.0x tapscript | Bounded by `g_script_size_policy_limit`. Only miner-constructed txs can exceed this. |

The 5.2x consensus-level ratio for hash-dominated blocks is an accepted
trade-off: it is inherent to post-quantum element sizes and cannot be reduced
below ~2.0x without either (a) capping element sizes below PQ signature sizes
(infeasible) or (b) extending validation-weight charging to non-sig opcodes
(deferred to a future revision; see Section 1.5). The signature-dominated
threshold (≤ 1.2x) is the hard gate; the hash-dominated ratio is a monitored
metric with a documented future mitigation path.

### C.3 Benchmark Execution Model

Benchmark results on shared/virtualized CI runners (GitHub Actions, etc.) are
too noisy for performance gating — variance from co-tenancy and CPU throttling
makes pass/fail thresholds flaky. The benchmark suite uses a two-tier model:

**Tier 1 — CI smoke tests** (GitHub-hosted runners, every PR):
- Run `bench_mldsa_verify` and `bench_slhdsa_verify` as regression detectors.
- No hard pass/fail threshold. Flag >2x regression vs baseline as a warning.
- Purpose: catch accidental performance regressions (e.g., debug logging left
  in hot path), not enforce absolute targets.

**Tier 2 — Release-gating benchmarks** (self-hosted perf runner OR manual
pre-release checklist):
- Run on a **dedicated reference machine** with:
  - Isolated cores (no co-tenancy), CPU governor set to `performance`
  - Specific hardware: document the exact CPU model, RAM, OS version
  - **Recommended reference**: AMD Ryzen 5 5600X (mid-range, representative
    of validators and miners) OR equivalent Xeon E-2300 series
- Execute the full suite: `bench_mldsa_verify`, `bench_slhdsa_verify`,
  `bench_worst_case_p2mr_block` (adversarial block construction).
- Compare against C.1 (per-algo) and C.2 (block-level) thresholds.
- Record results in `doc/pq-benchmark-results.md` with commit hash, hardware
  ID, and raw timing data.
- **Gate**: release is blocked if any threshold is exceeded.

If a self-hosted runner is available, Tier 2 runs automatically on release
branches. Otherwise, it runs as a manual pre-release checklist item — a
designated engineer executes the suite on the reference machine and signs off
on the results before tagging.

### C.4 Mining Load Constraint

The benchmark gate must also ensure that PQ verification does not add
unacceptable overhead to **block template construction and mining**:

- Miners must validate their own block templates. If worst-case P2MR
  block validation takes too long, miners experience stale-rate increases.
- The C.2 signature-dominated threshold (≤ 1.2x worst-case tapscript) applies
  equally to miners: PQ signature verification must not make BTX blocks
  materially harder to mine than equivalent tapscript-only blocks. The
  hash-dominated ratio (~5.2x at consensus) is a monitored metric; miners
  constructing their own blocks control which scripts they include.
- The validation weight budget is the primary control: by bounding the number
  of PQ sigops per input, total block validation cost scales linearly with
  block weight, just as it does for tapscript.
- **No additional per-block scanning or computation** is introduced by CTV
  or CSFS beyond what already exists for P2MR checksig opcodes. CTV is a
  single SHA-256 (negligible). CSFS reuses the same `CPQPubKey::Verify()` that
  miners already execute for P2MR checksig spends.

### C.5 Fail-Closed Rule

If any benchmark target is not met:

- **Do not ship** with the current constants.
- Adjust the validation weight constants upward until the block validation
  time target is met.
- If no constant adjustment can meet the target (algorithm is too slow for
  any reasonable budget), escalate: consider removing the algorithm from the
  standard relay set (policy-only rejection) or reducing the per-input budget.
- Document the final calibrated values and the benchmark results that justify
  them in a `doc/pq-benchmark-results.md` file committed alongside the code.

### C.6 Verification Checklist

- [ ] Tier 1 CI smoke tests exist and run on every PR.
- [ ] Tier 2 release-gating benchmarks run on dedicated reference machine
      (or manual pre-release checklist is in place).
- [ ] Reference machine hardware is documented.
- [ ] Per-algorithm verify times are within C.1 thresholds on reference machine.
- [ ] Worst-case block validation time is within C.2 thresholds.
- [ ] Mining load impact assessed: PQ block validation ≤ 1.2x tapscript (C.4).
- [ ] Final validation weight constants are documented with benchmark evidence
      in `doc/pq-benchmark-results.md`.
- [ ] Fail-closed rule has been applied (constants adjusted if needed).

---

## Appendix D: CSFS OP_SUCCESS Range Safety Policy

CSFS uses opcode 0xbd, which is in the `IsOpSuccess` range (0xbb-0xfe). In
tapscript, this opcode makes any output trivially spendable (anyone-can-spend).
This is by design — P2MR-only opcodes in the OP_SUCCESS range match the
convention established by `OP_CHECKSIG_MLDSA` (0xbb) and `OP_CHECKSIG_SLHDSA`
(0xbc). However, accidental use of 0xbd in a tapscript leaf would result in
**catastrophic, irrecoverable loss of funds** — the output is immediately
spendable by anyone monitoring the mempool.

> **L2 context**: This risk is amplified for L2 protocols where script
> construction may be automated or generated by counterparty negotiation.
> A bug in a channel factory or vault script compiler that accidentally
> places a P2MR-only opcode in a tapscript leaf creates an anyone-can-spend
> output with no recovery path. The tooling safeguards below are mandatory.

### D.1 Chosen Strategy: Wallet/Compiler Ban + Static Analysis

BTX adopts strategy (A): strict tooling enforcement to prevent accidental use
of P2MR-only opcodes in non-P2MR contexts.

**Requirements**:

1. **Wallet-level ban**: Any wallet or script construction library that
   generates tapscript leaves must reject `OP_CHECKSIGFROMSTACK` (0xbd),
   `OP_CHECKSIG_MLDSA` (0xbb), and `OP_CHECKSIG_SLHDSA` (0xbc) in tapscript
   context. These opcodes are only valid in P2MR (witness v2) leaves.

2. **Descriptor validation**: The descriptor parser must reject descriptors
   that place P2MR-only opcodes inside `tr()` (taproot/v1) descriptors.
   P2MR-only opcodes are only valid inside `mr()` (witness v2) descriptors.

   **Concrete enforcement points**:

   - `tr()` parsing (`descriptor.cpp:2353-2412`) accepts tapscript leaf
     sub-expressions via `ParseScript(key_exp_index, sarg,
     ParseScriptContext::P2TR, out, error)` (line 2386). The most targeted
     enforcement point is inside `ParseScript()`: when
     `ctx == ParseScriptContext::P2TR`, reject any sub-expression that
     would produce a script containing opcodes 0xbb-0xbd. This can be
     checked either during parsing (if new descriptor functions like `csfs()`
     or `checksig_mldsa()` are recognized) or as a post-construction scan
     of the generated `CScript` bytes.

   - For `raw()` descriptors (`descriptor.cpp:2474-2483`), which accept
     arbitrary hex scripts, add a check when the output type is tapscript:
     scan the decoded script bytes for 0xbb-0xbd opcodes and reject unless
     the `--allow-op-success` override is active.

   - For `rawtr()` descriptors (`descriptor.cpp:2454-2468`), no leaf scripts
     are involved (keypath-only), so no check is needed.

   > **Scope note**: BTX makes witness v1 (Taproot) outputs **non-standard
   > by policy** (`policy.cpp:138-146` — only `WITNESS_V2_P2MR` and
   > `NULL_DATA` are relay-standard), but the consensus layer **does**
   > execute Taproot v1 spends (`interpreter.cpp:2045-2073`). A miner
   > could include a v1 output in a block and it would be consensus-valid.
   > Therefore the OP_SUCCESS risk for P2MR opcodes in tapscript leaves is
   > **not moot** — it is a real (if unlikely) attack surface for
   > miner-constructed transactions or blocks containing non-standard
   > outputs. The `tr()` descriptor ban and CI lint are genuine safety
   > requirements, not just defense-in-depth. The codebase also still
   > parses `tr()` descriptors, which reinforces the need for the ban to
   > prevent accidental use in testing or cross-chain tooling.

3. **Explicit unsafe override**: For intentional OP_SUCCESS testing or
   research, the wallet/descriptor tooling must require an explicit override
   flag (e.g., `--allow-op-success` CLI flag or `allow_op_success=true`
   parameter in RPC calls). Without this override, any attempt to construct
   a tapscript leaf containing a P2MR-only opcode must hard-error (not
   warn). The override must not be settable via configuration file — it
   must be specified per-invocation to prevent accidental persistence.

4. **Lint/static analysis**: Add a CI check that scans test vectors and
   functional tests for accidental construction of tapscript leaves containing
   P2MR-only opcodes (0xbb-0xbd). Flag any such construction as a potential
   anyone-can-spend bug unless explicitly annotated with a
   `// INTENTIONAL_OP_SUCCESS_TEST` comment.

5. **Policy layer**: `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS` is already in
   `STANDARD_SCRIPT_VERIFY_FLAGS`. Tapscript leaves containing 0xbd are
   policy-rejected at relay. Only a miner deliberately including such a
   transaction could create an anyone-can-spend output.

### D.2 Why Not an Alternative Opcode?

Assigning CSFS to a non-OP_SUCCESS opcode (e.g., repurposing another NOP)
would require CSFS to have NOP fallback semantics in tapscript, which is
undesirable: CSFS popping 3 items from the stack and pushing a result is
not NOP-compatible. The OP_SUCCESS range is the correct home for P2MR-only
opcodes that have no meaningful behavior outside P2MR. This matches the
existing convention for OP_CHECKSIG_MLDSA and OP_CHECKSIG_SLHDSA.

### D.3 Verification Checklist

- [ ] `ParseScript()` in `descriptor.cpp`, when `ctx == ParseScriptContext::P2TR`,
      rejects script sub-expressions containing opcodes 0xbb-0xbd (hard error,
      not warning) unless `--allow-op-success` override is active.
- [ ] `raw()` descriptor construction in tapscript context scans decoded script
      bytes for 0xbb-0xbd and rejects (unless override active).
- [ ] `--allow-op-success` override exists for intentional testing; requires
      per-invocation flag, not persistent config.
- [ ] CI lint catches accidental P2MR-opcode-in-tapscript in test vectors
      (unless annotated `// INTENTIONAL_OP_SUCCESS_TEST`).
- [ ] `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS` prevents relay of tapscript
      leaves containing 0xbb-0xbd.
- [ ] L2 script compiler test suite includes negative test: tapscript leaf
      with 0xbd must be rejected by default.
- [ ] Test: `tr(<internal_key>, raw(<hex_containing_0xbd>))` rejected by
      descriptor parser without override.

---

## Appendix E: L2/Lightning Integration Profile

CTV and CSFS enable several L2 construction patterns. This appendix specifies
what is supported, what is explicitly not supported, and the operational
requirements for L2 integration.

### E.1 Supported Channel Constructions

| Construction | Opcodes Used | Description |
|-------------|-------------|-------------|
| **CTV vaults** | CTV | Pre-signed spending paths with time-locked recovery. Single CTV leaf commits to a specific withdrawal transaction structure. |
| **CTV payment trees** | CTV | Batch payouts via Merkle tree of CTV-locked outputs. Each leaf commits to a subset of recipients. Logarithmic on-chain cost. |
| **Delegated closes** | CSFS + CHECKSIG | Oracle/watchtower signs a close-state message via CSFS; channel participant authorizes via CHECKSIG. Both must agree for close to execute. |
| **Factory trees** | CTV + CSFS | Hierarchical channel factories using CTV for state commitments and CSFS for authorized state transitions. |
| **Covenant-guarded channels** | CTV | Restrict channel outputs to pre-approved destinations (e.g., only to a cold-storage recovery address after timeout). |

### E.2 Not Supported (Requires Additional Opcodes)

| Construction | Missing Primitive | Notes |
|-------------|-------------------|-------|
| **Eltoo/LN-Symmetry** | `SIGHASH_ANYPREVOUT` (APO) | Eltoo requires rebindable signatures that can spend any prior state. CTV commits to transaction structure (including input count), which prevents rebinding. APO is a separate proposal not included in this plan. |
| **Recursive covenants** | `OP_CAT` + introspection | CTV is non-recursive: the committed transaction structure is fixed at construction time. Recursive covenants (where the covenant re-applies to outputs) require stack concatenation and self-referential script hash computation. |
| **Stateful scripts** | Persistent state | P2MR scripts are stateless; each spend is evaluated independently. State channels require L2 protocols to manage state externally. |

### E.3 Fee-Bumping and Package Relay

CTV-locked transactions have **fixed output structures** — the outputs are
committed in the template hash. This constrains fee-bumping:

| Strategy | Compatibility | Notes |
|----------|--------------|-------|
| **CPFP (child-pays-for-parent)** | Fully compatible | Add a fee-bumping output to the CTV template at construction time. The child transaction is unconstrained. **Recommended approach.** |
| **RBF (replace-by-fee)** | Partially compatible | The replacement transaction must match the CTV template exactly (same outputs). Only the fee input can change. Requires the CTV template to include a fee-input slot. |
| **Anchor outputs** | Fully compatible | Include a zero-value or dust anchor output in the CTV template. Anyone can spend it via CPFP. |
| **Package relay** | Required for vaults | CTV vault withdrawal transactions may have zero fee if fee is paid by a CPFP child. Package relay (`submitpackage` RPC, mempool package acceptance) must be available for vault operations. |

**Operational requirement**: L2 implementations using CTV vaults **must**
design their covenant trees with fee-bumping in mind. A CTV template that
commits to fixed fees without a CPFP anchor output is non-upgradable — if
fee rates rise above the committed fee, the transaction cannot confirm.

### E.4 Verification Checklist

- [ ] CTV vault construction includes a fee-bumping output (anchor or CPFP).
- [ ] Delegation/oracle close pattern (CSFS + CHECKSIG) tested end-to-end
      in functional tests.
- [ ] Package relay is functional for zero-fee CTV transactions with CPFP
      children.
- [ ] Documentation explicitly states that eltoo/APO is not supported.

---

## Appendix F: Mempool Policy Extensibility Roadmap

The `ParsePolicyP2MRLeafScript()` template matcher (Section 4.2.2) uses an
enumerated list of safe leaf patterns (`P2MRLeafType`). This is deliberately
conservative for launch: each pattern has known witness layout, signature
count, and resource bounds, making DoS analysis tractable.

### F.1 Limitation

Strict template matching becomes a bottleneck as new use cases emerge. Every
novel script pattern requires a new enum variant, a new parser branch, policy
tests, and a review cycle. Complex multi-clause scripts (e.g., timelocked
fallbacks, multi-oracle quorums) are consensus-valid but relay-blocked until
their exact pattern is added.

### F.2 Graduation Roadmap

The long-term goal is to replace strict template matching with **constrained
script-policy classification** — a policy that accepts any P2MR leaf script
meeting bounded resource criteria, without enumerating patterns.

**Phase 1 (current)**: Enumerated templates. Ship with the patterns in
Section 4.2.2. Gather real-world usage data.

**Phase 2 (post-launch)**: Opcode family allowlist. Define opcode families
(push, flow-control, signature, covenant, arithmetic) and accept any leaf
script composed of allowed opcode families with bounded:
- Total script size ≤ `g_script_size_policy_limit`
- Witness stack items ≤ max (currently 5)
- Signature count ≤ max per leaf (derived from validation weight budget)
- No unbounded loops (P2MR has no looping opcodes)

**Phase 3 (future)**: Resource-bounded acceptance. Accept any P2MR leaf
script where the validation weight budget bounds the worst-case CPU cost.
The policy layer only needs to verify that the witness size is standard
and the leaf size is within limits. The validation weight budget provides
the DoS guarantee regardless of script content.

### F.3 Backwards Compatibility

Each phase is policy-only (no consensus changes). Relaxing policy does not
require a hard fork or flag day. Nodes can upgrade independently. Stricter
nodes will reject transactions that more permissive nodes accept (the
standard policy-divergence behavior).

### F.4 Verification Checklist

- [ ] Phase 1 template matcher is implemented and tested.
- [ ] Roadmap phases are documented for future contributors.
- [ ] Complex scripts that are consensus-valid but policy-rejected have
      clear documentation on how to submit them (see Appendix G).

---

## Appendix G: Operator Guidance — Consensus-Valid Non-Standard Transactions

Several transaction types in this plan are consensus-valid but non-standard
(rejected by the default mempool policy). This appendix provides operator
guidance for handling them.

### G.1 Non-Standard Transaction Types

| Transaction Type | Why Non-Standard | Consensus Valid? |
|-----------------|-----------------|-----------------|
| Two-ML-DSA delegation leaf (~2633 bytes) | Exceeds `g_script_size_policy_limit` (1650) | Yes |
| Novel P2MR leaf patterns not in `P2MRLeafType` | Not recognized by template matcher | Yes |
| CSFS with message > 520 bytes | Exceeds policy message size limit | Yes |
| Witness stack > 5 items | Exceeds policy stack size limit | Yes |

### G.2 Miner Direct Submission

Non-standard transactions must be submitted directly to a miner that
includes them. Paths:

1. **`submitblock` with custom block template**: The miner constructs a
   block template via `getblocktemplate`, manually adds the non-standard
   transaction, and mines the block.

2. **`-acceptnonstdtxn` flag**: Running a node with this flag disables
   standardness checks for mempool acceptance. The transaction can then be
   included in block templates normally. **Warning**: this also accepts
   other non-standard transactions, broadening the node's attack surface.

3. **Mining pool API**: Submit the raw transaction to a mining pool's
   direct-inclusion API (pool-specific, not part of Bitcoin/BTX protocol).

### G.3 Recommended `-maxscriptsize` Changes

For operators that need to relay two-ML-DSA delegation transactions:

```
# Raise leaf script size policy limit to 3000 bytes
btxd -maxscriptsize=3000
```

This allows leaves up to 3000 bytes to relay through the mempool. The
operator should understand that this increases the relay surface for larger
scripts and may increase validation time for transactions they relay.

**Do not set `-maxscriptsize` higher than necessary.** The default (1650)
is calibrated for single-key and standard delegation patterns.

### G.4 Propagation Impact

Non-standard transactions do not propagate through the default P2P network.
A miner including a non-standard transaction will produce a valid block that
all nodes accept (consensus-valid), but the transaction will not have been
pre-validated by most nodes. This means:

- **Block validation time**: Nodes validate the non-standard transaction for
  the first time when they receive the block. No caching benefit from mempool
  pre-validation.
- **Compact block relay**: The transaction will not be in other nodes' mempools,
  so compact block relay cannot short-circuit it. The full transaction must be
  fetched, adding latency to block propagation.
- **No policy-consensus divergence**: The transaction is consensus-valid.
  Nodes will accept the block regardless of their policy settings.

### G.5 Verification Checklist

- [ ] `-acceptnonstdtxn` flag is documented and tested.
- [ ] `-maxscriptsize` flag is documented with recommended values.
- [ ] Non-standard transaction types are listed in user-facing documentation.
- [ ] Compact block relay behavior with non-standard transactions is tested.

---

## Appendix H: ScriptError Compatibility Governance

`ScriptError` values are used by downstream tooling (block explorers, analytics
pipelines, logging infrastructure) that may parse or store the numeric error
values. This appendix formalizes the compatibility rules.

### H.1 Stability Rules

1. **Append-only**: New `SCRIPT_ERR_*` values are inserted immediately before
   `SCRIPT_ERR_ERROR_COUNT`. No existing values may be renumbered, reordered,
   or removed.

2. **No gaps**: Values must be contiguous. Do not skip numeric values.

3. **No aliasing**: Each numeric value maps to exactly one error code. Do not
   assign two names to the same value.

4. **String stability**: Once a `ScriptErrorString()` case is shipped, the
   returned string for that error code must not change. Downstream tools may
   pattern-match on error strings.

### H.2 New Error Codes in This Plan

| Error Code | Numeric Value | String | Section |
|-----------|---------------|--------|---------|
| `SCRIPT_ERR_CTV_HASH_SIZE` | (next available) | `"CTV hash must be exactly 32 bytes"` | 2.4 |
| `SCRIPT_ERR_CTV_HASH_MISMATCH` | (next available) | `"CTV hash mismatch"` | 2.4 |
| `SCRIPT_ERR_CSFS_PUBKEY_SIZE` | (next available, if added) | `"Invalid CSFS public key size"` | 3.6 |

The exact numeric values are determined by insertion order before
`SCRIPT_ERR_ERROR_COUNT`. They will be assigned during implementation and
must be documented in release notes.

### H.3 Downstream Consumer Guidance

For tools that consume `ScriptError` values:

- **Do not hardcode numeric values**. Use symbolic names or string matching.
  Numeric values may differ between BTX versions if errors are added in
  different order during development (though the final release order is frozen).
- **Handle unknown error codes gracefully**. If a tool encounters a numeric
  value >= its known `SCRIPT_ERR_ERROR_COUNT`, it should display
  `"Unknown script error (<numeric>)"` rather than crash.
- **Subscribe to release notes**. New error codes are documented in release
  notes with their final numeric values and string representations.

### H.4 Verification Checklist

- [ ] All new `SCRIPT_ERR_*` values are appended before `SCRIPT_ERR_ERROR_COUNT`.
- [ ] `ScriptErrorString()` has a case for every new value.
- [ ] Release notes template includes a "New ScriptError Codes" section.
- [ ] No existing error code numeric values are changed.
