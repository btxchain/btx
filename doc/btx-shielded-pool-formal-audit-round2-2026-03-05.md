# BTX Shielded Pool — Formal Audit Report (Round 2)

Status note (2026-03-24): this audit records the March 5 prelaunch snapshot.
Parameter values and benchmarks inside it are historical, not the current
merged-main launch surface. Current `main` defaults to shielded ring size `8`,
supports configured rings `8..32` on the same wire surface, and the current
benchmark baseline lives in `doc/btx-shielded-production-status-2026-03-20.md`.

**Date:** 2026-03-05
**Branch under review:** `codex/shielded-pool-overhaul` merged into `claude/review-branch-merge-BBa9g`
**Scope:** Full codebase deep scan — cryptographic proofs, side-channels, conformance, scalability, security
**Auditor:** Independent third-party review — ring-signature security, side-channel/timing, conformance vectors, adversarial review
**Previous audit:** `btx-shielded-pool-formal-audit-2026-03-05.md` (31 findings, 7 P0-critical)

---

## Executive Summary

This is a **Round 2 formal review** following remediation of 7 P0-critical findings from the initial audit. The codebase has undergone significant improvements. Of the original 7 P0-critical issues, **4 are fully resolved** and **3 are partially resolved**. However, **new critical findings** have been identified, and several previous high-severity items remain open.

### Remediation Scorecard (Previous P0-Critical)

| # | Original Finding | Status | Detail |
|---|-----------------|--------|--------|
| 1 | Rejection sampling negative gap (NORM_BOUND=127) | **FIXED** | `SECRET_SMALL_ETA`→2, `RESPONSE_NORM_BOUND`=130952, Signed24 serialization |
| 2 | SampleChallenge never called (scalar challenges) | **PARTIAL** | Ring signatures now use polynomial challenges. Range/balance proofs still use scalar challenges |
| 3 | Range proof masking nonce too small (eta=4) | **FIXED** | Masking now from `[-131072, 131072]` via `SampleMaskingVec()` |
| 4 | Independent reference vectors missing | **NOT FIXED** | Still self-referential KAT vectors only |
| 5 | Range/balance proof KAT vectors missing | **NOT FIXED** | Still no deterministic KAT for these components |
| 6 | Ring member uniqueness validation | **FIXED** | `HasInvalidRingMembers()` + `ValidateEffectivePublicKeysUnique()` |
| 7 | Secret-dependent branching in range proof | **FIXED** | Constant-time `CtSwapBytes()` replaces `if (real_branch == 0)` |

---

## AUDIT 1: Ring-Signature Security Argument vs MatRiCT+ Assumptions

### Parameters (Updated)

| Parameter | Previous | Current | Required |
|-----------|----------|---------|----------|
| `POLY_Q` | 8,380,417 | 8,380,417 | OK (Dilithium) |
| `POLY_N` | 256 | 256 | OK (Dilithium) |
| `MODULE_RANK` | 4 | 4 | OK (NIST Level 2) |
| `BETA_CHALLENGE` | 60 | 60 | OK (weight-60 ternary) |
| `GAMMA_RESPONSE` | 131,072 | 131,072 (2^17) | OK |
| `RESPONSE_NORM_BOUND` | **127** (broken) | **130,952** | OK: `γ - β·η = 131072 - 120 = 130952` |
| `SECRET_SMALL_ETA` | **4** (broken) | **2** | OK: `β·η = 120 < 130952` |
| `RING_SIZE` | 16 | 16 | Acceptable |
| Ring sig challenges | **Scalar (~7 bits)** | **Polynomial (>200 bits)** | OK |
| Range proof challenges | **Scalar (~7 bits)** | **Scalar (~7 bits)** | **STILL DEFICIENT** |
| Balance proof challenges | **Scalar (~23 bits)** | **Scalar (~23 bits)** | **STILL DEFICIENT** |

### Finding RS-R2-001 — HIGH: Range proof bit-level OR proof soundness is ~7 bits

**Files:** `range_proof.cpp:60-70, 480-491`
**Status:** OPEN (from previous audit Finding 2, partially fixed)

The ring signature now correctly uses polynomial challenges via `SampleChallenge()` (>200-bit challenge space). However, the range proof's per-bit OR proofs still use scalar challenges:

```cpp
// range_proof.cpp:67-70
[[nodiscard]] int64_t ChallengeScalarFromDigest(const uint256& digest)
{
    return DeriveBoundedChallenge(digest, BIT_CHALLENGE_BOUND);  // BIT_CHALLENGE_BOUND = 60
}
```

The challenge scalar maps 256-bit hashes to [-60, 60] (121 values ≈ 6.9 bits). While the overall bit challenge `c_total` is a 256-bit hash, and the constraint `c0 + c1 = c_total` is over uint256, the *verification equation* only uses the scalar reduction: `A*z - c_scalar * statement`. Multiple different uint256 values map to the same scalar, so an adversary can find alternative `(c0, c1)` pairs that satisfy both the sum constraint and produce valid simulations for both branches.

**Impact:** An adversary could forge a range proof for an out-of-range value by searching for challenge collisions in the 121-value scalar space. Expected work per bit: ~2^7. Combined with 51 bits, the weakest link determines overall soundness at ~7 bits.

**Severity:** HIGH (not CRITICAL because exploiting this requires forging each of 51 bit proofs, and the balance proof provides an additional layer of protection — a forged range proof with wrong value would still fail the balance check unless the balance proof is also forged).

### Finding RS-R2-002 — HIGH: Balance proof soundness is ~23 bits

**Files:** `balance_proof.cpp:52-72`
**Status:** OPEN (from previous audit Finding 2, partially fixed)

The balance proof uses `ScalarFromTranscript()` which reduces a 256-bit hash to Z_q (q = 8,380,417 ≈ 2^23):

```cpp
// balance_proof.cpp:60
const uint64_t v = ReadLE64(sample.begin());
// ...
int64_t c = static_cast<int64_t>(v % q);
```

The Schnorr verification equation `Commit(0, response) == nonce_commitment + c * statement` has soundness bounded by the challenge space log₂(q) ≈ 22.9 bits. A motivated adversary can forge a balance proof with work ~2^23.

**Impact:** An adversary could forge a balance proof that claims inputs balance with outputs + fee, enabling **inflation attacks** (creating value from nothing). This requires only ~2^23 work.

**Severity:** HIGH (the ring signature's polynomial challenge binding via `ComputeProofChallenge` hashes all sub-proof transcripts together, providing an additional integrity check — but this binding only verifies that sub-proofs haven't been tampered with post-generation; it does not retroactively strengthen individual sub-proof soundness).

### Finding RS-R2-003 — MEDIUM: Rejection sampling acceptance rate analysis

**Files:** `ring_signature.cpp:773, 832-842`

With the updated parameters:
- α sampled from [-131072, 131072]
- c is a weight-60 ternary polynomial
- s has coefficients in [-2, 2]
- z = α + c·s has coefficients bounded by |α_i| + 60·2 = |α_i| + 120

Acceptance requires ||z||∞ ≤ 130952. Per-coefficient acceptance: (130952 × 2 + 1)/(131072 × 2 + 1) ≈ 0.99908.
Over 4 × 256 = 1024 coefficients: 0.99908^1024 ≈ 0.39 (39%).

This gives an average of ~2.6 attempts per input, which is acceptable but should be documented.

### Finding RS-R2-004 — SOUND: Ring signature challenge chain and polynomial challenges

The ring signature now correctly:
1. Uses `ChallengeFromDigest()` → `SampleChallenge()` for polynomial challenges (weight-60, >200-bit entropy)
2. Uses Fisher-Yates shuffle for constant-time challenge generation
3. Implements proper Lyubashevsky rejection sampling with positive gap
4. Uses per-member public key offsets for ring binding
5. Validates effective public key uniqueness
6. Cleanses secret material (alpha, secret, secret_ntt, z_real)

### Finding RS-R2-005 — SOUND: Commitment scheme

`Commit(v, r) = A*r + g*v (mod q)` with nothing-up-my-sleeve generators from domain-separated SHA-256 seeds. Computationally binding under Module-SIS, hiding under MLWE. Correct.

### Finding RS-R2-006 — SOUND: Key image and nullifier binding

Key images `KI = H(cm)·s` are deterministic. Nullifiers = SHA256("BTX_MatRiCT_RingSig_Nullifier_V1" || KI). Double-spend detection via `VerifyRingSignatureNullifierBinding()`. Duplicate key image rejection in `RingSignature::IsValid()`. Correct.

### Finding RS-R2-007 — SOUND: Cross-component proof binding

`ComputeProofChallenge` in `matrict.cpp:34-47` hashes ring signature challenge_seed, balance proof transcript, all range proof transcripts, note commitments, fee, and tx_binding_hash. This prevents mix-and-match attacks across sub-proofs.

---

## AUDIT 2: Side-Channel / Timing Assessment

### Previous Critical Timing Issues

| # | Previous Finding | Status | Detail |
|---|-----------------|--------|--------|
| T1 | Rejection loop leaks real signer index | **MITIGATED** | Loop still variable-time, but with MASKING_BOUND=131072 acceptance is ~39% per attempt — timing variation is much smaller. Still technically variable-time. |
| T2 | Secret bit controls branch in range proof | **FIXED** | `CtSwapBytes()` constant-time conditional swap replaces branching |
| T3 | `secret_ntt` never cleansed | **FIXED** | `CleansePolyVec(secret_ntt)` at ring_signature.cpp:899 |
| T4 | Range proof blinds not cleansed | **PARTIALLY FIXED** | `weighted_bit_blind_sum` and `nonce_blind` cleansed (line 460-461). `statement_blind` (line 442) and per-bit `bit_blind` still not explicitly cleansed |
| T5 | Balance proof blinds not cleansed | **FIXED** | `balance_blind` and `nonce_blind` cleansed (lines 193-194) |
| T6 | Range proof rejection loop count leaks | **MITIGATED** | With MASKING_BOUND=131072 and bit_blind eta=2, acceptance ~39% per bit — much less variation |
| T7 | `SampleChallenge` cache-observable | **FIXED** | Fisher-Yates shuffle replaces rejection-collision approach |
| T8 | `InfNorm` branching | **FIXED** | Constant-time arithmetic masking at poly.cpp:78-91 |
| T9 | Variable-time rejection on challenges | **ACCEPTABLE** | Public data, not secret-dependent |
| T10 | Plaintext vectors not cleansed | **FIXED** | `memory_cleanse(plaintext.data(), ...)` in note_encryption.cpp |
| T11 | SHA256 state after nullifier | **OPEN** | SHA256 internal state still not explicitly cleansed in note.cpp |
| T12 | `randrange` timing in `SampleSmall` | **OPEN** | `FastRandomContext::randrange()` may have variable timing |
| T13 | Direct modulo in `DeriveBoundedChallenge` | **FIXED** | Balance proof uses rejection-rehash. Range proof bit challenge still uses direct modulo but on public data |

### New Timing Findings

| # | Location | Issue | Severity |
|---|----------|-------|----------|
| T-R2-1 | `range_proof.cpp:442` | `statement_blind` not cleansed. This PolyVec contains the difference `opening.blind - weighted_bit_blind_sum`, which is equivalent to the balance secret. | **HIGH** |
| T-R2-2 | `range_proof.cpp:362-432` | Per-bit `bit_blind` allocated inside loop, goes out of scope without cleanse. 51 × MODULE_RANK × POLY_N = 52,224 secret coefficients left on stack. | **HIGH** |
| T-R2-3 | `ring_signature.cpp:773` | Rejection sampling loop (`MAX_REJECTION_ATTEMPTS=512`) is still variable-time. While ~39% acceptance rate reduces variation, the loop count still correlates with the real signer's secret via the challenge polynomial product `c·s`. | **MEDIUM** |
| T-R2-4 | `sampling.cpp:41-48` | `SampleSmall` uses `rng.randrange(eta+1)` twice per coefficient. `randrange` may branch on the bound value. With eta=2, `randrange(3)` — timing depends on internal rejection. | **LOW** |
| T-R2-5 | `note.cpp:24-39` | CSHA256 objects created on stack process spending_key material. Stack-allocated SHA256 internal state (64 bytes) not cleansed after `Finalize()`. | **LOW** |

---

## AUDIT 3: External Conformance Vectors and Adversarial Review

### KAT Vector Status

| Component | Has Deterministic KAT? | Independent Reference? | Previous Status | Current Status |
|-----------|----------------------|----------------------|-----------------|----------------|
| Ring Signature | Yes (pinned SHA-256) | No — self-referential | Same | **UNCHANGED** |
| MatRiCT Proof | Yes (pinned SHA-256) | No — self-referential | Same | **UNCHANGED** |
| Nullifier Derivation | Yes (pinned value) | No — self-referential | Same | **UNCHANGED** |
| Range Proof | **No** | N/A | Missing | **STILL MISSING** |
| Balance Proof | **No** | N/A | Missing | **STILL MISSING** |
| Commitment | **No** | N/A | Missing | **STILL MISSING** |

**Finding CV-R2-001 (HIGH):** No independent reference implementation exists. All KAT vectors are generated by the same code they test. A systematic error in NTT, domain separators, polynomial arithmetic, or commitment construction would be invisible. A Python/SageMath reference is critically needed.

### Adversarial Test Coverage (Updated)

| Attack Vector | Previous | Current |
|--------------|----------|---------|
| Tampered proof components | Yes | Yes (expanded with offset tamper) |
| Random forgery | Yes | Yes |
| Duplicate key images | Yes | Yes |
| Duplicate ring members | Yes | Yes (now rejected) |
| Null ring members | Not tested | **Now tested** |
| Effective PK collision | Not tested | **Now tested** |
| Zero input secret | Not tested | **Now tested** |
| Oversized input count | Not tested | **Now tested** |
| CTV shielded binding | Partial | **Full bundle commitment** |
| P2P deserialization DoS | Not tested | **Now tested** |
| ViewGrant overflow | Not tested | **Now tested** |
| Truncated proofs | Partial | Partial (unchanged) |
| Partial sub-proof substitution | **No** | **STILL MISSING** |
| Cross-transaction proof replay | **No** | **STILL MISSING** |
| Corrupted polynomial deserialize | **No** | **STILL MISSING** |
| Zero-value range proofs | **No** | **STILL MISSING** |
| All-zero proof vectors | **No** | **STILL MISSING** |
| Multi-input (3+) proofs | **No** | **STILL MISSING** |
| Commitment ordering sensitivity | **No** | **STILL MISSING** |

### Finding CV-R2-002 (HIGH): Missing adversarial tests for critical attack vectors

The following attack vectors remain untested:
1. **Partial sub-proof substitution**: Replace ring_signature in valid MatRiCT proof with different valid ring_signature — should fail `ComputeProofChallenge` binding
2. **Cross-transaction proof replay**: Reuse proof from tx A in tx B — should fail tx_binding_hash
3. **Zero-value range proofs**: value=0 is a valid edge case that exercises different code paths
4. **Multi-input (3+)**: Only 1 and 2 inputs tested; 3+ inputs may expose indexing bugs

---

## Deep Scan: External Function Gaps and Scalability

### Function Gaps

| # | Location | Issue | Severity |
|---|----------|-------|----------|
| FG-1 | `spend_auth.cpp:21-27` | Creates "stripped" tx copy and clears proof/ring data — this duplicates identical logic in `matrict.cpp:65-70` (`ComputeMatRiCTBindingHash`). The two stripping operations should be unified to prevent divergence. | **LOW** |
| FG-2 | `nullifier.cpp:70-72` | Cache eviction is `m_cache.clear()` — all-or-nothing flush. Under steady-state insertion just above 2M, every block clears the entire cache, causing a performance cliff. | **HIGH** |
| FG-3 | `merkle_tree.cpp:172-188` | `Truncate()` rebuilds from scratch: O(n) appends where n = new_size. For deep reorgs (depth ~100, ~1000 commitments removed), this triggers O(n) SHA-256 hashes. Acceptable for current scale but not for millions of leaves. | **MEDIUM** |

### Scalability Assessment (Updated)

| Component | Previous | Current | Notes |
|-----------|----------|---------|-------|
| Nullifier cache | Hard 2M cliff | **STILL HARD 2M CLIFF** | No LRU eviction added |
| Nullifier hash | SipHash now | **FIXED** | `NullifierHasher` uses SipHash with random salt |
| Merkle tree truncation | O(n log n) rebuild | O(n) rebuild | Correct but expensive at scale |
| Proof size | ~30KB per output | ~30KB per output | Unchanged — inherent to lattice proofs |
| Proof verification | Parallelized | Parallelized | Good design via check queues |

---

## Deep Scan: Security Vulnerabilities Across Full Codebase

### Consensus Safety

| # | Issue | Severity |
|---|-------|----------|
| CS-1 | Balance proof soundness ~23 bits enables inflation with ~2^23 work | **HIGH** |
| CS-2 | Range proof soundness ~7 bits per bit enables out-of-range values | **HIGH** |
| CS-3 | `value_balance` overflow: `sum_in += opening.value` in `balance_proof.cpp:146` — no overflow check on CAmount addition | **MEDIUM** |

### Memory Safety

| # | Location | Issue | Severity |
|---|----------|-------|----------|
| MS-1 | `proof_encoding.h:231` | `accumulator |= ... << accumulator_bits` — if `accumulator_bits` reaches 41+ (23-bit coeff + 18-bit carry), the `uint64_t` shift could theoretically overflow. Analysis: max accumulator_bits before drain is 23+7=30, safe. | **None** (verified safe) |
| MS-2 | `range_proof.cpp:169` | `int64_t * int64_t` multiplication in `PolyVecScaleCentered`: `vec[i].coeffs[j] * scalar` where scalar can be up to `POLY_Q-1 ≈ 8.4M` and coeff up to `MASKING_BOUND ≈ 131072`. Product ≈ 1.1 × 10^12, well within int64 range. | **None** (verified safe) |

### Network/DoS

| # | Location | Issue | Severity |
|---|----------|-------|----------|
| ND-1 | `validation.cpp:32-33` | `commitment_cache.reserve(inputs * RING_SIZE)` — with MAX_SHIELDED_SPENDS_PER_TX inputs and RING_SIZE=16, this could be large but is bounded by tx size limits. | **LOW** |
| ND-2 | `ring_signature.cpp:773` | `MAX_REJECTION_ATTEMPTS=512` × expensive NTT operations per input. For a valid 128-input transaction, worst case ~65536 NTT rounds. Bounded by MAX_RING_SIGNATURE_INPUTS=128 and timeouts. | **MEDIUM** |

---

## COMPLETE UPDATED TASK LIST

### P0 — CRITICAL (Merge blockers)

| # | Task | Files | Status |
|---|------|-------|--------|
| 1 | ~~Resolve rejection sampling negative gap~~ | `params.h`, `ring_signature.cpp` | **FIXED** |
| 2 | ~~Fix range proof masking nonce~~ | `range_proof.cpp` | **FIXED** |
| 3a | ~~Switch ring sig to polynomial challenges~~ | `ring_signature.cpp`, `sampling.cpp` | **FIXED** |
| 3b | **Switch range proof to polynomial challenges** | `range_proof.cpp` | **OPEN** |
| 3c | **Switch balance proof to polynomial challenges** | `balance_proof.cpp` | **OPEN** |
| 4 | **Produce independent reference vectors** | New `test/reference/` | **OPEN** |
| 5 | **Add deterministic KAT for range/balance/commitment** | Test files | **OPEN** |
| 6 | ~~Fix ring member uniqueness~~ | `ring_signature.cpp`, `validation.cpp` | **FIXED** |
| 7 | ~~Eliminate secret-dependent branching in range proof~~ | `range_proof.cpp` | **FIXED** |

### P1 — HIGH (Must fix before production)

| # | Task | Files | Status |
|---|------|-------|--------|
| 8 | **Cleanse `statement_blind` in range proof** | `range_proof.cpp:442` | **OPEN** |
| 9 | **Cleanse per-bit `bit_blind` in range proof** | `range_proof.cpp:362-432` | **OPEN** |
| 10 | **Add adversarial test suite** — partial sub-proof substitution, cross-tx replay, zero-value, multi-input | Test files | **OPEN** |
| 11 | **Implement nullifier cache LRU eviction** | `nullifier.cpp` | **OPEN** |
| 12 | Add constant-time rejection sampling (fixed iterations) | `ring_signature.cpp`, `range_proof.cpp` | **OPEN** |

### P2 — MEDIUM (Must fix before mainnet)

| # | Task | Files | Status |
|---|------|-------|--------|
| 13 | Add proof deserialization fuzzing | New fuzz targets | **OPEN** |
| 14 | Document threat model and parameter derivation | Documentation | **OPEN** |
| 15 | Add Merkle tree thread-safety annotations | `merkle_tree.h` | **OPEN** |
| 16 | Add multi-input (3+) MatRiCT proof tests | Test files | **OPEN** |
| 17 | Add deep reorg functional tests | Functional tests | **OPEN** |
| 18 | Add scalability benchmarks at production volume | Bench files | **OPEN** |

### P3 — LOW (Recommended hardening)

| # | Task | Files | Status |
|---|------|-------|--------|
| 19 | Cleanse SHA256 state after spending key processing | `note.cpp` | **OPEN** |
| 20 | Add `mlock()` for secret key buffers | `ring_signature.cpp` | **OPEN** |
| 21 | Unify tx stripping logic (spend_auth + matrict) | `spend_auth.cpp`, `matrict.cpp` | **OPEN** |

---

## Summary

| Priority | Total | Fixed | Open |
|----------|-------|-------|------|
| **P0 — Critical** | 7 | **4** | **3** |
| **P1 — High** | 5 | 0 | **5** |
| **P2 — Medium** | 6 | 0 | **6** |
| **P3 — Low** | 3 | 0 | **3** |
| **Total** | 21 | **4** | **17** |

### Verdict: Significant Progress, Not Yet Ready to Merge

The remediation effort has been substantial and effective:
- The **rejection sampling crisis** is fully resolved (positive gap, Signed24 serialization)
- The **ring signature** now uses proper polynomial challenges with >200-bit entropy
- The **range proof branching** is now constant-time via `CtSwapBytes()`
- **Ring member validation** is comprehensive (null rejection, duplicate rejection, effective PK uniqueness)
- **Memory cleansing** is significantly improved

However, **two fundamental soundness issues remain**:
1. Range proof bit-level OR proofs have only ~7-bit soundness (scalar challenges)
2. Balance proof has only ~23-bit soundness (scalar challenge mod q)

These must be elevated to use polynomial challenges (the infrastructure exists via `SampleChallenge()`) before the proof system achieves the >128-bit security target claimed by MatRiCT+. Additionally, independent conformance vectors remain absent.
