# BTX Shielded Pool — Formal Audit Report

Status note (2026-03-24): this audit records the March 5 prelaunch snapshot.
Parameter values and benchmarks inside it are historical, not the current
merged-main launch surface. Current `main` defaults to shielded ring size `8`,
supports configured rings `8..32` on the same wire surface, and the current
benchmark baseline lives in `doc/btx-shielded-production-status-2026-03-20.md`.

**Date:** 2026-03-05
**Branch under review:** `codex/shielded-pool-overhaul`
**Scope:** 50 commits, 220 files changed, ~29,600 lines added
**Auditor:** Independent review of ring-signature security, side-channel/timing, and conformance vectors

---

## Executive Summary

This branch implements a complete lattice-based shielded pool (confidential transactions with ring signatures) for the BTX blockchain. The architecture and design intent are sound, but the **parameter choices create a critical mismatch** between the implementation and the MatRiCT+ security model it claims to follow. Seven P0-critical issues must be resolved before merge consideration.

---

## What This Branch Enables

### Shielded (Private) Transactions
- Users can **shield** transparent coins into a private pool and **unshield** them back
- Shielded-to-shielded transfers hide sender, receiver, and amount
- Uses a **turnstile** mechanism to track total pool balance and prevent inflation

### Post-Quantum Cryptographic Foundation
- **ML-KEM-768** (NIST-standardized) for note encryption (key encapsulation)
- **Lattice-based ring signatures** (MLWE) instead of elliptic-curve-based ones
- **MatRiCT+ proof system** combining ring signatures, range proofs, and balance proofs into a single unified proof
- All built on polynomial ring arithmetic over `R_q = Z_q[X]/(X^256+1)` using NTT from the Dilithium reference

### Full Protocol Stack
- **Note commitments** with domain-separated SHA-256
- **Nullifier set** (LevelDB-backed with 2M-entry in-memory cache) for double-spend prevention
- **Incremental Merkle tree** (depth 32, frontier-based, Zcash-style) for commitment storage
- **View grants** for selective disclosure to auditors
- **Ring member selection** using a gamma distribution biased toward recent outputs

### Wallet, RPC, and P2P Integration
- Full wallet with `z_getnewaddress`, `z_shieldfunds`, `z_mergenotes`, `z_viewtransaction`, etc.
- P2P relay with version-gated shielded data propagation and rate limiting
- Mempool nullifier conflict detection
- Reorg handling with defensive rebuild-on-mismatch pattern
- Height-based hard activation

---

## AUDIT 1: Ring-Signature Security Argument vs MatRiCT+ Assumptions

### Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| `POLY_Q` | 8,380,417 | Dilithium-2 |
| `POLY_N` | 256 | Dilithium-2 |
| `MODULE_RANK` | 4 | Dilithium-2 (NIST Level 2) |
| `BETA_CHALLENGE` | 60 | Weight-60 ternary challenge |
| `GAMMA_RESPONSE` | 131,072 (2^17) | Response masking bound |
| `RESPONSE_NORM_BOUND` | **127** (clamped to int8 max) | `min(131012, 127)` |
| `RING_SIZE` | 16 | Anonymity set |
| `VALUE_BITS` | 51 | Covers MAX_MONEY ~ 2.1x10^15 |
| `SECRET_SMALL_ETA` | 4 | Secret coefficients in [-4, 4] |

### Finding 1 — CRITICAL: Rejection sampling efficiency crisis / anonymity break

**Files**: `ring_signature.cpp:39-41, 648-700`

`GAMMA_RESPONSE = 131072` is declared but entirely overridden by the `int8_t` serialization bound, making `RESPONSE_NORM_BOUND = 127`. The real member's response `z = alpha + c*s` has coefficients up to `|127 + 60*4| = 367`, but is rejected unless `|z| <= 127`.

The standard Lyubashevsky rejection gap is `gamma - beta*eta = 127 - 240 = -113` (negative). Signing only succeeds when the chain-closure challenge `c` happens to be near zero. When `c = 0` (probability 1/121), `z = alpha` is trivially independent of the secret — but the real signer's position becomes **identifiable** as the member whose challenge scalar is zero or near-zero. This breaks ring signature anonymity.

### Finding 2 — CRITICAL: Scalar challenges vs polynomial challenges (soundness gap)

**Files**: `sampling.cpp:85-99`, `ring_signature.cpp:45-68`

The function `SampleChallenge` correctly implements polynomial challenges with Hamming weight 60 (challenge space `C(256,60) * 2^60 > 2^200`). However, **this function is declared and implemented but never called**. All three sub-protocols use scalar challenges:

- Ring signature: `ChallengeScalarFromDigest` → integers in [-60, 60] (~6.9 bits)
- Balance proof: `ScalarFromTranscript` → integers in [1, q-1) (~22.9 bits)
- Range proof: Same scalar approaches

The MatRiCT+ security proof requires polynomial challenges. The forking lemma reduction with scalar challenges loses ~7 bits, and the balance proof's standalone soundness is only ~23 bits.

### Finding 3 — CRITICAL: Range proof masking nonce destroys confidentiality

**Files**: `range_proof.cpp:88-95, 316-346`

The range proof's `SampleBoundedResponse` calls `SampleSmallVec(rng, MODULE_RANK, eta=4)`, producing masking nonces in **[-4, 4]**. This is a *different function* from the ring signature's identically-named function (which samples from [-127, 127]), hidden in a separate anonymous namespace.

With bit blinds of `eta=2` and challenges in [-60, 60], the response `z = y + c*blind` has `|z_i| <= 4 + 120 = 124`. The masking range [-4, 4] is dwarfed by the secret contribution [-120, 120]. The response is almost entirely determined by `c * blind`, **leaking the blinding factor to within ±4**. An observer can reconstruct each committed bit value and learn the exact transaction amount. This completely breaks range proof confidentiality.

### Finding 4 — SOUND: Challenge chain closure

Verification at `ring_signature.cpp:347-382` correctly checks a circular Fiat-Shamir challenge chain. Each member's `(w, u)` pair deterministically produces the next member's challenge. The closure prevents forgery without knowledge of the secret.

### Finding 5 — SOUND: Key image linkability

Key images `KI = H(cm) * s` are deterministic for a given note and spending key. Nullifiers are `SHA256(tag || KI)`. Double-spending produces identical nullifiers, caught by the nullifier set. `VerifyRingSignatureNullifierBinding` correctly checks match and uniqueness.

### Finding 6 — SOUND: Public key offset binding

`offset = A*s - pk_derived`. Verifier computes `effective_pk = pk_derived + offset = A*s`. Correctly binds the signer's witness without revealing which ring member is real.

### Finding 7 — SOUND: Cross-component binding in MatRiCT

`ComputeProofChallenge` hashes `ring_signature.challenge_seed`, `balance_proof.transcript_hash`, all range proof transcript hashes, note commitments, fee, and `tx_binding_hash`. Prevents mix-and-match attacks.

### Finding 8 — SOUND: Commitment scheme

`Commit(v, r) = A*r + g*v (mod q)` with nothing-up-my-sleeve generators. Computationally binding under Module-SIS, hiding under MLWE. Homomorphic operations correctly apply modular reduction.

---

## AUDIT 2: Side-Channel / Timing Assessment

### Critical Vulnerabilities

| # | Location | Issue | Severity |
|---|----------|-------|----------|
| T1 | `ring_signature.cpp:648-746` | Rejection sampling loop count leaks real signer index via wall-clock timing. Each iteration involves O(RING_SIZE) NTT operations (~50μs), making variation measurable. | **Critical** |
| T2 | `range_proof.cpp:301-358` | Secret bit value directly controls branch assignment (`if real_branch == 0`). Each of 51 bit positions executes a conditional branch controlled by a secret bit of the committed value. Branch-prediction attacker recovers all 51 bits. | **Critical** |

### High Vulnerabilities

| # | Location | Issue | Severity |
|---|----------|-------|----------|
| T3 | `ring_signature.cpp:619` | `secret_ntt` (NTT of spending-key-derived secret) is never cleansed. Also `alpha` (line 651) and `z_real` (line 698). | **High** |
| T4 | `range_proof.cpp:293-377` | Blinding factors `bit_blind`, `weighted_bit_blind_sum`, `statement_blind`, `nonce_blind` never cleansed | **High** |
| T5 | `balance_proof.cpp:100-136` | `balance_blind`, `nonce_blind`, and `blinds` vector never cleansed | **High** |
| T6 | `range_proof.cpp:316-361` | Rejection loop count leaks blinding factor norms. 51 independent measurements. | **High** |
| T7 | `sampling.cpp:85-99` | `SampleChallenge` uses rejection-based position selection with cache-line-observable array access patterns | **High** |

### Medium Vulnerabilities

| # | Location | Issue | Severity |
|---|----------|-------|----------|
| T8 | `poly.cpp:80-90` | `InfNorm` uses `std::abs`/`std::max` with potential branching on secret data | **Medium** |
| T9 | `ring_signature.cpp:45-63` | `DeriveBoundedChallengeScalar` variable-time rejection on public challenges | **Medium** |
| T10 | `note_encryption.cpp:116, 74` | Decrypted/encrypted plaintext vectors never cleansed (note value persists in heap) | **Medium** |
| T11 | `note.cpp:42-54` | SHA256 internal state not cleansed after nullifier computation | **Medium** |
| T12 | `sampling.cpp:40-49` | `randrange` timing variation in `SampleSmall` | **Medium** |
| T13 | `range_proof.cpp:29-34` | `DeriveBoundedChallenge` uses direct modulo (no rejection) — inconsistent with ring sig approach | **Medium** |

### Positive Findings
- NTT/InverseNTT (Dilithium reference): Fully constant-time butterfly operations
- Montgomery reduction, `reduce32`, `caddq`: All branchless/constant-time
- Polynomial arithmetic (`+`, `-`, `PointwiseMul`): Fixed iteration, no branches
- Note encryption: Proper `memory_cleanse` on AEAD keys and shared secrets
- Spend auth hash: No secret data involvement

---

## AUDIT 3: External Conformance Vectors and Adversarial Review

### KAT Vector Assessment

| Component | Has Deterministic KAT? | Independent Reference? |
|-----------|----------------------|----------------------|
| Ring Signature | Yes (pinned SHA-256) | No — self-referential |
| MatRiCT Proof | Yes (pinned SHA-256) | No — self-referential |
| Nullifier Derivation | Yes (pinned value) | No — self-referential |
| Range Proof | **No** | N/A |
| Balance Proof | **No** | N/A |
| Commitment | **No** | N/A |

All existing KAT hashes were generated by the same code they test. A systematic error in NTT, domain separators, or polynomial arithmetic would be invisible.

### Adversarial Test Coverage

| Attack Vector | Tested? | Details |
|--------------|---------|---------|
| Tampered proof components | Yes | Responses, challenges, offsets, key images |
| Random forgery | Yes | Single + 32-trial Monte Carlo |
| Duplicate key images | Yes | Creation and verification |
| Duplicate ring members | Yes | Rejected at creation |
| Truncated proofs | Partial | 1-byte proof tested at validation layer only |
| Partial sub-proof substitution | **No** | Never tested |
| Cross-transaction proof replay | **No** | tx_binding_hash mechanism untested |
| Corrupted polynomial deserialize | **No** | ModQ23/Signed8 adversarial inputs untested |
| Zero-value edge cases | **No** | value=0 range proof untested |
| All-zero proof vectors | **No** | Untested |
| Multi-input (3+) proofs | **No** | Only 1 and 2 inputs tested |
| Commitment ordering sensitivity | **No** | Swapped input/output order untested |

### Documentation Gaps
- Audit handoff claims "deterministic conformance vectors available" but omits that range/balance proofs have none
- Parameters are Dilithium parameters, not original MatRiCT+ paper parameters — no mapping justification
- `VALUE_BITS=51` and `RING_SIZE=16` choices not justified
- Serialization format (Signed8, Signed16, ModQ23, ModQ24) not documented
- No threat model section

---

## Scalability Assessment

| Component | Issue | Severity |
|-----------|-------|----------|
| **Nullifier cache** | Hard 2M-entry cutoff with no eviction — creates performance cliff where every lookup hits LevelDB | **High** |
| **Nullifier hash function** | Uses only first 8 bytes of 256-bit nullifier — unnecessary collision concentration | **Medium** |
| **Merkle tree truncation** | O(n log n) rebuild from scratch — expensive for deep reorgs | **Medium** |
| **Proof size** | Range proofs ~30KB per output, full MatRiCT proofs <600KB — large but bounded | **Low** |
| **Anchor lookup** | Linear search over 100-entry deque — fine | **None** |
| **Proof verification** | Parallelized via dedicated check queue — good design | **None** |

---

## Consensus and Wallet Integration Assessment

### Consensus Safety (Fork Risk): MEDIUM
- Value balance arithmetic with overflow checks
- Nullifier uniqueness enforced at tx and block level
- Height-based activation with proper early-rejection
- ConnectBlock state updates are conditional and atomic
- **Risk**: Hard activation requires 100% upgrade coordination

### Wallet Correctness (Reorg Handling): MEDIUM-LOW
- Automatic rebuild-on-mismatch pattern prevents state corruption
- Proper nested locking with `cs_wallet` and `cs_shielded`
- Conservative witness invalidation on disconnect
- **Risk**: Complex tree truncation depends on Merkle tree implementation correctness

### DoS Resistance (P2P): MEDIUM
- Proof verification parallelized via dedicated check queues
- Rate-limited shielded data relay
- Transaction size limits enforced (2MB max)
- **Risk**: Expensive proof verification could saturate thread pools under load

---

## COMPLETE TASK LIST

### P0 — CRITICAL (Merge blockers)

| # | Task | Files | Issue |
|---|------|-------|-------|
| 1 | **Resolve rejection sampling efficiency / anonymity break** — change response serialization to Signed16 and raise `RESPONSE_NORM_BOUND` to `GAMMA_RESPONSE - BETA_CHALLENGE * SECRET_SMALL_ETA - slack ≈ 130,576` | `params.h`, `ring_signature.cpp`, `range_proof.cpp`, `proof_encoding.h` | NORM_BOUND=127 yields negative gap; signing only works on near-zero challenges, breaking anonymity |
| 2 | **Fix range proof masking nonce** — replace `SampleSmallVec(eta=4)` in range proof's `SampleBoundedResponse` with uniform sampling from `[-NORM_BOUND, NORM_BOUND]` | `range_proof.cpp:88-95` | Masking range [-4,4] is dwarfed by secret contribution [-120,120], destroying value confidentiality |
| 3 | **Switch from scalar to polynomial challenges** — replace `ChallengeScalarFromDigest`/`ScalarFromTranscript` with calls to existing `SampleChallenge`; update verification equations to polynomial multiplication | `ring_signature.cpp`, `range_proof.cpp`, `balance_proof.cpp` | `SampleChallenge` exists but is never called; scalar challenges provide only 7-23 bits vs >128 bits needed |
| 4 | **Produce independent reference vectors** — Python/SageMath script computing `Commit(v,b)`, `ComputeNullifierFromKeyImage`, `RingSignatureMessageHash`, `DeriveSecretVec` for known inputs | New `test/reference/generate_vectors.py`, update tests | All KAT vectors are self-referential — systematic bugs invisible |
| 5 | **Add deterministic KAT vectors for range proofs, balance proofs, and commitments** | `ringct_range_proof_tests.cpp`, `ringct_balance_proof_tests.cpp`, `ringct_commitment_tests.cpp` | No pinned outputs exist for these components |
| 6 | **Fix ring member uniqueness validation** — require all positions distinct | `validation.cpp` (~lines 43-63) | Ring with 15/16 identical positions reduces anonymity set to 2 |
| 7 | **Eliminate secret-dependent branching in range proof** — replace `if (real_branch == 0)` with constant-time conditional swap | `range_proof.cpp:301-302, 324-330, 348-358` | Each value bit leaked through branch prediction |

> **Note**: Items 1, 2, and 3 are interdependent and must be addressed as a single coordinated change. The existing `SerializePolyVecSigned16` in `proof_encoding.h` and `SampleChallenge` in `sampling.cpp` provide the necessary infrastructure. All domain-separation version tags must be incremented to reject old proofs.

### P1 — HIGH (Must fix before production deployment)

| # | Task | Files | Issue |
|---|------|-------|-------|
| 8 | **Add constant-time rejection sampling** — run fixed iterations with dummy ops, select first valid via constant-time conditional assignment | `ring_signature.cpp:648-746`, `range_proof.cpp:316-361` | Variable loop count leaks secret information |
| 9 | **Add `memory_cleanse` for all uncleansed secret vectors** — `secret_ntt`, `alpha`, `z_real`, `bit_blind`, `weighted_bit_blind_sum`, `statement_blind`, `nonce_blind`, `balance_blind`, `blinds`, encryption/decryption `plaintext` | `ring_signature.cpp`, `range_proof.cpp`, `balance_proof.cpp`, `note_encryption.cpp` | Secret-derived data persists in stack/heap memory |
| 10 | **Make `SampleChallenge` constant-time** — use Fisher-Yates shuffle instead of rejection-based collision avoidance | `sampling.cpp:85-99` | Cache-timing side channel on challenge polynomial structure |
| 11 | **Add 100+ adversarial proof verification tests** — truncated proofs, wrong ring size, zero-value range proofs, MAX_MONEY+1, forged balance with wrong fee, partial sub-proof substitution, cross-tx replay, all-zero vectors | `shielded_validation_checks_tests.cpp` | Only 2 test cases for ZK proof verification |
| 12 | **Add boundary-value range proof tests** — roundtrips for value=0, 1, 2^50, 2^51-1, MAX_MONEY; rejection for -1, 2^51, MAX_MONEY+1 | `ringct_range_proof_tests.cpp` | No boundary-value testing exists |
| 13 | **Add cross-transaction proof replay test** | `shielded_validation_checks_tests.cpp` | `tx_binding_hash` mechanism completely untested |
| 14 | **Add partial sub-proof substitution tests** — in valid MatRiCT proof, replace individual sub-proofs with zeroed or differently-valid proofs | `ringct_matrict_tests.cpp` | No tests probe cross-component binding |
| 15 | **Fix `ComputeShieldedSpendAuthSigHash` stripping** — implement actual stripping or remove unnecessary copy | `spend_auth.cpp` | Creates "stripped" tx copy but never strips anything |
| 16 | **Implement nullifier cache LRU eviction** | `nullifier.cpp` | 2M-entry hard cutoff creates performance cliff |
| 17 | **Improve nullifier hash function** — XOR first 8 bytes with last 8, or use SipHash | `nullifier.h` | Only first 8 bytes used, causing collision concentration |

### P2 — MEDIUM (Must fix before mainnet launch)

| # | Task | Files | Issue |
|---|------|-------|-------|
| 18 | **Add proof deserialization fuzzing** — libfuzzer targets for packed format deserializers | New `src/test/fuzz/` targets | No fuzzing for complex bitpacking in `proof_encoding.h` |
| 19 | **Add constant-time `InfNorm`** — use arithmetic masking instead of `std::abs`/`std::max` | `poly.cpp:80-90` | Branch prediction leak on secret data |
| 20 | **Add deep reorg functional tests** — depth approaching SHIELDED_ANCHOR_DEPTH (100) | `wallet_shielded_reorg_recovery.py` | Only shallow reorgs tested |
| 21 | **Add scalability benchmarks at production volume** — NullifierSet 1M+, Merkle tree 1M+ leaves, parallel verification throughput | New `src/bench/` files | Current tests use 1K nullifiers and 10K leaves |
| 22 | **Add privacy property tests for ring selection** — chi-squared for real-index uniformity, KS test for gamma conformance | `ring_selection_tests.cpp` | Determinism tested but not privacy guarantees |
| 23 | **Document threat model and security assumptions** — adversary model, MLWE security level, parameter derivation, serialization format, timing leak rationale | `btx-shielded-cryptographic-audit-handoff.md` | Missing critical documentation |
| 24 | **Add Merkle tree thread-safety annotations** — `std::mutex` or `EXCLUSIVE_LOCKS_REQUIRED` | `merkle_tree.h` | `Append()` not thread-safe; easy to misuse |
| 25 | **Add multi-input (3+) MatRiCT proof tests** — 3-in/3-out and 4-in/1-out | `ringct_matrict_tests.cpp` | Only 1 and 2 inputs tested |
| 26 | **Rename misleading test** — `checktransaction_accepts_shield_only_negative_value_balance` only tests structural acceptance | `shielded_tx_check_tests.cpp` | Name implies validation coverage it doesn't provide |

### P3 — LOW (Recommended hardening)

| # | Task | Files | Issue |
|---|------|-------|-------|
| 27 | **Add `mlock()` for secret key buffers** | `ring_signature.cpp` | Secret PolyVec allocations could be swapped to disk |
| 28 | **Add balance proof fee=0 test** | `ringct_balance_proof_tests.cpp` | Pure transfer case untested |
| 29 | **Consider soft-fork activation mechanism** | `consensus/params.h`, `validation.cpp` | Hard activation requires 100% upgrade or chain fork |
| 30 | **Add commitment ordering sensitivity tests** | `ringct_matrict_tests.cpp` | Swapped input/output order untested |
| 31 | **Cleanse SHA256 internal state after spending key processing** | `note.cpp` | Residual spending key info in stack |

---

## Summary

| Priority | Count | Description |
|----------|-------|-------------|
| **P0 — Critical** | **7** | Merge blockers |
| **P1 — High** | **10** | Pre-production deployment |
| **P2 — Medium** | **9** | Pre-mainnet launch |
| **P3 — Low** | **5** | Hardening |
| **Total** | **31** | |

### Verdict: Not Ready to Merge

The architecture and design are sound — this is serious, well-structured work implementing a complete post-quantum shielded pool. However:

1. **The rejection sampling gap is negative**, causing signing to only succeed on near-zero challenges, which breaks anonymity.
2. **The range proof masking nonce is too small**, leaking transaction amounts through the response distribution.
3. **Polynomial challenges exist in the code but are never called**, leaving only 7-23 bit scalar challenges instead of the >128-bit polynomial challenges required by MatRiCT+.
4. **All KAT vectors are self-referential** with no independent validation.
5. **Test coverage is insufficient** for a privacy-critical consensus feature (2 proof verification tests).

Items 1-3 are interdependent and should be resolved as a single coordinated parameter/protocol change. The existing `SerializePolyVecSigned16` and `SampleChallenge` infrastructure already in the codebase provides the foundation for the fix. After resolution, the scheme would achieve ~15% acceptance rate (~7 attempts average), >128-bit challenge entropy, and proper zero-knowledge from wide masking distributions — fully aligning with the published MatRiCT+ security proof.
