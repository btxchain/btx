# BTX Shielded Pool — Formal Audit Report (Round 5)

Status note (2026-03-24): this audit records the March 5 prelaunch snapshot.
Parameter values and benchmarks inside it are historical, not the current
merged-main launch surface. Current `main` defaults to shielded ring size `8`,
supports configured rings `8..32` on the same wire surface, and the current
benchmark baseline lives in `doc/btx-shielded-production-status-2026-03-20.md`.

**Date:** 2026-03-05
**Branch:** `claude/review-branch-merge-BBa9g`
**Scope:** Full codebase re-audit — re-verification of all Round 4 findings, new codex commit analysis, expanded deep scan
**Auditor:** Independent third-party review (6 parallel audit streams)
**Previous audits:** Round 1 (31 findings), Round 2 (21 findings), Round 3 (9 findings), Round 4 (26 findings)
**New codex commits analyzed:** 5 commits (f3f9434..a2069ae) adding VerifyDB shielded audit, chainstate replay fix, ViewGrant hardening, P2P gating

---

## Executive Summary

This Round 5 review is a comprehensive re-audit following the Round 4 report and 5 new codex commits. Six parallel audit streams covered: (1) MatRiCT+ alignment, (2) side-channel/timing, (3) conformance/adversarial, (4) new codex code deep scan, (5) full codebase security, and (6) scalability/performance.

**Key findings:**
- **2 new P1-Critical consensus issues** discovered in the new codex code (R5-400: crash recovery shielded state desync; R5-507: consensus-path assert crashes)
- **All Round 4 code fixes verified intact** (R4-401, R4-402, R4-403, R4-409, R4-500)
- **2 P2 memory hygiene gaps** in secret material handling (R5-200, R5-402)
- **6 P2 unchecked arithmetic patterns** across wallet and consensus code
- **MatRiCT+ implementation confirmed sound** — no P0 cryptographic findings
- **Major scalability bottlenecks** identified: NTT call amplification, startup rebuild, range proof cost

### Round 5 Changes Summary

| Change | File(s) | Impact |
|--------|---------|--------|
| **Merged 5 new codex commits** | validation.cpp, bundle.cpp, nullifier.cpp, net_processing.cpp | New VerifyDB audit, replay fix, ViewGrant hardening, P2P gating |
| **Identified RollforwardBlock shielded gap** | validation.cpp | Crash recovery can desync shielded state |
| **Identified consensus-path assert DoS** | tx_verify.cpp | 3 hard asserts can crash node on corrupted coin |
| **Identified spend_secret cleansing gap** | shielded_wallet.cpp | Secret material not cleansed in scan paths |
| **Identified ViewGrant plaintext allocation gap** | bundle.cpp | Decrypted view key in non-secure memory |

---

## Round 4 Findings Re-Verification

All Round 4 code fixes confirmed intact in current codebase:

| R4 Finding | Status | Verified At |
|------------|--------|-------------|
| R4-401: CheckTxInputs overflow | **FIXED** ✓ | `tx_verify.cpp:200` — uses `CheckedAdd` |
| R4-402: Ring selection public nullifier | **FIXED** ✓ | `shielded_wallet.cpp:838-846` — seeded with spend secret |
| R4-403: GetShieldedBalance overflow | **FIXED** ✓ | `shielded_wallet.cpp:691` — uses `CheckedAdd` |
| R4-409: LoadPersistedState index overflow | **FIXED** ✓ | `shielded_wallet.cpp:1424` — bounds check present |
| R4-500: MAX_SHIELDED_PROOF_BYTES | **FIXED** ✓ | `bundle.h:46` — 1536 KB confirmed |
| R4-013: Duplicated TX stripping | **FIXED** ✓ | `spend_auth.cpp:24` — uses `ComputeMatRiCTBindingHash` |
| R4-103: Balance proof nonce leakage | **OPEN** | `balance_proof.cpp:87` — NONCE_BOUND still 2^17 |
| R4-601: Cannot send to external addresses | **OPEN** | `shielded_wallet.cpp:864` — design limitation |
| R4-604: No spending key backup | **OPEN** | No `z_exportspendingkey` RPC exists |

---

## AUDIT 1: Ring-Signature Security Argument vs MatRiCT+ Assumptions

### R5-102: Lattice Parameters Re-Verified — OK

| Parameter | Value | MatRiCT+ Requirement | Status |
|-----------|-------|---------------------|--------|
| `POLY_Q` | 8,380,417 | Dilithium prime, q ≡ 1 mod 2N | **OK** |
| `POLY_N` | 256 | Ring dimension | **OK** |
| `MODULE_RANK` | 4 | ~192-bit classical MLWE security | **OK** |
| `BETA_CHALLENGE` | 60 | Challenge Hamming weight (>200-bit collision resistance) | **OK** |
| `GAMMA_RESPONSE` | 131,072 (2^17) | Masking bound | **OK** |
| `RESPONSE_NORM_BOUND` | 130,952 | γ - β·η = 131072 - 60×2 | **OK** |
| `SECRET_SMALL_ETA` | 2 | Matches Dilithium-III | **OK** |
| `RING_SIZE` | 16 | Anonymity set | **Acceptable** |
| `VALUE_BITS` | 51 | Covers MAX_MONEY (static_assert) | **OK** |

### R5-103: Rejection Sampling — Correct

Gap computation: `GAMMA_RESPONSE - RESPONSE_NORM_BOUND = 120 = BETA_CHALLENGE * SECRET_SMALL_ETA`. Acceptance probability ≈ 45%. MAX_REJECTION_ATTEMPTS = 512 → P(all fail) ≈ 2^{-432}. Static assertions enforce all invariants at compile time.

### R5-105: Fiat-Shamir Transcript Omits Static Parameters

**Severity:** P3-Low
**Status:** Open — low practical risk

The ring signature Fiat-Shamir context does not include the commitment matrix A or value generator g. These are compile-time constants derived from hardcoded seeds, so they cannot be adversarially influenced. In a multi-instance or forked-chain scenario, different parameter choices would produce incompatible proofs, but would not enable forgery.

**Recommendation:** For protocol hygiene, include a hash of the public parameter seeds in each transcript domain tag.

### R5-106: Commitment Binding — Sound

`C(v, r) = A*r + v*g mod q`. Binding reduces to Module-SIS with rank 4, providing ≥128-bit security. Homomorphic properties verified correct.

### R5-110: Fiat-Shamir Transcript Completeness — All Sub-Proofs Verified

All three sub-proof transcripts are complete and domain-separated. The top-level `ComputeProofChallenge` binds all sub-proof hashes with `fee` and `tx_binding_hash`. No omissions found.

### R5-112: Challenge Zero-Divisor Probability — Negligible

Challenge polynomial has exactly 60 nonzero coefficients in {-1, +1}. Probability of being a zero-divisor in R_q is bounded by 2^{-800}.

### New Codex Impact on MatRiCT+: None

The new codex commits to `bundle.cpp`, `nullifier.cpp`, `validation.cpp`, and `net_processing.cpp` introduce **no new consensus-critical weaknesses** and do not degrade any MatRiCT+ security assumptions.

---

## AUDIT 2: Side-Channel / Timing Assessment

### R5-200: `spend_secret` Not Cleansed in Wallet Scan Paths — NEW

**Severity:** P2-Medium
**Status:** Open

**Files:** `wallet/shielded_wallet.cpp:459-462, 642-644`

The `spend_secret` (32 bytes of spending key material from `DeriveShieldedSpendSecretMaterial`) is never cleansed in the block-scan and mempool-scan wallet paths. The spend-construction path at line 811 correctly uses `ScopedByteVectorCleanse`, but these two call sites do not.

**Recommendation:** Wrap `spend_secret` in `ScopedByteVectorCleanse` at both sites.

### R5-201: Secret-Dependent Branch in Ring Signature Creation — Accepted

**Severity:** P3-Low
**Status:** Accepted (local-only threat model)

**File:** `ring_signature.cpp:731-737`

Branch on `member_idx == real_index` selects between `PolyVecSub` (cheap) and `SamplePublicKeyOffsetVec` (expensive). The real signer index is secret. Acceptable under local-signing-only threat model.

### R5-202: All `randrange()` Calls Use Public Bounds — Verified

No secret-dependent `randrange()` calls found. All bounds derive from public constants (`eta+1`, `2*bound+1`, `POLY_Q`).

### R5-203: NTT/Montgomery/InfNorm — All Branchless — Verified

Upstream Dilithium reference implementations confirmed branchless with fixed access patterns.

### R5-204: Poly256::InfNorm — Branchless — Verified

Uses arithmetic shift masking. No data-dependent branches.

### R5-205: Range Proof CtSwapBytes — Correct — Verified

XOR-mask swap operates on fixed-size values. Both branches computed unconditionally before selection.

### R5-206: Rejection Sampling Iteration Count — Accepted

**Severity:** P3-Low
**Status:** Accepted

Iteration count depends on `||z||_∞` where z involves the secret. Per-iteration O(ms) NTT/hash work dominates wall-clock noise. Acceptable for production.

### R5-207: ViewGrant Crypto — Constant-Time — Verified

ML-KEM (constant-time ref), HKDF-SHA256, AEADChaCha20Poly1305 — all constant-time. Failed plaintext cleansed. `PQCLEAN_PREVENT_BRANCH_HACK` confirmed in `compat.h:68` using inline asm to prevent compiler optimization of constant-time patterns.

### R5-212: ViewGrant Plaintext in Non-Secure Memory — NEW

**Severity:** P2-Medium
**Status:** Open

**File:** `bundle.cpp:74, 96`

The decrypted `plaintext` buffer uses default allocator rather than `secure_allocator<uint8_t>`. On the success path, the view key material may be paged to swap. Inconsistent with the `aead_key` on line 70 which correctly uses `secure_allocator`.

**Recommendation:** Use `secure_allocator<uint8_t>` for plaintext vector.

### R5-209: Memory Cleansing Coverage — 1 Gap Found

Comprehensive `memory_cleanse` coverage confirmed across all shielded code (ring sig, range proof, balance proof, note encryption, ML-KEM). One gap: R5-200 (`spend_secret` in scan paths).

---

## AUDIT 3: External Conformance Vectors and Adversarial Review

### Test Inventory

**282 C++ unit test cases** across 20 test files. **9 Python functional tests.**

| Test File | Cases |
|-----------|-------|
| `shielded_merkle_tests.cpp` | 40 |
| `shielded_kat_tests.cpp` | 38 |
| `ringct_ring_signature_tests.cpp` | 30 |
| `shielded_transaction_tests.cpp` | 25 |
| `shielded_proof_adversarial_tests.cpp` | 22 |
| `shielded_tx_check_tests.cpp` | 16 |
| `shielded_validation_checks_tests.cpp` | 16 |
| `ringct_range_proof_tests.cpp` | 13 |
| `shielded_note_tests.cpp` | 13 |
| `ring_selection_tests.cpp` | 12 |
| `ringct_matrict_tests.cpp` | 11 |
| `ringct_commitment_tests.cpp` | 10 |
| `ringct_balance_proof_tests.cpp` | 9 |
| `nullifier_set_tests.cpp` | 8 |
| Other (6 files) | 19 |

### KAT Vector Coverage

| Component | Frozen KAT? | Status |
|-----------|-------------|--------|
| Commitment matrix hash | Yes | OK |
| Value generator hash | Yes | OK |
| NTT unit poly (Python cross-validated) | Yes | OK |
| NTT constant 42 (Python cross-validated) | Yes | OK |
| Domain separator fingerprint (22 seps) | Yes | OK |
| Ring sig challenge seed | Yes | OK |
| MatRiCT full proof | Yes | OK |
| Nullifier from note | **Logged but not asserted** | Gap (R5-301) |
| Commitment opening | **Logged but not asserted** | Gap (R5-302) |
| Balance proof | **No KAT exists** | Gap (R5-303) |
| Range proof | **No KAT exists** | Gap (R5-304) |

### R5-301: Nullifier Derivation KAT Not Frozen — NEW

**Severity:** P2-Medium
**Status:** Open

**File:** `shielded_kat_tests.cpp:712-716`

Test computes deterministic nullifier but only logs it via `BOOST_TEST_MESSAGE` — never asserts against a frozen value. A silent change to nullifier derivation breaks consensus compatibility undetected.

**Recommendation:** Add `BOOST_CHECK_EQUAL(nf.GetHex(), "<frozen_value>")`.

### R5-302: Commitment KAT Not Frozen — NEW

**Severity:** P2-Medium
**Status:** Open

**File:** `ringct_commitment_tests.cpp:141`

Same pattern as R5-301. Commitment hash logged but not asserted.

### R5-303: No Frozen KAT for Balance Proof — CARRIED from R1

**Severity:** P2-Medium
**Status:** Open (carried from R1 finding #5, R4)

### R5-304: No Frozen KAT for Range Proof — CARRIED from R1

**Severity:** P2-Medium
**Status:** Open (carried from R1 finding #5, R4)

### R5-305: No Malformed Proof Deserialization Tests — CARRIED from R4-319

**Severity:** P2-Medium
**Status:** Open

No tests feeding truncated/garbage byte streams into proof deserializers. Given the complex nested polynomial serialization formats (Signed8, Signed16, ModQ24, ModQ23), this is high-risk for crashes from malicious network input.

### R5-306: No Consensus-Level Double-Spend Rejection Test — NEW

**Severity:** P2-Medium
**Status:** Open

No C++ test exercises the `ConnectBlock` path rejecting a block with a duplicate nullifier. A bug in consensus enforcement would be invisible to the current test suite.

### R5-307: No DisconnectBlock Nullifier Rollback Test — NEW

**Severity:** P2-Medium
**Status:** Open

No test verifies that `DisconnectBlock` correctly removes nullifiers from the set, enabling re-spending after reorg. Both double-spend (missing rollback) and fund-loss (permanent marking) risks are untested.

### R5-311: Four Pre-Existing Ring Sig Test Failures — CARRIED from R4-008

**Severity:** P2-Medium
**Status:** Open

4 tests still failing: size threshold, statistical bias threshold, duplicate-ring setup, KAT hash mismatch.

### R5-312: No Fuzz Harness for Shielded Deserialization — CARRIED from R4-319

**Severity:** P2-Medium
**Status:** Open

No fuzz targets for any shielded serialization type.

### R5-316: Domain Separator Fingerprint Cross-Validation — Verified

Both C++ and Python list the same 22 domain separators with matching combined fingerprint `893f7f47...`. Confirmed no drift.

---

## AUDIT 4: New Codex Code Deep Scan

### R5-400: RollforwardBlock Does Not Apply Shielded State — CRITICAL NEW

**Severity:** P1-Critical
**Status:** Open — consensus-critical

**File:** `validation.cpp:6017-6036, 6106`

During crash-recovery replay (`ReplayBlocks`), the rollback path correctly passes `apply_shielded_state=true` to `DisconnectBlock`. However, `RollforwardBlock` only applies UTXO effects (AddCoins/SpendCoin). It does NOT:
- Re-insert nullifiers
- Re-append commitments to the Merkle tree
- Update the pool balance

After crash recovery through blocks containing shielded transactions, the in-memory shielded state will be inconsistent. Consequences include missing nullifiers (enabling double-spends), Merkle root mismatch, and pool balance drift.

**Mitigation:** `EnsureShieldedStateInitialized` does wipe and rebuild from scratch, which can mask this if it runs after replay completes. But any code checking shielded state between replay and re-init observes stale state.

**Recommendation:** Either extend `RollforwardBlock` to apply shielded state effects, or trigger a full shielded state rebuild at the end of `ReplayBlocks`. Add a functional test.

### R5-401: Anchor Root Pop During Multi-Block Disconnect — Fragile

**Severity:** P1-High (downgraded from initial P1 due to cs_main serialization)
**Status:** Partially mitigated

**File:** `validation.cpp:2912-2922`

During multi-block reorg, sequential `pop_front()` calls on the anchor deque can create transiently inconsistent state. The fallback `RebuildShieldedAnchorHistory` repairs this. Safe today due to cs_main serialization preventing concurrent anchor queries, but fragile.

**Recommendation:** Replace incremental pop_front with a single post-reorg rebuild.

### R5-402: Decrypted ViewGrant Plaintext in Non-Secure Memory

**Severity:** P2-Medium
**Status:** Open

**File:** `bundle.cpp:74, 96`

(Same as R5-212 — identified by both audit streams independently.)

### R5-403: NullifierSet Check-Then-Insert Relies on External Lock

**Severity:** P2-Medium
**Status:** Latent risk — safe today via cs_main

**File:** `nullifier.cpp:32-49, 52-84`

No atomic check-and-insert API. Any future caller omitting cs_main would introduce a TOCTOU double-spend vulnerability.

**Recommendation:** Add `EXCLUSIVE_LOCKS_REQUIRED(::cs_main)` annotations, or provide atomic `InsertIfNotExists`.

### R5-404: VerifyDB Shielded Audit Has Narrow Activation Criteria

**Severity:** P2-Medium
**Status:** By design

**File:** `validation.cpp:5992-5996`

Requires `nCheckLevel >= 4` AND full chain with no pruning and sufficient dbcache. Default configurations never trigger the shielded audit.

**Recommendation:** Implement lightweight shielded sanity check at checklevel 1-2.

### R5-405: Cache Eviction Not Insertion-Ordered

**Severity:** P2-Medium
**Status:** Open (confirmed by 3 audit streams independently)

**File:** `nullifier.cpp:72-80`

Comment claims "retaining most recently inserted entries" but `unordered_set` iteration is hash-order. No correctness impact.

### R5-406: Audit Does Not Verify Absence of Spurious DB Nullifiers

**Severity:** P3-Low
**Status:** Open

**File:** `validation.cpp:229-243`

Checks count match and that every expected nullifier exists, but does not check the reverse. Theoretically, count-matched corruption (spurious + missing canceling) could pass.

### R5-408: Shielded Data Cache Not Invalidated on Reorg

**Severity:** P3-Low
**Status:** Safe in current flow

Cache entries for reorged blocks are not cleared, but the handler checks `ActiveChain().Contains(pindex)` before cache lookup.

### R5-411: ViewGrant Bounds Checks — Correct

Codex hardening confirmed correct. `Create` rejects oversized input, `Decrypt` cleansed on failure, bounds consistent with `CheckStructure`.

---

## AUDIT 5: Full Codebase Security Vulnerabilities

### R5-507: Consensus-Path `assert(!coin.IsSpent())` Crashes Node — CRITICAL NEW

**Severity:** P1-Critical
**Status:** Open

**File:** `consensus/tx_verify.cpp:139, 161, 180`

Three hard `assert(!coin.IsSpent())` in `GetP2SHSigOpCount`, `GetTransactionSigOpCost`, and `CheckTxInputs` — all consensus-critical paths invoked during `ConnectBlock`. If a UTXO cache corruption delivers a spent coin, the node terminates immediately. A crafted block triggering this condition crashes every node, constituting a network-wide DoS vector.

**Recommendation:** Replace with proper `state.Invalid()` returns.

### R5-501: Add-Then-Check Arithmetic in Consensus CheckTxInputs

**Severity:** P2-Medium
**Status:** Open

**File:** `tx_verify.cpp:189-190`

`nValueIn += coin.out.nValue` without overflow check, then `MoneyRange(nValueIn)` after. Inconsistent with `CheckedAdd` at line 200.

### R5-502: Unchecked Triple Addition in CreateShieldedSpend

**Severity:** P2-Medium
**Status:** Open

**File:** `shielded_wallet.cpp:754`

`total_needed = total_shielded_out + total_transparent_out + fee` — no overflow check.

### R5-503: Unchecked `total_input` Accumulation in CreateShieldedSpend

**Severity:** P2-Medium
**Status:** Open

**File:** `shielded_wallet.cpp:759`

Loop accumulates note values without overflow checking. Corrupted wallet DB could cause UB.

### R5-504: Unchecked `total` Accumulation in MergeNotes

**Severity:** P2-Medium
**Status:** Open

**File:** `shielded_wallet.cpp:1045`

Same pattern as R5-503.

### R5-505: Unchecked `total_in` Accumulation in ShieldFunds

**Severity:** P2-Medium
**Status:** Open

**File:** `shielded_wallet.cpp:979`

MoneyRange check at line 983 occurs only after the loop exits.

### R5-506: Unchecked Accumulations in Shielded RPC Handlers

**Severity:** P2-Medium
**Status:** Open

**Files:** `shielded_rpc.cpp:339, 438`

Both `z_shieldcoinbase` and `z_shieldfunds` accumulate without overflow checks.

### R5-508: Assert(MoneyRange) Kills Node in Mempool

**Severity:** P2-Medium
**Status:** Open

**File:** `policy/coin_age_priority.cpp:75`

### R5-509: Assert(MoneyRangeSigned) in CTxMemPoolEntry Constructor

**Severity:** P2-Medium
**Status:** Open

**File:** `kernel/mempool_entry.h:161`

### R5-510: `z_getbalance` and `z_listunspent` Accept Negative `minconf`

**Severity:** P3-Low
**Status:** Open

**File:** `shielded_rpc.cpp:116, 161`

### R5-511: Signed-to-Unsigned Truncation of `max_notes` in `z_mergenotes`

**Severity:** P3-Low
**Status:** Open

**File:** `shielded_rpc.cpp:509`

Negative RPC input wraps to very large `size_t`.

### R5-520: Race Condition Between Note Selection and Transaction Commit

**Severity:** P2-Medium
**Status:** Open

**File:** `shielded_rpc.cpp:248-277` (and 3 other RPC handlers)

Lock released between `CreateShieldedSpend` and `CommitShieldedTransactionOrThrow`. Concurrent RPC calls can select the same notes.

**Recommendation:** Hold lock through commit, or implement note-reservation mechanism.

---

## AUDIT 6: Scalability and Performance

### R5-600: NTT Call Amplification in Ring Signature Verification

**Severity:** P1-High (performance)
**Status:** Open

**File:** `ring_signature.cpp:422-523`

Per-proof verification invokes up to ~26,624 NTT operations in worst case. Uses scalar Dilithium reference NTT exclusively.

**Recommendation:** Enable AVX2 NTT backend for 5-10x speedup. Batch NTT transforms.

### R5-603: Range Proof Verification Cost O(51 bits) with Heavy NTT

**Severity:** P1-High (performance)
**Status:** Open

**File:** `range_proof.cpp:488-530`

Each of 51 bit-proofs requires heavy NTT usage. ~306 NTT operations per output for bit verification alone.

### R5-607: Startup Rebuilds Entire Shielded State from Genesis

**Severity:** P1-High (performance)
**Status:** Open

**File:** `validation.cpp:7527-7581`

`EnsureShieldedStateInitialized` reads every block, re-appends all commitments, rebuilds entire nullifier DB. At 800k blocks → 15-30 minutes.

**Recommendation:** Persist Merkle tree frontier and nullifier DB checkpoint.

### R5-602: PolyVec Heap Allocation Churn

**Severity:** P2-Medium
**Status:** Open

`PolyVec = std::vector<Poly256>` — every operation returns new heap allocation. Hundreds per proof verification.

**Recommendation:** Change to `std::array<Poly256, MODULE_RANK>`.

### R5-604: Nullifier AnyExist() Sequential LevelDB Reads

**Severity:** P2-Medium
**Status:** Open

Each cache miss triggers single-key LevelDB read (~10-100μs).

**Recommendation:** Add Bloom filter for fast negative lookups.

### R5-606: Merkle Tree Truncate O(n) Rebuild

**Severity:** P2-Medium
**Status:** Open

Re-appends all retained commitments on disconnect.

### R5-608: Anchor History Rebuild — 100× Truncation Loop

**Severity:** P2-Medium
**Status:** Open

### R5-611: Wallet UpdateWitnesses O(W×K) Per Block

**Severity:** P2-Medium
**Status:** Open

Wallet with 10,000 notes × 1,000 block outputs = 10M incremental updates.

### R5-614: Range Proof Redundant Matrix NTT

**Severity:** P3-Low
**Status:** Open

`range_proof.cpp` calls generic `MatVecMul(CommitmentMatrix(), z)` without pre-NTT'd matrix, unlike `ring_signature.cpp` which caches the NTT form. Eliminates ~5,100 redundant NTTs per output.

### R5-617: Block Disconnect Fallback Rebuilds from Genesis

**Severity:** P2-Medium
**Status:** Open

When `Truncate()` fails, falls back to full genesis rebuild.

---

## Cross-Reference: Round 4 Open Items

| R4 ID | R4 Status | R5 Status | Notes |
|-------|-----------|-----------|-------|
| R4-601 | P0 Open | **Still Open** (R5-313) | Cannot send to external shielded addresses |
| R4-604 | P1 Open | **Still Open** (R5-314) | No spending key backup/restore RPCs |
| R4-103 | P2 Open | **Still Open** | Balance proof nonce leakage unchanged |
| R4-002 | P2 Documented | Confirmed | Rejection sampling timing — acceptable |
| R4-405 | P2 Documented | Confirmed | KEM secret key plaintext — unchanged |
| R4-406 | P2 Documented | Confirmed | Relay burst 4MB — unchanged |
| R4-408 | P2 Documented | Confirmed | z_exportviewingkey cleartext — unchanged |
| R4-008 | P2 Pre-existing | **Still Open** (R5-311) | 4 ring sig test failures |
| R4-324 | P2 Documented | Confirmed (R5-409) | Nullifier DB wipe-on-init |
| R4-314 | P2 Documented | Confirmed | No E2E functional test |
| R4-319 | P2 Documented | **Still Open** (R5-305/312) | No fuzz testing |
| R4-508 | P2 Documented | Confirmed (R5-600) | NTT uses reference C |
| R4-517 | P2 Documented | Confirmed (R5-602) | Heap allocation churn |
| R4-502 | P2 Documented | Confirmed (R5-405) | Cache eviction not recency-preserving |
| R4-410 | P3 Documented | Confirmed | Turnstile arithmetic fragile |
| R4-407 | P3 Documented | Confirmed (R5-610) | Anchor validation linear search |
| R3-014 | P3 Open | Confirmed (R5-606) | Merkle Truncate O(n) |
| R3-010 | P2 Partial | Confirmed (R5-310) | Python vectors lack commitment-level |

---

## Summary of All Open Items

### P1-Critical (Consensus/Safety)

| ID | Description | Status |
|----|-------------|--------|
| R5-400 | RollforwardBlock omits shielded state — crash recovery desync | **NEW — Open** |
| R5-507 | Consensus-path assert(!coin.IsSpent()) crashes node (DoS) | **NEW — Open** |
| R4-601 | Cannot send to external shielded addresses | Carried — design limitation |
| R5-600 | NTT verification uses reference C, no SIMD (performance) | Open |
| R5-603 | Range proof O(51) bit-proofs per output (performance) | Open |
| R5-607 | Startup rebuilds entire shielded state from genesis (performance) | Open |

### P1-High (Data Loss)

| ID | Description | Status |
|----|-------------|--------|
| R4-604 | No spending key backup/restore RPCs | Carried — Open |
| R5-401 | Anchor root pop_front fragile during multi-block disconnect | Partially mitigated |

### P2-Medium (26 findings)

| ID | Description | Category |
|----|-------------|----------|
| R5-200 | spend_secret not cleansed in scan paths | Memory hygiene |
| R5-212/R5-402 | ViewGrant plaintext in non-secure memory | Memory hygiene |
| R5-403 | NullifierSet check-then-insert relies on cs_main | Latent race |
| R5-404 | VerifyDB shielded audit narrow activation | Coverage gap |
| R5-405 | Nullifier cache eviction comment inaccurate | Documentation |
| R5-501 | CheckTxInputs add-then-check | Arithmetic safety |
| R5-502 | CreateShieldedSpend triple addition unchecked | Arithmetic safety |
| R5-503 | CreateShieldedSpend total_input unchecked | Arithmetic safety |
| R5-504 | MergeNotes total unchecked | Arithmetic safety |
| R5-505 | ShieldFunds total_in unchecked | Arithmetic safety |
| R5-506 | RPC handler accumulations unchecked | Arithmetic safety |
| R5-508 | assert(MoneyRange) in coin_age_priority | Crash risk |
| R5-509 | assert(MoneyRangeSigned) in mempool_entry | Crash risk |
| R5-520 | Note selection race in RPC handlers | Race condition |
| R5-301 | Nullifier derivation KAT not frozen | Test gap |
| R5-302 | Commitment KAT not frozen | Test gap |
| R5-303 | No balance proof KAT | Test gap (carried R1) |
| R5-304 | No range proof KAT | Test gap (carried R1) |
| R5-305 | No malformed proof deserialization tests | Test gap |
| R5-306 | No consensus-level double-spend test | Test gap |
| R5-307 | No DisconnectBlock nullifier rollback test | Test gap |
| R5-311 | 4 pre-existing ring sig test failures | Test gap |
| R5-312 | No fuzz harness for proof deserialization | Test gap |
| R5-602 | PolyVec heap allocation churn | Performance |
| R5-604 | Nullifier AnyExist() sequential reads | Performance |
| R4-103 | Balance proof nonce leakage (~5 bits/coeff) | Cryptographic |

### P3-Low (11 findings)

| ID | Description |
|----|-------------|
| R5-105 | Fiat-Shamir omits static parameter hashes |
| R5-201 | Secret-dependent branch in ring sig creation |
| R5-206 | Rejection sampling iteration count leak |
| R5-406 | Audit doesn't check spurious DB nullifiers |
| R5-408 | Shielded data cache not cleared on reorg |
| R5-510 | z_getbalance accepts negative minconf |
| R5-511 | z_mergenotes signed-to-unsigned truncation |
| R5-606 | Merkle tree Truncate O(n) |
| R5-608 | Anchor history 100x truncation loop |
| R5-614 | Range proof redundant matrix NTT |
| R5-617 | Block disconnect genesis fallback |

### Informational (5 findings)

| ID | Description |
|----|-------------|
| R5-102 | Lattice parameters verified |
| R5-316 | Domain separator fingerprint verified |
| R5-411 | ViewGrant bounds checks correct |
| R5-514 | sprintf in vendored test utilities |
| R5-517 | HACK comments documenting known workarounds |

---

## Severity Distribution

| Severity | Count | Notes |
|----------|-------|-------|
| P1-Critical | 3+3 perf | R5-400, R5-507 NEW; R4-601 carried; R5-600/603/607 performance |
| P1-High | 2 | R4-604, R5-401 |
| P2-Medium | 26 | 14 new, 12 carried/confirmed from R4 |
| P3-Low | 11 | 6 new, 5 carried |
| Informational | 5 | Verified and positive findings |
| **Total** | **50** | |

---

## Top Priority Remediation Actions

1. **R5-400 (P1):** Fix `RollforwardBlock` to apply shielded state effects during crash recovery. **Must resolve before any release.**

2. **R5-507 (P1):** Replace 3 `assert(!coin.IsSpent())` in `tx_verify.cpp` with proper error returns. **Remote DoS vector.**

3. **R4-601 (P1):** Resolve external address sending — requires protocol-level design decision (embed KEM pubkey in address, registry, or RPC parameter).

4. **R4-604 (P1):** Implement `z_exportspendingkey` / `z_importspendingkey` RPCs to prevent permanent fund loss.

5. **R5-200, R5-212 (P2):** Fix secret material handling gaps (spend_secret cleansing, ViewGrant secure_allocator).

6. **R5-501-506 (P2):** Apply `CheckedAdd` to all 6 unchecked arithmetic patterns.

7. **R5-520 (P2):** Fix note-selection race condition in RPC handlers.

8. **R5-301-304 (P2):** Freeze KAT vectors for nullifier, commitment, balance proof, and range proof.

---

## Verification Methodology

1. **6 parallel audit agents** covering MatRiCT+ alignment, side-channels, conformance, new codex code, full codebase security, and scalability
2. **Manual cross-referencing** of all 26 Round 4 findings against current code
3. **New codex commit analysis** — all 5 commits (validation, bundle, nullifier, P2P, tests) reviewed line-by-line
4. **Parameter verification** against MatRiCT+ (ePrint 2021/545) and Dilithium-III
5. **282 C++ tests + 9 Python functional tests** inventoried and gap-analyzed
6. **ML-KEM implementation** reviewed for constant-time properties (PQClean reference with `PREVENT_BRANCH_HACK`)
7. **Independent confirmation** — R5-402/R5-212 and R5-405 each identified by multiple independent audit streams
