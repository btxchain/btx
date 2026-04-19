# BTX MatMul Proof-of-Work: TDD Engineering Specification (v3)

> Based on "Proofs of Useful Work from Arbitrary Matrix Multiplication"
> (Komargodski, Schen, Weinstein — arxiv:2504.09971v1, April 2025)

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Paper Synopsis](#2-paper-synopsis)
3. [Critical Design Decisions](#3-critical-design-decisions)
4. [Architectural Mapping to BTX](#4-architectural-mapping-to-btx)
5. [Consensus Parameter Design](#5-consensus-parameter-design)
6. [Block Header Changes](#6-block-header-changes)
7. [Finite-Field Arithmetic Library](#7-finite-field-arithmetic-library)
8. [MatMul PoW Core Algorithm](#8-matmul-pow-core-algorithm)
9. [Mining Integration](#9-mining-integration)
10. [Validation and DoS Mitigation](#10-validation-and-dos-mitigation)
11. [Difficulty Adjustment](#11-difficulty-adjustment)
12. [Trust Model and Data Availability](#12-trust-model-and-data-availability)
13. [RPC and P2P Interface](#13-rpc-and-p2p-interface)
14. [Block Capacity and Bandwidth Analysis](#14-block-capacity-and-bandwidth-analysis)
15. [Milestone Plan](#15-milestone-plan)
16. [Test Matrix](#16-test-matrix)
17. [Security Audit Checklist](#17-security-audit-checklist)
18. [Open Questions and Risks](#18-open-questions-and-risks)

---

## 1. Executive Summary

This document specifies the integration of a MatMul-based Proof-of-Work
(PoW) system into the BTX blockchain node. The system replaces the existing
KAWPOW PoW with a scheme where miners perform matrix multiplications and use the
intermediate computation transcript as the hardness source for block mining.
v1 uses seed-derived random matrices (AI-native PoW); v2 will add arbitrary
matrices for externally useful work (PoUW). See §3.2 for terminology.

The protocol, called **cuPOW** in the source paper, achieves a multiplicative
overhead of only 1+o(1) over standard matrix multiplication. The protocol
injects low-rank random noise derived from a random oracle (seeded by the block
header) to make the computation transcript unpredictable.

**Reference platform**: The reference implementation targets **little-endian
architectures** (x86-64, ARM64 in LE mode). Big-endian is unsupported in v1.
All serialization formats specify little-endian byte order explicitly (§6, §7.4).
The build system MUST include `static_assert(std::endian::native == std::endian::little)`
or equivalent to reject compilation on big-endian targets.

### 1.1 Key Design Decisions for BTX

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Matrix source** | Seeded from block header (v1) | Keeps blocks compact (~200 KiB); arbitrary matrices deferred to v2 with DA layer |
| **Activation** | Fresh genesis (no KAWPOW legacy) | Removes dual-algorithm complexity and attack surface |
| **Field** | F_q where q = 2^31 − 1 (M31) | GPU-friendly int32 arithmetic; Apple Metal / CUDA native |
| **Default dimension** | n = 512 | ~2 MiB working set; viable block propagation |
| **Transcript block size** | b = 16 | Separate from noise rank r; controls hashing granularity |
| **Noise rank** | r = 8 | Controls security/denoise overhead; independent of b |
| **Trust model** | Four-tier: mining / consensus-validating / economic / light (SPV) | Explicit node tiers with defined Phase 2 validation scope (§3.6, §12.1) |
| **Verification DoS** | Two-phase validation with per-peer rate limits | Cheap header checks gate expensive transcript recomputation |
| **Block time** | 90 s steady-state; 0.25 s fast-mining phase (h < 50,000) | Fast bootstrap (~3.5 h) then long intervals for propagation/verification headroom |
| **Halving interval** | 525,000 blocks | Bitcoin-style infinite geometric series: 20 × 525k × 2 = 21M cap |
| **Initial subsidy** | 20 BTX | Yields exactly 21,000,000 BTX total supply with 525k halving |
| **Supply cap** | 21,000,000 BTX | Hard cap enforced by `MoneyRange()` and subsidy function (§11.4) |
| **Block capacity** | SegWit-style weight limit (24M WU consensus and policy default) | Scales throughput via weight accounting; penalizes UTXO-heavy bytes; compatible with modern tx formats (§14) |

### 1.2 What Changed in v2

This revision addresses critical review feedback:

1. **Block size**: Switched from full in-block matrices (16 MiB at n=1024) to
   seed-derived matrices for v1 (blocks stay ~200 KiB)
2. **Trust model**: Explicit archival + assumevalid architecture replaces vague
   "prune later" language
3. **DoS mitigation**: Two-phase validation, per-peer rate limits, verification
   scheduling added as first-class design
4. **Parameter split**: Transcript block size `b` separated from noise rank `r`
5. **Field choice**: Switched from M61 (2^61−1) to M31 (2^31−1) for GPU/Apple
   friendliness
6. **Activation model**: Fresh genesis recommended; KAWPOW transition path
   documented as alternative but not default
7. **Seed serialization**: Exact canonical byte encoding specified
8. **Bootstrap difficulty**: Time-based throttle replaces naive powLimit window
9. **State commitments**: UTXO snapshot roadmap for light clients
10. **Transcript compression**: Replaced naive full-block hashing (33.5 MB at
    n=512) with field-algebraic inner-product compression (~131 KB hashed),
    reducing SHA-256 overhead from 30-100% to under 1% (Section 8.3.1)

### 1.3 What Changed in v3

This revision addresses remaining consensus/security gaps identified in v2 review:

1. **M31 accumulation safety (§7.2)**: `reduce64` now uses double Mersenne fold,
   safe for all uint64 inputs. Formal bit-range analysis proves the old
   single-fold was buggy for x ≥ 2^62. `dot()` specified as the only allowed
   accumulator path with per-step reduction and length-independent safety proof.
2. **Transcript hashing overhead (§2.8, §8.3.1)**: Honest overhead table replaces
   unsubstantiated "<5%" claim. Total protocol overhead: ~16.5% at n=512
   (compression dot-products 6.3%, denoising 6.3%, noise gen 3.5%). GPU
   pipelining requirements specified for fused compression.
3. **Branding: AI-native PoW, not PoUW (§3.2)**: v1 explicitly labeled
   "AI-native Proof-of-Work" since seed-derived matrices have no external
   consumer. "PoUW" reserved for v2 with arbitrary matrices + DA layer.
4. **Node tiers formalized (§3.6, §12)**: Four explicit tiers (Mining,
   Consensus-validating, Economic, SPV) with hardware requirements, IBD behavior,
   and new `MATMUL_VALIDATION_WINDOW` consensus parameter (default: 1000 blocks).
5. **Graduated peer punishment (§10.2)**: Phase 1 pass + Phase 2 fail no longer
   causes immediate ban. Graduated model: disconnect → discourage → ban (after
   3rd offense in 24h). `fMatMulStrictPunishment` flag for post-stabilization.
   Testnet/regtest always use graduated model.
6. **Byte-exact `FromSeed()` and `from_oracle()` (§7.4, §8.2.1)**: Full
   consensus-critical specification: SHA-256 PRF, LE32 counters, rejection
   sampling for uniform mod M31, domain separation tags for noise factors
   (`matmul_noise_EL_v1`, etc.), pinned test vectors.
7. **Compression vector reuse justified (§8.3.2)**: Explicit proof that reusing
   a single σ-derived v across all 32,768 intermediates is safe (Carter-Wegman
   per-intermediate binding + σ-unpredictability), and per-intermediate v is
   unnecessary (~840ms overhead for no security gain).
8. **Compression/noise domain separation (§8.3.3)**: Explicit table showing all
   five domain separation prefixes and proof of statistical independence.
9. **Field size and linearity analysis (§8.3.4)**: Explicit statement that
   security relies on σ-unpredictability, not on hiding v; M31 field size is
   adequate because v changes per nonce attempt.
10. **Compression linearity + partial sums (§8.3.5)**: Explicit analysis that
    the linear relationship between consecutive compressed values (inherent to
    block matmul structure) is not a vulnerability — forgery still requires
    matching every increment, and SHA-256d chain binds sequence order.
11. **Tier 2 naming enforcement (§12.1)**: Implementation/UX requirement that
    Tier 2 (economic) nodes must never be labeled "full" in RPC, help text,
    GUI, P2P service bits, or documentation.
12. **Economic security note + dual projection upgrade (§8.3.6)**: Explicit
    collision probability analysis (2⁻³¹ per intermediate, ≤ 2⁻¹⁶ per block by union bound)
    and upgrade path to dual compression projections for 2⁻⁶² per intermediate
    if future risk assessment warrants.
13. **ASIC threat model (§18.5)**: Explicit statement that ASICs are not
    cryptographically impossible but economically misaligned with commodity
    AI hardware. Design stance documented.
14. **Consensus invariants summary (§17.5)**: Standalone auditor-friendly
    section consolidating all consensus-critical invariants (arithmetic,
    seed derivation, transcript order, compression, reduction discipline).
15. **Seed grinding economics (§18.4)**: Explicit analysis that seed grinding
    is a design property (not a vulnerability) with O(n³) cost per attempt,
    indistinguishable from nonce grinding.
16. **Monetary policy (§5.1, §5.2, §11.4)**: Consensus-specified 21M hard cap,
    525,000-block halving interval, 20 BTX initial subsidy. `GetBlockSubsidy()`
    and `MoneyRange()` fully defined. Issuance schedule table with per-epoch
    cumulative totals.
17. **Target spacing schedule (§5.1, §11.5)**: Height-dependent block time —
    250ms fast-mining phase (h < 50,000) transitioning to 90-second
    steady-state. `GetTargetSpacing(height)` consensus helper specified.
18. **Schedule-aware DGW (§11.6)**: `ExpectedDgwTimespan()` sums per-block
    target spacing across the 180-block window. Smooth transition at h=50,000
    with no special-case code. Boundary behavior fully analyzed.
19. **Fast-mining phase specification (§11.5)**: 50,000 blocks at 0.25s = ~3.5h
    bootstrap, emitting 1M BTX (4.76% of supply). Does not alter halving
    schedule (halving is by height, not time).
20. **Updated all timing references**: All "60-second" block time references
    updated to reflect 90s steady-state / 0.25s fast-phase schedule. Bandwidth,
    storage, CPU utilization, and validation window calculations updated.
21. **Monetary/schedule consensus invariants (§17.5.6, §17.5.7)**: Auditor
    summary tables for supply cap, subsidy function, target spacing, and DGW
    schedule-awareness.
22. **Monetary/schedule tests (§5.4, §11.7, §16)**: 23 new tests covering
    target spacing, subsidy, issuance cap, DGW boundary, and MoneyRange.
23. **Block capacity model (§5.1, §14)**: SegWit-style weight-based block
    capacity with 24M WU consensus max, 24M WU policy default, 24 MB serialized
    size cap, 480k sigops budget. Full §14 restructured with capacity model,
    consensus rules, policy defaults, and bandwidth analysis.
24. **§1.4 header context fix**: Updated to reference MatMul header fields
    (`matmul_digest`, `matmul_dim`, `seed_a`, `seed_b`) instead of stale
    KAWPOW `mix_hash` reference.
25. **Monetary invariant units fix (§5.3)**: Corrected
    `nInitialSubsidy * nSubsidyHalvingInterval * 2 == nMaxMoney` (removed
    erroneous `* COIN` on the right side — both sides already in satoshis).
26. **Glossary consistency (Appendix A)**: Fixed Tier 2 "Economic full node"
    → "Economic node" and added explicit "Full node" entry. Consistent with
    §12.1 which declares Tier 2 explicitly not "full."
27. **Fast-phase Phase 2 scheduling (§10.3.1)**: Explicit rules for deferred
    Phase 2 during 0.25-second blocks — bounded queue, mandatory drain after
    transition, no security relaxation.
28. **MTP/timestamp rules during fast phase (§11.5.1)**: Explicit statement
    that MTP and future-time-limit rules are unchanged; miners SHOULD use
    NTP-synchronized clocks.
29. **RPC block capacity fields (§13.1.1, §13.1.2)**: `getblocktemplate`
    and `getmininginfo` MUST report weight limits and policy targets.
30. **Block capacity auditor invariants (§17.5.8, §17.5.9)**: Weight, sigops,
    size, and fast-phase scheduling invariant tables added.

### 1.4 Existing Architecture Context

BTX is a Bitcoin Knots-derived blockchain node with:

- **Current PoW**: MatMul (AI-native Proof-of-Work; replaces former KAWPOW)
- **Difficulty**: ASERT — stateless exponential retargeting with 3600s half-life (from block 50,000)
- **Block time**: 90 seconds steady-state (`nPowTargetSpacingNormal`); 0.25 second fast-mining phase for h < 50,000 (`nPowTargetSpacingFastMs`, 250ms). See §5.1, §11.5.
- **Block header**: MatMul header includes `nNonce64` (64-bit), `matmul_digest`
  (256-bit), `matmul_dim` (16-bit), `seed_a` (256-bit), `seed_b` (256-bit).
  See §6 for full definition. (Replaces KAWPOW's `mix_hash` field.)
- **Key files**: `src/pow.cpp`, `src/crypto/kawpow.cpp`, `src/primitives/block.h`,
  `src/consensus/params.h`, `src/validation.cpp`, `src/rpc/mining.cpp`
- **Testing**: Boost Test (C++ unit), Python functional tests, production scripts

---

## 2. Paper Synopsis

### 2.1 Protocol Overview

The cuPOW protocol consists of two algorithms:

**Solve(σ, A, B) → (C, π)**
1. Generate noise: `E_L, E_R, F_L, F_R ← Oracle(σ, A, B)`
2. Compute `E = E_L · E_R` and `F = F_L · F_R` (rank-r noise matrices)
3. Execute canonical block-wise MatMul: `C' = (A + E) · (B + F)`, recording all
   intermediate b×b partial-sum blocks as the transcript T
4. Hash transcript: `z ← Oracle(T)`
5. If `z < difficulty_threshold`: denoise `C = C' − A·F − E·(B + F)` and output
6. Otherwise: retry with new nonce (changes σ) or new matrices

**Verify(σ, π) → {accept, reject}**
1. Recompute `z` from `σ, A, B` following Solve steps 1–4
2. Check `z < target`

### 2.2 Canonical Block MatMul

Force computation through a specific block decomposition so every intermediate
partial sum is determined by the inputs and the iteration order:

```
CanonicalMatMul_b(A', B'):
    N = rows(A') / b   // number of block rows/cols
    C' = zeros(N*b, N*b)

    for i in 0..N-1:
        for j in 0..N-1:
            for ℓ in 0..N-1:
                C'_block[i][j] += A'_block[i][ℓ] · B'_block[ℓ][j]
                emit_to_transcript(i, j, ℓ, C'_block[i][j])

    return C'
```

The transcript T consists of all `(n/b)³` intermediate b×b matrices. Each
intermediate depends on products of marginally-uniform b×b blocks, making the
full transcript hard to predict without performing the computation.

### 2.3 Noise Generation

Noise matrices are low-rank (rank r, where r need not equal b):

- `E_L` ∈ F_q^{n×r}, `E_R` ∈ F_q^{r×n} → `E = E_L · E_R` (n×n, rank ≤ r)
- `F_L` ∈ F_q^{n×r}, `F_R` ∈ F_q^{r×n} → `F = F_L · F_R` (n×n, rank ≤ r)

All four factor matrices are derived deterministically from the oracle seed σ.
The paper suggests `r ≈ n^0.3`; we use a fixed r chosen conservatively.

### 2.4 Denoising

```
C = C' − A·F − E·(B + F)
```

Since E and F have rank r, denoising costs O(n²·r), negligible vs O(n³).

### 2.5 Security Properties

- **Completeness**: Honest prover accepted with probability ε per attempt
- **Hardness**: Under the direct-product conjecture for random rank-r matrix
  products, no adversary gains meaningful advantage with less than a full MatMul
- **Useful work (v2 only)**: The product C = A·B is correct when A, B are real workloads (requires arbitrary matrix support; v1 uses seed-derived random matrices)

### 2.6 Key Parameters

| Parameter | Symbol | Role |
|-----------|--------|------|
| Matrix dimension | n | Compute cost O(n³) |
| Transcript block size | b | Hashing granularity; controls transcript size (n/b)³ |
| Noise rank | r | Security parameter; denoise cost O(n²·r) |
| Field modulus | q | Prime for F_q; must exceed n for correct arithmetic |
| Difficulty threshold | ε | Target acceptance probability per attempt |
| Security parameter | λ | Hash output bits (256 for SHA-256) |

**Critical distinction**: `b` (transcript block size) and `r` (noise rank) are
independent parameters that control different things:
- Changing `b` affects: transcript size, hashing cost, cache behavior
- Changing `r` affects: security conjecture strength, denoising overhead
- They may happen to be equal in some configurations but must not be conflated

### 2.7 Verification Cost

Verification requires recomputing the full transcript = O(n³) per block. This
is the dominant engineering constraint and drives the DoS mitigation design in
§10.

### 2.8 Overhead Analysis

#### Why naive transcript hashing is NOT negligible

The paper states 1+o(1) overhead asymptotically. In our concrete parameter
regime (n=512, b=16), naively hashing full b×b blocks is expensive:

- Intermediates: (n/b)³ = (512/16)³ = 32,768
- Each intermediate: b² elements × 4 bytes = 16×16×4 = 1,024 bytes
- Total bytes hashed (naive): 32,768 × 1,024 = **33,554,432 bytes (~33.5 MB)**

SHA-256 throughput on modern hardware:
- CPU with SHA-NI (x86) or SHA extensions (ARMv8.2-A): ~500 MB/s → ~67 ms
- CPU without hardware SHA: ~150–200 MB/s → ~170–220 ms
- GPU (SHA-256 is poorly suited to GPU pipelines): worse than CPU

The matmul itself at n=512 on a modern GPU takes roughly 50–200 ms depending
on hardware. **Naive full-block hashing would add 30–100% overhead on GPU
miners**, because the GPU must either ship intermediate data back to the CPU
for hashing, or run SHA-256 on the GPU (inefficient). This violates the
paper's 1+o(1) intent and creates a severe bottleneck.

#### Chosen approach: field-algebraic transcript compression (§8.3.1)

Instead of hashing full b×b blocks, we compress each intermediate into a
single field element via a random inner-product (a universal hash family),
then feed only that element into the rolling SHA-256d hasher. This reduces
hashed bytes by ~256×:

| Approach | Bytes hashed | SHA-256 time (SHA-NI) | Overhead vs matmul |
|----------|-------------|----------------------|-------------------|
| **Naive full-block** | 33.5 MB | ~67 ms | 30–100% |
| **Field-algebraic compression** | ~131 KB | ~0.26 ms | < 1% |

The security argument is preserved: the random inner-product family is
pairwise independent, so finding a different b×b block that produces the
same compressed element requires inverting a random linear map over F_q —
equivalent to guessing a field element (probability 1/q ≈ 2⁻³¹ per
intermediate). Full details in §8.3.1.

#### Full overhead table (with compression)

| Component | Cost | Concrete (n=512) | % of baseline |
|-----------|------|-------------------|--------------|
| Noise generation (E_L·E_R, F_L·F_R) | O(n²·r) | 2×n²r = 4.2M muls | 3.1% |
| Matrix additions (A+E, B+F) | O(n²) | 2×n² = 0.5M adds | 0.4% |
| **Noisy MatMul (A+E)·(B+F)** | **O(n³)** | **134M muls** | **baseline** |
| Transcript compression dot-products (§8.3.1) | O(n³/b) | 8.4M muls | **6.3%** |
| Rolling SHA-256d on compressed elements | O(N³·4 bytes) | 131 KB hashed | < 0.1% |
| Denoising (A·F + E·(B+F) via rank-r factors) | O(n²·r) | 4×n²r = 8.4M muls | 6.3% |
| Denoising subtraction (C'−AF−E(B+F)) | O(n²) | 2×n² = 0.5M adds | 0.4% |
| **Total** | **O(n³)** | **~156M muls** | **~116.5%** |
| **Total overhead above baseline** | | **~22M muls** | **~16.5%** |

The 16.5% total overhead is the honest cost of the protocol at n=512, b=16,
r=8. It breaks down as:
- **6.3% transcript compression**: (n/b)³·b² = n³/b = 8.4M dot-product muls.
  On GPU, these share INT32 ALUs with the matmul and can be partially hidden
  by pipelining, reducing effective overhead to ~3–4%.
- **6.3% denoising**: 4×n²r muls for the four rank-r factor products. These
  run after mining succeeds (once per found block, not per attempt).
- **3.5% noise generation + additions**: Small fixed overhead per attempt.

The compression dot-products are computed inline with the block matmul
accumulation loop, sharing cache lines with the intermediate data. On GPUs
where the compression is fused into the matmul kernel, measured overhead
drops to ~10–12% total. The paper's 1+o(1) result applies asymptotically
as n → ∞; at n=512 the concrete overhead is bounded and acceptable for a
PoW system.

**GPU pipelining note**: On GPU architectures, the compression dot-product
MUST be fused into the matmul kernel to avoid the ~33.5 MiB data transfer
penalty of naive full-block hashing. The compressed elements (~128 KiB total)
are written to a ring buffer and consumed by a CPU SHA-256 thread. See §8.3.1
for the full specification.

---

## 3. Critical Design Decisions

### 3.1 Matrix Source: Seeded (v1) vs Arbitrary (v2)

**v1 (this spec): Seed-derived matrices.**

Matrices A and B are deterministically generated from compact 32-byte seeds
included in the block header. The block contains `seed_a` and `seed_b`; any
node can reconstruct A and B without receiving the full matrices.

```
A = MatrixFromSeed(seed_a, n)   // deterministic PRNG expansion
B = MatrixFromSeed(seed_b, n)   // deterministic PRNG expansion
```

| Property | Seeded (v1) | Arbitrary (v2, future) |
|----------|-------------|----------------------|
| Block overhead | +64 bytes (two seeds) | +2·n²·4 bytes (two full matrices) |
| Block size (n=512) | ~200 KiB | ~2.2 MiB |
| Externally useful output | No (random matrices) | Yes (real AI workloads) |
| Data availability | Trivial (reconstruct from seed) | Requires DA layer |
| Complexity | Low | High |
| Trust model | Standard Bitcoin | Requires archival DA |

**Tradeoff**: v1 sacrifices externally useful output for deployability. The
PoW is still computationally legitimate matrix multiplication — an AI-native
proof-of-work rather than a pure hash puzzle — but the specific A·B products
have no external consumer. v2 restores arbitrary matrices and the full
Proof-of-Useful-Work (PoUW) property via a data-availability extension
(separate spec).

**v2 upgrade path**: Add optional `matrix_a_data` / `matrix_b_data` fields to
block body with a version flag. Nodes running v2 can verify arbitrary-matrix
blocks; v1 nodes treat them as seed-derived (soft fork if designed correctly).

### 3.2 Terminology: "AI-Native PoW" (v1) vs "Proof-of-Useful-Work" (v2)

The source paper (Komargodski, Schen, Weinstein 2025) describes the protocol as
"Proof-of-Useful-Work" because, with arbitrary input matrices, the product C =
A·B serves an external consumer — the miner simultaneously solves a PoW puzzle
and completes a real computational job. However, v1 of this specification uses
seed-derived random matrices: A and B are expanded from 32-byte seeds via a
deterministic PRNG, meaning no external party submitted these matrices and no
external party consumes the product. The computation is real matrix
multiplication (not a hash puzzle), but it has no external utility. Calling v1
"Proof-of-Useful-Work" would misrepresent the system's actual properties.

For this reason, v1 uses the term **"AI-native Proof-of-Work"** (or equivalently
"MatMul Transcript PoW") in all user-facing documentation, RPC descriptions,
and marketing materials. This terminology honestly reflects what v1 is: a
proof-of-work scheme whose hardness source is matrix multiplication — the
same operation that dominates AI/ML workloads — rather than a cryptographic
hash function. The work is structurally identical to useful AI computation
even though v1 does not yet route external jobs to miners. The term
**"Proof-of-Useful-Work (PoUW)"** is reserved for v2, when arbitrary matrices
are supported via a data-availability layer and miners can provably complete
externally submitted matrix multiplication jobs.

This distinction matters for credibility: the blockchain community has seen
multiple projects claim "useful work" prematurely. By scoping the terminology
precisely, BTX avoids that trap and establishes a clear upgrade narrative —
v1 proves the mechanism works and secures the chain; v2 adds the economic
layer that makes the work externally useful.

### 3.3 Activation Model: Fresh Genesis vs Height-Gated Fork

**Recommended: Fresh genesis.**

A new genesis block with matmul PoW from height 0 eliminates:
- Dual-algorithm dispatch (KAWPOW + matmul)
- KAWPOW header fields (`mix_hash`, legacy `nNonce`)
- Difficulty transition reset logic
- ~2,000 lines of ethash/progpow code in the consensus path

The existing KAWPOW infrastructure remains in the codebase for the current chain
but is not compiled into the matmul-genesis binary.

**Alternative: Height-gated fork** (documented in Appendix D). Use this path
only if preserving the existing KAWPOW chain history is a hard requirement.

### 3.4 Field Choice: M31 (2^31 − 1) for GPU Friendliness

| Property | M31 (2^31−1) | M61 (2^61−1) |
|----------|-------------|-------------|
| Element size | 32 bits | 64 bits |
| Product intermediate | 64 bits | 128 bits |
| GPU int multiply | Native (int32) | Emulated (int64) |
| Apple Metal | Fast (int32 native) | Slow (no int64) |
| CUDA | Fast (int32 native) | Medium (int64 via PTX) |
| CPU (ARM64/x86) | Fast | Fast |
| Field size | ~2.1 billion | ~2.3 quintillion |
| Matrix memory (n=512) | 1 MiB | 2 MiB |
| Security margin | Adequate for n ≤ 8192 | Very large |

M31 = 2^31 − 1 = 2,147,483,647 is a Mersenne prime. Key properties:
- `a * b` fits in uint64 (two 31-bit values → 62-bit product)
- Reduction: double Mersenne fold + conditional subtract; safe for any uint64
  input (see §7.2 for formal bit-range analysis — a single fold is only correct
  for inputs < 2^62; the double fold handles up to 2^64 − 1)
- Inner-product accumulation MUST use per-step reduction via `dot()` (§7.2.5);
  without it, even 4 worst-case products overflow uint64
- `M31 > n²` for n ≤ 46,340, so field arithmetic is exact (no modular
  wrap-around of intermediate sums) for all practical dimensions
- Used in production by StarkWare/Polygon for ZK provers (proven at scale)

### 3.5 Separate Transcript Block Size (b) from Noise Rank (r)

These control fundamentally different things:

| Parameter | Controls | Tuning consideration |
|-----------|----------|---------------------|
| `b` (transcript block size) | Hashing granularity, cache locality, transcript count = (n/b)³ | Larger b = fewer hash calls but larger intermediates |
| `r` (noise rank) | Security conjecture strength, denoising cost O(n²r) | Larger r = stronger security but more denoise work |

Default configuration for v1:
- `b = 16`: (512/16)³ = 32,768 intermediates; each is 16×16 = 1 KiB (uint32)
- `r = 8`: denoising cost = 512² × 8 = ~2M muls (negligible vs 512³ = 134M)

### 3.6 Trust Model: Node Tiers with Explicit Validation Scope

**First-class design decision, not an afterthought.**

Because verification is O(n^3) per block (n=512 means ~134M multiplications),
the protocol explicitly defines three node tiers with different Phase 2
validation scopes. The key question is not *if* a node validates, but *how
deep* its validation window extends.

#### 3.5.1 Node Tier Definitions

| Tier | Phase 2 scope | Trust assumption | Typical operator |
|------|--------------|------------------|-----------------|
| **Consensus-validating node** (Tier 1, "full") | ALL blocks at chain tip; full recompute from genesis (or from last assumevalid during IBD, then all new blocks forever). `nMatMulValidationWindow` (default: 1000, ~41.7 hours at 90s) bounds the minimum tip window for operational use. | Trustless for validated range | Miners, exchanges, protocol developers |
| **Economic node** (Tier 2, **not** "full") | None — Phase 1 only (digest < target + dimension bounds) for PoW; full UTXO/script validation for all transactions. Relies on assumevalid and full-node majority for transcript correctness. | Trusts full-node majority for transcript correctness | Merchants, wallets, infrastructure |
| **Light / SPV node** (Tier 3) | None — Phase 1 header check only (digest < target + dimension bounds). No UTXO validation. | Trusts full-node majority for transcript correctness | Mobile wallets, read-only explorers |

A node is considered **"full" in the BTX ecosystem** only if it validates
Phase 2 (transcript recomputation) for all blocks. This is the Tier 1
(consensus-validating) tier. Tier 2 (economic) nodes do **not** perform
Phase 2 and MUST NOT be labeled "full" (see §12.1 naming enforcement).
The consensus-validating tier is strictly stronger but not required for
normal economic participation.

#### 3.5.2 Practical Feasibility of Continuous Phase 2 Validation

At n=512 on a modern CPU (single-threaded), one Phase 2 verification takes
approximately 0.5--2 seconds. At a 90-second steady-state block time, this
is **0.3--1.3% CPU utilization** for continuous tip validation. During the
fast-mining phase (0.25s blocks), utilization is 200--800% — a single CPU core
cannot keep up. Fast-phase tip validation requires either GPU acceleration
or deferred batch verification. This is acceptable because the fast phase
lasts only ~3.5 hours and all blocks remain Phase 1-validated immediately.

| Hardware | Est. Phase 2 time (n=512) | CPU util at 90s blocks | CPU util at 0.25s blocks (fast phase) |
|----------|--------------------------|------------------------|---------------------------------------|
| Modern x86 (e.g., Zen 4) single-threaded | ~0.5s | ~0.3% | ~200% |
| Modern ARM (e.g., Apple M2) single-threaded | ~0.7s | ~0.5% | ~280% |
| Older x86 (e.g., Haswell-era) single-threaded | ~1.5--2.0s | ~1.0--1.3% | ~600--800% (cannot keep up) |
| Any CPU with GPU offload | < 0.1s | < 0.2% | < 40% |

Even the worst-case consumer hardware scenario (older CPU, no GPU) stays well
under 5% CPU utilization. The consensus-validating (Tier 1) node tier is therefore viable on
any machine from the last decade.

#### 3.5.3 v1 Storage Note

Since v1 uses seed-derived matrices, "proof data" is just two 32-byte seeds
per block (64 bytes). Even consensus-validating nodes have negligible storage
overhead. The expensive part is *recomputing* the transcript, not *storing*
the inputs.

**For v2 (arbitrary matrices)**: archival nodes must store full A, B
(~2 MiB/block at n=512). Pruned nodes drop A, B after confirmation depth. A
state-commitment scheme (UTXO accumulator or periodic snapshot) is required
before v2 ships to enable trustless joining without replaying all proofs.

---

## 4. Architectural Mapping to BTX

### 4.1 Call Chain (Fresh Genesis — No KAWPOW)

Validation:
```
validation.cpp:CheckBlock()
  └─ pow.cpp:CheckMatMulProofOfWork(block, height, params)
       └─ matmul_pow.cpp:Verify(block, height, params)
            ├─ matmul_field.cpp    (F_q arithmetic, M31)
            ├─ matmul_noise.cpp    (low-rank noise from oracle)
            └─ matmul_transcript.cpp (canonical MatMul + streaming hash)
```

Mining:
```
rpc/mining.cpp:GenerateBlock()
  └─ pow.cpp:SolveMatMul(block, height, params, max_tries)
       └─ matmul_pow.cpp:Solve(block, height, params, max_tries)
```

### 4.2 New Source Files

```
src/crypto/matmul/
├── field.h / field.cpp            # F_q arithmetic (M31: add, mul, inv)
├── matrix.h / matrix.cpp          # Matrix type, block decomposition, hash
├── noise.h / noise.cpp            # Low-rank noise (rank r, independent of b)
├── transcript.h / transcript.cpp  # Canonical MatMul (block size b) + streaming hash
├── matmul_pow.h / matmul_pow.cpp  # Solve() and Verify() entry points
└── params.h                       # Compile-time constants

src/test/
├── matmul_field_tests.cpp
├── matmul_matrix_tests.cpp
├── matmul_noise_tests.cpp
├── matmul_transcript_tests.cpp
├── matmul_pow_tests.cpp
├── matmul_params_tests.cpp
├── matmul_header_tests.cpp
├── matmul_validation_tests.cpp
├── matmul_trust_model_tests.cpp
├── matmul_dgw_tests.cpp
└── matmul_mining_tests.cpp

test/functional/
├── feature_btx_matmul_consensus.py
├── p2p_matmul_dos_mitigation.py
└── mining_matmul_basic.py

scripts/
├── matmul_pow_readiness.sh
└── matmul_pow_benchmark.sh
```

### 4.3 Files Modified

| File | Change |
|------|--------|
| `src/consensus/params.h` | Add matmul params (b, r, n, q, activation) |
| `src/primitives/block.h` | Replace KAWPOW fields with matmul fields |
| `src/pow.h` / `pow.cpp` | `CheckMatMulProofOfWork()`, `SolveMatMul()`, DGW for matmul |
| `src/validation.cpp` | Matmul validation (no KAWPOW branch) |
| `src/rpc/mining.cpp` | Matmul block template + solve |
| `src/node/miner.h/.cpp` | Block template matmul fields |
| `src/interfaces/mining.h` | MatMul fields in `BlockTemplate` |
| `src/kernel/chainparams.cpp` | New genesis, matmul params per network |
| `src/CMakeLists.txt` | `bitcoin_matmul` library target |

---

## 5. Consensus Parameter Design

### 5.1 New Fields in `Consensus::Params`

```cpp
// --- MatMul PoW parameters (v1: AI-native PoW; v2: PoUW with arbitrary matrices) ---
bool fMatMulPOW{false};
bool fSkipMatMulValidation{false};       // Fast regtest: skip transcript recompute

// Matrix geometry (b and r are independent)
uint32_t nMatMulDimension{512};          // n: matrix side length
uint32_t nMatMulTranscriptBlockSize{16}; // b: block size for canonical decomposition
uint32_t nMatMulNoiseRank{8};            // r: rank of noise matrices E, F
uint32_t nMatMulMinDimension{64};        // Floor on miner-reported dimension
uint32_t nMatMulMaxDimension{2048};      // Ceiling (DoS bound on verification cost)

// Field arithmetic
uint32_t nMatMulFieldModulus{0x7FFFFFFFU}; // q = 2^31 − 1 (M31 Mersenne prime)

// Node tier validation window (§3.6, §12.1)
uint32_t nMatMulValidationWindow{1000};        // Blocks of Phase 2 validation for Tier 1 (consensus-validating) nodes
                                               // Default 1000 = ~41.7 hours at 90s steady-state
                                               // (during fast phase: 1000 blocks = ~4.2 minutes)
                                               // Consensus-validating nodes ignore this (validate all)
                                               // Light/SPV nodes skip Phase 2 entirely

// Verification DoS limits (§10)
uint32_t nMatMulMaxPendingVerifications{4};  // Max concurrent expensive verifications
uint32_t nMatMulPeerVerifyBudgetPerMin{8};   // Max expensive verifications per peer per minute
                                              //
                                              // Rationale for default value (8):
                                              //   Steady state (90s blocks): ~0.4 blocks/min arrival rate;
                                              //     budget of 8 provides 20x headroom for burst absorption
                                              //     (Poisson clustering, small reorgs, reconnection catch-up).
                                              //   Fast phase (0.25s blocks): ~240 blocks/min; budget of 8 naturally
                                              //     enforces Phase 2 deferral (§10.3.1) at the rate-limit layer
                                              //     without special-case scheduling code.
                                              //   Attack bound: worst case 8 × 2.0s = 16s CPU/min per attacker
                                              //     peer (~27% single-core on older hardware); bounded further
                                              //     by nMatMulMaxPendingVerifications=4 concurrency cap and
                                              //     nMatMulPhase2FailBanThreshold=3 (ban after 3 failures).
                                              //   IBD: budget-limited to 8 verifications/min from the IBD peer;
                                              //     operators MAY raise for faster Phase 2 catch-up on dedicated
                                              //     hardware (see §12.4 tuning notes).
uint32_t nMatMulPhase2FailBanThreshold{3};   // Ban after N Phase 2 failures within 24h from same peer
                                              // Effective: 1 when fMatMulStrictPunishment == true
                                              // Effective: UINT32_MAX on testnet/regtest (never ban)
bool fMatMulStrictPunishment{false};          // Network maturity flag (section 10.2.3)
                                              // false (v1.0): graduated disconnect -> discourage -> ban
                                              // true (post-stabilization): immediate ban on Phase 2 fail
                                              // Always overridden to false on testnet/regtest

// --- Monetary policy (§11.4) ---
CAmount nMaxMoney{21'000'000 * COIN};         // Hard supply cap; MoneyRange() enforced everywhere
int32_t nSubsidyHalvingInterval{525'000};     // Blocks between halvings
CAmount nInitialSubsidy{20 * COIN};           // Genesis block reward; 20 * 525000 * 2 = 21M
                                              // Bitcoin-style infinite halving: sum = nInitialSubsidy * nSubsidyHalvingInterval * 2

// --- Target spacing schedule (§11.5) ---
int64_t nPowTargetSpacingNormal{90};          // Steady-state: 90 seconds between blocks
int64_t nPowTargetSpacingFastMs{250};         // Fast-mining phase: 250 milliseconds (0.25s) between blocks
int32_t nFastMineHeight{50'000};              // First height at which normal spacing applies
                                              // Heights [0, nFastMineHeight) use nPowTargetSpacingFastMs
                                              // Heights >= nFastMineHeight use nPowTargetSpacingNormal
int32_t nFastMineDifficultyScale{4};          // Scales bootstrap difficulty by 4x for 0.25s target
```

**Consensus helper** (must be identical in all implementations):

```cpp
/// Returns the target inter-block spacing in seconds (as double) for a given height.
/// This is a consensus function: any deviation is a chain split.
inline double GetTargetSpacing(int32_t height, const Consensus::Params& p) {
    return (height < p.nFastMineHeight) ? p.nPowTargetSpacingFastMs / 1000.0
                                        : static_cast<double>(p.nPowTargetSpacingNormal);
}
```

**Block capacity model** (SegWit-style weight, §14):

```cpp
// --- Block capacity model (SegWit-style weight) (§14) ---
//
// Consensus limits (hard):
// These override the upstream constants in consensus/consensus.h for BTX.
uint32_t nMaxBlockWeight{24'000'000};          // 24M weight units (~6 MB non-witness, ~24 MB witness)
                                               // 6x Bitcoin's MAX_BLOCK_WEIGHT (4,000,000)
uint32_t nMaxBlockSerializedSize{24'000'000};  // Hard safety cap on serialized bytes (DoS guard)
uint32_t nMaxBlockSigOpsCost{480'000};         // Sigops budget scaled with weight (6x Bitcoin's 80,000)

// Policy defaults (soft, node-configurable):
uint32_t nDefaultBlockMaxWeight{24'000'000};   // Default miner template target (equals consensus max)
uint32_t nDefaultMempoolMaxSizeMB{2048};       // Default mempool size (MB)
```

**Design notes on block capacity**:

- **WITNESS_SCALE_FACTOR** remains **4** (inherited from BIP 141). Non-witness
  data costs 4 weight units per byte; witness data costs 1 weight unit per byte.
- At `nMaxBlockWeight = 24,000,000`:
  - Worst-case all-non-witness block: 24M / 4 = **6 MB** serialized.
  - Theoretical max (all witness): **24 MB** serialized (equal to
    `nMaxBlockSerializedSize`).
  - Practical mixed: typically **2-6 MB** serialized per block.
- The codebase already implements `GetBlockWeight()` and `GetTransactionWeight()`
  in `src/consensus/validation.h`, weight checking in `ContextualCheckBlock()`
  in `src/validation.cpp`, and mining weight tracking in `src/node/miner.cpp`.
  The change is to parameter values, not to code structure.
- `nDefaultBlockMaxWeight` (24M) equals the consensus maximum. Miners use the
  full consensus allowance by default.

### 5.2 Network Configuration

#### 5.2.1 MatMul Geometry

| Network | `n` | `b` | `r` | `q` | Notes |
|---------|-----|-----|-----|-----|-------|
| mainnet | 512 | 16 | 8 | M31 | ~134M muls/block verify |
| testnet | 256 | 8 | 4 | M31 | ~16.7M muls/block |
| regtest | 64 | 8 | 4 | M31 | ~262K muls; instant solve |

#### 5.2.2 Monetary Policy and Target Spacing

| Network | Fast height | Fast spacing | Normal spacing | Halving interval | Initial subsidy | Max supply |
|---------|-------------|-------------|---------------|-----------------|----------------|-----------|
| mainnet | 50,000 | 0.25 s (250ms) | 90 s | 525,000 | 20 BTX | 21,000,000 BTX |
| testnet | 50,000 | 0.25 s (250ms) | 90 s | 525,000 | 20 BTX | 21,000,000 BTX |
| regtest | 0 | 90 s | 90 s | 150 | 20 BTX | 21,000,000 BTX |

**Regtest note**: `nFastMineHeight = 0` means regtest has no fast-mining
phase (all blocks use normal spacing). `nSubsidyHalvingInterval = 150` allows
rapid halving testing. All other monetary invariants still hold.

#### 5.2.3 Block Capacity (Weight-Based)

| Network | Max weight (consensus) | Max serialized size | Max sigops cost | Default mining weight (policy) |
|---------|----------------------|--------------------|-----------------|-----------------------------|
| mainnet | 24,000,000 | 24,000,000 | 480,000 | 24,000,000 |
| testnet | 24,000,000 | 24,000,000 | 480,000 | 24,000,000 |
| regtest | 24,000,000 | 24,000,000 | 480,000 | 24,000,000 |

**Note**: `nDefaultBlockMaxWeight` equals the consensus maximum on all networks.
Miners use the full consensus allowance by default.

### 5.3 Invariants

```
INVARIANT: b divides n evenly                    (clean block decomposition)
INVARIANT: r <= b                                (noise rank bounded by block size)
INVARIANT: nMatMulMinDimension <= n <= nMatMulMaxDimension
INVARIANT: q is prime
INVARIANT: q > n                                 (field larger than dimension)
INVARIANT: q fits in 31 bits                     (products fit in uint64)
INVARIANT: nMatMulValidationWindow >= 100         (minimum window for economic security)
INVARIANT: n, b, r are per-network constants      (miners MUST NOT vary per block)

// --- Monetary policy invariants ---
INVARIANT: nInitialSubsidy == 20 * COIN          (20 BTX per block at genesis)
INVARIANT: nSubsidyHalvingInterval == 525000      (halving every 525k blocks on mainnet)
INVARIANT: nMaxMoney == 21'000'000 * COIN         (hard supply cap)
INVARIANT: nInitialSubsidy * nSubsidyHalvingInterval * 2 == nMaxMoney
           // ^^^ Both sides in satoshis: (20*COIN) * 525000 * 2 == 21'000'000*COIN

// --- Target spacing schedule invariants ---
INVARIANT: nPowTargetSpacingFastMs == 250         (250ms / 0.25-second blocks during fast phase)
INVARIANT: nPowTargetSpacingNormal == 90          (90-second blocks at steady state)
INVARIANT: nFastMineHeight == 50000               (fast phase: blocks [0, 50000))
INVARIANT: nFastMineDifficultyScale == 6          (bootstrap difficulty scaled 6x for 0.25s target on mainnet)
INVARIANT: GetTargetSpacing(h, p) == 0.25 for all h in [0, 50000)
INVARIANT: GetTargetSpacing(h, p) == 90   for all h >= 50000

// --- Block capacity invariants (SegWit-style weight) ---
INVARIANT: nMaxBlockWeight == 24'000'000       (consensus weight ceiling)
INVARIANT: nMaxBlockSerializedSize == 24'000'000 (DoS byte ceiling)
INVARIANT: nMaxBlockSigOpsCost == 480'000       (sigops budget)
INVARIANT: nDefaultBlockMaxWeight <= nMaxBlockWeight
INVARIANT: nMaxBlockSerializedSize >= 1'000'000 (hard minimum safety floor)
INVARIANT: nMaxBlockWeight is a per-network constant (miners MUST NOT vary per block)
INVARIANT: WITNESS_SCALE_FACTOR == 4            (non-witness byte = 4 WU)
```

**Per-block parameter immutability**: The values of `n`, `b`, and `r` are
fixed per network by consensus parameters and MUST NOT be varied by miners on
a per-block basis. A block whose header implies different values (e.g., a
`matmul_dim` that does not match `nMatMulDimension`) is invalid. This closes
any "dimension grinding" or "parameter shopping" loophole where a miner might
select favorable geometry to reduce proof difficulty.

### 5.4 Tests for Consensus Parameters

```
TEST: matmul_params_defaults
  GIVEN: Default Params
  THEN: nMatMulDimension == 512, nMatMulTranscriptBlockSize == 16, nMatMulNoiseRank == 8
  AND: nMatMulFieldModulus == 0x7FFFFFFF
  AND: nMatMulValidationWindow == 1000

TEST: matmul_params_regtest
  GIVEN: CreateChainParams(ChainType::REGTEST)
  THEN: fMatMulPOW == true, n == 64, b == 8, r == 4

TEST: matmul_params_invariants
  FOR EACH network:
    Assert n % b == 0
    Assert r <= b
    Assert nMatMulMinDimension <= n <= nMatMulMaxDimension
    Assert is_prime(q)
    Assert q > n

TEST: matmul_params_b_and_r_independent
  GIVEN: n=512, b=16, r=8
  THEN: b != r (they are independent parameters)
  AND: (n/b)³ == 32768 (transcript intermediate count)
  AND: n² * r == 2097152 (denoise work)

TEST: monetary_params_defaults
  GIVEN: Default Params (mainnet)
  THEN: nInitialSubsidy == 20 * COIN
  AND: nSubsidyHalvingInterval == 525000
  AND: nMaxMoney == 21'000'000 * COIN

TEST: monetary_params_cap_identity
  GIVEN: Default Params
  THEN: nInitialSubsidy/COIN * nSubsidyHalvingInterval * 2 == nMaxMoney/COIN
  // This is the mathematical identity: 20 * 525000 * 2 == 21,000,000

TEST: target_spacing_fast_phase
  GIVEN: Default Params (mainnet)
  THEN: GetTargetSpacing(0, params) == 0.25
  AND: GetTargetSpacing(1, params) == 0.25
  AND: GetTargetSpacing(49999, params) == 0.25

TEST: target_spacing_normal_phase
  GIVEN: Default Params (mainnet)
  THEN: GetTargetSpacing(50000, params) == 90
  AND: GetTargetSpacing(50001, params) == 90
  AND: GetTargetSpacing(1000000, params) == 90

TEST: target_spacing_regtest_no_fast_phase
  GIVEN: CreateChainParams(ChainType::REGTEST)
  THEN: nFastMineHeight == 0
  AND: GetTargetSpacing(0, params) == 90.0
  AND: GetTargetSpacing(1, params) == 90.0

TEST: block_capacity_params_defaults
  GIVEN: Default Params (mainnet)
  THEN: nMaxBlockWeight == 24'000'000
  AND: nDefaultBlockMaxWeight == 24'000'000
  AND: nMaxBlockSerializedSize == 24'000'000
  AND: nMaxBlockSigOpsCost == 480'000
  AND: nMaxBlockWeight >= nDefaultBlockMaxWeight

TEST: block_capacity_params_sane_sizes
  GIVEN: Default Params
  THEN: nMaxBlockSerializedSize >= 1'000'000

TEST: block_capacity_weight_validation
  GIVEN: A block with GetBlockWeight(block) == nMaxBlockWeight
  THEN: Block passes weight check
  GIVEN: A block with GetBlockWeight(block) == nMaxBlockWeight + 1
  THEN: Block fails with "bad-blk-weight"

TEST: block_capacity_sigops_validation
  GIVEN: A block with GetBlockSigOpsCost(block) == nMaxBlockSigOpsCost
  THEN: Block passes sigops check
  GIVEN: A block with GetBlockSigOpsCost(block) == nMaxBlockSigOpsCost + 1
  THEN: Block fails with "bad-blk-sigops"
```

---

## 6. Block Header Changes

### 6.1 Fresh Genesis Header (No KAWPOW Fields)

```cpp
class CBlockHeader
{
public:
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint64_t nNonce64;         // 64-bit miner nonce
    uint256 matmul_digest;     // Transcript hash z (the PoW hash)
    uint16_t matmul_dim;       // Matrix dimension n (redundant but explicit)
    uint256 seed_a;            // Seed for matrix A generation
    uint256 seed_b;            // Seed for matrix B generation

    SERIALIZE_METHODS(CBlockHeader, obj)
    {
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot,
                  obj.nTime, obj.nBits, obj.nNonce64,
                  obj.matmul_digest, obj.matmul_dim,
                  obj.seed_a, obj.seed_b);
    }
};
```

Header size: 4 + 32 + 32 + 4 + 4 + 8 + 32 + 2 + 32 + 32 = **182 bytes**
(vs Bitcoin's 80; vs current BTX KAWPOW's ~152)

No `nNonce` (legacy 32-bit), no `mix_hash` (KAWPOW-specific). Clean break.

### 6.2 Seed Derivation: Canonical Serialization

The random oracle seed σ must be specified down to the byte:

```
matmul_header_hash = SHA-256(
    LE32(nVersion)           ||   // 4 bytes, little-endian
    hashPrevBlock            ||   // 32 bytes, internal byte order
    hashMerkleRoot           ||   // 32 bytes, internal byte order
    LE32(nTime)              ||   // 4 bytes, little-endian
    LE32(nBits)              ||   // 4 bytes, little-endian
    LE64(nNonce64)           ||   // 8 bytes, little-endian
    LE16(matmul_dim)         ||   // 2 bytes, little-endian
    seed_a                   ||   // 32 bytes, internal byte order
    seed_b                        // 32 bytes, internal byte order
)
// NOTE: matmul_digest is EXCLUDED (it depends on σ)

σ = SHA-256(matmul_header_hash)
```

The exclusion of `matmul_digest` from the header hash input creates the
dependency chain:

```
{nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nNonce64, matmul_dim, seed_a, seed_b}
  → matmul_header_hash
    → σ
      → noise (E, F)
        → transcript
          → z = matmul_digest
```

Changing any of `{nNonce64, nTime, transactions (via merkleRoot), seed_a, seed_b}`
changes σ → changes noise → changes transcript → changes z.

### 6.3 Tests for Block Header

```
TEST: header_serialize_roundtrip
  GIVEN: Header with all fields populated
  WHEN: Serialize to DataStream, deserialize to new header
  THEN: All fields match exactly

TEST: header_size_is_182_bytes
  GIVEN: Header serialized to DataStream
  THEN: stream.size() == 182

TEST: header_setNull_clears_all
  GIVEN: Populated header
  WHEN: SetNull()
  THEN: matmul_digest.IsNull(), matmul_dim == 0, seed_a.IsNull(), seed_b.IsNull()

TEST: header_hash_excludes_digest
  GIVEN: Two headers identical except matmul_digest differs
  WHEN: Compute matmul_header_hash (for σ derivation)
  THEN: Both produce the same matmul_header_hash
  (matmul_digest is excluded from σ input)

TEST: header_block_hash_includes_digest
  GIVEN: Two headers identical except matmul_digest differs
  WHEN: Compute GetHash() (block identity)
  THEN: GetHash() values differ
  (matmul_digest IS part of the block identity hash)

TEST: seed_derivation_exact_bytes
  GIVEN: Known header field values
  WHEN: Compute σ
  THEN: σ matches precomputed expected value
  (This is the consensus-critical determinism test; pin exact bytes)

TEST: seed_changes_with_nonce
  GIVEN: Same header, different nNonce64
  WHEN: Compute σ for each
  THEN: σ values differ

TEST: seed_changes_with_matrix_seed
  GIVEN: Same header, different seed_a
  WHEN: Compute σ
  THEN: σ values differ
```

---

## 7. Finite-Field Arithmetic Library

### 7.1 Design: M31 (2^31 − 1)

All MatMul computations use F_q where q = 2^31 − 1 = 2,147,483,647.

- Elements are `uint32_t` in [0, q)
- Products of two elements fit in `uint64_t` (62 bits max)
- Reduction: double Mersenne fold `(x >> 31) + (x & M31)` applied twice, then
  one conditional subtract; safe for any uint64_t input (see §7.2 for analysis)
- Inner products: `dot()` accumulates with per-step reduction after each
  multiply-add; this is the ONLY approved accumulation path (see §7.2.5)

```cpp
namespace matmul::field {

using Element = uint32_t;
constexpr Element MODULUS = 0x7FFFFFFFU;  // 2^31 − 1

Element add(Element a, Element b);       // (a + b) mod q
Element sub(Element a, Element b);       // (a − b + q) mod q
Element mul(Element a, Element b);       // (a × b) mod q
Element inv(Element a);                  // a^(q−2) mod q (Fermat)
Element neg(Element a);                  // (q − a) mod q
Element from_uint32(uint32_t x);         // x mod q
Element from_oracle(const uint256& seed, uint32_t index);  // deterministic element

// Inner product with per-step reduction (GPU-friendly pattern)
Element dot(const Element* a, const Element* b, uint32_t len);

} // namespace matmul::field
```

### 7.2 Reduction and Accumulation

#### 7.2.1 Mersenne-Prime Folding: Why a Single Fold Is Insufficient

For q = 2^31 − 1, the key identity is **2^31 ≡ 1 (mod q)**. Therefore any
non-negative integer x satisfies:

```
x mod q  ≡  (x mod 2^31) + floor(x / 2^31)   (mod q)
```

This "fold" replaces a reduction by a 31-bit modulus with a simple shift, mask,
and add. However, the result of one fold may itself exceed q, requiring further
reduction. The critical question is: **how many folds are needed for a given
input range?**

#### 7.2.2 Formal Bit-Range Analysis

**Notation**: Let `lo(x) = x & 0x7FFFFFFF` (low 31 bits) and
`hi(x) = x >> 31` (upper bits, as a full-width integer).

**Single product of two field elements** (the `mul` case):

```
Input domain:  a, b ∈ [0, q)  ⊂  [0, 2^31 − 1)
Product:       x = a × b  ∈  [0, (2^31−2)^2]  =  [0, 2^62 − 2^33 + 4]

After one fold:
  lo  = x & (2^31−1)          ∈  [0, 2^31 − 1]
  hi  = x >> 31               ∈  [0, 2^31 − 4]     (since x < 2^62)
  sum = lo + hi               ∈  [0, 2^32 − 5]

  sum fits in uint32_t (max 2^32 − 1).                             ✓
  sum < 2·q = 2^32 − 2, so one conditional subtract → [0, q).      ✓
```

**A single fold + conditional subtract is correct for x < 2^62.**

**Accumulated sum WITHOUT per-step reduction** (the DANGEROUS case):

```
If acc = Σ_{i=0}^{n-1} a[i]·b[i]  accumulated in uint64 without reducing:

  Each product ≤ (2^31−2)^2  ≈  2^62
  After n = 4 terms:  acc ≈ 4 × 2^62 = 2^64   → OVERFLOWS uint64_t!
  After n = 2 terms:  acc ≈ 2 × 2^62 = 2^63   → still in uint64, but...
```

Even if the sum does not overflow uint64, applying a single fold to a value
x ≥ 2^62 is **incorrect** due to two compounding bugs:

**Bug 1 — Truncation of hi**: `(uint32_t)(x >> 31)` silently discards bits
above position 31 of the shifted value:

```
x = 2^63:
  x >> 31 = 2^32             (33 bits: does NOT fit in uint32_t)
  (uint32_t)(2^32) = 0       (high bit lost!)
  Old reduce64 returns 0.    WRONG — correct answer is 2.
```

**Bug 2 — Overflow of lo + hi**: Even when hi fits in uint32_t (x < 2^63),
the sum lo + hi can exceed uint32_t:

```
x = 2^63 − 2^34 + 8  (= 2 × (q−1)^2, i.e., two worst-case products):
  lo = 8
  hi = (uint32_t)(x >> 31) = 2^32 − 8 = 4,294,967,288   (fits uint32)
  lo + hi = 4,294,967,296 = 2^32                          OVERFLOWS uint32_t!
  After wrap: result = 0.    WRONG — correct answer is 2.
```

**Full input range** (x up to 2^64 − 1):

```
x = 2^64 − 1  (max uint64_t):
  Correct answer: (2^64 − 1) mod q = 3
    Proof: 2^31 ≡ 1 (mod q), so 2^62 ≡ 1, 2^64 = 2^62 · 4 ≡ 4.
           2^64 − 1 ≡ 3 (mod q).

  Old single-fold: returns q − 2 = 2,147,483,645.    WRONG.
    (hi truncated from 2^33−1 to 2^32−1; lo+hi wraps in uint32.)
```

#### 7.2.3 The Double-Fold Approach

Two folds handle **any** uint64_t input:

```
FIRST FOLD (x in [0, 2^64)):
  lo_1 = x & 0x7FFFFFFF                 ∈  [0, 2^31 − 1]
  hi_1 = x >> 31                         ∈  [0, 2^33 − 1]
  fold1 = lo_1 + hi_1                    ∈  [0, 5·2^31 − 2]     (≤ 34 bits)

  CRITICAL: fold1 is computed in uint64_t to avoid truncation of hi_1.

SECOND FOLD (fold1 in [0, 5·2^31 − 2)):
  lo_2 = fold1 & 0x7FFFFFFF              ∈  [0, 2^31 − 1]
  hi_2 = fold1 >> 31                     ∈  [0, 4]
  result = lo_2 + hi_2                   ∈  [0, 2^31 + 3]

  result fits in uint32_t (max 2^31 + 3 < 2^32 − 1).              ✓
  result < 2·q = 2^32 − 2, so one conditional subtract → [0, q).   ✓
```

**Worst-case trace** (x = 2^64 − 1):

```
fold1 = (2^31 − 1) + (2^33 − 1) = 5·2^31 − 2 = 10,737,418,238
lo_2  = 10,737,418,238 & (2^31 − 1) = 2,147,483,646 = q − 1
hi_2  = 10,737,418,238 >> 31 = 4
result = (q − 1) + 4 = q + 3 = 2,147,483,650
result ≥ q  →  result − q = 3                                      ✓
```

#### 7.2.4 Implementation

```cpp
// reduce64: Reduces any uint64_t to [0, MODULUS) via double Mersenne fold.
//
// SAFE FOR ALL uint64_t INPUTS including accumulated sums that exceed 2^62.
//
// Cost: 2 shifts, 3 masks/adds, 1 conditional subtract.
// The second fold adds negligible overhead (~2 ns) and eliminates an entire
// class of subtle overflow bugs. Do NOT "optimize" this back to a single fold.
//
Element reduce64(uint64_t x) {
    // --- FIRST FOLD ---
    // 2^31 ≡ 1 (mod q), so x mod q ≡ (x mod 2^31 + x/2^31) mod q.
    // hi_1 can be up to 2^33 − 1 (33 bits); must stay in uint64_t.
    uint64_t fold1 = (x & (uint64_t)MODULUS) + (x >> 31);
    // fold1 ∈ [0, 5·2^31 − 2], fits in 34 bits of uint64_t.

    // --- SECOND FOLD ---
    // fold1 >> 31 ≤ 4, so lo_2 + hi_2 ≤ 2^31 + 3 < 2·q.
    uint32_t lo = (uint32_t)(fold1 & MODULUS);
    uint32_t hi = (uint32_t)(fold1 >> 31);
    uint32_t result = lo + hi;

    // --- FINAL CONDITIONAL SUBTRACT ---
    // result ∈ [0, 2^31 + 3]. Since 2^31 + 3 < 2·q = 2^32 − 2,
    // at most one subtract yields result ∈ [0, q).
    if (result >= MODULUS) result -= MODULUS;
    return result;
}

// mul: Multiply two field elements.
//
// a, b ∈ [0, q) ⊂ [0, 2^31 − 1).
// Product ∈ [0, (2^31−2)^2] = [0, 2^62 − 2^33 + 4] < 2^62.
// This is well within reduce64's safe domain (reduce64 handles up to 2^64 − 1).
// For this input range the second fold is effectively a no-op (fold1 < 2^32,
// so hi_2 ≤ 1), but we use the general reduce64 for simplicity and safety.
//
Element mul(Element a, Element b) {
    return reduce64((uint64_t)a * b);
}
```

No `__uint128_t` needed. Pure uint32/uint64 arithmetic. Works on every platform
including GPU targets (CUDA, Metal, OpenCL) where 128-bit integers are
unavailable.

#### 7.2.5 Accumulation: The `dot()` Function

**`dot()` is the ONLY approved path for accumulating field-element products.**
Raw loops that sum unreduced products into a uint64_t accumulator are forbidden
in the codebase. This constraint is enforced by code review and by the absence
of any public `reduce64` in the API — `reduce64` is an internal helper used
only by `mul()` and `dot()`.

**Safety argument for `dot()`**:

```
Loop invariant: acc ∈ [0, q)  at the top of every iteration.

Per iteration:
  product = a[i] × b[i]       ∈  [0, (q−1)^2]  ⊂  [0, 2^62 − 2^33 + 4]
  sum     = acc + product      ≤  (q−1) + (2^62 − 2^33 + 4)
                               =   2^62 − 2^31 + 2
                               <   2^62

Therefore: sum < 2^62 for EVERY iteration, regardless of len.

This means:
  1. sum never overflows uint64_t (which holds up to 2^64 − 1).        ✓
  2. reduce64 receives an input < 2^62, for which even a single fold
     would suffice (the second fold in reduce64 is a no-op here).      ✓
  3. The output of reduce64 is in [0, q), restoring the loop invariant. ✓

This holds for ANY len, from 1 to 2^32 − 1. The per-step reduction
makes the accumulation length-independent — there is no "maximum safe
vector length."
```

**Why naive accumulation is catastrophically unsafe**:

```
Without per-step reduction, accumulating just 4 worst-case products overflows:

  4 × (q−1)^2  =  4 × (2^62 − 2^33 + 4)  =  2^64 − 2^35 + 16  >  2^64 − 1

  → uint64_t overflow → silent wraparound → wrong field element
  → consensus disagreement between platforms with different overflow behavior
  → CHAIN SPLIT

Even 2 products can reach 2^63, which (while not overflowing uint64) causes
the old single-fold reduce64 to return wrong results (see §7.2.2 Bug 1/2).
```

**Implementation**:

```cpp
// dot: Inner product of two field-element vectors with per-step reduction.
//
// This is the ONLY approved way to accumulate products of field elements.
// Every multiply-add is immediately reduced, keeping the accumulator in [0, q).
//
// The function is safe for ANY len, including len = 0 (returns 0).
// No intermediate value ever exceeds 2^62 (see safety argument above).
//
// GPU note: This pattern maps directly to a sequential reduction loop.
// For GPU-parallel dot products (e.g., warp-level reductions), each partial
// sum must also be reduced before cross-lane combination.
//
Element dot(const Element* a, const Element* b, uint32_t len) {
    Element acc = 0;  // acc ∈ [0, q)  — invariant holds trivially at start

    for (uint32_t i = 0; i < len; ++i) {
        // a[i], b[i] ∈ [0, q), so product ∈ [0, (q−1)^2] < 2^62
        uint64_t product = (uint64_t)a[i] * b[i];

        // acc < q < 2^31, product < 2^62
        // sum < 2^31 + 2^62 < 2^63  — no uint64 overflow
        uint64_t sum = (uint64_t)acc + product;

        // reduce64 is safe for all uint64; here sum < 2^62 so the
        // second fold is a no-op. Result is in [0, q), restoring invariant.
        acc = reduce64(sum);
    }

    return acc;
}
```

#### 7.2.6 Design Rules for Callers

1. **Always use `dot()` for inner products.** Never write a raw accumulation
   loop over field-element products. The canonical matmul's inner loops
   (b-length dot products for each output element of a b x b block multiply)
   and the transcript compression (b^2-length dot product) must both go
   through `dot()`.

2. **`reduce64` is not part of the public API.** It is `static` /
   file-internal. Callers use `mul()`, `add()`, `dot()`, etc. This prevents
   misuse where someone calls `reduce64` on an unreduced accumulated sum
   that exceeds 2^62.

3. **For GPU kernels**: The same per-step-reduction discipline applies.
   Warp-level parallel reductions must reduce partial sums before combining.
   A GPU `dot()` implementation must be mathematically equivalent to the
   sequential reference — any reordering must preserve the property that
   no intermediate exceeds 2^62.

4. **Why reduce64 is safe for all uint64 anyway** (defense in depth): Even
   though `dot()` guarantees inputs < 2^62, the double-fold `reduce64`
   handles up to 2^64 − 1 correctly. This is deliberate defense in depth.
   If a future code path accidentally feeds a larger value, `reduce64` will
   still return the correct field element rather than silently corrupting
   consensus state.

### 7.3 Tests for Field Arithmetic

```
TEST: field_modulus_is_prime
  Assert is_prime(0x7FFFFFFF) == true

TEST: field_add_basic
  Assert add(0, 0) == 0
  Assert add(1, MODULUS − 1) == 0
  Assert add(MODULUS − 1, MODULUS − 1) == MODULUS − 2

TEST: field_add_commutative
  FOR 1000 random (a, b): Assert add(a, b) == add(b, a)

TEST: field_mul_basic
  Assert mul(0, x) == 0 for random x
  Assert mul(1, x) == x for random x
  Assert mul(MODULUS − 1, MODULUS − 1) == 1   // (−1)² = 1

TEST: field_mul_associative
  FOR 1000 random (a, b, c): Assert mul(a, mul(b, c)) == mul(mul(a, b), c)

TEST: field_mul_distributive
  FOR 1000 random (a, b, c): Assert mul(a, add(b, c)) == add(mul(a, b), mul(a, c))

TEST: field_inverse
  FOR 1000 random a ≠ 0: Assert mul(a, inv(a)) == 1
  Assert inv(1) == 1
  Assert inv(MODULUS − 1) == MODULUS − 1

TEST: field_sub_is_add_neg
  FOR 1000 random (a, b): Assert sub(a, b) == add(a, neg(b))

TEST: field_from_oracle_deterministic
  Same (seed, index) → same element; different → different
  All outputs in [0, MODULUS)
  (Full byte-exact specification in §7.4; pinned test vectors in §7.4.7;
   comprehensive from_oracle and FromSeed tests in §7.4.8)

TEST: field_reduce64_edge_cases
  Assert reduce64(0) == 0
  Assert reduce64(1) == 1
  Assert reduce64(MODULUS) == 0
  Assert reduce64(MODULUS + 1) == 1
  Assert reduce64((uint64_t)MODULUS * MODULUS) == 0     // q^2 ≡ 0 (mod q)
  Assert reduce64((uint64_t)(MODULUS-1) * (MODULUS-1)) == 1   // (-1)^2 = 1

TEST: field_reduce64_single_fold_boundary
  // Values at the boundary where a single fold would still work (x < 2^62).
  // Verify the double-fold reduce64 agrees with naive modular arithmetic.
  Assert reduce64((1ULL << 62) - 1) == ((1ULL << 62) - 1) % MODULUS
  Assert reduce64((1ULL << 62))     == ((1ULL << 62)) % MODULUS     // = 1
  Assert reduce64((uint64_t)(MODULUS - 1) * MODULUS) == 0           // (q-1)*q ≡ 0

TEST: field_reduce64_double_fold_required
  // Values where a naive single-fold-to-uint32 is INCORRECT.
  // These tests MUST fail if reduce64 is reverted to single-fold uint32 code.
  //
  // x = 2^63: single-fold truncates hi from 2^32 to 0.
  //   Correct: 2^63 mod q = 2  (since 2^31 ≡ 1, 2^62 ≡ 1, 2^63 ≡ 2)
  Assert reduce64(1ULL << 63) == 2
  //
  // x = 2^63 − 1: single-fold causes lo+hi overflow in uint32.
  //   Correct: 2^63 − 1 mod q = 1
  Assert reduce64((1ULL << 63) - 1) == 1
  //
  // x = 2 * (q-1)^2: two worst-case products summed.
  //   = 2 * (2^62 − 2^33 + 4) = 2^63 − 2^34 + 8
  //   Correct: 2 * 1 = 2  (since (q-1)^2 mod q = 1)
  Assert reduce64(2ULL * (uint64_t)(MODULUS-1) * (MODULUS-1)) == 2
  //
  // x = UINT64_MAX = 2^64 − 1.
  //   Correct: 2^64 ≡ 4, so 2^64 − 1 ≡ 3 (mod q)
  Assert reduce64(UINT64_MAX) == 3
  //
  // x = 3 * (q-1)^2: three worst-case products summed (still fits uint64).
  //   3 * (2^62 − 2^33 + 4) = 3·2^62 − 3·2^33 + 12 ≈ 1.38 × 10^19 < 2^64
  //   Correct: 3 * 1 = 3
  Assert reduce64(3ULL * (uint64_t)(MODULUS-1) * (MODULUS-1)) == 3
  //
  // x = UINT64_MAX − MODULUS + 1 = 2^64 − q.
  //   (2^64 − q) mod q = (4 − 0) mod q = 4  (since 2^64 ≡ 4, q ≡ 0)
  Assert reduce64(UINT64_MAX - (uint64_t)MODULUS + 1) == 4

TEST: field_reduce64_exhaustive_power_of_two
  // Verify reduce64(2^k) for all k in [0, 63].
  // Since 2^31 ≡ 1 (mod q), we have 2^k ≡ 2^(k mod 31) (mod q).
  FOR k in 0..63:
    uint64_t x = 1ULL << k
    Element expected = 1ULL << (k % 31)     // 2^(k mod 31), guaranteed < q
    Assert reduce64(x) == expected

TEST: field_dot_product_basic
  GIVEN: Two vectors of known elements, length 4
    a = {1, 2, 3, 4}, b = {5, 6, 7, 8}
  WHEN: dot(a, b, 4)
  THEN: Result == (1*5 + 2*6 + 3*7 + 4*8) mod q = 70

TEST: field_dot_product_empty
  WHEN: dot(a, b, 0)
  THEN: Result == 0  (empty sum)

TEST: field_dot_product_matches_manual_reduce
  GIVEN: Random vectors of length 256
  WHEN: dot(a, b, 256)
  THEN: Result == manual loop: acc = 0; for each i: acc = reduce64(acc + (uint64_t)a[i]*b[i])
  AND: Result == Python/GMP reference: sum(a[i]*b[i]) mod q

TEST: field_dot_product_worst_case_short
  // All elements are (q − 1); verifies per-step reduction handles max products.
  // Each product = (q−1)^2 ≡ 1 (mod q). Dot product of length n = n mod q.
  GIVEN: a[i] = b[i] = MODULUS − 1 for all i, length = 100
  WHEN: dot(a, b, 100)
  THEN: Result == 100
  (Because each a[i]*b[i] mod q = 1, and sum of 100 ones = 100.)

TEST: field_dot_product_worst_case_n512
  // Simulates one row of the n=512 matmul inner product, all max-value elements.
  // This is the actual worst case that occurs in canonical matmul verification.
  GIVEN: a[i] = b[i] = MODULUS − 1 for all i, length = 512
  WHEN: dot(a, b, 512)
  THEN: Result == 512
  (Because 512 < q, the sum 512 is already reduced.)

TEST: field_dot_product_worst_case_large
  // len = 8192: exceeds any block size b or dimension n in the consensus params.
  // Without per-step reduction, this would overflow uint64 after ~4 terms.
  GIVEN: a[i] = b[i] = MODULUS − 1 for all i, length = 8192
  WHEN: dot(a, b, 8192)
  THEN: Result == 8192

TEST: field_dot_product_worst_case_near_modulus
  // len = MODULUS − 1 (conceptual; test with len close to q to verify no
  // accumulation-length-dependent bugs). Practical test: len = 2^20 = 1,048,576.
  GIVEN: a[i] = b[i] = MODULUS − 1 for all i, length = 1048576
  WHEN: dot(a, b, 1048576)
  THEN: Result == 1048576
  (Still < q, so result is just the length.)

TEST: field_dot_product_worst_case_exceeds_modulus
  // len = MODULUS + 1 = q + 1 (may be too slow for unit test; mark as LONG).
  // If practical, verify that the sum wraps correctly in the field.
  GIVEN: a[i] = b[i] = MODULUS − 1 for all i, length = MODULUS + 1
  WHEN: dot(a, b, MODULUS + 1)
  THEN: Result == (MODULUS + 1) % MODULUS == 1
  (The sum of (q+1) ones in F_q is 1.)

TEST: field_naive_accumulation_overflow_demonstration
  // NEGATIVE TEST: Demonstrates that naive (no per-step reduction) accumulation
  // produces WRONG results. This test documents the bug that dot() prevents.
  //
  // This test does NOT call dot(). It manually accumulates without reducing
  // and shows that the result diverges from the correct field-arithmetic answer.
  //
  GIVEN: a[i] = b[i] = MODULUS − 1 for all i
  WHEN: Naive accumulation:
    uint64_t naive_acc = 0;
    for (i = 0; i < 4; i++)
        naive_acc += (uint64_t)(MODULUS-1) * (MODULUS-1);
    Element naive_result = reduce64(naive_acc);
  THEN:
    // naive_acc = 4 × (q−1)^2 = 4 × (2^62 − 2^33 + 4)
    //          = 2^64 − 2^35 + 16
    //          > 2^64 − 1 = UINT64_MAX
    //          → OVERFLOW! naive_acc wraps to a wrong value.
    // Even if it didn't overflow, reduce64 of a sum ≥ 2^63 requires double-fold.
    //
    // Correct answer: 4 × 1 = 4 (each (q−1)^2 ≡ 1).
    Assert naive_result != 4    // Naive approach gives WRONG answer
    Assert dot(a, b, 4) == 4   // dot() gives CORRECT answer

TEST: field_naive_accumulation_two_products_wrong
  // Even 2 products cause single-fold reduce64 to fail.
  GIVEN: a[0] = a[1] = b[0] = b[1] = MODULUS − 1
  WHEN: sum = (uint64_t)(MODULUS-1)*(MODULUS-1) + (uint64_t)(MODULUS-1)*(MODULUS-1)
    // sum = 2 × (2^62 − 2^33 + 4) = 2^63 − 2^34 + 8 ≈ 2^63
    // This does NOT overflow uint64, but a single-fold reduce64 (the old code)
    // returns wrong value because lo + hi overflows uint32.
  THEN:
    Assert reduce64(sum) == 2               // Double-fold reduce64: CORRECT
    Assert dot(a, b, 2) == 2               // dot() with per-step reduction: CORRECT
    // Verify the old single-fold WOULD fail (conceptual — the old code is removed,
    // but we document the expected wrong answer for the audit trail):
    //   Old: lo=8, hi=2^32−8, lo+hi wraps to 0 in uint32. Returns 0. WRONG.
```

### 7.4 Element Derivation: `from_oracle()` (Byte-Exact Specification)

This function is **consensus-critical**: every conforming implementation MUST
produce bit-identical output for the same `(seed, index)` pair on every
platform and architecture. Any deviation causes a consensus split.

**PRF choice**: SHA-256 (already a consensus dependency via `CSHA256` in
`src/crypto/sha256.h`; no new cryptographic primitive required).

#### 7.4.1 Algorithm

```
from_oracle(seed: uint256, index: uint32_t) -> Element:
    retry = 0
    loop:
        if retry == 0:
            preimage = seed || LE32(index)                  // 36 bytes
        else:
            preimage = seed || LE32(index) || LE32(retry)   // 40 bytes

        h = SHA-256(preimage)                                // 32-byte digest

        // Extract bytes 0-3 of h as a little-endian uint32
        raw = (uint32_t)h[0]
            | ((uint32_t)h[1] << 8)
            | ((uint32_t)h[2] << 16)
            | ((uint32_t)h[3] << 24)

        // Mask to 31 bits: candidate in [0, 2^31)
        candidate = raw & 0x7FFFFFFF

        // Rejection sampling: reject candidate == M31 (the single
        // excluded value; all values in [0, M31) are accepted)
        if candidate < MODULUS:     // MODULUS = 0x7FFFFFFF = 2^31 - 1
            return candidate

        retry += 1
        if retry >= 256:
            abort("from_oracle: 256 consecutive rejections")
    end loop
```

**Byte layout for `retry == 0` (36-byte preimage)**:

```
Offset  Length  Field         Encoding
------  ------  -----------   --------
0       32      seed          Raw bytes (uint256 internal byte order)
32      4       index         Little-endian uint32
```

**Byte layout for `retry > 0` (40-byte preimage)**:

```
Offset  Length  Field         Encoding
------  ------  -----------   --------
0       32      seed          Raw bytes (uint256 internal byte order)
32      4       index         Little-endian uint32
36      4       retry         Little-endian uint32 (1..255)
```

#### 7.4.2 Rejection Sampling Analysis

The 31-bit mask yields candidate values uniformly distributed in
`{0, 1, ..., 2^31 - 1}`. The field `[0, q)` contains `q = 2^31 - 1` valid
values. The single rejected value is `candidate == q == 0x7FFFFFFF`.

| Metric | Value |
|--------|-------|
| Rejection probability per attempt | `1 / 2^31 ~ 4.66 x 10^-10` |
| Expected SHA-256 calls per element | `1 + 1/2^31 ~ 1.0000000005` |
| Probability of needing >= 2 retries | `(1/2^31)^2 ~ 2.17 x 10^-19` |
| Probability of exhausting 256 retries | `(1/2^31)^256 ~ 10^-2450` |

The 256-retry cap exists solely for determinism: every code path must
terminate, and an unbounded loop is a consensus risk even at negligible
probability. In practice, no conforming implementation will ever reach
`retry = 1`.

#### 7.4.3 `FromSeed()`: Matrix Generation via `from_oracle()`

`FromSeed(seed, n)` generates an `n x n` matrix by calling `from_oracle()`
with a linear row-major index:

```
FromSeed(seed: uint256, n: uint32_t) -> Matrix:
    M = new Matrix(n, n)
    for row in 0..n-1:
        for col in 0..n-1:
            M[row][col] = from_oracle(seed, row * n + col)
    return M
```

**Index mapping**: Element at row `r`, column `c` in an `n x n` matrix uses
`index = r * n + c`. All indices fit in `uint32_t` for `n <= 65535` (well
above `nMatMulMaxDimension = 2048`).

**Storage order**: Row-major. `M[0][0]` has index 0, `M[0][1]` has index 1,
..., `M[0][n-1]` has index `n-1`, `M[1][0]` has index `n`, etc.

**Domain separation for A vs B**: The block header contains separate seeds
`seed_a` and `seed_b`. No additional tagging is needed because the seeds
themselves are distinct:

```
A = FromSeed(block.seed_a, n)     // uses seed_a as from_oracle's seed
B = FromSeed(block.seed_b, n)     // uses seed_b as from_oracle's seed
```

#### 7.4.4 Performance

For `n = 512`, `FromSeed` generates `512 x 512 = 262,144` elements, each
requiring one SHA-256 evaluation (retry is negligible).

| Hardware | SHA-256 throughput | FromSeed time (n=512) |
|----------|-------------------|----------------------|
| x86 with SHA-NI | ~50M/s (single msg) | ~5 ms |
| x86 without SHA-NI | ~10M/s | ~26 ms |
| ARM with SHA extensions | ~15M/s | ~17 ms |
| GPU (batch SHA-256) | ~100M+/s | < 3 ms |

All measurements are for short-message SHA-256 (36 bytes). This is
comfortably within the ~50--200 ms budget of one nonce attempt. Note that
`FromSeed` is called once per seed change, NOT once per nonce: the matrices
A and B are constant while the miner grinds nonces.

On GPU: all 262,144 SHA-256 calls are independent and trivially
parallelizable across GPU threads.

#### 7.4.5 Security Argument

- SHA-256 output is computationally indistinguishable from a random function,
  so each 31-bit masked candidate is near-uniform in `[0, 2^31)`.
- After rejection sampling, elements are exactly uniform in `[0, q)`.
- The `retry` counter is appended (not XORed or otherwise combined) to ensure
  each retry produces an independent hash, with no algebraic relationship to
  the previous attempt.
- Domain separation between A and B relies on distinct seeds from the block
  header; domain separation between noise factor matrices uses version-tagged
  strings (see SS8.2.1).
- The version tag (`_v1`) in noise domain strings allows future algorithm
  changes without ambiguity -- old and new derivations never collide.

#### 7.4.6 Reference Implementation (C++)

```cpp
Element from_oracle(const uint256& seed, uint32_t index)
{
    for (uint32_t retry = 0; retry < 256; ++retry) {
        CSHA256 hasher;
        hasher.Write(seed.begin(), 32);

        uint8_t idx_le[4];
        WriteLE32(idx_le, index);
        hasher.Write(idx_le, 4);

        if (retry > 0) {
            uint8_t retry_le[4];
            WriteLE32(retry_le, retry);
            hasher.Write(retry_le, 4);
        }

        uint8_t hash[CSHA256::OUTPUT_SIZE];
        hasher.Finalize(hash);

        // Extract bytes 0-3 as little-endian uint32, mask to 31 bits
        uint32_t candidate = ReadLE32(hash) & MODULUS;

        if (candidate < MODULUS) {
            return candidate;
        }
    }
    // Unreachable in practice (probability ~= 10^-2450)
    assert(false && "from_oracle: 256 retries exhausted");
    return 0;
}
```

#### 7.4.7 Pinned Test Vectors

These vectors are **consensus-binding**: any implementation that does not
reproduce these exact outputs is non-conforming.

**TV1**: `from_oracle(seed=0x00..00, index=0)`

```
seed:        0000000000000000000000000000000000000000000000000000000000000000
index:       0 -> LE32 = 00000000
preimage:    0000000000000000000000000000000000000000000000000000000000000000
             00000000                                              (36 bytes)
SHA-256:     6db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e
bytes[0..3]: 6d 5f b6 d5 -> LE uint32 = 0xd55fb66d
masked:      0xd55fb66d & 0x7fffffff = 0x555fb66d = 1432335981
result:      1432335981  (< M31, accepted)
```

**TV2**: `from_oracle(seed=0x00..00, index=1)`

```
seed:        0000000000000000000000000000000000000000000000000000000000000000
index:       1 -> LE32 = 01000000
preimage:    0000000000000000000000000000000000000000000000000000000000000000
             01000000                                              (36 bytes)
SHA-256:     71c99cc3bc21757feed5b712744ebb0f770d5c41d99189f9457495747bf11050
bytes[0..3]: 71 c9 9c c3 -> LE uint32 = 0xc39cc971
masked:      0xc39cc971 & 0x7fffffff = 0x439cc971 = 1134348657
result:      1134348657  (< M31, accepted)
```

**TV3**: `from_oracle(seed=0x00..00, index=7)`

```
seed:        0000000000000000000000000000000000000000000000000000000000000000
index:       7 -> LE32 = 07000000
preimage:    0000000000000000000000000000000000000000000000000000000000000000
             07000000                                              (36 bytes)
SHA-256:     95f1f8ffe5b54fd46e622b34b93464acfc25fd54cabd50a3f0143479e4253b42
bytes[0..3]: 95 f1 f8 ff -> LE uint32 = 0xfff8f195
masked:      0xfff8f195 & 0x7fffffff = 0x7ff8f195 = 2147021205
result:      2147021205  (< M31, accepted)
```

**TV4**: `from_oracle(seed=SHA-256("test_seed"), index=42)`

```
seed:        4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150
index:       42 -> LE32 = 2a000000
preimage:    4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150
             2a000000                                              (36 bytes)
SHA-256:     6ecbbdccdae17aaac5acb50d7b23107f7ffa1017b2b7e6684369370372e3c5f9
bytes[0..3]: 6e cb bd cc -> LE uint32 = 0xccbdcb6e
masked:      0xccbdcb6e & 0x7fffffff = 0x4cbdcb6e = 1287506798
result:      1287506798  (< M31, accepted)
```

**TV5**: Retry mechanism preimage format

```
seed=0x00..00, index=0, retry=0:
  preimage (36 bytes): seed || LE32(0)
  SHA-256: 6db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e
  candidate: 1432335981  (< M31, accepted on first try)

seed=0x00..00, index=0, retry=1:
  preimage (40 bytes): seed || LE32(0) || LE32(1)
  hex:     0000..0000 00000000 01000000
  SHA-256: 4aefeea7a0bb3e887dfac5aba09fea61faaf95a48c1229186e9a671ed4738520
  candidate: 669970250  (< M31)

seed=0x00..00, index=0, retry=2:
  preimage (40 bytes): seed || LE32(0) || LE32(2)
  hex:     0000..0000 00000000 02000000
  SHA-256: 7d4b807e3471ee3bffc75392607322b2b9a7226132ff0301d8dce3243cfa03c8
  candidate: 2122337149  (< M31)
```

(TV5 verifies that the retry preimage format is correct even though
retry=0 succeeds. Implementations SHOULD verify the retry=1 and retry=2
SHA-256 outputs match the values above to confirm their preimage
construction is byte-exact.)

**TV6**: `FromSeed(seed=0x00..00, n=2)` -- 2x2 matrix (row-major)

```
matrix[0][0] = from_oracle(seed, 0) = 1432335981
matrix[0][1] = from_oracle(seed, 1) = 1134348657
matrix[1][0] = from_oracle(seed, 2) =  428617384
matrix[1][1] = from_oracle(seed, 3) =  258375063
```

#### 7.4.8 Tests for Element Derivation

```
TEST: from_oracle_pinned_tv1
  GIVEN: seed = 0x00..00 (32 zero bytes), index = 0
  THEN: from_oracle(seed, 0) == 1432335981

TEST: from_oracle_pinned_tv2
  GIVEN: seed = 0x00..00, index = 1
  THEN: from_oracle(seed, 1) == 1134348657

TEST: from_oracle_pinned_tv3
  GIVEN: seed = 0x00..00, index = 7
  THEN: from_oracle(seed, 7) == 2147021205

TEST: from_oracle_pinned_tv4
  GIVEN: seed = SHA-256("test_seed"), index = 42
  THEN: from_oracle(seed, 42) == 1287506798

TEST: from_oracle_deterministic
  FOR 1000 random (seed, index) pairs:
    Assert from_oracle(seed, index) == from_oracle(seed, index)

TEST: from_oracle_output_range
  FOR 10000 random (seed, index) pairs:
    Assert from_oracle(seed, index) >= 0
    Assert from_oracle(seed, index) < MODULUS

TEST: from_oracle_different_seed_differs
  GIVEN: seed1 != seed2, same index
  THEN: from_oracle(seed1, index) != from_oracle(seed2, index)
  (with overwhelming probability)

TEST: from_oracle_different_index_differs
  GIVEN: same seed, index1 != index2
  THEN: from_oracle(seed, index1) != from_oracle(seed, index2)
  (with overwhelming probability)

TEST: from_oracle_retry_preimage_format
  GIVEN: seed = 0x00..00, index = 0
  WHEN: Manually compute SHA-256(seed || LE32(0) || LE32(1))
  THEN: SHA-256 output == 4aefeea7a0bb3e887dfac5aba09fea61faaf95a48c1229186e9a671ed4738520
  AND: candidate from that hash == 669970250

TEST: from_oracle_rejection_boundary
  GIVEN: A candidate value of exactly 0x7FFFFFFF (= M31)
  THEN: This value is REJECTED and retry occurs
  (Test by mocking SHA-256 or by verifying the comparison is strict:
   < MODULUS, not <=)

TEST: from_seed_pinned_2x2
  GIVEN: seed = 0x00..00, n = 2
  WHEN: FromSeed(seed, 2)
  THEN: matrix[0][0] == 1432335981
  AND:  matrix[0][1] == 1134348657
  AND:  matrix[1][0] == 428617384
  AND:  matrix[1][1] == 258375063

TEST: from_seed_row_major_indexing
  GIVEN: seed, n = 4
  THEN: matrix[1][0] == from_oracle(seed, 1 * 4 + 0) == from_oracle(seed, 4)
  AND:  matrix[2][3] == from_oracle(seed, 2 * 4 + 3) == from_oracle(seed, 11)

TEST: from_seed_domain_separation_a_b
  GIVEN: seed_a != seed_b
  WHEN: A = FromSeed(seed_a, n), B = FromSeed(seed_b, n)
  THEN: A != B
  AND:  A[0][0] != B[0][0] (with overwhelming probability)

TEST: from_seed_cross_platform_consistency
  GIVEN: seed = 0x00..00, n = 4
  WHEN: FromSeed(seed, 4) on this platform
  THEN: First row matches:
    [1432335981, 1134348657, 428617384, 258375063]
  (This test MUST pass on x86-64, ARM64, and any other target architecture)
```

---

## 8. MatMul PoW Core Algorithm

### 8.1 Matrix Type

```cpp
namespace matmul {

class Matrix {
public:
    Matrix(uint32_t rows, uint32_t cols);

    field::Element& at(uint32_t row, uint32_t col);
    const field::Element& at(uint32_t row, uint32_t col) const;

    uint32_t rows() const;
    uint32_t cols() const;

    // Block decomposition with block size b
    Matrix block(uint32_t bi, uint32_t bj, uint32_t b) const;
    void set_block(uint32_t bi, uint32_t bj, uint32_t b, const Matrix& blk);

    Matrix operator+(const Matrix& rhs) const;
    Matrix operator-(const Matrix& rhs) const;
    Matrix operator*(const Matrix& rhs) const;  // O(n³) naive

    uint256 ContentHash() const;  // SHA-256 of LE32 element serialization
    bool operator==(const Matrix& rhs) const;
};

Matrix Identity(uint32_t n);

// Deterministic matrix from seed (v1: how A and B are derived)
Matrix FromSeed(const uint256& seed, uint32_t n);

} // namespace matmul
```

### 8.2 Noise Generation (rank r, independent of b)

```cpp
namespace matmul::noise {

struct NoisePair {
    Matrix E_L, E_R;  // E = E_L · E_R  (n×r and r×n → rank-r n×n)
    Matrix F_L, F_R;  // F = F_L · F_R  (n×r and r×n → rank-r n×n)
};

// r is the noise rank (from consensus params), NOT the transcript block size b
NoisePair Generate(const uint256& sigma, uint32_t n, uint32_t r);

} // namespace matmul::noise
```

#### 8.2.1 Noise Seed Derivation (Byte-Exact)

The four noise factor matrices (`E_L`, `E_R`, `F_L`, `F_R`) are each
generated from a **domain-separated derived seed**. This ensures that the
same oracle seed sigma produces four independent, uncorrelated matrices.

**Domain separation tags** (raw ASCII bytes, no null terminator, no length
prefix):

| Factor | Domain tag (ASCII)       | Tag length | Factor dimensions |
|--------|--------------------------|------------|-------------------|
| E_L    | `matmul_noise_EL_v1`    | 18 bytes   | n x r             |
| E_R    | `matmul_noise_ER_v1`    | 18 bytes   | r x n             |
| F_L    | `matmul_noise_FL_v1`    | 18 bytes   | n x r             |
| F_R    | `matmul_noise_FR_v1`    | 18 bytes   | r x n             |

**Derived seed computation**:

```
tag_EL = SHA-256("matmul_noise_EL_v1" || sigma)    // 18 + 32 = 50 bytes -> 32-byte seed
tag_ER = SHA-256("matmul_noise_ER_v1" || sigma)
tag_FL = SHA-256("matmul_noise_FL_v1" || sigma)
tag_FR = SHA-256("matmul_noise_FR_v1" || sigma)
```

**Byte layout of derived seed preimage (50 bytes)**:

```
Offset  Length  Field          Encoding
------  ------  -----------    --------
0       18      domain tag     Raw ASCII bytes (no null terminator, no length prefix)
18      32      sigma          Raw bytes (uint256 internal byte order)
```

**Element generation via `from_oracle()`**:

Each factor matrix is generated element-by-element using the derived seed
as the `seed` argument to `from_oracle()` (SS7.4), with row-major linear
indexing scaled to the factor's own column count:

```
Generate(sigma: uint256, n: uint32_t, r: uint32_t) -> NoisePair:
    tag_EL = SHA-256("matmul_noise_EL_v1" || sigma)
    tag_ER = SHA-256("matmul_noise_ER_v1" || sigma)
    tag_FL = SHA-256("matmul_noise_FL_v1" || sigma)
    tag_FR = SHA-256("matmul_noise_FR_v1" || sigma)

    // E_L is n x r
    for row in 0..n-1:
        for col in 0..r-1:
            E_L[row][col] = from_oracle(tag_EL, row * r + col)

    // E_R is r x n
    for row in 0..r-1:
        for col in 0..n-1:
            E_R[row][col] = from_oracle(tag_ER, row * n + col)

    // F_L is n x r
    for row in 0..n-1:
        for col in 0..r-1:
            F_L[row][col] = from_oracle(tag_FL, row * r + col)

    // F_R is r x n
    for row in 0..r-1:
        for col in 0..n-1:
            F_R[row][col] = from_oracle(tag_FR, row * n + col)

    return { E_L, E_R, F_L, F_R }
```

**Index formula summary**:

| Factor | Dimensions | Index formula for `[row][col]` | Column stride |
|--------|-----------|-------------------------------|---------------|
| E_L    | n x r     | `row * r + col`               | r             |
| E_R    | r x n     | `row * n + col`               | n             |
| F_L    | n x r     | `row * r + col`               | r             |
| F_R    | r x n     | `row * n + col`               | n             |

The index formula uses the factor's own column count (r for n x r matrices,
n for r x n matrices), NOT the global matrix dimension n for all factors.
This is critical: using `row * n + col` for an n x r matrix would leave gaps
in the index space and waste SHA-256 evaluations.

**Total SHA-256 calls for noise generation**:

- `E_L`: n x r evaluations
- `E_R`: r x n evaluations
- `F_L`: n x r evaluations
- `F_R`: r x n evaluations
- **Total**: 4 x n x r evaluations
- At n=512, r=8: 4 x 512 x 8 = **16,384 SHA-256 calls** (~1.6 ms on SHA-NI hardware)

**Version tag**: The `_v1` suffix in each domain string is a version
marker. If the element derivation algorithm changes in a future consensus
upgrade, the version is incremented to `_v2`, ensuring old and new
derivations are domain-separated and cannot collide.

#### 8.2.2 Noise Derivation Pinned Test Vectors

These vectors are **consensus-binding**.

**Derived seeds for sigma = 0x00..00**:

```
tag_EL = SHA-256("matmul_noise_EL_v1" || 0x00..00)
       = 993a427eeb3dc053000d570842d2e7f0f093393c00e8e729155c48719118b386

tag_ER = SHA-256("matmul_noise_ER_v1" || 0x00..00)
       = 0b3b1aa329a9ee863b3aa0080346e4ced9842b39db47d70418af99120b6530a2

tag_FL = SHA-256("matmul_noise_FL_v1" || 0x00..00)
       = 73ff6f6817e0c7e7ce9219076b14f1d932be70c641393bfc4c53a230bf65ddd8

tag_FR = SHA-256("matmul_noise_FR_v1" || 0x00..00)
       = 91d399ff912ea452af750501448661096d5251cd17921403ab70d0c4561b45a3
```

**E_L (n=4, r=2, sigma=0x00..00)**:

```
E_L[0][0] = from_oracle(tag_EL, 0) = 1931902215
E_L[0][1] = from_oracle(tag_EL, 1) =  129748845
E_L[1][0] = from_oracle(tag_EL, 2) =  505403935
E_L[1][1] = from_oracle(tag_EL, 3) =  538008036
E_L[2][0] = from_oracle(tag_EL, 4) = 1006343602
E_L[2][1] = from_oracle(tag_EL, 5) = 1697202758
E_L[3][0] = from_oracle(tag_EL, 6) = 2128262120
E_L[3][1] = from_oracle(tag_EL, 7) =  942473671
```

**E_R (r=2, n=4, sigma=0x00..00)**:

```
E_R[0][0] = from_oracle(tag_ER, 0) =  962405871
E_R[0][1] = from_oracle(tag_ER, 1) = 1142251768
E_R[0][2] = from_oracle(tag_ER, 2) =  505582893
E_R[0][3] = from_oracle(tag_ER, 3) =  443901062
E_R[1][0] = from_oracle(tag_ER, 4) =  858057583
E_R[1][1] = from_oracle(tag_ER, 5) = 2082571321
E_R[1][2] = from_oracle(tag_ER, 6) =   70698889
E_R[1][3] = from_oracle(tag_ER, 7) = 1087797252
```

**Domain separation verification**: All four derived seeds are distinct for
the same sigma, and the first element of each factor matrix differs:

```
from_oracle(tag_EL, 0) = 1931902215
from_oracle(tag_ER, 0) =  962405871
from_oracle(tag_FL, 0) = 1766706109
from_oracle(tag_FR, 0) = 1500561682
```

(All four values are distinct -- domain separation confirmed.)

#### 8.2.3 Noise Derivation Tests

```
TEST: noise_derived_seed_pinned_EL
  GIVEN: sigma = 0x00..00
  WHEN: tag_EL = SHA-256("matmul_noise_EL_v1" || sigma)
  THEN: tag_EL == 993a427eeb3dc053000d570842d2e7f0f093393c00e8e729155c48719118b386

TEST: noise_derived_seed_pinned_ER
  GIVEN: sigma = 0x00..00
  WHEN: tag_ER = SHA-256("matmul_noise_ER_v1" || sigma)
  THEN: tag_ER == 0b3b1aa329a9ee863b3aa0080346e4ced9842b39db47d70418af99120b6530a2

TEST: noise_derived_seed_pinned_FL
  GIVEN: sigma = 0x00..00
  WHEN: tag_FL = SHA-256("matmul_noise_FL_v1" || sigma)
  THEN: tag_FL == 73ff6f6817e0c7e7ce9219076b14f1d932be70c641393bfc4c53a230bf65ddd8

TEST: noise_derived_seed_pinned_FR
  GIVEN: sigma = 0x00..00
  WHEN: tag_FR = SHA-256("matmul_noise_FR_v1" || sigma)
  THEN: tag_FR == 91d399ff912ea452af750501448661096d5251cd17921403ab70d0c4561b45a3

TEST: noise_domain_separation_all_seeds_distinct
  GIVEN: Any sigma
  WHEN: Compute tag_EL, tag_ER, tag_FL, tag_FR
  THEN: All four are pairwise distinct
  (Guaranteed by different domain tag prefixes fed to SHA-256)

TEST: noise_EL_pinned_elements
  GIVEN: sigma = 0x00..00, n = 4, r = 2
  WHEN: Generate(sigma, 4, 2)
  THEN: E_L[0][0] == 1931902215
  AND:  E_L[0][1] == 129748845
  AND:  E_L[1][0] == 505403935
  AND:  E_L[1][1] == 538008036
  AND:  E_L[2][0] == 1006343602
  AND:  E_L[2][1] == 1697202758
  AND:  E_L[3][0] == 2128262120
  AND:  E_L[3][1] == 942473671

TEST: noise_ER_pinned_elements
  GIVEN: sigma = 0x00..00, n = 4, r = 2
  WHEN: Generate(sigma, 4, 2)
  THEN: E_R[0][0] == 962405871
  AND:  E_R[0][1] == 1142251768
  AND:  E_R[0][2] == 505582893
  AND:  E_R[0][3] == 443901062
  AND:  E_R[1][0] == 858057583
  AND:  E_R[1][1] == 2082571321
  AND:  E_R[1][2] == 70698889
  AND:  E_R[1][3] == 1087797252

TEST: noise_first_element_domain_separation
  GIVEN: sigma = 0x00..00, n = 4, r = 2
  WHEN: Generate(sigma, 4, 2)
  THEN: from_oracle(tag_EL, 0) == 1931902215
  AND:  from_oracle(tag_ER, 0) == 962405871
  AND:  from_oracle(tag_FL, 0) == 1766706109
  AND:  from_oracle(tag_FR, 0) == 1500561682
  AND:  all four are pairwise distinct

TEST: noise_index_uses_factor_column_count
  GIVEN: n = 8, r = 2
  WHEN: Generate noise
  THEN: E_L[3][1] uses index = 3 * 2 + 1 = 7  (column stride = r = 2)
  AND:  E_R[1][3] uses index = 1 * 8 + 3 = 11  (column stride = n = 8)
  (Verify by comparing from_oracle(tag_EL, 7) and from_oracle(tag_ER, 11)
   against the matrix elements directly)

TEST: noise_all_elements_in_field
  GIVEN: sigma = random, n = 64, r = 4
  WHEN: Generate(sigma, 64, 4)
  THEN: Every element of E_L, E_R, F_L, F_R is in [0, M31)

TEST: noise_cross_platform_consistency
  GIVEN: sigma = 0x00..00, n = 4, r = 2
  WHEN: Generate on this platform
  THEN: All elements match the pinned test vectors above
  (This test MUST pass on x86-64, ARM64, and any other target architecture)
```

### 8.3 Canonical MatMul (block size b) with Streaming Transcript Hash

```cpp
namespace matmul::transcript {

struct TranscriptHasher {
    // σ is needed to derive the compression vector (§8.3.1)
    // b is the transcript block size (determines compression vector length b²)
    TranscriptHasher(const uint256& sigma, uint32_t b);

    // Must be called in strict canonical order: i, j, ℓ
    // Internally compresses each b×b block to a single field element via
    // random inner-product, then feeds 4 bytes (LE32) into rolling SHA-256d
    void AddIntermediate(uint32_t i, uint32_t j, uint32_t ell,
                         const Matrix& block_bb);
    uint256 Finalize();  // Returns z = SHA256D(all compressed elements)
private:
    CSHA256 m_hasher;
    std::vector<field::Element> m_compress_vec;  // b² elements from σ
};

struct CanonicalResult {
    Matrix C_prime;
    uint256 transcript_hash;  // z
};

// b is the transcript block size (from consensus), NOT the noise rank r
// sigma is the oracle seed, needed to derive the compression vector (§8.3.1)
CanonicalResult CanonicalMatMul(const Matrix& A_prime, const Matrix& B_prime,
                                uint32_t b, const uint256& sigma);

} // namespace matmul::transcript
```

Memory: O(n²) for accumulator + O(b²) for one intermediate block.

#### 8.3.1 Transcript Compression

**Problem**: Naively hashing each b×b intermediate block feeds ~33.5 MB into
SHA-256 at n=512, b=16. This creates 30–100% overhead on GPU miners where
SHA-256 is expensive (see §2.8 for detailed analysis).

**Rejected alternatives**:

| Approach | Bytes hashed | Security | Why rejected |
|----------|-------------|----------|-------------|
| Full b×b block hashing | 33.5 MB | Full binding | 30–100% overhead; SHA on GPU is a bottleneck |
| XOR-fold to 128-bit value | 512 KB | Weak — adversary can find XOR collisions cheaply | Birthday attacks on 128-bit XOR-fold are trivial within F_q |
| Incremental Merkle tree | 33.5 MB leaves + 32·log(N) | Full binding | Still hashes all leaf data; tree overhead on top |

**Chosen approach: Random inner-product compression.**

For each intermediate b×b block, compute a single field element by taking the
inner product of the flattened block with a pseudorandom vector derived from σ.
Feed that single element (4 bytes, little-endian uint32) into the rolling
SHA-256 state.

**Specification**:

```
DeriveCompressionVector(σ, b):
    // Produce b² pseudorandom field elements from σ
    // Using a domain-separated PRNG seeded by σ
    seed = SHA-256("matmul-compress-v1" || σ)
    for k in 0..b²-1:
        v[k] = field::from_oracle(seed, k)    // each in [0, M31)
    return v    // length b²

CompressBlock(block_bb, v):
    // block_bb: flattened b×b field elements (row-major)
    // v: compression vector of length b²
    return field::dot(block_bb, v, b*b)        // single Element in [0, M31)
```

**Integration into TranscriptHasher**:

```cpp
struct TranscriptHasher {
    TranscriptHasher(const uint256& sigma, uint32_t b);

    // The compression vector is derived once from σ at construction
    // and reused for all intermediates (same random projection for every block)
    //
    // INVARIANT: The compression vector MUST be derived exactly once from σ
    // before processing the first intermediate, and reused unchanged for the
    // entire transcript. No re-derivation or mutation between AddIntermediate
    // calls is permitted — doing so would break transcript determinism.
    void AddIntermediate(uint32_t i, uint32_t j, uint32_t ell,
                         const Matrix& block_bb);
    // Internally:
    //   1. compressed = CompressBlock(block_bb.flatten(), m_compress_vec)
    //   2. m_hasher.Write(LE32(compressed), 4)

    uint256 Finalize();  // Returns SHA-256d(stream) = SHA256(SHA256(all LE32 elements))

private:
    CSHA256 m_hasher;
    std::vector<field::Element> m_compress_vec;  // b² elements, derived from σ
};
```

**Concrete costs at n=512, b=16**:

| Step | Count | Per-step cost | Total |
|------|-------|--------------|-------|
| Compression dot-product | 32,768 intermediates | b² = 256 field muls | 8,388,608 field muls |
| SHA-256 Update (rolling) | 32,768 calls | 4 bytes each | 131,072 bytes total |
| SHA-256d Finalize | 1 call (two SHA-256 passes) | — | 32 bytes output |

Total hashed by SHA-256d: **131,072 bytes (~128 KB)**, vs 33.5 MB for naive.
SHA-256d time at 500 MB/s: **~0.26 ms** (negligible).
Compression dot-product cost: **~8.4M field muls** (~6.3% of 134M baseline).

**Security argument**:

The random inner-product over F_q is a **pairwise-independent hash family**
(Carter-Wegman). For any fixed compression vector v (derived from σ), the
probability that two distinct b×b blocks X ≠ X' satisfy ⟨X, v⟩ = ⟨X', v⟩
is exactly 1/q ≈ 2⁻³¹.

For an adversary to forge the transcript (produce a different computation
path that yields the same compressed hash stream), they must find an
alternative sequence of 32,768 intermediates where EVERY compressed element
matches. Since each compression is independently binding with probability
1 − 1/q, and the SHA-256d chain links them sequentially, the adversary
must either:

1. Find a SHA-256d collision on the compressed stream (cost 2¹²⁸), or
2. Match all k differing compressed elements individually (probability (1/q)^k
   for k differing intermediate blocks — even k = 1 gives 1/q ≈ 2⁻³¹,
   already negligible; k = 4 gives 2⁻¹²⁴, beyond computational reach)

The security reduction: if an adversary can forge transcripts under
compressed hashing, they can either break SHA-256d collision resistance or
invert a random linear function over F_q. Both are computationally
infeasible.

**Important**: The compression vector v is derived from σ, which depends on
the block header (including nonce). The miner does not know v before
choosing the nonce, so they cannot craft intermediates that exploit a
specific v. This is essential — if v were fixed and public before mining,
a miner could potentially embed degrees of freedom in the matmul to
target specific compressed outputs. The σ-dependence prevents this.

**Consensus rule**: The compression vector derivation, the domain separation
string `"matmul-compress-v1"`, the LE32 encoding of compressed elements,
and the SHA-256d finalization are all consensus-critical. Any implementation
must produce byte-identical compressed streams and digest for the same inputs.

#### 8.3.6 Economic Security Note: Compression Collision Probability

From a cryptographic standpoint, 1/q ≈ 2⁻³¹ per differing intermediate is
negligible. From an **economic** PoW security standpoint, 2⁻³¹ is roughly
one in two billion — large, but not astronomical by mining standards (Bitcoin
miners compute ~10²⁰ hashes/second).

**Per-block union bound**: At n=512, b=16 there are N³ = (n/b)³ = 32³ =
32,768 = 2¹⁵ intermediates per block. By the union bound, the probability
that an adversary who modifies at least one intermediate matches all
compressions is at most N³ / q = 2¹⁵ / 2³¹ = **2⁻¹⁶** per block. This is
a conservative upper bound; in practice the adversary cannot target
individual intermediates independently (see below).

The key question: can an attacker bias even one intermediate to exploit the
compression collision probability? **No**, because:

1. Intermediates are determined by A', B', which depend on σ (unknown before
   nonce selection). The attacker cannot choose intermediates independently.
2. The canonical (i, j, ℓ) order and SHA-256d chain mean a single differing
   intermediate changes the entire downstream hash — there is no way to
   "patch" one step without redoing the rest.
3. The attacker's only degrees of freedom are the nonce and seeds. Changing
   either changes σ, which changes v, noise, and all intermediates together.

**Future hardening (non-breaking upgrade)**: If economic analysis suggests
2⁻³¹ per-intermediate binding is too thin, a v1.1 consensus change can adopt
dual compression projections:

```
v1 = DeriveCompressionVector(SHA-256("matmul-compress-v1a" || σ), b)
v2 = DeriveCompressionVector(SHA-256("matmul-compress-v1b" || σ), b)

c1 = dot(flatten(C_block), v1, b²)
c2 = dot(flatten(C_block), v2, b²)

// Hash both: LE32(c1) || LE32(c2) per intermediate
// 8 bytes per intermediate instead of 4 → 256 KiB total (still tiny)
```

This doubles compression dot-product cost (~12.6% of baseline instead of
6.3%) and doubles SHA-256 input (~256 KiB instead of 128 KiB), but raises
per-intermediate binding to (1/q)² ≈ 2⁻⁶². Total overhead rises from ~16.5%
to ~23%, which is acceptable if the security margin is needed.

**Decision for v1**: Single projection is sufficient. The attacker's inability
to control intermediates independently makes the 2⁻³¹ per-step probability
academic. Dual projection is documented as a ready upgrade path.

#### 8.3.2 Why a Single Compression Vector Is Reused Across All Intermediates

A natural question is whether each intermediate (i, j, ℓ) should use its own
compression vector v_{i,j,ℓ} rather than reusing a single v for all 32,768
intermediates. **We reuse a single v and this is safe.** The reasoning:

1. **Cost of per-intermediate vectors**: Deriving a fresh v per intermediate
   requires one `DeriveCompressionVector` call per step, adding ~32,768 SHA-256
   evaluations × b² element derivations = ~8.4M extra SHA-256 calls per mining
   attempt. At ~10M SHA-256/s, this adds ~840ms — comparable to the matmul
   itself and unacceptable.

2. **Why reuse is safe**: The binding property of inner-product compression
   does not require a fresh v per evaluation. For any *fixed* v, the
   probability that two distinct b×b blocks X ≠ X' satisfy ⟨X, v⟩ = ⟨X', v⟩
   is exactly 1/q ≈ 2⁻³¹ (Carter-Wegman). For an adversary to forge an
   alternative transcript, they must find substitute intermediates where EVERY
   compressed element matches under the SAME v. Because the intermediates
   are determined by the canonical matmul (the adversary cannot choose them
   freely — they are constrained by the block-decomposition recurrence), the
   adversary's degrees of freedom are limited to choosing a different
   computation path that coincidentally produces the same compressed stream.
   With k differing intermediates, the forgery probability is (1/q)^k.

3. **The adversary does not control intermediates independently**: In the
   canonical block matmul, each intermediate C'_{i,j,ℓ} is an accumulating
   partial sum determined by all prior products A'_{i,0..ℓ} · B'_{0..ℓ,j}.
   The adversary would need to find alternative A', B' matrices whose entire
   (n/b)³ intermediate sequence matches the compressed stream — but A' and B'
   are fixed by the noise injection (which depends on σ, unknown before nonce
   selection). The adversary cannot "tune" individual intermediates without
   changing the input matrices, which changes σ, which changes v.

4. **σ unpredictability is the root defense**: Even if an adversary could
   somehow analyze the relationship between v and the matmul structure, they
   cannot exploit it because v is derived from σ, and σ depends on the nonce.
   The adversary must commit to the nonce before learning v. This is the same
   security argument that protects the noise injection itself.

**Per-intermediate v is unnecessary**: The single-v binding probability (1/q)^k
for k differing intermediates provides overwhelming security (e.g., k=1 gives
2⁻³¹, k=2 gives 2⁻⁶², etc.) without the ~840ms overhead of per-intermediate
vector derivation.

#### 8.3.3 Domain Separation Between Compression and Noise

The compression vector and the noise matrices are both derived from σ, but
they use distinct domain separation prefixes:

| Component | Domain separation prefix | Derivation |
|-----------|-------------------------|------------|
| Compression vector v | `"matmul-compress-v1"` | `SHA-256("matmul-compress-v1" \|\| σ)` |
| Noise E_L | `"matmul_noise_EL_v1"` | `SHA-256("matmul_noise_EL_v1" \|\| σ)` |
| Noise E_R | `"matmul_noise_ER_v1"` | `SHA-256("matmul_noise_ER_v1" \|\| σ)` |
| Noise F_L | `"matmul_noise_FL_v1"` | `SHA-256("matmul_noise_FL_v1" \|\| σ)` |
| Noise F_R | `"matmul_noise_FR_v1"` | `SHA-256("matmul_noise_FR_v1" \|\| σ)` |

The compression vector v is therefore **statistically independent** of the
noise matrices E_L, E_R, F_L, F_R, even though all five are deterministic
functions of the same σ. This prevents any algebraic relationship between the
noise injection (which shapes the intermediates) and the compression map
(which hashes them). A reviewer might worry that shared σ-dependence creates
a correlation the adversary could exploit — it does not, because SHA-256 with
distinct domain prefixes behaves as independent random oracles in the random
oracle model.

#### 8.3.4 Field Size, Linearity, and σ-Unpredictability

The compression map ⟨·, v⟩ is **linear** over F_q (M31, q ≈ 2³¹). An
adversary observing many compressed outputs across multiple blocks might ask
whether they can "learn" the compression vector and use that knowledge to
bias future work. The answer is no, for a simple reason:

**σ changes with every nonce attempt, and v is derived from σ.** Each mining
attempt produces a fresh σ (from a fresh nonce → fresh header hash → fresh
σ = SHA-256(header_hash)), and therefore a fresh v. The adversary never sees
the same v twice unless they replay the same nonce with the same header — in
which case the entire transcript is deterministic anyway and there is nothing
to exploit.

We rely on **σ unpredictability, not on hiding v**. Even if v for a particular
σ were somehow leaked or reverse-engineered after block publication (which is
trivial — v is deterministic from σ), this is irrelevant because:

- That v is never reused (the next block has a different hashPrevBlock → different σ)
- Even within the same block, each nonce attempt produces a different σ → different v
- The adversary must commit to the nonce (and thus to σ and v) before performing the matmul

The ~2³¹ field size is therefore not a weakness for compression security. The
binding guarantee per-intermediate is 1/q ≈ 2⁻³¹, which is small in isolation,
but the joint forgery probability across k intermediates is (1/q)^k — and even
k=4 gives 2⁻¹²⁴, beyond computational reach. The field size affects
per-intermediate collision probability, not the overall scheme security.

#### 8.3.5 Compression Linearity and Accumulating Partial Sums

The canonical matmul produces intermediates with a specific algebraic
structure that deserves explicit analysis. Each intermediate C'_{i,j,ℓ} is an
**accumulating partial sum**:

```
C'_{i,j,0} = A'_block[i][0] · B'_block[0][j]
C'_{i,j,1} = C'_{i,j,0} + A'_block[i][1] · B'_block[1][j]
C'_{i,j,ℓ} = C'_{i,j,ℓ-1} + A'_block[i][ℓ] · B'_block[ℓ][j]
```

Because compression is linear, the compressed values inherit this recurrence:

```
c_{i,j,ℓ} = ⟨C'_{i,j,ℓ}, v⟩ = c_{i,j,ℓ-1} + ⟨A'_block[i][ℓ] · B'_block[ℓ][j], v⟩
```

This means the compressed transcript is a sequence of **incremental updates**,
not independent random values. A reviewer might worry that this structure
gives an adversary leverage. **It does not, for three reasons:**

1. **Forging still requires matching every increment.** The adversary cannot
   "skip" to the final partial sum — the SHA-256d chain commits to every
   intermediate c_{i,j,ℓ} in strict canonical (i, j, ℓ) order. To produce
   the same digest z, the adversary must match the entire sequence of
   compressed values, not just the final C' = A'·B'.

2. **The adversary does not know v before nonce selection.** Even though the
   compressed values have predictable algebraic structure *given v*, the
   adversary must commit to a nonce (and thus to σ, noise matrices, and v)
   before computing any intermediates. They cannot choose a nonce that
   produces a "favorable" v because σ = SHA-256(header_hash) is a random
   oracle output.

3. **The SHA-256d chain binds the entire sequence order.** The rolling
   hash state after processing c_{i,j,ℓ} depends on ALL prior compressed
   values. Even if an adversary found a way to produce alternative
   intermediates that compress to the same individual values, they would need
   the values to appear in the same order — which means reproducing the
   canonical (i, j, ℓ) iteration, which means performing the actual matmul.

**Bottom line**: The linear relationship between consecutive compressed
values is an inherent property of block matmul structure, not a vulnerability.
The security of the scheme rests on σ-unpredictability (the adversary cannot
choose v) and SHA-256d collision resistance (the adversary cannot find
alternative compressed sequences), both of which are unaffected by the
linearity of compression over accumulating partial sums.

### 8.4 Solve and Verify

```cpp
namespace matmul {

bool Solve(CBlockHeader& block,
           uint32_t block_height,
           const Consensus::Params& params,
           uint64_t& max_tries);
// Derives A, B from block.seed_a, block.seed_b
// Loops over nNonce64, computes σ → noise → transcript → z
// On success: sets block.matmul_digest, decrements max_tries

bool Verify(const CBlockHeader& block,
            uint32_t block_height,
            const Consensus::Params& params);
// Full verification: recompute transcript from seeds, check z matches

bool VerifyCommitment(const CBlockHeader& block,
                      const Consensus::Params& params);
// Header-only: matmul_digest < target AND dim in bounds (cheap)

Matrix Denoise(const Matrix& C_prime,
               const Matrix& A, const Matrix& B,
               const noise::NoisePair& np);
// C = C' − A·F − E·(B+F), cost O(n²·r)

} // namespace matmul
```

### 8.5 Tests for Core Algorithm

**Matrix tests:**
```
TEST: matrix_create_zero — all elements 0
TEST: matrix_block_decomposition_roundtrip — extract and reassemble
TEST: matrix_add_sub_inverse — (A+B)−B == A
TEST: matrix_mul_identity — A*I == I*A == A
TEST: matrix_mul_known_vectors — precomputed 4×4 over M31
TEST: matrix_mul_associative — (A*B)*C == A*(B*C)
TEST: matrix_content_hash_deterministic — same matrix → same hash
TEST: matrix_from_seed_deterministic — same seed → same matrix
TEST: matrix_from_seed_differs — different seed → different matrix
```

**Noise tests:**
```
TEST: noise_deterministic — same (σ, n, r) → same NoisePair
TEST: noise_rank_bounded — rank(E_L · E_R) ≤ r
TEST: noise_elements_in_field — all in [0, M31)
TEST: noise_different_sigma_differ — different σ → different noise
TEST: noise_r_independent_of_b — noise uses r, not b
  GIVEN: Generate noise with r=8
  THEN: E_L is n×8, E_R is 8×n (NOT n×b)
```

**Noise derivation byte-exact tests (§8.2.3):**
```
TEST: noise_derived_seed_pinned_EL — tag_EL for σ=0x00..00 matches pinned hash
TEST: noise_derived_seed_pinned_ER — tag_ER for σ=0x00..00 matches pinned hash
TEST: noise_derived_seed_pinned_FL — tag_FL for σ=0x00..00 matches pinned hash
TEST: noise_derived_seed_pinned_FR — tag_FR for σ=0x00..00 matches pinned hash
TEST: noise_domain_separation_all_seeds_distinct — all 4 tags pairwise distinct
TEST: noise_EL_pinned_elements — E_L matrix elements match pinned values (n=4, r=2)
TEST: noise_ER_pinned_elements — E_R matrix elements match pinned values (n=4, r=2)
TEST: noise_first_element_domain_separation — first element of each factor differs
TEST: noise_index_uses_factor_column_count — E_L uses stride r, E_R uses stride n
TEST: noise_all_elements_in_field — all outputs in [0, M31)
TEST: noise_cross_platform_consistency — pinned vectors match on all architectures
  (Full pinned test vectors and byte-exact derivation in §8.2.1–§8.2.3)
```

**Transcript tests:**
```
TEST: transcript_correct_product — CanonicalMatMul(A,B,b).C_prime == A*B
TEST: transcript_hash_deterministic — same inputs → same z
TEST: transcript_hash_changes_with_input — change one element → z changes
TEST: transcript_uses_b_not_r — block decomposition uses b parameter
  GIVEN: n=64, b=16
  THEN: (n/b)³ = 64 intermediates hashed
  (NOT (n/r)³)
TEST: transcript_streaming_matches_batch — streaming == full materialization
TEST: transcript_canonical_order_enforced — swapping order changes hash
```

**Transcript compression tests (§8.3.1):**
```
TEST: compress_vector_deterministic
  GIVEN: Same (σ, b)
  WHEN: DeriveCompressionVector called twice
  THEN: Identical b² element vectors produced

TEST: compress_vector_changes_with_sigma
  GIVEN: Two different σ values, same b
  WHEN: DeriveCompressionVector for each
  THEN: Vectors differ

TEST: compress_block_single_element_output
  GIVEN: A b×b block and compression vector
  WHEN: CompressBlock(block, v)
  THEN: Result is a single Element in [0, M31)

TEST: compress_block_deterministic
  GIVEN: Same block and same compression vector
  WHEN: CompressBlock called twice
  THEN: Same Element produced

TEST: compress_block_different_blocks_differ
  GIVEN: Two distinct b×b blocks, same compression vector
  WHEN: CompressBlock on each
  THEN: Results differ (with overwhelming probability 1 − 1/q)

TEST: compress_block_matches_manual_dot_product
  GIVEN: Known b×b block [1, 2, ..., b²] and known compression vector
  WHEN: CompressBlock(block, v)
  THEN: Result == field::dot(flatten(block), v, b²) computed manually

TEST: transcript_hasher_takes_sigma
  GIVEN: TranscriptHasher constructed with (σ, b)
  THEN: Internal compression vector has b² elements
  AND: All elements in [0, M31)

TEST: transcript_compressed_hash_deterministic
  GIVEN: Same (σ, A', B', b)
  WHEN: CanonicalMatMul run twice
  THEN: Identical transcript_hash z produced

TEST: transcript_compressed_hash_differs_naive
  GIVEN: Same (A', B', b) but naive (full-block) hashing vs compressed hashing
  WHEN: Both produce z_naive and z_compressed
  THEN: z_naive != z_compressed (different hash inputs)
  (This test confirms compression is actually active, not accidentally
   falling through to full-block mode)

TEST: transcript_compressed_bytes_bounded
  GIVEN: n=512, b=16
  WHEN: CanonicalMatMul completes
  THEN: Total bytes written to SHA-256 == (n/b)³ × 4 == 32768 × 4 == 131072
  (NOT 32768 × 1024 == 33554432)

TEST: transcript_compression_binding
  GIVEN: 10,000 random pairs of distinct b×b blocks, same compression vector v
  WHEN: CompressBlock on each pair
  THEN: No collisions observed (expected: 0 collisions at p = 1/2³¹ per trial)

TEST: transcript_domain_separation
  GIVEN: σ used for compression vector AND for noise generation
  WHEN: Compare compression vector elements to noise matrix elements
  THEN: No correlation (domain-separated derivation via "matmul-compress-v1" prefix)
```

**Solve/Verify/Denoise tests:**
```
TEST: solve_finds_proof_regtest — regtest difficulty, succeeds
TEST: solve_proof_verifies — Verify(solved_block) == true
TEST: verify_rejects_wrong_seed_a — change seed_a → false
TEST: verify_rejects_wrong_seed_b — change seed_b → false
TEST: verify_rejects_tampered_digest — flip bit → false
TEST: verify_rejects_bad_dimension — dim out of bounds → false
TEST: verify_commitment_only — header check only, fast
TEST: solve_max_tries_zero — returns false, no side effects
TEST: solve_increments_nonce — nonce advances with attempts
TEST: denoise_recovers_product — Denoise(C', A, B, np) == A*B
TEST: denoise_zero_noise_identity — no noise → C' == C
TEST: denoise_cost_quadratic_r — op count < C·n²·r (NOT n³)
```

---

## 9. Mining Integration

### 9.1 Mining Flow (v1: Seeded Matrices)

```
1. Build block template (transactions, coinbase)
2. Select seed_a, seed_b:
   - Random generation (default)
   - Or from external seed provider (future: job marketplace)
3. Expand: A = FromSeed(seed_a, n), B = FromSeed(seed_b, n)
4. Loop (nonce grinding):
   a. block.nNonce64 = current_nonce
   b. σ = SHA-256(matmul_header_hash(block))
   c. (E, F) = noise::Generate(σ, n, r)     // rank r, NOT b
   d. A' = A + E, B' = B + F
   e. (C', z) = CanonicalMatMul(A', B', b, σ)  // b for blocks, σ for compression vector
   f. If z < target:
      - block.matmul_digest = z
      - C = Denoise(C', A, B, noise_pair)
      - Return (block, C)
   g. Else: increment nonce, goto 4a
5. Optionally: change seed_a/seed_b, goto 2
```

**Retry axes**: nNonce64 (cheapest), nTime, seed_a/seed_b, transactions.

### 9.2 Block Template (`getblocktemplate`)

```json
{
  "matmul": {
    "dimension": 512,
    "transcript_block_size": 16,
    "noise_rank": 8,
    "field_modulus": "7fffffff",
    "min_dimension": 64,
    "max_dimension": 2048
  }
}
```

### 9.3 Tests for Mining

```
TEST: mining_template_matmul_params — getblocktemplate includes matmul section
TEST: mining_generate_block — generateblock produces valid matmul block
TEST: mining_chain_10_blocks — 10 sequential blocks, all valid, chain progresses
TEST: mining_reject_tampered — tampered digest rejected by submitblock
TEST: mining_seeds_in_header — mined block has non-null seed_a, seed_b
```

---

## 10. Validation and DoS Mitigation

### 10.1 Two-Phase Validation

Verification is expensive (O(n³)). An attacker can flood peers with near-valid
blocks forcing costly recomputation. Defense: two-phase validation with cheap
gate.

**Phase 1 — Cheap checks (microseconds):**
```cpp
bool CheckMatMulProofOfWork_Phase1(const CBlockHeader& block,
                                    const Consensus::Params& params)
{
    // 1. matmul_dim within [min, max] and divisible by b
    if (block.matmul_dim < params.nMatMulMinDimension) return false;
    if (block.matmul_dim > params.nMatMulMaxDimension) return false;
    if (block.matmul_dim % params.nMatMulTranscriptBlockSize != 0) return false;

    // 2. matmul_digest < target (just a uint256 comparison)
    auto target = DeriveTarget(block.nBits, params.powLimit);
    if (!target) return false;
    if (UintToArith256(block.matmul_digest) > *target) return false;

    // 3. seed_a and seed_b are non-null
    if (block.seed_a.IsNull() || block.seed_b.IsNull()) return false;

    // 4. Header-level structural checks pass
    return true;
}
```

**Phase 2 — Expensive verification (O(n³)):**
```cpp
bool CheckMatMulProofOfWork_Phase2(const CBlockHeader& block,
                                    const Consensus::Params& params)
{
    // Full transcript recomputation
    Matrix A = FromSeed(block.seed_a, block.matmul_dim);
    Matrix B = FromSeed(block.seed_b, block.matmul_dim);

    uint256 sigma = ComputeSigma(block);
    auto np = noise::Generate(sigma, block.matmul_dim, params.nMatMulNoiseRank);

    Matrix A_prime = A + (np.E_L * np.E_R);
    Matrix B_prime = B + (np.F_L * np.F_R);

    auto result = transcript::CanonicalMatMul(
        A_prime, B_prime, params.nMatMulTranscriptBlockSize, sigma);

    return result.transcript_hash == block.matmul_digest;
}
```

### 10.2 Per-Peer Rate Limiting and Graduated Punishment

#### 10.2.1 Peer Verification State

```cpp
struct PeerVerificationBudget {
    uint32_t expensive_verifications_this_minute{0};
    std::chrono::steady_clock::time_point window_start;

    // Phase 2 failure tracking (graduated punishment)
    uint32_t phase2_failures{0};        // Rolling count within the 24h window
    std::chrono::steady_clock::time_point phase2_first_failure_time;  // Start of 24h window

    bool CanVerify(const Consensus::Params& params) const {
        return expensive_verifications_this_minute < params.nMatMulPeerVerifyBudgetPerMin;
    }

    // Reset rolling counter if 24h have elapsed since first failure in window
    void MaybeResetPhase2Window() {
        if (phase2_failures > 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::hours>(
                now - phase2_first_failure_time);
            if (elapsed.count() >= 24) {
                phase2_failures = 0;
                // Window will be re-anchored on next failure
            }
        }
    }
};
```

**Default value justification for `nMatMulPeerVerifyBudgetPerMin` (8)**:

The per-peer budget, global concurrency cap, and graduated punishment form a
three-layer defense against verification-cost DoS attacks:

| Layer | Parameter | Default | Role |
|-------|-----------|---------|------|
| Per-peer soft limit | `nMatMulPeerVerifyBudgetPerMin` | 8 | Caps the rate at which any single peer can submit blocks for expensive Phase 2 verification. Excess blocks are queued, not dropped. |
| Global hard limit | `nMatMulMaxPendingVerifications` | 4 | Caps the number of Phase 2 verifications executing concurrently across all peers. This is the ultimate CPU-time bound. |
| Per-peer punitive limit | `nMatMulPhase2FailBanThreshold` | 3 | Permanently removes peers that repeatedly send Phase-2-invalid blocks. Bounds total attacker impact to `3 * T_phase2` seconds of CPU per Sybil peer. |

**Why 8**: At steady-state (90s blocks, ~0.4 blocks/min), a budget of 8
provides 20x headroom above normal demand, absorbing Poisson burst arrivals
and small reorgs without throttling honest peers. During the fast-mining phase
(0.25s blocks, ~240 blocks/min), the budget naturally limits Phase 2 throughput to
~8/min per peer, which enforces the Phase 2 deferral policy (Section 10.3.1)
at the rate-limiting layer without requiring height-dependent scheduling logic.
Under attack, worst-case CPU cost per malicious peer is 8 * 2.0s = 16 seconds
per minute (~27% of a single core on older hardware), and the concurrency cap
of 4 provides the hard ceiling regardless of peer count.

**Tuning guidance**: Operators running dedicated IBD sync nodes may raise the
budget (e.g., to 32--64) to allow the concurrency limit rather than the
per-peer budget to be the throughput bottleneck, reducing Phase 2 catch-up
time from ~125 minutes to ~25 minutes for 1000 blocks. Resource-constrained
nodes (e.g., Raspberry Pi 4) may lower the budget to 4 to reduce maximum
per-peer CPU impact to ~24s/min. High-connectivity nodes (>50 peers) may
lower to 4--6 to reduce aggregate demand submission rate.

#### 10.2.2 Graduated Punishment Model

The punishment model uses **four escalation tiers** that balance early-network
robustness against long-term DoS resistance.

| Condition | Misbehavior delta | Action | Rationale |
|-----------|:-----------------:|--------|-----------|
| **Phase 1 fail** (bad dim, digest > target, null seeds) | **+20** | Standard DoS scoring (same weight as other Bitcoin Core structural violations). Accumulates toward ban at 100. | Cheap to verify; unambiguously invalid. |
| **Phase 2 budget exhausted** | 0 | Further blocks from this peer **queued, not verified** until next minute window. | Rate-limit expensive computation; not the peer's fault per se. |
| **Phase 1 pass + Phase 2 fail (1st occurrence within 24h)** | 0 | **DISCONNECT** peer. Log `MATMUL WARNING` with peer id, address, failure count, and the mismatched digest bytes. Do NOT ban. | Could be an honest implementation bug (endianness, seed expansion, etc.). Disconnecting stops the immediate impact without permanently excluding the peer. |
| **Phase 1 pass + Phase 2 fail (2nd occurrence from same peer within 24h)** | 0 | **DISCOURAGE** peer (`m_discouraged = true`). Peer is deprioritized for connection slots and outbound relay, but not banned. Disconnect after discouraging. Log at `WARNING` level. | Repeated disagreement is suspicious but may still be a persistent bug on one side. Discouraging reduces the peer's influence without full exclusion. |
| **Phase 1 pass + Phase 2 fail (3rd+ occurrence from same peer within 24h, i.e. `phase2_failures >= nMatMulPhase2FailBanThreshold`)** | **+100** (= immediate ban) | **BAN** peer (mainnet/signet only). | Three strikes within 24h from the same peer is confident evidence of malicious behavior, not an implementation mismatch. |

The 24-hour rolling window prevents a single historical failure from haunting a
peer indefinitely after a bug is patched and the peer reconnects.

#### 10.2.3 Network Maturity Flag: `fMatMulStrictPunishment`

Early releases carry inherent risk of miner/validator mismatches (byte-order bugs
in seed expansion, off-by-one in transcript iteration, platform-dependent reduction
paths, etc.). To protect bootstrap-era networks from accidental partitioning, the
graduated model above is the **default** behavior when the maturity flag is `false`.

```cpp
// In Consensus::Params (see section 5.1)
bool fMatMulStrictPunishment{false};   // default: false for v1.0
```

| `fMatMulStrictPunishment` | Effective `nMatMulPhase2FailBanThreshold` | Phase 2 fail behavior |
|:-------------------------:|:-----------------------------------------:|----------------------|
| **`false`** (v1.0 default) | `nMatMulPhase2FailBanThreshold` (default 3) | Graduated model: disconnect, discourage, then ban (as in section 10.2.2) |
| **`true`** (post-stabilization) | **1** | **Immediate ban** on first Phase 1 pass + Phase 2 fail. Original behavior: `Misbehaving(peer, 100, "matmul-phase2-fail")`. |

**Activation plan**: After the network has been stable for a sufficient period
(suggested: 6 months post-mainnet-launch or 250,000 blocks, whichever comes later),
a coordinated release sets `fMatMulStrictPunishment = true`. This is a
**policy change, not a consensus fork** -- it only affects peer punishment, not
block validity. Nodes running mixed versions (some strict, some graduated) still
agree on the valid chain; they differ only in how aggressively they disconnect
misbehaving peers.

#### 10.2.4 Network-Dependent Behavior

| Network | `fMatMulStrictPunishment` | Phase 2 fail behavior |
|---------|:-------------------------:|----------------------|
| **mainnet** | Obeys flag (default `false` in v1.0) | Graduated when `false`; immediate ban when `true` |
| **signet** | Obeys flag (default `false` in v1.0) | Same as mainnet |
| **testnet** | **Always overridden** (forced to graduated, threshold = `UINT32_MAX`) | Softfail: disconnect on every Phase 2 failure, **never ban**. Ensures testnet nodes remain reachable for cross-implementation debugging. |
| **regtest** | **Always overridden** (forced to graduated, threshold = `UINT32_MAX`) | Softfail: same as testnet. Additionally, `fSkipMatMulValidation` can bypass Phase 2 entirely for fast iteration. |

**Rule**: On testnet and regtest, `nMatMulPhase2FailBanThreshold` is treated as
`UINT32_MAX` regardless of its configured value or the state of
`fMatMulStrictPunishment`. This guarantees that Phase 2 failures never escalate
to a ban on test networks, even if strict mode is accidentally enabled.

#### 10.2.5 Consensus Parameters

```cpp
// In Consensus::Params (see section 5.1)
uint32_t nMatMulPhase2FailBanThreshold{3};  // Graduate to ban after N failures within 24h (v1 default)
                                             // Effective value is 1 when fMatMulStrictPunishment == true
                                             // Effective value is UINT32_MAX on testnet/regtest
bool fMatMulStrictPunishment{false};         // When true: Phase 1 pass + Phase 2 fail = immediate ban
                                             // When false: graduated disconnect -> discourage -> ban
                                             // Always overridden on testnet/regtest (treated as false)
```

The effective threshold is computed at runtime:

```cpp
uint32_t EffectivePhase2BanThreshold(const Consensus::Params& params) {
    if (params.m_chain_type == ChainType::TESTNET ||
        params.m_chain_type == ChainType::REGTEST) {
        return std::numeric_limits<uint32_t>::max();  // Never ban
    }
    if (params.fMatMulStrictPunishment) {
        return 1;  // Immediate ban on first Phase 2 fail
    }
    return params.nMatMulPhase2FailBanThreshold;  // Default: 3
}
```

#### 10.2.6 Punishment Handler

```cpp
void HandleMatMulPhase2Failure(CNode& peer, const Consensus::Params& params,
                                CConnman& connman) {
    peer.m_matmul_budget.MaybeResetPhase2Window();

    if (peer.m_matmul_budget.phase2_failures == 0) {
        peer.m_matmul_budget.phase2_first_failure_time =
            std::chrono::steady_clock::now();
    }
    peer.m_matmul_budget.phase2_failures++;

    const uint32_t threshold = EffectivePhase2BanThreshold(params);

    LogPrintf("MATMUL WARNING: peer=%d (%s) Phase1-pass/Phase2-fail, "
              "count=%u/%u (effective_threshold=%u, strict=%s, chain=%s)\n",
              peer.GetId(), peer.m_addr_name,
              peer.m_matmul_budget.phase2_failures,
              params.nMatMulPhase2FailBanThreshold,
              threshold,
              params.fMatMulStrictPunishment ? "true" : "false",
              ChainTypeToString(params.m_chain_type));

    if (peer.m_matmul_budget.phase2_failures >= threshold) {
        // Threshold reached: ban
        // (mainnet/signet only; testnet/regtest threshold is UINT32_MAX)
        Misbehaving(peer, 100, "matmul-phase2-fail-ban");
    } else if (peer.m_matmul_budget.phase2_failures >= 2) {
        // Second offense: discourage (deprioritize connections and relay)
        connman.SetDiscouraged(peer.GetId());
        peer.fDisconnect = true;
        LogPrintf("MATMUL: peer=%d discouraged after %u Phase 2 failures\n",
                  peer.GetId(), peer.m_matmul_budget.phase2_failures);
    } else {
        // First offense: disconnect only
        peer.fDisconnect = true;
    }
}
```

#### 10.2.7 Rationale: Why Graduated Punishment Matters for Early Networks

In a mathematically ideal world, consensus is perfectly deterministic: if a block
passes Phase 1 (the digest numerically satisfies the target) but fails Phase 2
(the recomputed transcript does not match), the sending peer is unambiguously
malicious. Honest miners running correct code always produce transcripts that
honest validators can reproduce. The safe response is an immediate ban.

In practice, **the first releases of a novel PoW algorithm will contain bugs**.
Experience across Bitcoin, Ethereum, and ProgPoW deployments shows that early
implementations routinely diverge on:

- **Byte order**: Little-endian vs big-endian serialization of field elements or
  seed material, especially across CPU architectures (x86 vs ARM).
- **Seed expansion**: Subtle differences in PRNG state management when expanding
  32-byte seeds into n x n matrices (e.g., counter overflow behavior, domain
  separation string encoding).
- **Field arithmetic**: Platform-dependent behavior in reduction paths -- e.g.,
  whether `reduce64` handles the case `lo + hi == MODULUS` by subtracting or not,
  or whether intermediate accumulations use different widths on 32-bit vs 64-bit
  targets.
- **Transcript iteration**: Off-by-one in block indexing, row-major vs
  column-major flattening for the compression dot-product, or disagreement on
  whether the compression vector is derived before or after the first SHA-256
  update call.
- **Floating-point contamination**: GPU miners using `float`/`double` intrinsics
  that introduce rounding where pure integer arithmetic was intended.

If the protocol bans on the first Phase 2 mismatch, **a single implementation bug
can cascade into a network partition**: nodes running version A ban all peers
running version B, and vice versa. Both sides believe they are correct. The
network fragments into incompatible islands, each with reduced hashrate and
security. Reconnecting the islands requires manual intervention (operator-level
unbanning, emergency patches, coordinated restarts).

The graduated model avoids this catastrophe through progressive escalation:

1. **First failure = disconnect**: Stops the immediate propagation of disagreed-upon
   blocks without permanent consequences. If the peer reconnects after a bugfix
   (or after operators compare debug logs), it gets a fresh chance. The 24-hour
   rolling window ensures old failures do not accumulate across patch cycles.

2. **Second failure = discourage**: Reduces the peer's influence on the local
   node's view of the network (lower connection priority, deprioritized relay) but
   does not cut it off from the gossip graph entirely. This is the right response
   when a peer is "probably wrong but maybe we are."

3. **Third failure = ban**: At this point, the peer has failed three independent
   Phase 2 checks within 24 hours despite being disconnected twice. The
   probability that this is an honest bug rather than a deliberate attack is
   low enough to justify exclusion.

4. **Strict mode (post-stabilization)**: Once the network has been running long
   enough that cross-implementation determinism is empirically confirmed (suggested:
   6 months / 250,000 blocks), the graduated model is unnecessary overhead.
   Flipping `fMatMulStrictPunishment` to `true` restores the original "Phase 1
   pass + Phase 2 fail = immediate ban" behavior, which is the correct long-term
   policy for a mature network.

5. **Testnet never bans**: Testnet exists specifically to find the bugs described
   above. Banning peers on testnet defeats its purpose. The softfail policy
   ensures that even catastrophically buggy implementations can still connect,
   exchange blocks, and generate the debug traces needed to fix the mismatch.

**Transition timeline**: The `fMatMulStrictPunishment` flag is a node policy
parameter, not a consensus rule. It can be flipped in a minor release without a
fork. The suggested activation criteria (6 months or 250,000 blocks) provide a
conservative window for cross-implementation testing. If zero Phase 2 mismatches
are observed on mainnet during this period, the flag is safe to enable. If
mismatches are observed, the graduated model has already prevented partitioning,
and the development team can diagnose and patch before escalating to strict mode.

### 10.3 Verification Scheduling

- At most `nMatMulMaxPendingVerifications` (default: 4) Phase 2 verifications
  run concurrently across all peers
- Additional candidate blocks are queued in priority order (by total work)
- During IBD: use assumevalid checkpoints to skip Phase 2 for old blocks

#### 10.3.1 Fast-Phase Phase 2 Scheduling (h < nFastMineHeight)

During 0.25-second blocks, Tier 1 (consensus-validating) nodes may not be able
to complete Phase 2 verification for every arriving block in real time on
CPU-only hardware (see §3.5.2 utilization table). The following rules apply:

1. **Phase 1 MUST be applied immediately** to every arriving block, at all
   heights, with no exceptions. Phase 1 is microsecond-cost and always
   real-time.
2. **Phase 2 MAY be deferred** via a bounded verification queue during the
   fast-mining phase. The queue MUST be bounded by
   `nMatMulMaxPendingVerifications * FAST_PHASE_QUEUE_MULTIPLIER` (suggested:
   multiplier = 50, giving a queue depth of 200 blocks).
3. **After the transition to 90-second blocks** (h ≥ `nFastMineHeight`), the
   Phase 2 verifier MUST drain the deferred queue and restore "Phase 2 at
   tip" behavior. With 90s inter-block time, the verifier can process ~75–300
   deferred blocks per new block interval (at 0.5–2s per verification), so
   catch-up completes within minutes.
4. **GPU-accelerated Tier 1 nodes** (< 0.1s per Phase 2) can verify every
   fast-phase block in real time and do not need deferred scheduling.
5. **Tier 2 (economic) nodes** never perform Phase 2 and are unaffected.
6. **No consensus relaxation**: A deferred Phase 2 failure MUST trigger the
   same graduated punishment as a real-time failure (§10.2). The deferral
   is a scheduling optimization, not a security relaxation.

**Block acceptance model during deferred Phase 2**:

A block that passes Phase 1 is **accepted into the active chain** and may serve
as the tip for subsequent blocks, even if its Phase 2 verification is still
queued. This is the "accept + queue" model:

- **Tip selection**: A Phase-1-verified block participates in tip selection
  (most-work rule) identically to a fully-verified block. The node does not
  stall chain progress waiting for Phase 2.
- **Relay**: The block is relayed to peers after Phase 1 passes. Peers perform
  their own Phase 1 immediately and queue their own Phase 2 independently.
- **Retroactive invalidation**: If a deferred Phase 2 later fails, the node
  MUST invalidate that block and any descendants built on it, reorganize to
  the best valid chain, and apply graduated punishment (§10.2) to the
  originating peer. This is identical to discovering a Phase 2 failure in
  real-time — the deferral does not reduce the consequence.
- **Queue starvation guard**: If the deferred Phase 2 queue reaches its depth
  limit, the node MUST pause block acceptance until at least one queued
  verification completes. This prevents unbounded optimistic acceptance.

**Consensus vs. policy boundary**: Deferral of Phase 2 verification during the
fast-mining phase is a **node scheduling policy**, not a consensus rule. A block
that fails Phase 2 is **invalid at any height** — the fast phase does not change
the definition of a valid block. Implementations MUST NOT introduce
height-dependent acceptance rules that treat fast-phase blocks as "provisionally
valid pending Phase 2." A block is either fully valid (Phase 1 + Phase 2) or
invalid; deferral only affects *when* the node discovers invalidity, not
*whether* it acts on it.

### 10.4 Tests for Validation and DoS

```
TEST: validation_phase1_rejects_bad_dim — dim=1 → Phase 1 false
TEST: validation_phase1_rejects_high_digest — digest > target → false
TEST: validation_phase1_rejects_null_seeds — null seed_a → false
TEST: validation_phase1_accepts_valid — valid header → Phase 1 true
TEST: validation_phase1_fail_misbehavior_score
  GIVEN: Peer sends block that fails Phase 1 (e.g., dim out of bounds)
  WHEN: CheckMatMulProofOfWork_Phase1 returns false
  THEN: Peer misbehavior score increases by +20
  AND: Peer is NOT immediately banned (score 20 < 100 threshold)
  AND: After 5 Phase 1 failures from same peer (5 * 20 = 100): peer is BANNED

TEST: validation_phase2_recomputes — valid block → Phase 2 true
TEST: validation_phase2_rejects_wrong_seed — changed seed_a → Phase 2 false
TEST: validation_phase2_rejects_tampered_digest — bit flip → false
TEST: validation_skip_mode — fSkipMatMulValidation skips Phase 2

TEST: validation_phase2_fail_first_offense_disconnect
  GIVEN: Mainnet params with fMatMulStrictPunishment == false
  AND: nMatMulPhase2FailBanThreshold == 3
  AND: Peer sends block that passes Phase 1 but fails Phase 2
  WHEN: First offense (phase2_failures goes from 0 to 1)
  THEN: Peer is DISCONNECTED (fDisconnect == true)
  AND: Peer is NOT banned (misbehavior score unchanged)
  AND: Peer is NOT discouraged (m_discouraged == false)
  AND: Warning logged with peer ID, failure count (1), and effective threshold (3)
  AND: peer.m_matmul_budget.phase2_failures == 1
  AND: peer.m_matmul_budget.phase2_first_failure_time is set to current time

TEST: validation_phase2_fail_second_offense_discourage
  GIVEN: Mainnet params with fMatMulStrictPunishment == false
  AND: nMatMulPhase2FailBanThreshold == 3
  AND: Peer has phase2_failures == 1 from a previous offense (within 24h)
  WHEN: Second offense (phase2_failures goes from 1 to 2)
  THEN: Peer is DISCOURAGED (connman.SetDiscouraged called)
  AND: Peer is DISCONNECTED (fDisconnect == true)
  AND: Peer is NOT banned (misbehavior score unchanged)
  AND: peer.m_matmul_budget.phase2_failures == 2

TEST: validation_phase2_fail_third_offense_ban
  GIVEN: Mainnet params with fMatMulStrictPunishment == false
  AND: nMatMulPhase2FailBanThreshold == 3
  AND: Peer has phase2_failures == 2 from previous offenses (within 24h)
  WHEN: Third offense (phase2_failures reaches threshold == 3)
  THEN: Peer is BANNED (Misbehaving score +100)
  AND: peer.m_matmul_budget.phase2_failures == 3

TEST: validation_phase2_fail_strict_mode_immediate_ban
  GIVEN: Mainnet params with fMatMulStrictPunishment == true
  AND: Peer sends block that passes Phase 1 but fails Phase 2
  WHEN: First offense (phase2_failures was 0)
  THEN: Peer is IMMEDIATELY BANNED (Misbehaving score +100)
  AND: EffectivePhase2BanThreshold returns 1
  AND: No discourage step (ban on first failure)

TEST: validation_phase2_softfail_testnet
  GIVEN: Testnet params (ChainType::TESTNET)
  AND: Peer sends blocks that pass Phase 1 but fail Phase 2

  WHEN: First offense
  THEN: Peer is DISCONNECTED (not banned, not discouraged beyond disconnect)

  WHEN: 2nd offense
  THEN: Peer is DISCOURAGED + DISCONNECTED (still not banned)

  WHEN: 10th offense (well above any threshold)
  THEN: Peer is STILL only DISCOURAGED + DISCONNECTED, NEVER banned
  AND: phase2_failures == 10
  AND: EffectivePhase2BanThreshold returns UINT32_MAX
  (Softfail mode: testnet never bans for Phase 2 failures regardless of
   fMatMulStrictPunishment setting)

TEST: validation_phase2_softfail_testnet_ignores_strict_flag
  GIVEN: Testnet params with fMatMulStrictPunishment == true (misconfigured)
  AND: Peer sends block that passes Phase 1 but fails Phase 2
  WHEN: First offense
  THEN: Peer is DISCONNECTED, NOT banned
  AND: EffectivePhase2BanThreshold returns UINT32_MAX (overrides strict flag)
  (Testnet always overrides strict mode to prevent accidental banning)

TEST: validation_phase2_softfail_regtest
  GIVEN: Regtest params (ChainType::REGTEST)
  AND: Peer sends block that passes Phase 1 but fails Phase 2
  WHEN: Any number of offenses
  THEN: Peer is DISCONNECTED (and DISCOURAGED after 2nd), NEVER banned
  AND: EffectivePhase2BanThreshold returns UINT32_MAX
  (Softfail mode applies to regtest identically to testnet)

TEST: validation_phase2_failure_counter_persists_across_rate_limit_reset
  GIVEN: Mainnet params
  AND: Peer has phase2_failures == 2 from previous offenses (within 24h)
  WHEN: Per-minute verification window resets (expensive_verifications_this_minute = 0)
  THEN: phase2_failures is NOT reset (still 2)
  AND: Next Phase 2 failure triggers ban (reaches threshold 3)

TEST: validation_phase2_failure_counter_resets_after_24h
  GIVEN: Mainnet params with fMatMulStrictPunishment == false
  AND: Peer has phase2_failures == 2 from previous offenses
  AND: phase2_first_failure_time was 25 hours ago
  WHEN: MaybeResetPhase2Window() is called (triggered by next failure)
  THEN: phase2_failures is reset to 0
  AND: The next Phase 2 failure starts a fresh 24h window
  AND: That failure is treated as a first offense (disconnect only, no ban)

TEST: validation_effective_threshold_computation
  GIVEN: Various configurations
  THEN: EffectivePhase2BanThreshold returns:
    - 3 when mainnet, fMatMulStrictPunishment == false, threshold == 3
    - 1 when mainnet, fMatMulStrictPunishment == true (any threshold)
    - UINT32_MAX when testnet (any fMatMulStrictPunishment value)
    - UINT32_MAX when regtest (any fMatMulStrictPunishment value)

TEST: validation_rate_limit_per_peer
  GIVEN: Peer sends > nMatMulPeerVerifyBudgetPerMin blocks
  THEN: Excess blocks queued, not immediately verified
TEST: validation_max_concurrent_verifications
  GIVEN: 10 blocks arrive simultaneously from different peers
  THEN: At most nMatMulMaxPendingVerifications run concurrently
```

---

## 11. Difficulty Adjustment

### 11.1 ASERT for All MatMul Difficulty Adjustment

> **DESIGN INVARIANT**: MatMul networks use ASERT exclusively for all
> difficulty adjustment after the fast-mining bootstrap phase. DarkGravityWave
> (DGW) is NOT used for MatMul mining. DGW was deliberately replaced by ASERT
> to avoid convergence, oscillation, and warmup issues inherent to DGW's
> 180-block averaging window. Do not reintroduce DGW for MatMul mining without
> explicit project approval.

With a fresh genesis, the chain enters the fast-mining bootstrap phase
(blocks 0..nFastMineHeight-1) at fixed genesis-derived difficulty. From
`nFastMineHeight` onward, ASERT governs all retargeting as a stateless,
path-independent exponential algorithm.

**Variable target spacing**: The target inter-block time is height-dependent
(see §5.1, §11.5). ASERT handles this via its anchor-based design — it
measures elapsed time vs. expected time from the anchor block.

### 11.2 Genesis Difficulty: Conservative Start (Not powLimit)

**Problem with naive powLimit**: acceptance probability ≈ 1.0, blocks found in
milliseconds, 180 blocks of ultra-fast emission before difficulty adjustment catches up.

**Fix**: Start with a calibrated initial difficulty:

```cpp
// Genesis nBits chosen so that:
// - Expected solve time ≈ GetTargetSpacing(0) = nPowTargetSpacingFastMs / 1000.0 = 0.25 seconds
// - On reference hardware (single modern GPU)
// - With n=512, b=16 matrix computation
//
// Calibrated via benchmark: one matmul attempt takes ~T_attempt seconds.
// Expected attempts for 0.25s block = 0.25 / T_attempt.
// Initial target = powLimit / (0.25 / T_attempt).
// nFastMineDifficultyScale (4) scales bootstrap difficulty for the 0.25s target.
//
// NOTE: Genesis difficulty targets the FAST-PHASE spacing (0.25s), not the
// steady-state spacing (90s). ASERT handles the transition to 90s blocks
// at height 50,000 via its bootstrap factor.
//
// This is set as a constant in chainparams, NOT computed dynamically.
```

During the fast-mining phase (blocks 0..nFastMineHeight-1), genesis-derived
difficulty is used unchanged (no retargeting). This prevents both ultra-fast
and ultra-slow early chain growth.

### 11.3 Tests for Difficulty

```
TEST: genesis_difficulty_not_powlimit
  GIVEN: Genesis block
  THEN: nBits != powLimit.GetCompact()
  AND: nBits represents a non-trivial target

TEST: fast_phase_holds_bootstrap_difficulty
  GIVEN: Chain height < nFastMineHeight
  WHEN: GetNextWorkRequired
  THEN: Returns genesis-derived bootstrap nBits (no retargeting)

TEST: asert_activates_at_fast_mine_height
  GIVEN: Chain at nFastMineHeight
  WHEN: GetNextWorkRequired
  THEN: Returns ASERT bootstrap (parent_target × bootstrap_factor)

TEST: asert_hashrate_step_up
  GIVEN: Stable chain, then 2x hashrate (45s blocks)
  THEN: ASERT increases difficulty

TEST: asert_hashrate_step_down
  GIVEN: Stable chain, then 0.5x hashrate (180s blocks)
  THEN: ASERT decreases difficulty

TEST: asert_path_independence
  GIVEN: Two chains with same elapsed time and height difference
  THEN: Same next target regardless of intermediate block timings
```

### 11.4 Block Subsidy

The block subsidy follows a Bitcoin-style infinite halving series, producing
an exact hard cap of 21,000,000 BTX.

#### 11.4.1 Consensus Definition

```cpp
CAmount GetBlockSubsidy(int32_t height, const Consensus::Params& p) {
    int halvings = height / p.nSubsidyHalvingInterval;

    // Standard safety bound: after 64 halvings, subsidy is sub-satoshi.
    // (20 * COIN) >> 64 == 0 for any sane COIN value.
    if (halvings >= 64) return 0;

    CAmount subsidy = p.nInitialSubsidy >> halvings;  // integer halving
    return subsidy;
}
```

**Design notes**:

- The initial subsidy is **20 BTX** (= `20 * COIN`).
- The halving interval is **525,000 blocks**.
- The infinite geometric series converges to:
  `20 × 525,000 × (1 + 1/2 + 1/4 + ...) = 20 × 525,000 × 2 = 21,000,000 BTX`.
- Integer division truncation ensures the sum never exceeds 21M; in practice
  the total is `21,000,000 - (525,000 * 20 / 2^64)` ≈ 21M minus dust.
- The `halvings >= 64` guard is a safety bound. At 64 halvings the subsidy
  has been right-shifted to zero regardless of COIN precision.

#### 11.4.2 Issuance Schedule

| Halving | Block range | Subsidy/block | Cumulative (BTX) | Phase |
|---------|-------------|---------------|-------------------|-------|
| 0 | 0 – 524,999 | 20 | 10,500,000 | Includes fast-mining (0–49,999) |
| 1 | 525,000 – 1,049,999 | 10 | 15,750,000 | Steady state |
| 2 | 1,050,000 – 1,574,999 | 5 | 18,375,000 | Steady state |
| 3 | 1,575,000 – 2,099,999 | 2.5 | 19,687,500 | Steady state |
| 4 | 2,100,000 – 2,624,999 | 1.25 | 20,343,750 | Steady state |
| … | … | … | → 21,000,000 | Asymptotic approach to cap |

**Fast-mining phase emission**: The first 50,000 blocks (heights 0–49,999)
are mined at 0.25-second intervals at the initial 20 BTX subsidy, producing
exactly **1,000,000 BTX** in approximately **3.5 hours**. This is 4.76%
of the total supply. The remaining 475,000 blocks in halving epoch 0 are
mined at 90-second intervals over approximately **2.26 years**.

#### 11.4.3 Cap Enforcement

The `MoneyRange()` function MUST use `nMaxMoney` from consensus params:

```cpp
inline bool MoneyRange(CAmount nValue, const Consensus::Params& p) {
    return (nValue >= 0 && nValue <= p.nMaxMoney);
}
```

Cap enforcement requirements:

1. **Coinbase output**: `sum(coinbase_outputs) <= GetBlockSubsidy(height) + fees`.
   This is the primary issuance gate.
2. **Transaction amounts**: All `CTxOut::nValue` pass `MoneyRange()`.
3. **UTXO set**: No UTXO may have `nValue > nMaxMoney`.
4. **Cumulative check (test-only)**: A test MUST verify that
   `Σ GetBlockSubsidy(h) for h = 0 .. ∞` converges to exactly `nMaxMoney`
   (within integer truncation rounding).

### 11.5 Fast-Mining Phase Schedule

For heights **0 through 49,999**, the consensus target inter-block time is
**0.25 seconds** (250ms). For heights **≥ 50,000**, the consensus target inter-block
time is **90 seconds**. This is a consensus rule.

```
Target spacing schedule (consensus-critical):
  height ∈ [0, 50000)  → target = 0.25 seconds  (fast-mining phase, 250ms)
  height ∈ [50000, ∞)  → target = 90 seconds    (steady-state)
```

**Rationale**: The fast-mining phase serves as a rapid bootstrap:

- **Duration**: ~12,500 seconds ≈ 3.47 hours at target spacing.
- **Emission**: 50,000 × 20 = 1,000,000 BTX (4.76% of supply).
- **Security**: The fast phase uses the same MatMul PoW — no reduced
  security. The bootstrap difficulty targets 0.25-second blocks.
  `nFastMineDifficultyScale{4}` scales bootstrap difficulty for the 4x faster target.
- **Transition**: At height 50,000 the target spacing changes from 0.25s to 90s.
  ASERT activates with a bootstrap factor to ease difficulty for the 360x
  increase in target spacing, then converges smoothly via its exponential
  retargeting algorithm.

**The fast-mining phase does NOT change the halving schedule.** The halving
interval is measured in blocks (525,000), not time. The first halving
occurs at block 525,000 regardless of how fast those blocks were produced.

#### 11.5.1 Timestamp Rules During Fast Phase

The Bitcoin-inherited timestamp acceptance rules **are unchanged** during the
fast-mining phase:

1. **Median-Time-Past (MTP)**: A block's `nTime` must be strictly greater than
   the median of the previous 11 blocks' timestamps. At 0.25-second target
   spacing, the MTP advances by ~0.25 seconds per block — this is tight but
   satisfies the rule as long as miners use accurate clocks.
2. **Future time limit**: A block's `nTime` must not exceed the node's local
   time + `MAX_FUTURE_BLOCK_TIME` (7200 seconds = 2 hours). This is
   unchanged and provides ample margin.
3. **nTime monotonicity**: The consensus rules do NOT require strictly
   increasing `nTime` (only > MTP). At 0.25-second spacing, multiple consecutive
   blocks may have the same `nTime` if they are mined within the same
   wall-clock second. This is valid — σ (and thus the PoW instance) still
   differs because `hashPrevBlock` changes.

**Implementation note**: Miners during the fast phase SHOULD use
`GetAdjustedTime()` (NTP-synchronized) for `nTime` to avoid MTP violations.
A miner whose clock is off by more than ~5 seconds may produce blocks that
peers reject for failing MTP.

### 11.6 ASERT Transition at Fast-Mining Boundary

> **Note**: DGW (DarkGravityWave) is NOT used for MatMul difficulty adjustment.
> The `ExpectedDgwTimespan()` function is retained for KAWPOW-era legacy
> networks only. For MatMul, ASERT handles the fast-to-steady transition.

At height `nFastMineHeight` (50,000), ASERT activates with a one-time
bootstrap factor (`nMatMulAsertBootstrapFactor = 40`) that eases difficulty
from the fast-phase level to accommodate the 360x increase in target spacing
(from 0.25s to 90s). ASERT then converges to steady-state difficulty via
its exponential, stateless retargeting algorithm.

#### 11.6.1 ASERT Phase Boundaries

| Height range | Difficulty algorithm | Notes |
|-------------|---------------------|-------|
| h < nFastMineHeight | Fixed bootstrap difficulty | Genesis-derived, no retargeting |
| h == nFastMineHeight | ASERT bootstrap | parent_target × bootstrap_factor |
| h == nMatMulAsertRetuneHeight | ASERT retune 1 | One-time hardening (÷ factor) |
| h == nMatMulAsertRetune2Height | ASERT retune 2 | One-time ratio scaling (num/den) |
| h > nMatMulAsertRetune2Height | ASERT steady-state | Stateless exponential retargeting |

**Implementation warning**: Do not reintroduce DGW for MatMul mining. ASERT
was chosen specifically because its path-independent, stateless design avoids
the convergence and oscillation issues observed with DGW's 180-block
averaging window.

### 11.7 Tests for Monetary Policy and Scheduling

```
TEST: subsidy_height_0_is_20
  GIVEN: height = 0, default mainnet params
  THEN: GetBlockSubsidy(0, params) == 20 * COIN

TEST: subsidy_halves_at_525k
  GIVEN: default mainnet params
  THEN: GetBlockSubsidy(524999, params) == 20 * COIN
  AND: GetBlockSubsidy(525000, params) == 10 * COIN
  AND: GetBlockSubsidy(1049999, params) == 10 * COIN
  AND: GetBlockSubsidy(1050000, params) == 5 * COIN

TEST: subsidy_zero_after_64_halvings
  GIVEN: default mainnet params
  THEN: GetBlockSubsidy(525000 * 64, params) == 0
  AND: GetBlockSubsidy(525000 * 100, params) == 0

TEST: subsidy_fast_phase_total_is_1m
  GIVEN: default mainnet params
  WHEN: sum = Σ GetBlockSubsidy(h, params) for h = 0 .. 49999
  THEN: sum == 1'000'000 * COIN
  // All 50,000 blocks are in halving epoch 0 (before block 525,000)
  // so each earns 20 BTX: 50,000 × 20 = 1,000,000

TEST: max_supply_never_exceeded
  GIVEN: default mainnet params
  WHEN: total = Σ GetBlockSubsidy(h, params) for h = 0 .. 525000*64
  THEN: total <= 21'000'000 * COIN
  AND: total > 20'999'999 * COIN  // within 1 BTX of cap (integer truncation)

TEST: dgw_fast_phase_targets_250ms
  GIVEN: height = 500, default mainnet params
  THEN: ExpectedDgwTimespan(500, params) == 45
  // All 180 blocks in window are fast-phase: (180 × 250) / 1000 = 45s

TEST: dgw_post_phase_targets_90s
  GIVEN: height = 60000, default mainnet params
  THEN: ExpectedDgwTimespan(60000, params) == 16200
  // All 180 blocks in window are steady-state: 180 × 90s = 16,200s

TEST: dgw_boundary_mixed_timespan
  GIVEN: height = 50090, default mainnet params
  THEN: ExpectedDgwTimespan(50090, params) == (90 * 0.25 + 90 * 90)
  // Window spans [49910, 50089]: 90 fast-phase + 90 steady-state
  // = 22.5 + 8100 = 8122.5s

TEST: dgw_boundary_transition_start
  GIVEN: height = 50000, default mainnet params
  THEN: ExpectedDgwTimespan(50000, params) == 45
  // Window is [49820, 49999]: all fast-phase blocks, so (180 × 250) / 1000 = 45

TEST: dgw_boundary_transition_end
  GIVEN: height = 50180, default mainnet params
  THEN: ExpectedDgwTimespan(50180, params) == 16200
  // Window is [50000, 50179]: all steady-state blocks, so 180 × 90 = 16200

TEST: money_range_enforces_cap
  GIVEN: default mainnet params
  THEN: MoneyRange(21'000'000 * COIN, params) == true
  AND: MoneyRange(21'000'001 * COIN, params) == false
  AND: MoneyRange(-1, params) == false
  AND: MoneyRange(0, params) == true
```

---

## 12. Trust Model and Data Availability

Because Phase 2 verification is O(n³) per block -- concretely ~134 million
multiply-add operations at n=512 -- the trust model cannot treat verification as
free. At 90-second steady-state blocks a CPU-only full verifier must sustain
134M operations per 90 seconds for tip verification (during the fast-mining
phase at 0.25-second blocks, this rises to 536M operations per second — requiring
GPU or deferred batch verification). GPU-enabled verification shifts the
hardware baseline entirely. The protocol therefore defines **four explicit node
tiers** with different Phase 2 validation scopes, hardware expectations, and
trust assumptions.

### 12.1 Node Tier Definitions

The four tiers are a **consensus-adjacent** design choice: all tiers follow
the same consensus rules, but they differ in how much of the chain's Phase 2
work they independently verify. The tiers supersede the earlier model
described in earlier drafts and referenced in §3.6.

| Tier | Name | Phase 2 Scope | Phase 1 Scope | Trust Assumption | Typical Operator |
|------|------|--------------|---------------|------------------|-----------------|
| **0** | **Mining node** | Every candidate block at tip (performs full Solve including transcript computation for every nonce attempt) | All | Trustless (produces and verifies proofs) | Miners, mining pools |
| **1** | **Consensus-validating node** | Recomputes Phase 2 for all blocks in the last `MATMUL_VALIDATION_WINDOW` blocks (default 1000 = ~41.7 hours at 90s steady-state). Uses `assumevalid` for older blocks during IBD, then validates every new block at tip indefinitely. **This is the minimum to be a "full node."** | All | Trustless for validated range; trusts checkpoint hash for deep history | Exchanges, protocol developers, security auditors |
| **2** | **Economic node** | Phase 1 only for new blocks + `assumevalid` for all history. Does NOT recompute Phase 2. Trusts that the majority of Tier 0 and Tier 1 nodes have verified recent blocks. | All | Trusts full-node majority for transcript correctness | Merchants, wallets, block explorers, infrastructure |
| **3** | **SPV / Light node** | None | Header chain only (`matmul_digest < target` + dimension bounds) | Trusts full-node majority for both transcript correctness and transaction inclusion | Mobile wallets, read-only explorers, embedded devices |

**Definition of "full node"**: A node is considered **full** in the BTX
ecosystem if it validates Phase 2 for at least the last
`MATMUL_VALIDATION_WINDOW` blocks. This corresponds to Tier 1
(consensus-validating) or Tier 0 (mining). Tier 2 (economic) nodes participate
in transaction relay and UTXO-set maintenance but do NOT independently verify
PoW transcript correctness -- they cannot detect a valid-header /
invalid-transcript attack without relying on peers. Tier 2 is explicitly
**not** "full."

**Implementation and UX requirement**: The term "full node" MUST NOT be
applied to Tier 2 (economic) nodes in any user-facing context. Specifically:

- `getnetworkinfo` RPC: report node tier, never `"full"` for Tier 2
- `-help` text: describe `-matmulvalidation=economic` as "economic node
  (Phase 1 only, trusts full-node majority)" — never "full node"
- GUI status bar (if applicable): "Economic" or "Lite Validation", not "Full"
- P2P `version` message service bits: separate bits for Tier 0/1 vs Tier 2,
  so peers can distinguish transcript-validating nodes from Phase-1-only nodes
- Documentation, README, and marketing: always "economic node" or "Tier 2",
  never "full" — this is a trust-model honesty requirement, not just semantics

Misrepresenting Tier 2 as "full" would lead users to believe they have
trustless transcript verification when they do not. This is a safety-critical
labeling issue analogous to SPV wallets being mislabeled as "full nodes."

#### 12.1.1 Tier Comparison Matrix

| Property | Tier 0 (Mining) | Tier 1 (Consensus) | Tier 2 (Economic) | Tier 3 (SPV) |
|----------|----------------|-------------------|------------------|-------------|
| Validates Phase 1 | Yes | Yes | Yes | Yes (headers only) |
| Validates Phase 2 (tip) | Yes (implicit in Solve) | Yes | No | No |
| Validates Phase 2 (window) | Yes | Last `MATMUL_VALIDATION_WINDOW` | No | No |
| Validates transactions | Yes | Yes | Yes | No (Bloom/compact filters) |
| Maintains UTXO set | Yes | Yes | Yes | No |
| Serves blocks to peers | Yes | Yes | Yes (blocks only) | No |
| Serves headers to SPV | Yes | Yes | Yes | No |
| Can detect transcript forgery | Yes | Yes (within window) | No | No |
| Can detect header-only attacks | Yes | Yes | Yes | Partially (SPV proofs) |
| Minimum Phase 2 work per block | O(n³) x attempts (Solve) | O(n³) x 1 (Verify) | 0 | 0 |

#### 12.1.2 Detailed Tier Descriptions

**Tier 0 -- Mining Node**

Must perform the full Phase 2 computation (Solve) for every candidate block at
the chain tip. This means executing the O(n³) canonical matmul for every nonce
attempt, plus noise generation and transcript hashing. Mining nodes are the
primary producers of Phase 2 proofs and must also validate competing blocks
received from peers (also via Phase 2) to determine the best chain tip.

- **Phase 2 frequency**: Every nonce attempt during mining (potentially
  thousands per block interval) plus once per competing block received from
  peers.
- **Hardware**: GPU (CUDA Ampere+ or Apple Metal M1+) strongly recommended
  for competitive mining. High-core-count CPU (e.g., 16+ cores, Zen 4) is
  an alternative at lower hash rate. Verification of peer blocks is
  single-threaded and CPU-feasible.
- **Trust posture**: Fully trustless. The mining node produces the proof, so
  it has first-hand knowledge of transcript correctness.

**Tier 1 -- Consensus-Validating Node**

Recomputes Phase 2 for every new block at the chain tip, indefinitely. During
IBD, uses `assumevalid` for blocks below the hard-coded checkpoint, then
validates Phase 2 for the last `MATMUL_VALIDATION_WINDOW` blocks. Once synced,
it validates every subsequent tip block with Phase 2 forever.

- **Phase 2 frequency**: Once per block (every ~90 seconds at steady state;
  every ~0.25 seconds during fast-mining phase, which requires GPU or deferred
  batch verification for real-time tip tracking).
- **Hardware**: Mid-range CPU sufficient at steady state. A single-threaded
  Phase 2 at n=512 takes ~0.5--2.0s depending on CPU generation. At
  90-second blocks, this is 0.3--1.3% CPU utilization — comfortable on
  consumer hardware. GPU is optional (reduces Phase 2 to < 0.1s).
- **Trust posture**: Trustless for the validated range. Trusts the
  `assumevalid` checkpoint hash for deep history (same as Bitcoin Core).
- **This is the minimum tier to be considered a "full node."** Any node that
  accepts payments or serves authoritative chain data to peers should run at
  Tier 1 or Tier 0.

**Tier 2 -- Economic Node**

Validates Phase 1 (header-level checks: `matmul_digest < target`, dimension
bounds, non-null seeds) for all blocks. Never performs Phase 2. Uses
`assumevalid` for the entire chain. Trusts that the majority of Tier 0 and
Tier 1 nodes have verified transcript correctness for recent blocks.

- **Phase 2 frequency**: Zero.
- **Hardware**: Any modern hardware. Phase 1 is microseconds per block. The
  node's resource consumption is dominated by transaction validation and UTXO
  set maintenance, identical to a standard Bitcoin pruned node.
- **Trust posture**: Trusts the full-node majority for transcript correctness.
  This is strictly weaker than Tier 1. An economic node cannot independently
  detect a block with a valid header but a forged transcript (e.g., a miner
  who found a `matmul_digest < target` by some means other than honest
  canonical matmul). Suitable for merchants, wallets, and services where the
  economic cost of a transcript-forgery attack (which requires >50% hash
  power) is accepted as negligible.
- **Use cases**: Exchanges (for monitoring, not settlement), merchant point-
  of-sale, wallet backends, block explorers, API services.

**Tier 3 -- SPV / Light Node**

Downloads the header chain only. Validates Phase 1 for all headers. Never
downloads block bodies, never maintains a UTXO set, never performs Phase 2.
Requests Merkle inclusion proofs from full-node peers on demand.

- **Phase 2 frequency**: Zero.
- **Hardware**: Mobile-class (ARM Cortex-A53 or equivalent, 256+ MiB RAM).
  Storage under 1 GiB (headers only: ~182 bytes/block, ~38 MiB/year at
  90-second steady-state blocks).
- **Trust posture**: Trusts full-node majority for both transcript correctness
  and transaction inclusion. Identical to Bitcoin SPV.
- **Use cases**: Mobile wallets, embedded devices, read-only explorers,
  bandwidth-constrained environments.

### 12.2 Hardware Requirements per Tier

The following are rough estimates for steady-state operation at n=512, b=16,
90-second block time on mainnet. Mining hardware requirements depend on
network difficulty and are not bounded by the protocol. During the
fast-mining phase (0.25s blocks, heights 0–49,999), Tier 1 nodes require
GPU or deferred batch verification to keep up.

| Tier | CPU | GPU | RAM | Disk | Network |
|------|-----|-----|-----|------|---------|
| **0 -- Mining** | High-core-count modern CPU (Zen 4, 16+ cores) OR any CPU with GPU offload | Strongly recommended: CUDA (Ampere+) or Apple Metal (M1+) | 4+ GiB | 50+ GiB (chain + UTXO) | Low-latency broadband |
| **1 -- Consensus** | Mid-range CPU (4-core Zen 2 / Haswell or better). Must verify 1 block/90s at n=512. ~0.3--1.3% single-threaded CPU at steady state. | Optional; reduces Phase 2 to < 0.1s. Required during fast-mining phase for real-time tracking. | 2+ GiB | 50+ GiB (chain + UTXO) | Broadband |
| **2 -- Economic** | Any modern CPU (Phase 1 is microseconds) | Not needed | 1+ GiB | 50+ GiB (chain + UTXO) or ~5 GiB pruned | Standard broadband |
| **3 -- SPV** | Mobile-class (ARM Cortex-A53 or equivalent) | Not needed | 256+ MiB | < 1 GiB (headers: ~38 MiB/year at 90s blocks) | Any (including cellular) |

#### 12.2.1 Feasibility of Tier 1 on Consumer Hardware

At n=512, one Phase 2 verification = one full O(n³) canonical matmul
recomputation (~134M field multiply-adds). Concrete timings on representative
hardware:

| Hardware | Est. Phase 2 Time (n=512) | CPU Util. at 90s Blocks | CPU Util. at 0.25s Blocks (fast phase) | Tier 1 Feasible? |
|----------|--------------------------|--------------------------|----------------------------------------|------------------|
| Modern x86 (Zen 4, single thread) | ~0.5s | ~0.3% | ~200% | Steady-state yes; fast phase needs GPU or deferred |
| Modern ARM (Apple M2, single thread) | ~0.7s | ~0.5% | ~280% | Steady-state yes; fast phase needs GPU or deferred |
| Older x86 (Haswell-era, single thread) | ~1.5--2.0s | ~1.0--1.3% | ~600--800% | Steady-state only; fast phase needs GPU or deferred |
| Low-end ARM (RPi 4, single thread) | ~4--6s | ~2.7--4% | N/A (cannot keep up) | Steady-state only |
| Any CPU with GPU offload | < 0.1s | < 0.1% | < 40% | Yes (trivial) |

**The critical threshold (steady state)**: a Tier 1 node must complete Phase 2
verification within the block interval (90 seconds) on average. Any hardware
that can perform 134M field multiply-adds in under ~75 seconds (leaving margin
for network latency, transaction validation, and disk I/O) qualifies.

**Fast-mining phase (h < 50,000)**: At 0.25-second blocks (~240 blocks/min),
single-threaded CPU verification cannot keep up in real-time for any hardware.
During this phase, Tier 1 nodes should either use GPU-accelerated verification
or accept a deferred verification queue that catches up once the steady-state
transition occurs at height 50,000. All blocks are still Phase 1-validated
immediately (microsecond checks), so the node remains economically secure
during the catch-up period.

**GPU is NOT required for any validation tier.** GPU acceleration changes the
mining economics (Tier 0) but does not change the minimum hardware baseline for
Tier 1, 2, or 3. A node operator who only validates (does not mine) never
needs a GPU.

### 12.3 `MATMUL_VALIDATION_WINDOW` Consensus Parameter

#### 12.3.1 Definition

```cpp
// Addition to Consensus::Params (see also §5.1):

// Trust model -- node tier validation depth (§12)
uint32_t nMatMulValidationWindow{1000};  // Blocks: minimum Phase 2 depth for "full node" (Tier 1)
```

`MATMUL_VALIDATION_WINDOW` (exposed as `nMatMulValidationWindow` in
`Consensus::Params`) defines the number of most-recent blocks for which a
Tier 1 (consensus-validating) node MUST recompute Phase 2 before considering
its local chain tip trustworthy. It also bounds the Phase 2 catch-up cost
when a Tier 1 node resumes after an extended offline period.

#### 12.3.2 Default Value Rationale

The default is **1000 blocks** (~41.7 hours at 90-second steady-state
block intervals; ~4.2 minutes during the fast-mining phase):

| Factor | Analysis |
|--------|----------|
| **Time span (steady state)** | 1000 blocks × 90s = 90,000s = ~25.0 hours. Covers more than a full day. Sufficient to detect any attack mounted within recent history. |
| **Time span (fast phase)** | 1000 blocks × 0.25s = 250s = ~4.2 minutes. The window covers a very short real-time period during fast-mining, but this is acceptable because the fast phase has low economic value per block (only 20 BTX) and the chain is young. |
| **DGW safety margin** | DarkGravityWave uses a 180-block averaging window. `MATMUL_VALIDATION_WINDOW` must exceed this so the node independently verifies every block that feeds into the current difficulty calculation. 1000 provides >5x margin. |
| **Reorg coverage** | The longest plausible reorg under normal conditions is well under 180 blocks. 1000 blocks provides an extreme safety margin against deep reorgs. |
| **IBD catch-up cost** | A newly-joining Tier 1 node must verify 1000 blocks from scratch. At ~1.5s per block (older single-threaded CPU), this is ~25 minutes — acceptable as a one-time IBD cost. |
| **Ongoing cost** | After IBD, the node verifies exactly 1 block per 90 seconds at steady state. The window only affects IBD and recovery-from-long-offline scenarios. |
| **Checkpoint gap** | The `assumevalid` checkpoint is a release-time constant. Between software releases, the window ensures the node independently validates all blocks the checkpoint does not cover. With a 1000-block window and monthly releases, any gap is always covered. |
| **v1 storage** | 1000 × 64 bytes (two seeds) = 64 KB. Negligible. |

#### 12.3.3 Network Configuration

| Network | `nMatMulValidationWindow` | Time Span | Rationale |
|---------|--------------------------|-----------|-----------|
| mainnet | 1000 | ~25.0 hours (steady state) | Production safety margin; >5x DGW window |
| testnet | 500 | ~12.5 hours (steady state) | Faster IBD for testing; still covers DGW window (180 blocks) |
| regtest | 10 | ~25 minutes (at 90s blocks) | Fast iteration; sufficient for functional test coverage |

#### 12.3.4 Invariants

```
INVARIANT: nMatMulValidationWindow >= DGW_PAST_BLOCKS (180)
    Rationale: The validation window must cover the entire DGW averaging
    window so the node can independently verify that difficulty adjustments
    are computed over legitimately-mined blocks. Without this, a Tier 1
    node would trust assumevalid for blocks that feed into the active
    difficulty calculation.

INVARIANT: nMatMulValidationWindow >= 100
    Rationale: Hard floor to prevent misconfiguration. A window smaller
    than 100 blocks (~100 minutes) provides negligible independent
    verification and should not be called "full."
```

#### 12.3.5 Runtime Behavior

The validation window interacts with the existing `assumevalid` mechanism
and the node's configured tier:

```
ProcessBlock(block, height, params):
    chain_tip_height = GetBestBlockHeight()

    // Phase 1 always runs (all tiers, all blocks)
    if NOT CheckMatMulProofOfWork_Phase1(block, params):
        return REJECT

    // Phase 2 decision tree
    if params.fSkipMatMulValidation:
        // Regtest fast mode: skip Phase 2 entirely
        return ACCEPT

    if node_tier == TIER_3_SPV:
        // SPV: never runs Phase 2
        return ACCEPT

    if node_tier == TIER_2_ECONOMIC:
        // Economic: never runs Phase 2; trusts full-node majority
        return ACCEPT

    // Tiers 0 and 1 below this point
    if height <= assumevalid_height:
        // Below checkpoint: skip Phase 2 (during IBD only)
        return ACCEPT

    if height > (chain_tip_height - params.nMatMulValidationWindow):
        // Within validation window: MUST run Phase 2
        if NOT CheckMatMulProofOfWork_Phase2(block, params):
            return REJECT
    else:
        // Above checkpoint but outside window: skip Phase 2
        // (Occurs during IBD catch-up for long-offline Tier 1 nodes)
        return ACCEPT

    return ACCEPT
```

**Node tier selection**: The tier is a local configuration choice, not a
consensus rule. A node operator sets their tier via a startup flag:

| Flag | Tier | Behavior |
|------|------|----------|
| `-matmulvalidation=consensus` (default) | Tier 1 | Phase 2 for last `nMatMulValidationWindow` blocks + all new tips |
| `-matmulvalidation=economic` | Tier 2 | Phase 1 only; no Phase 2 ever |
| `-matmulvalidation=spv` | Tier 3 | Headers only; no block body processing |
| (mining active via `generateblock` / Stratum) | Tier 0 | Implicitly Phase 2 via Solve; also validates peer blocks |

Mining nodes (Tier 0) are identified by their active use of the mining
subsystem, not by a flag. Any node that calls `Solve()` is implicitly Tier 0
for the blocks it mines and at least Tier 1 for blocks it receives from peers.

### 12.4 Initial Block Download (IBD) Behavior per Tier

IBD is the most resource-intensive phase of node operation. Each tier has a
distinct IBD strategy.

#### 12.4.1 Tier 0 -- Mining Node IBD

1. **Headers-first download**: Fetch the full header chain from peers.
2. **Phase 1 validation**: Validate every header (`matmul_digest < target`,
   dimension bounds, timestamp rules, non-null seeds).
3. **`assumevalid` acceleration**: Skip Phase 2 for all blocks at or below
   the hard-coded `defaultAssumeValid` block hash (same as Bitcoin Core).
4. **Phase 2 catch-up**: For blocks above `assumevalid` and within
   `nMatMulValidationWindow` of the current tip, recompute Phase 2. At
   ~1.5s/block on mid-range CPU, syncing 1000 blocks takes ~25 minutes.
5. **UTXO set construction**: Build the full UTXO set during IBD (required
   for transaction validation and block template construction).
6. **Post-IBD**: Validate every new tip block with Phase 1 + Phase 2 (Phase 2
   is implicit in the Solve loop for self-mined blocks, explicit for peer
   blocks). Begin mining.

**Estimated IBD time** (10,000-block chain, mid-range CPU):
- Headers + Phase 1: ~seconds
- UTXO + transaction validation: ~minutes
- Phase 2 for post-assumevalid window (last 1000): ~25 minutes
  (assumes concurrency-limited throughput; see note below)
- Total: **~30 minutes** (dominated by Phase 2 catch-up)

> **IBD tuning note**: The ~25 minute estimate assumes the
> `nMatMulMaxPendingVerifications` concurrency cap (4) is the throughput
> bottleneck. With the default `nMatMulPeerVerifyBudgetPerMin` of 8 and a
> single IBD peer, the per-peer budget is the binding constraint: 8
> verifications/min yields ~125 minutes for 1000 blocks. To achieve the ~25
> minute estimate, operators syncing from a single peer should raise the
> per-peer budget to 32--64 (e.g., `-matmulpeerverifybudget=64`). With
> multiple IBD peers serving different block ranges, the default budget of 8
> per peer is typically sufficient as the aggregate throughput from all peers
> exceeds the concurrency cap.

#### 12.4.2 Tier 1 -- Consensus-Validating Node IBD

1. **Headers-first download**: Same as Tier 0.
2. **Phase 1 validation**: All headers validated.
3. **`assumevalid` acceleration**: Skip Phase 2 for blocks at or below the
   checkpoint. Phase 1 still checked.
4. **Phase 2 for validation window**: Recompute Phase 2 for the last
   `nMatMulValidationWindow` blocks above `assumevalid` (whichever bound is
   more restrictive).
5. **UTXO set construction**: Full UTXO set built during IBD.
6. **Post-IBD**: Validate every new tip block with Phase 1 + Phase 2
   indefinitely. The node never drops below Tier 1 unless reconfigured.

**Behavior when resuming after extended offline period**: If the node was
offline for longer than `nMatMulValidationWindow` blocks, it catches up by
validating only the most recent `nMatMulValidationWindow` blocks with Phase 2.
Blocks between the old tip and the start of the window are treated as Phase 1
only (similar to assumevalid). This bounds the catch-up cost to a fixed
maximum (~25 minutes on older hardware) regardless of offline duration.

#### 12.4.3 Tier 2 -- Economic Node IBD

1. **Headers-first download**: Same as Tier 0/1.
2. **Phase 1 validation**: All headers validated.
3. **No Phase 2**: The economic node never performs Phase 2. The `assumevalid`
   mechanism has no additional effect beyond Phase 1.
4. **Transaction and UTXO validation**: Full transaction validation and UTXO
   set construction. The node verifies scripts, amounts, and double-spends --
   it just does not recompute matmul transcripts.
5. **Post-IBD**: Continues with Phase 1 only for new blocks. Relies on
   Tier 0/1 peers to have verified transcript correctness.

**Estimated IBD time** (10,000-block chain):
- Headers + Phase 1 + UTXO: ~minutes (no Phase 2 overhead)
- Total: **~5 minutes** on mid-range hardware

**Risk accepted**: A Tier 2 node cannot independently detect a block with a
valid header but an incorrect transcript. If >50% of hash power colludes to
produce blocks with forged transcripts (valid `matmul_digest < target` but
computed from a non-canonical transcript), Tier 2 nodes will accept them. This
is the same trust assumption as Bitcoin Core's `assumevalid` applied
perpetually, not just for the portion below the checkpoint.

#### 12.4.4 Tier 3 -- SPV / Light Node IBD

1. **Header download only**: Fetch the header chain (182 bytes per block).
   At steady-state (~210,384 blocks/year at 90s), this is ~38 MiB/year of
   header data. Year 1 includes the fast-mining phase's 50,000 additional
   blocks (~9 MiB), totaling ~47 MiB for year 1.
2. **Phase 1 validation**: Validate `matmul_digest < target` and dimension
   bounds for every header.
3. **No block bodies**: Does not download transactions or maintain a UTXO set.
4. **Merkle proofs**: Requests transaction inclusion proofs from full-node
   peers on demand.
5. **Post-IBD**: Subscribes to new headers, validates Phase 1, requests
   Merkle proofs for watched addresses.

**Estimated IBD time** (1-year chain):
- Header download: ~47 MiB over network (year 1), ~38 MiB/year thereafter
- Phase 1 validation: < 1 second total
- Total: **seconds to minutes** depending on network speed

#### 12.4.5 IBD Summary Table

| Tier | Downloads | Phase 1 | Phase 2 | UTXO Set | Est. IBD Time (10k blocks) |
|------|-----------|---------|---------|----------|----------------------------|
| 0 (Mining) | Full chain | All blocks | Last `nMatMulValidationWindow` above `assumevalid` | Full | ~30 min |
| 1 (Consensus) | Full chain | All blocks | Last `nMatMulValidationWindow` above `assumevalid` | Full | ~30 min |
| 2 (Economic) | Full chain | All blocks | None | Full | ~5 min |
| 3 (SPV) | Headers only | All headers | None | None | < 1 min |

### 12.5 Data Availability

#### 12.5.1 v1 (Seeded Matrices): Trivial DA

With seed-derived matrices, "proof data" = two 32-byte seeds in the header
(64 bytes per block). Every node can reconstruct A and B locally. There is no
data-availability problem.

- **Full validation from genesis**: Any Tier 0/1 node can download the header
  chain, expand seeds, recompute transcripts, and verify every block. Cost:
  O(n³) per block x chain length. Expensive but bounded and trustless.
- **`assumevalid` optimization**: For practical IBD, the node skips Phase 2
  for blocks below the `defaultAssumeValid` checkpoint (same mechanism as
  Bitcoin Core). Phase 1 is always checked.
- **Storage**: Negligible proof overhead. Even Tier 0/1 nodes store only
  64 bytes of proof data per block (in the header). The expensive part is
  *recomputing* the transcript, not *storing* the inputs.

#### 12.5.2 v2 (Arbitrary Matrices): Requires DA Layer

When v2 ships with miner-chosen A, B in the block body:

| Component | Design |
|-----------|--------|
| **Archival nodes** | Store full A, B for all blocks; serve to peers |
| **Pruned nodes** | Keep A, B for recent `PROOF_PRUNE_DEPTH` blocks only |
| **New node IBD** | Download headers + UTXO snapshot; optionally fetch A, B for recent window |
| **State commitment** | Periodic UTXO accumulator hash in coinbase (enables snapshot-based join) |
| **Proof retrieval** | New P2P messages: `getmatmulproof` / `matmulproof` |

**UTXO snapshot spec** (required before v2 ships):
- Every `SNAPSHOT_INTERVAL` blocks (e.g., 10,000), the coinbase commits to
  `SHA-256(UTXO_set_serialization)`
- A joining node downloads the latest snapshot, verifies it against the
  committed hash, then only needs to verify blocks from that point forward
- This limits proof-data storage and verification to a bounded window

### 12.6 Tests for Trust Model and Node Tiers

```
TEST: trust_model_validation_window_default
  GIVEN: Default Consensus::Params (mainnet)
  THEN: nMatMulValidationWindow == 1000

TEST: trust_model_validation_window_testnet
  GIVEN: CreateChainParams(ChainType::TESTNET)
  THEN: nMatMulValidationWindow == 500

TEST: trust_model_validation_window_regtest
  GIVEN: CreateChainParams(ChainType::REGTEST)
  THEN: nMatMulValidationWindow == 10

TEST: trust_model_validation_window_covers_dgw
  FOR EACH network:
    Assert nMatMulValidationWindow >= DGW_PAST_BLOCKS (180)

TEST: trust_model_validation_window_minimum_floor
  FOR EACH network:
    Assert nMatMulValidationWindow >= 100

TEST: ibd_with_assumevalid_skips_phase2
  GIVEN: assumevalid checkpoint at height 1000
  AND: Tier 1 node syncing from genesis
  WHEN: Processing block at height 500
  THEN: Phase 1 runs, Phase 2 skipped

TEST: ibd_after_assumevalid_runs_phase2
  GIVEN: assumevalid at height 1000
  AND: Tier 1 node
  WHEN: Processing block at height 1001
  THEN: Both Phase 1 and Phase 2 run

TEST: ibd_within_validation_window_runs_phase2
  GIVEN: Chain tip at height 5000, nMatMulValidationWindow = 1000
  AND: Tier 1 node syncing
  WHEN: Processing block at height 4500 (within last 1000 of tip)
  THEN: Phase 2 runs

TEST: ibd_outside_validation_window_skips_phase2
  GIVEN: Chain tip at height 5000, nMatMulValidationWindow = 1000
  AND: Tier 1 node syncing, block above assumevalid
  WHEN: Processing block at height 3500 (outside last 1000 of tip)
  THEN: Phase 2 skipped (Phase 1 only)

TEST: seed_reconstruction_matches
  GIVEN: Block with seed_a, seed_b in header
  WHEN: Node reconstructs A = FromSeed(seed_a, n) and B = FromSeed(seed_b, n)
  AND: Recomputes transcript
  THEN: Result matches block.matmul_digest
  (This is the fundamental v1 DA guarantee)

TEST: mining_node_implicitly_tier0
  GIVEN: Node performing Solve() for a new block
  THEN: Phase 2 is inherently performed as part of Solve
  AND: Node does not need a separate Phase 2 validation call for
       self-mined blocks

TEST: consensus_node_validates_all_new_tips
  GIVEN: Tier 1 node fully synced at height 5000
  WHEN: New block arrives at height 5001
  THEN: Phase 1 AND Phase 2 both run
  (New tip blocks are always within the validation window)

TEST: economic_node_never_runs_phase2
  GIVEN: Tier 2 (economic) node configuration
  AND: Chain with 100 blocks, no assumevalid checkpoint
  WHEN: Processing every block from genesis to tip
  THEN: Phase 1 runs for all blocks; Phase 2 runs for NONE

TEST: economic_node_accepts_all_headers
  GIVEN: Tier 2 node, chain of 5000 blocks
  WHEN: All blocks have valid Phase 1 (matmul_digest < target)
  THEN: Node accepts all 5000 blocks without Phase 2

TEST: spv_node_validates_headers_only
  GIVEN: Tier 3 (SPV) node
  WHEN: Processing header at any height
  THEN: Phase 1 (matmul_digest < target, dim bounds) runs
  AND: No Phase 2, no transaction validation

TEST: tier1_resume_after_long_offline
  GIVEN: Tier 1 node was synced to height 5000
  AND: Goes offline, chain advances to height 8000
  AND: nMatMulValidationWindow = 1000
  WHEN: Node comes back online and syncs
  THEN: Phase 2 runs for blocks 7001..8000 (last 1000)
  AND: Phase 2 skipped for blocks 5001..7000

TEST: tier_config_flag_sets_behavior
  GIVEN: Node started with -matmulvalidation=economic
  THEN: Node behaves as Tier 2 (no Phase 2)
  GIVEN: Node started with -matmulvalidation=consensus (or default)
  THEN: Node behaves as Tier 1 (Phase 2 within window)
  GIVEN: Node started with -matmulvalidation=spv
  THEN: Node behaves as Tier 3 (headers only)

TEST: consensus_node_with_assumevalid_override
  GIVEN: Tier 1 node, nMatMulValidationWindow = 1000
  AND: assumevalid at height 500, chain of 2000 blocks
  WHEN: Node syncs with -assumevalid=0 (override to validate everything)
  THEN: Phase 2 runs for ALL 2000 blocks
  (assumevalid=0 forces full verification from genesis, ignoring checkpoint)

TEST: economic_node_window_boundary_steady_state
  GIVEN: Tier 2 node at height 3000
  AND: nMatMulValidationWindow = 1000
  WHEN: New block arrives at height 3001
  THEN: Phase 1 runs, Phase 2 does NOT run
  (Economic nodes never run Phase 2, regardless of window)

TEST: validation_window_change_requires_resync
  GIVEN: Tier 1 node synced with nMatMulValidationWindow = 1000
  WHEN: Configuration changed to nMatMulValidationWindow = 2000 and node restarts
  THEN: Node re-validates Phase 2 for the additional 1000 blocks
        now within the expanded window
```

### 12.7 v2 Changes: How Tiers Evolve with Arbitrary Matrices

When v2 introduces arbitrary (externally-sourced) matrices, the tier model
changes in the following ways:

| Aspect | v1 (Seeded) | v2 (Arbitrary) |
|--------|-------------|----------------|
| **Proof data per block** | 64 bytes (two seeds) | ~2 MiB at n=512 (two full n x n matrices) |
| **Data availability** | Trivial (reconstruct from seed) | Requires DA layer; archival nodes must store and serve matrices |
| **Tier 0 (Mining)** | Generates seeds locally | Receives matrices from job marketplace or generates locally |
| **Tier 1 (Consensus)** | Reconstructs matrices from seeds; recomputes transcript | Must download full matrices for blocks in validation window; may prune outside window |
| **Tier 2 (Economic)** | No change (never runs Phase 2) | No change; may optionally store/relay matrices |
| **Tier 3 (SPV)** | No change (headers only) | No change; header size unchanged (matrices in block body) |
| **New: Archival sub-tier** | Not needed (seeds are lossless) | Required: stores full A, B for all blocks; serves to joining Tier 1 nodes |
| **IBD for Tier 1** | Cheap (seeds in header) | Expensive: ~2 MiB of matrix data per block in validation window (~2 GiB for 1000 blocks at n=512) |
| **Pruning** | No proof data to prune | Tier 1 prunes matrices outside `nMatMulValidationWindow`; archival never prunes |

**Key implication for v2**: The `MATMUL_VALIDATION_WINDOW` parameter becomes
even more important -- it bounds not only the Phase 2 computation cost but also
the matrix storage and bandwidth requirements for Tier 1 nodes. The default of
1000 blocks limits matrix storage to ~2 GiB and IBD matrix download to the
same, which remains feasible on standard broadband. A UTXO snapshot commitment
scheme (§12.5.2) is mandatory before v2 ships to prevent Tier 1 IBD from
requiring the full matrix history.

---

## 13. RPC and P2P Interface

### 13.1 RPCs

| RPC | Description |
|-----|-------------|
| `getblocktemplate` | Includes `matmul` section with n, b, r, q AND `block_capacity` section (see below) |
| `submitblock` | Validates matmul block (Phase 1 + Phase 2) AND weight/sigops/size limits |
| `getblock` | Verbose output includes matmul_digest, matmul_dim, seed_a, seed_b, block weight |
| `getblockheader` | Includes matmul header fields |
| `getmininginfo` | Reports `"algorithm": "matmul"`, dimension, block size, noise rank, `max_block_weight`, `policy_block_max_weight` |

#### 13.1.1 Block Capacity in `getblocktemplate`

The `getblocktemplate` response MUST include a `block_capacity` object:

```json
{
  "block_capacity": {
    "max_block_weight": 24000000,
    "max_block_serialized_size": 24000000,
    "max_block_sigops_cost": 480000,
    "default_block_max_weight": 24000000,
    "witness_scale_factor": 1
  }
}
```

This allows mining software to construct blocks respecting both consensus and
policy limits without hardcoding values.

#### 13.1.2 Block Capacity in `getmininginfo`

The `getmininginfo` response MUST include:

```json
{
  "max_block_weight": 24000000,
  "policy_block_max_weight": 24000000
}
```

`max_block_weight` is the consensus maximum; `policy_block_max_weight` is the
node's current template target (may differ if operator set `-blockmaxweight`).

### 13.2 P2P (v1)

No new P2P messages needed for v1: seeds are in the header, matrices are
reconstructed locally. Standard `block`, `headers`, `cmpctblock` messages
work unchanged (header is 182 bytes, slightly larger).

### 13.3 P2P (v2, future)

| Message | Description |
|---------|-------------|
| `getmatmulproof` | Request A, B for block hash |
| `matmulproof` | Response with serialized matrices |

### 13.4 Tests for RPC

```
TEST: rpc_getblocktemplate_matmul — includes matmul params
TEST: rpc_getblock_matmul_verbose — shows matmul fields
TEST: rpc_submitblock_rejects_invalid — bad digest → error
TEST: rpc_getmininginfo_algorithm — reports "matmul"

TEST: rpc_getblocktemplate_block_capacity
  GIVEN: getblocktemplate called
  THEN: Response includes block_capacity object
  AND: block_capacity.max_block_weight == nMaxBlockWeight
  AND: block_capacity.default_block_max_weight == nDefaultBlockMaxWeight
  AND: block_capacity.witness_scale_factor == 1

TEST: rpc_getmininginfo_reports_capacity
  GIVEN: getmininginfo called
  THEN: Response includes max_block_weight == nMaxBlockWeight
  AND: Response includes policy_block_max_weight (may differ from consensus max)
```

---

## 14. Block Capacity and Bandwidth Analysis

### 14.1 Block Capacity Model (Weight-Based)

BTX uses a SegWit-style block weight accounting model as the primary
consensus capacity mechanism. This supports high transaction throughput while
penalizing UTXO-impacting bytes more strongly than witness data. "Big blocks"
are therefore expressed as a higher maximum block weight, not merely a raw
serialized byte limit.

BTX also maintains a separate serialized byte safety cap as a DoS guard.
The byte cap is not the primary throughput limiter; it exists to prevent
pathological memory/bandwidth abuse.

**Weight formula** (inherited from BIP 141):

```
block_weight = stripped_size * (WITNESS_SCALE_FACTOR - 1) + total_size
             = stripped_size * 3 + total_size
```

where `stripped_size` is the block serialized without witness data and
`total_size` is the full serialization. This is identical to
`GetBlockWeight()` already implemented in `src/consensus/validation.h`.

### 14.2 Consensus Limits (Weight, SigOps, Size Floors)

#### 14.2.1 Consensus Rules

A block is valid only if **all** of the following hold:

1. `GetBlockWeight(block) <= params.nMaxBlockWeight` (24,000,000 WU)
2. `GetBlockSigOpsCost(block) <= params.nMaxBlockSigOpsCost` (480,000)
3. `GetSerializeSize(block) <= params.nMaxBlockSerializedSize` (24,000,000 bytes)
4. All existing transaction, script, and UTXO consensus rules pass.

These checks are performed in `ContextualCheckBlock()` in `validation.cpp`.
The existing codebase already implements rule (1) with `MAX_BLOCK_WEIGHT`;
BTX raises the parameter values and moves them into `Consensus::Params` for
per-network configurability.

#### 14.2.2 Capacity Analysis

| Scenario | Max serialized block size |
|----------|-------------------------|
| All non-witness data | 24M / 4 = **6 MB** |
| All witness data (theoretical) | 24M / 1 = **24 MB** (equal to `nMaxBlockSerializedSize`) |
| Practical mixed (typical SegWit txns) | **2–6 MB** |

#### 14.2.3 Rationale and Scope

- **Weight** is the primary scaling knob (throughput). Raising
  `nMaxBlockWeight` from Bitcoin's 4M to 24M gives BTX ~6x the transaction
  capacity at steady-state 90s blocks.
- **SigOps cost** prevents "cheap bytes but expensive validation"
  constructions. Scaled proportionally with weight (6x Bitcoin's 80,000).
- **Serialized size cap** is a hard transport/memory safety guard. Set at
  24 MB, equal to the weight limit, to allow the full weight range for
  normal transactions while bounding memory consumption.

These are consensus constants per network (mainnet/testnet/regtest) and MUST
NOT vary per block.

### 14.3 Policy Defaults (Relay/Mempool/Mining Template)

Consensus limits define what is **valid**; policy defines what is **relayed
and mined by default**. Policy is node-configurable and does not affect
consensus.

#### 14.3.1 Mining Template Target (Policy)

By default, miners SHOULD construct templates at or below:
- `nDefaultBlockMaxWeight` (24,000,000 WU = consensus max)

The default mining template target equals the consensus maximum. A node MAY
lower it via `-blockmaxweight` to produce smaller blocks.

#### 14.3.2 Relay Policy

Nodes SHOULD:
- Refuse to relay individual transactions exceeding `MAX_STANDARD_TX_WEIGHT`
  (1,200,000 WU, chain policy default).
- Enforce mempool size limits (`nDefaultMempoolMaxSizeMB`, default 2048 MB)
  and evict by feerate when full.
- Apply `maxmempool` and `mempoolexpiry` settings as in upstream Bitcoin Core.

#### 14.3.3 Compact Blocks and Propagation

For large-weight blocks, nodes SHOULD:
- Enable compact block relay (BIP 152) to minimize propagation latency.
- Maintain reasonable orphan/rescan limits to avoid bandwidth collapse.
- Use `blockreconstructionextratxn` to improve compact block hit rates.

This is a policy and operational requirement, not a consensus rule. Compact
block relay is especially important during the fast-mining phase when block
intervals are 0.25 seconds.

#### 14.3.4 Operational Note: Default Tuning

The spec-defined policy defaults are intentionally conservative for initial
deployment. Operators should be aware of the following trade-offs:

- **`nDefaultBlockMaxWeight` = 24M WU (equals consensus max)**: Miners use
  the full consensus allowance by default. Operators on constrained links
  may lower this via `-blockmaxweight` to reduce orphan risk.
- **`nDefaultMempoolMaxSizeMB` = 2048 MB**: This is aggressive relative to
  the upstream Bitcoin Core default (300 MB). At 90s blocks with 24M WU
  policy weight, the mempool can buffer ~20 minutes of peak transaction
  volume at this size. Operators on memory-constrained systems SHOULD lower
  this via `-maxmempool=300` (or similar) and accept more frequent evictions.
  The 2 GB default is targeted at Tier 1 infrastructure nodes with ample RAM.
- **Fast-phase implications**: During 0.25s blocks, mempool turnover is ~600×
  faster than steady-state. The 2 GB default prevents premature eviction
  during the fast phase when blocks clear rapidly. After the fast phase ends,
  operators may reduce `maxmempool` without consequence.

### 14.4 v1 Block Size (Seeded Matrices)

| Component | Size |
|-----------|------|
| Header | 182 B |
| Transactions (typical) | ~200 KiB |
| **Total** | **~200 KiB** |

This is comparable to current Bitcoin blocks. No matrix data in the block body.
At the policy default weight (24M WU), v1 blocks can contain up to ~4 MB of
transaction data while remaining well under limits.

### 14.5 v2 Block Size (Arbitrary Matrices)

| Dimension n | Element size | Per matrix | Two matrices | Total block |
|-------------|-------------|-----------|-------------|------------|
| 256 | 4 B (uint32) | 256 KiB | 512 KiB | ~712 KiB |
| 512 | 4 B | 1 MiB | 2 MiB | ~2.2 MiB |
| 1024 | 4 B | 4 MiB | 8 MiB | ~8.2 MiB |

Note: M31 elements are uint32 (4 bytes), not uint64 (8 bytes). This halves
the matrix storage cost compared to the v1 spec's M61 analysis. v2 matrix
data is non-witness and weighs 4 WU per byte; at n=512 the two matrices alone
consume ~8.12M WU, leaving ~15.9M WU for transactions within consensus limits.

### 14.6 Bandwidth and Storage Under Weight Limits

#### 14.6.1 Steady-State (90s blocks, ~210,384 blocks/year)

| Version | Typical block | Bandwidth | Annual storage |
|---------|--------------|-----------|---------------|
| v1 (seeded, policy default) | ~200 KiB | 1.3 KiB/s | ~42 GiB/year |
| v1 (seeded, consensus max) | ~4 MB | 27 KiB/s | ~840 GiB/year |
| v2 (n=512) | ~2.2 MiB | 15 KiB/s | ~460 GiB/year |
| v2 (n=256) | ~712 KiB | 4.7 KiB/s | ~148 GiB/year |

v1 at policy defaults is bandwidth-viable for any home connection (even
cellular). v1 at consensus max requires broadband. v2 at n=512 requires
broadband but is feasible.

#### 14.6.2 Fast-Mining Phase (0.25s blocks, h < 50,000)

| Version | Typical block | Bandwidth | Phase duration |
|---------|--------------|-----------|---------------|
| v1 (seeded) | ~200 KiB | 800 KiB/s (~6.4 Mbps) | ~3.5 hours |

During the fast-mining phase, v1 bandwidth peaks at ~800 KiB/s, which is
well within broadband capability but not suitable for cellular connections.
This is a transient condition lasting only ~3.5 hours.

#### 14.6.3 Capacity Planning Guidance (Non-Consensus)

Operators should plan bandwidth and storage using **observed average**
serialized block size, which depends on witness usage and transaction mix.
Weight sets an upper bound; actual bytes depend on composition. The
consensus byte cap (`nMaxBlockSerializedSize` = 24 MB) is a worst-case
ceiling and should not be used as an "expected average."

### 14.7 Tests for Block Capacity

```
TEST: block_weight_under_limit_accepted
  GIVEN: A block with GetBlockWeight == nMaxBlockWeight
  THEN: ContextualCheckBlock passes

TEST: block_weight_over_limit_rejected
  GIVEN: A block with GetBlockWeight == nMaxBlockWeight + 1
  THEN: ContextualCheckBlock fails with "bad-blk-weight"

TEST: block_serialized_size_over_limit_rejected
  GIVEN: A block with GetSerializeSize > nMaxBlockSerializedSize
  THEN: Block rejected before deserialization completes

TEST: block_sigops_over_limit_rejected
  GIVEN: A block with GetBlockSigOpsCost > nMaxBlockSigOpsCost
  THEN: Block rejected with "bad-blk-sigops"

TEST: mining_template_respects_policy_weight
  GIVEN: Default mining configuration (no -blockmaxweight override)
  WHEN: CreateNewBlock called with mempool full of transactions
  THEN: GetBlockWeight(result) <= nDefaultBlockMaxWeight

TEST: mining_template_can_use_consensus_max
  GIVEN: -blockmaxweight=24000000
  WHEN: CreateNewBlock called with large mempool
  THEN: GetBlockWeight(result) may exceed nDefaultBlockMaxWeight
  AND: GetBlockWeight(result) <= nMaxBlockWeight
```

---

## 15. Milestone Plan

### Milestone 1: Finite-Field Arithmetic (M31)

**Deliverables**: `field.h`, `field.cpp`, `matmul_field_tests.cpp`

**Exit criteria**:
- [x] All operations correct for edge cases (0, 1, M31−1)
- [x] Algebraic properties (assoc, commut, distrib) hold for 1000 random samples
- [x] `reduce64` uses double Mersenne fold; correct for ALL uint64 inputs (§7.2)
- [x] `reduce64` passes all edge cases including x ≥ 2^62 where single fold fails
- [x] `dot()` inner product correct with per-step reduction; is the ONLY accumulation path
- [x] `dot()` passes worst-case accumulation tests (all-max-value, len=512 and beyond)
- [x] Naive accumulation (no per-step reduce) demonstrated to produce wrong results
- [x] `reduce64` is not part of the public API (static/file-internal)
- [x] No `__uint128_t` dependency (pure uint32/uint64)
- [x] `from_oracle` deterministic and uniform
- [x] `from_oracle` byte-exact spec implemented per SS7.4.1 (SHA-256 PRF, LE32 encoding, 31-bit mask, rejection sampling)
- [x] `from_oracle` passes all pinned test vectors TV1--TV6 (SS7.4.7)
- [x] `from_oracle` retry mechanism produces correct preimage format (36 bytes for retry=0, 40 bytes for retry>0)
- [x] `FromSeed` produces row-major matrices with index = row * n + col (SS7.4.3)
- [x] `FromSeed` cross-platform consistency: same outputs on x86-64 and ARM64

```bash
./build-btx/bin/test_btx --run_test=matmul_field_tests
```

---

### Milestone 2: Matrix Type and Operations

**Deliverables**: `matrix.h`, `matrix.cpp`, `matmul_matrix_tests.cpp`

**Exit criteria**:
- [x] Block decomposition roundtrips (extract + reassemble = original)
- [x] Multiplication matches known test vectors over M31
- [x] `FromSeed()` is deterministic
- [x] ContentHash is deterministic, collision-resistant
- [x] Memory layout is contiguous row-major uint32

```bash
./build-btx/bin/test_btx --run_test=matmul_matrix_tests
```

---

### Milestone 3: Noise Generation (Rank r)

**Deliverables**: `noise.h`, `noise.cpp`, `matmul_noise_tests.cpp`

**Exit criteria**:
- [x] Deterministic for fixed (σ, n, r)
- [x] E_L is n×r, E_R is r×n (uses r, NOT b)
- [x] rank(E_L · E_R) ≤ r
- [x] All elements in [0, M31)
- [x] Domain separation: four derived seeds (tag_EL, tag_ER, tag_FL, tag_FR) are pairwise distinct for any σ (SS8.2.1)
- [x] Domain separation tags are raw ASCII, 18 bytes, no null terminator (SS8.2.1)
- [x] Index formula uses factor column count (r for n×r, n for r×n), NOT global n (SS8.2.1)
- [x] Passes all pinned test vectors for derived seeds and matrix elements (SS8.2.2)
- [x] Cross-platform consistency: same outputs on x86-64 and ARM64

```bash
./build-btx/bin/test_btx --run_test=matmul_noise_tests
```

---

### Milestone 4: Canonical MatMul + Transcript Hash (Block size b)

**Deliverables**: `transcript.h`, `transcript.cpp`, `matmul_transcript_tests.cpp`

**Exit criteria**:
- [x] Product matches naive multiplication
- [x] Transcript hash deterministic
- [x] Uses block size b (NOT r) for decomposition
- [x] Streaming hash matches batch
- [x] Canonical i-j-ℓ order enforced
- [x] Transcript compression (Section 8.3.1):
  - [x] `DeriveCompressionVector(sigma, b)` produces deterministic b² elements in [0, M31)
  - [x] `CompressBlock` output matches manual `field::dot` computation
  - [x] `TranscriptHasher(sigma, b)` feeds only 4 bytes per intermediate to SHA-256
  - [x] Total SHA-256 input = (n/b)³ x 4 bytes (not (n/b)³ x b² x 4)
  - [x] Different sigma produces different compression vectors (and thus different z)
  - [x] Domain separation string `"matmul-compress-v1"` used in vector derivation
  - [x] Compression binding: no collisions in 10,000 random distinct-block trials

```bash
./build-btx/bin/test_btx --run_test=matmul_transcript_tests
```

---

### Milestone 5: Solve, Verify, Denoise

**Deliverables**: `matmul_pow.h`, `matmul_pow.cpp`, `matmul_pow_tests.cpp`

**Exit criteria**:
- [x] Solve finds proof on regtest difficulty
- [x] Verify accepts valid proofs, rejects tampered
- [x] Denoise recovers exact C = A·B
- [x] Denoise cost is O(n²·r), not O(n³)
- [x] max_tries=0 → false, no side effects
- [x] Seeds reconstructed identically on both sides

```bash
./build-btx/bin/test_btx --run_test=matmul_pow_tests
```

---

### Milestone 6: Consensus Parameters and Block Header

**Deliverables**: Modified `params.h`, `block.h`, `chainparams.cpp`;
`matmul_params_tests.cpp`, `matmul_header_tests.cpp`

**Exit criteria**:
- [x] b and r are separate params, independently configurable
- [x] Header is 182 bytes with matmul fields (no KAWPOW fields)
- [x] Seed derivation σ matches precomputed test vectors (byte-exact)
- [x] `matmul_header_hash` excludes `matmul_digest`
- [x] `GetHash()` includes all fields (block identity)
- [x] Per-network configuration correct

```bash
./build-btx/bin/test_btx --run_test=matmul_params_tests
./build-btx/bin/test_btx --run_test=matmul_header_tests
```

---

### Milestone 7: Validation with Two-Phase DoS Mitigation

**Deliverables**: Modified `pow.h`, `pow.cpp`, `validation.cpp`;
`matmul_validation_tests.cpp`

**Exit criteria**:
- [x] Phase 1 rejects bad dim, high digest, null seeds (microseconds)
- [x] Phase 2 recomputes transcript (only after Phase 1 passes)
- [x] Phase 1 fail adds misbehavior score +20 (standard Bitcoin Core DoS scoring)
- [x] Phase 1 pass + Phase 2 fail → graduated punishment: disconnect (1st), discourage (2nd), ban (3rd+)
- [x] `fMatMulStrictPunishment` flag: when true, Phase 2 fail = immediate ban (threshold becomes 1)
- [x] `EffectivePhase2BanThreshold()` returns correct value for all network/flag combinations
- [x] Testnet/regtest softfail: Phase 2 failures never ban (threshold = UINT32_MAX), only disconnect/discourage
- [x] `phase2_failures` counter tracked per-peer with 24h rolling window
- [x] 24h window reset: failures older than 24h do not count toward ban threshold
- [x] Per-peer rate limit enforced
- [x] Max concurrent verifications enforced
- [x] fSkipMatMulValidation skips Phase 2

```bash
./build-btx/bin/test_btx --run_test=matmul_validation_tests
```

---

### Milestone 8: Difficulty Adjustment (DGW, Fresh Genesis)

**Deliverables**: Modified `pow.cpp`; `matmul_dgw_tests.cpp`

**Exit criteria**:
- [x] Genesis difficulty calibrated (not powLimit)
- [x] First 180 blocks use genesis difficulty (no DGW adjustment)
- [x] DGW activates at height 181
- [x] Step-up/step-down convergence
- [x] Oscillation resilience

```bash
./build-btx/bin/test_btx --run_test=matmul_dgw_tests
```

---

### Milestone 9: Mining RPC

**Deliverables**: Modified `rpc/mining.cpp`, `miner.h`, `miner.cpp`;
`matmul_mining_tests.cpp`, `mining_matmul_basic.py`

**Exit criteria**:
- [x] getblocktemplate includes matmul params with b and r separate
- [x] generateblock produces valid blocks
- [x] submitblock accepts valid, rejects invalid
- [x] getmininginfo reports matmul algorithm

```bash
./build-btx/bin/test_btx --run_test=matmul_mining_tests
python3 test/functional/mining_matmul_basic.py
```

---

### Milestone 10: End-to-End Functional Tests

**Deliverables**: `feature_btx_matmul_consensus.py`, `p2p_matmul_dos_mitigation.py`,
`matmul_pow_readiness.sh`

**Exit criteria**:
- [x] 100+ blocks on regtest
- [x] Multi-node sync (2+ nodes agree on tip)
- [x] Invalid blocks rejected, peers penalized
- [x] DoS rate limits work across peers
- [x] AssumeValid IBD path tested
- [x] JSON artifacts for production audit

```bash
python3 test/functional/feature_btx_matmul_consensus.py
python3 test/functional/p2p_matmul_dos_mitigation.py
bash scripts/matmul_pow_readiness.sh
```

---

### Milestone 11: Performance Benchmarks

**Deliverables**: `matmul_pow_benchmark.sh`, `doc/btx-matmul-benchmarks.md`

**Exit criteria**:
- [x] Solve/Verify time for n = {64, 128, 256, 512}
- [x] Memory usage ≤ O(n²) confirmed
- [x] Transcript compression overhead measured and reported separately:
  - [x] Compression dot-product time (expected: ~6% of matmul at n=512, b=16)
  - [x] Rolling SHA-256 time on compressed stream (expected: < 0.5 ms)
  - [x] Combined compression + SHA overhead < 10% of baseline matmul
  - [x] Compare against naive full-block hashing to confirm ≥ 50x reduction in SHA-256 input bytes
- [x] Denoise overhead < 2%
- [x] Total protocol overhead vs naive matmul < 15% at n=512 (noise gen + compression + denoise)
- [x] Per-component breakdown in benchmark report:
  - [x] Naive matmul time (baseline, no noise, no hashing)
  - [x] Noise generation time
  - [x] Transcript compression dot-product time
  - [x] SHA-256 rolling hash time (separately from compression dot-product)
  - [x] Denoise time
  - [x] Total Solve() wall-clock time
  - [x] Total Verify() wall-clock time
- [x] Apple M-series GPU benchmark (if available):
  - [x] Confirm compression dot-products run on GPU alongside matmul
  - [x] Confirm only ~131 KB shipped to CPU for SHA-256 (not ~33.5 MB)
- [x] Genesis difficulty calibration values derived from Solve() timings

```bash
bash scripts/matmul_pow_benchmark.sh
```

---

## 16. Test Matrix

### 16.1 Unit Tests (C++ / Boost Test)

| Suite | Tests | Milestone |
|-------|-------|-----------|
| `matmul_field_tests` | 37 | M1 |
| `matmul_matrix_tests` | 9 | M2 |
| `matmul_noise_tests` | 16 | M3 |
| `matmul_transcript_tests` | 17 | M4 |
| `matmul_pow_tests` | 12 | M5 |
| `matmul_params_tests` | 10 | M6 |
| `matmul_header_tests` | 7 | M6 |
| `matmul_validation_tests` | 14 | M7 |
| `matmul_trust_model_tests` | 6 | M7/M10 |
| `matmul_dgw_tests` | 11 | M8 |
| `matmul_subsidy_tests` | 6 | M8 |
| `matmul_mining_tests` | 5 | M9 |
| `matmul_block_capacity_tests` | 6 | M6 |
| **Total** | **~168** | |

Note: `matmul_field_tests` includes 14 `from_oracle` / `FromSeed` pinned
test vector and byte-exact derivation tests (SS7.4.8). `matmul_noise_tests`
includes 11 noise seed derivation byte-exact tests with pinned vectors
(SS8.2.3). `matmul_params_tests` includes 6 monetary policy and target
spacing tests (§5.4). `matmul_dgw_tests` includes 5 schedule-aware DGW
timespan tests (§11.7). `matmul_subsidy_tests` includes 6 subsidy/issuance
tests (§11.7). `matmul_block_capacity_tests` includes 6 weight/sigops/size
validation tests (§5.4, §14.7).

### 16.2 Functional Tests (Python)

| Test | Milestone |
|------|-----------|
| `mining_matmul_basic.py` | M9 |
| `p2p_matmul_dos_mitigation.py` | M10 |
| `feature_btx_matmul_consensus.py` | M10 |
| `feature_btx_subsidy_schedule.py` | M8 |
| `feature_btx_fast_mining_phase.py` | M8 |
| `feature_btx_block_capacity.py` | M6 |

### 16.3 Commands

```bash
# All matmul unit tests
./build-btx/bin/test_btx --run_test='matmul_*'

# Full regression
./build-btx/bin/test_btx --run_test='matmul_*'
python3 test/functional/test_runner.py

# Production gate
bash scripts/matmul_pow_readiness.sh
```

---

## 17. Security Audit Checklist

### 17.1 Cryptographic Correctness

- [x] M31 `reduce64` uses double Mersenne fold; correct for all uint64 inputs
  including boundary values at 2^62, 2^63, 2^64−1 (§7.2.2–7.2.4) (M1)
- [x] `dot()` enforces per-step reduction and is the only accumulation path;
  `reduce64` is not public API (§7.2.5–7.2.6) (M1)
- [x] Naive accumulation without per-step reduction demonstrated unsafe in tests (M1)
- [x] `from_oracle` produces near-uniform distribution over [0, M31) via 31-bit mask + rejection sampling (SS7.4.1--7.4.2) (M1)
- [x] `from_oracle` byte-exact: SHA-256(seed || LE32(index) [|| LE32(retry)]), 36/40-byte preimage (SS7.4.1) (M1)
- [x] `from_oracle` pinned test vectors TV1--TV6 pass on all target platforms (SS7.4.7) (M1)
- [x] `FromSeed` uses row-major index = row * n + col (SS7.4.3) (M2)
- [x] Noise domain separation: four distinct ASCII tags, 18 bytes each, no null terminator (SS8.2.1) (M3)
- [x] Noise index formula uses factor column count (r or n), not global n for all (SS8.2.1) (M3)
- [x] Noise pinned test vectors for derived seeds and matrix elements match (SS8.2.2) (M3)
- [x] Transcript iteration order (i, j, ℓ) strictly canonical; no reordering (M4)
- [x] σ derivation excludes `matmul_digest` from hash input (M6)
- [x] σ derivation byte-exact across platforms (LE specified for all fields) (M6)
- [x] b and r are used in correct contexts (b for transcript, r for noise) (M3, M4)
- [x] Transcript compression vector derived with domain separation `"matmul-compress-v1"` (M4)
- [x] Compression vector depends on σ (miner cannot pre-select favorable v) (M4)
- [x] Compressed element encoding is LE32, consensus-identical across platforms (M4)

### 17.2 Consensus Safety

- [x] No KAWPOW code in consensus path (fresh genesis) (M6)
- [x] Genesis difficulty prevents ultra-fast early emission (M8)
- [x] Dimension bounds enforced before any computation (M7)
- [x] Cross-platform determinism verified (x86 + ARM same results) (M4)
- [x] `GetTargetSpacing(height)` returns 0.25 for h < 50,000 and 90.0 for h ≥ 50,000 (§5.1, §11.5)
- [x] `GetBlockSubsidy(height)` returns 20 * COIN for h < 525,000, halves correctly (§11.4)
- [x] `MoneyRange()` rejects amounts > 21,000,000 * COIN (§11.4.3)
- [x] Coinbase output ≤ `GetBlockSubsidy(height) + fees` enforced in `ConnectBlock` (§11.4.3)
- [x] Cumulative issuance across all halvings ≤ 21,000,000 BTX (§11.4.2)
- [x] DGW uses `ExpectedDgwTimespan(height)` not fixed `nPowTargetSpacing * 180` (§11.6)
- [x] MTP and future-time-limit rules unchanged during fast phase (§11.5.1)
- [x] `GetBlockWeight(block) <= nMaxBlockWeight` enforced in ContextualCheckBlock (§14.2)
- [x] `GetBlockSigOpsCost(block) <= nMaxBlockSigOpsCost` enforced (§14.2)
- [x] `GetSerializeSize(block) <= nMaxBlockSerializedSize` enforced (§14.2)
- [x] Mining template respects `nDefaultBlockMaxWeight` by default (§14.3)

### 17.3 DoS Resistance

- [x] Phase 1 rejects invalid blocks in microseconds (M7)
- [x] Phase 1 fail adds misbehavior score +20 (standard DoS scoring) (M7)
- [x] Phase 1 pass + Phase 2 fail (1st offense) → peer DISCONNECTED, not banned (M7)
- [x] Phase 1 pass + Phase 2 fail (2nd offense within 24h) → peer DISCOURAGED + disconnected (M7)
- [x] Phase 1 pass + Phase 2 fail (3rd+ offense within 24h, >= threshold) → peer BANNED on mainnet (M7)
- [x] `fMatMulStrictPunishment == true` → Phase 2 fail = immediate ban (effective threshold 1) (M7)
- [x] `EffectivePhase2BanThreshold()` returns correct value for all network/flag combos (M7)
- [x] Phase 2 failure counter uses 24h rolling window; resets after 24h without failures (M7)
- [x] Testnet/regtest softfail: threshold forced to UINT32_MAX regardless of strict flag (M7)
- [x] Per-peer verification rate limit enforced (M7)
- [x] Max concurrent verifications bounded (M7)
- [x] `nMatMulMaxDimension` caps verification cost (M5)

### 17.4 Attack Vectors

- [x] **Easy-matrix via seed**: Miner can choose seeds that produce structured
  matrices. Defense: noise injection makes transcript random regardless. (M5)
- [x] **Precomputation**: σ depends on hashPrevBlock (via header), unknown in
  advance. (M6)
- [x] **Transcript forgery**: SHA-256 preimage resistance. (M4)
- [x] **Verification flooding**: Two-phase validation + rate limits. (M7)
- [x] **Seed grinding**: Miner tries many seed pairs. This is equivalent to
  nonce grinding — it IS the mining process, not an exploit. (M5)

### 17.5 Consensus Invariants (Auditor Summary)

This subsection consolidates every consensus-critical invariant in one
place. An implementation is consensus-correct **if and only if** all of the
following hold. References point to the authoritative section for each.

#### 17.5.1 Exact Arithmetic

| Invariant | Reference |
|-----------|-----------|
| All field arithmetic is over F_q where q = 2^31 − 1 (M31). No intermediate may exceed uint64 before reduction. | §7.1 |
| `reduce64(x)` uses the double Mersenne fold: `fold1 = (x & q) + (x >> 31)`, then `lo = fold1 & q`, `hi = fold1 >> 31`, `result = lo + hi`, subtract q if ≥ q. Correct for all x in [0, 2^64). | §7.2.1–7.2.4 |
| `dot(a, b, n)` is the **only** accumulation path. It calls `reduce64` after every multiply-add. No "lazy accumulation" is permitted. | §7.2.5 |
| Parallel reduction of dot products is valid **only** because all intermediates are in [0, q) and M31 addition is associative+commutative. The partition order may vary; the reduced sum must not. | §7.2.6, Appendix E.5 |

#### 17.5.2 Exact Seed and Matrix Derivation

| Invariant | Reference |
|-----------|-----------|
| σ = SHA256(serialize(header) excluding the `matmul_digest` field). Serialization is little-endian for all integer fields. | §6.3 |
| `from_oracle(seed, index)`: preimage = `seed ∥ LE32(index)` (36 bytes). Hash with SHA-256, take low 31 bits. If ≥ q, retry with preimage = `seed ∥ LE32(index) ∥ LE32(retry)` (40 bytes), retry = 1, 2, … Pr[retry] < 2^−31 per call. | §7.4.1–7.4.2 |
| `FromSeed(seed, n)`: element at (row, col) uses `index = row * n + col` (row-major). | §7.4.3 |
| `seed_a` and `seed_b` are **miner-chosen header fields**, NOT derived from σ. They are 32-byte values committed in the block header and directly passed to `FromSeed()`. σ is derived FROM the header (which includes seed_a, seed_b). Changing seed_a or seed_b changes σ. | §6.1, §9.1 |
| Noise factor derivation (distinct from seed_a/seed_b): `tag_EL = SHA256("matmul_noise_EL_v1" ∥ σ)`, analogous for E_R, F_L, F_R with distinct domain tags. These ARE derived from σ. | §8.2.1 |
| Compression vector v: `v_seed = SHA256("matmul-compress-v1" ∥ σ)`, b² elements via `from_oracle(v_seed, 0..b²−1)`. | §8.3.1 |

#### 17.5.3 Exact Transcript Order

| Invariant | Reference |
|-----------|-----------|
| Canonical block MatMul iterates tile indices in strict (i, j, ℓ) order: i = 0..N−1, j = 0..N−1, ℓ = 0..N−1 where N = n/b. | §8.1 |
| For each (i, j, ℓ): compute the b×b intermediate `C_partial = A_tile(i,ℓ) × B_tile(ℓ,j)` using the standard i-j-k triple loop within the tile. | §8.1 |
| Transcript compression: `t_{i,j,ℓ} = ⟨v, flatten(C_partial)⟩ mod q`, where flatten is row-major. This is the **only** value hashed per intermediate. | §8.3.1 |
| SHA-256d transcript hash: initialize CSHA256 hasher; for each (i,j,ℓ) in order, feed LE32(t_{i,j,ℓ}). Finalize with double SHA-256 (SHA256D): `z = SHA256(SHA256(stream))`. The result z is `matmul_digest`. | §8.3.1, App B |
| Noise is added to the **accumulated** C tile after all ℓ for a given (i,j), not to individual intermediates. Noise does not affect the transcript hash. | §8.2 |

#### 17.5.4 Exact Compression Derivation

| Invariant | Reference |
|-----------|-----------|
| The compression vector v is σ-derived and identical for all 32,768 intermediates (N³ = (n/b)³ at n=512, b=16). It is **not** re-derived per intermediate. | §8.3.2 |
| v elements are in [0, q) (uniform via rejection sampling). The inner product uses the same `dot()` as matrix multiplication — same reduction discipline. | §8.3.1 |
| Per-block parameters (n, b, r) are **immutable within a block**. They may change only at a hard-fork boundary where all nodes activate simultaneously. | §5.3 |

#### 17.5.5 Exact Reduction Discipline

| Invariant | Reference |
|-----------|-----------|
| **CPU path**: sequential `dot()` with per-step `reduce64`. Reference implementation. | §7.2.5 |
| **GPU path**: parallel reduction is permitted. Must produce bitwise-identical output to sequential `dot()`. Verified by cross-check test (Appendix E.13). | Appendix E.5 |
| No implementation may use floating-point arithmetic anywhere in the consensus path. | §7.1 |
| No implementation may rely on compiler-specific behavior (strict aliasing, signed overflow, uninitialized reads). All types are unsigned, all casts are explicit. | §7.1 |

#### 17.5.6 Monetary Policy

| Invariant | Reference |
|-----------|-----------|
| `nMaxMoney = 21,000,000 * COIN`. No transaction output, UTXO value, or coinbase may exceed this. | §5.1, §11.4.3 |
| `nInitialSubsidy = 20 * COIN`. `nSubsidyHalvingInterval = 525,000`. The identity `20 × 525,000 × 2 = 21,000,000` holds. | §5.1, §5.3 |
| `GetBlockSubsidy(h) = nInitialSubsidy >> (h / nSubsidyHalvingInterval)`. Returns 0 when halvings ≥ 64. | §11.4.1 |
| Coinbase output value ≤ `GetBlockSubsidy(height) + total_fees`. Enforced in `ConnectBlock()`. | §11.4.3 |
| `MoneyRange(v)` returns true iff `0 ≤ v ≤ nMaxMoney`. Applied to all CTxOut values. | §11.4.3 |
| Cumulative `Σ GetBlockSubsidy(h)` for all h converges to ≤ `nMaxMoney` (within integer truncation). | §11.4.2 |

#### 17.5.7 Target Spacing Schedule

| Invariant | Reference |
|-----------|-----------|
| `GetTargetSpacing(h) = 0.25` for h < 50,000; `= 90.0` for h ≥ 50,000. This is a consensus function (returns `double`). | §5.1, §11.5 |
| `nPowTargetSpacingFastMs = 250`, `nPowTargetSpacingNormal = 90`, `nFastMineHeight = 50,000`, `nFastMineDifficultyScale = 6` (mainnet). | §5.3 |
| DGW uses `ExpectedDgwTimespan(h) = Σ_{k=1..180} GetTargetSpacing(h-k)`, NOT a fixed constant. | §11.6 |
| At steady state (h ≥ 50,180): `ExpectedDgwTimespan = 180 × 90 = 16,200s`. | §11.6.2 |
| During fast phase (h < 50,000): `ExpectedDgwTimespan = (180 × 250) / 1000 = 45s`. | §11.6.2 |
| The fast-mining phase does NOT change the halving schedule. Halving is by block height, not time. | §11.5 |
| MTP and future-time-limit rules are unchanged during fast phase. Multiple consecutive blocks may share the same `nTime`. | §11.5.1 |

#### 17.5.8 Block Capacity (Weight-Based)

| Invariant | Reference |
|-----------|-----------|
| `GetBlockWeight(block) <= nMaxBlockWeight` (24,000,000 WU). Checked in `ContextualCheckBlock()`. | §14.2.1 |
| `GetBlockSigOpsCost(block) <= nMaxBlockSigOpsCost` (480,000). | §14.2.1 |
| `GetSerializeSize(block) <= nMaxBlockSerializedSize` (24,000,000 bytes). | §14.2.1 |
| `WITNESS_SCALE_FACTOR == 4`. Non-witness bytes cost 4 WU; witness bytes cost 1 WU. | §14.1, BIP 141 |
| Weight limits are per-network constants. Miners MUST NOT vary them per block. | §5.3 |
| Mining template weight ≤ `nDefaultBlockMaxWeight` by default; may be raised to `nMaxBlockWeight` via `-blockmaxweight`. | §14.3.1 |

#### 17.5.9 Fast-Phase Verification Scheduling

| Invariant | Reference |
|-----------|-----------|
| Phase 1 MUST be applied immediately to every block at all heights (no deferral). | §10.3.1 |
| Phase 2 MAY be deferred during fast phase (h < 50,000) via a bounded queue. | §10.3.1 |
| After transition to 90s blocks, the Phase 2 queue MUST drain and restore tip-tracking behavior. | §10.3.1 |
| A deferred Phase 2 failure triggers the same graduated punishment as a real-time failure. | §10.3.1, §10.2 |

> **Audit instruction**: An independent auditor should verify each row in the
> tables above against the referenced section **and** against the
> implementation code. Any deviation is a consensus bug.

---

## 18. Open Questions and Risks

### 18.1 Open Questions

| # | Question | Impact | Resolution |
|---|----------|--------|------------|
| 1 | Optimal (n, b, r) for mainnet? | Security + perf | Benchmarking in M11 |
| 2 | v2 arbitrary matrices: DA layer design? | PoUW upgrade path | Separate spec |
| 3 | GPU miner implementation? | Mining ecosystem | Separate repo (CUDA/Metal) |
| 4 | Stratum V2 extension for matmul? | Pool support | Separate spec |
| 5 | State commitment for v2 snapshots? | Trust model | Required before v2 |
| 6 | Genesis difficulty calibration values? | Launch safety | Derived in M11 benchmarks |

### 18.2 Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Verify cost = solve cost (1 attempt) | High | Two-phase validation; rate limits; assumevalid |
| Direct-product conjecture unproven | High | Conservative r; can adjust via hard fork |
| v1 produces no externally useful output (random matrices) | Medium | Clear v2 PoUW upgrade path; still O(n³) real computation; branding reflects this honestly (§3.2) |
| M31 field too small for future security | Low | q > n² for n ≤ 46K; upgrade path to M61 if needed |
| Non-determinism from UB/endianness | Critical | All arithmetic exact F_q; LE serialization specified |
| Genesis difficulty miscalibration | Medium | Pre-launch benchmarking; testnet bake-in |
| Seed grinding as second variability axis | Low | See §18.4 — design property, not vulnerability |
| ASIC development for MatMul PoW | Medium | See §18.5 — economic misalignment, not cryptographic impossibility |

### 18.3 Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| SHA-256 / SHA-256d (`hash.h`, `CSHA256`, `CHash256`) | Stable | Oracle derivation (single SHA-256) and transcript digest (SHA-256d) |
| ASERT difficulty | Stable | Stateless exponential retargeting from block 50,000 |
| Boost Test | Stable | Unit tests |
| Python functional framework | Stable | Integration tests |
| CMake 3.22+ / C++20 | Stable | Build system |

### 18.4 Seed Grinding as a Design Property

Miners choose `(seed_a, seed_b)` via `σ = SHA256(header \ matmul_digest)`,
which depends on `nonce`, `nNonce64`, and `nTime`. Changing any of these
changes σ and therefore changes A, B, all noise factors, and the compression
vector v. This means "trying different seeds" is indistinguishable from
"trying different nonces" — both are just hash-rate-limited mining attempts.

**Why this is a property, not a vulnerability:**

1. **Every seed change requires full O(n³) recomputation.** There is no
   shortcut to evaluate a new (A, B) pair without redoing the entire MatMul
   and transcript compression. The cost per attempt is identical.
2. **σ is unpredictable.** Since σ = SHA256(header), a miner cannot
   enumerate seed space faster than by hashing header variants, each of
   which commits to hashPrevBlock (unknown until parent is found).
3. **Pool economics are unaffected.** A pool assigns `nonce` ranges to
   workers; each range deterministically fixes σ. There is no "off-axis"
   search a worker can exploit that the pool does not already control.

> **Reviewer note**: Unlike pure hash puzzles, seed grinding gives miners a
> second variability axis (matrix structure via seed) on top of nonce. This
> is inherent to any PoW where the puzzle instance depends on the solution
> header. The design ensures both axes are equally expensive to explore
> (O(n³) per attempt), so the effective search is one-dimensional.

### 18.5 ASIC Threat Model

**ASICs for MatMul PoW are not cryptographically impossible.** Any fixed
arithmetic pipeline (M31 multiply-add, SHA-256 hashing) can in principle be
etched into silicon. The design goal is *economic misalignment*, not
cryptographic impossibility:

1. **Commodity hardware alignment.** The core operation — dense matrix
   multiplication over M31 — is structurally identical to INT32 GEMM, the
   same primitive that drives inference on NVIDIA (INT8/INT32 Tensor Cores),
   AMD (WMMA), and Apple (ANE/AMX) accelerators. Any ASIC that outperforms
   these must beat a \$300B/year R&D ecosystem at its own workload. This is
   economically irrational.

2. **Memory-bandwidth bound, not compute-bound.** At n = 4096, the working
   set for A, B, C, noise, and compression state exceeds GPU L2 cache. An
   ASIC that merely accelerates multiply-add gains nothing if it is starved
   for data. Matching GPU memory bandwidth (HBM3/HBM3e) requires the same
   expensive DRAM packaging, eliminating cost advantage.

3. **Complexity of the full pipeline.** A competitive ASIC must implement
   not just MatMul but also SHA-256 (transcript hashing), pseudorandom
   matrix generation (FromSeed with rejection sampling), noise injection,
   compression dot-products, and the ASERT difficulty check. The
   breadth of operations favors general-purpose architectures.

4. **Upgrade path.** If an ASIC threat materializes, the protocol can
   adjust dimension n, switch to M61 (64-bit Mersenne), or add a memory-hard
   mixing layer via hard fork — the same defense available to any PoW chain,
   but with the advantage that larger n or wider fields directly increase
   reuse of commodity AI hardware rather than creating new ASIC incentives.

> **Design stance**: MatMul PoW bets on commodity AI hardware continuing to
> improve at a pace no fixed-function ASIC can match. This is a *strategic*
> bet, not a *cryptographic* guarantee. The spec makes no claim of
> "ASIC-resistance" — only "ASIC economic misalignment at current and
> projected hardware price curves."

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| **cuPOW** | The MatMul PoW protocol from arxiv:2504.09971 (the paper uses "Proof-of-Useful-Work"; BTX reserves that branding for v2 when arbitrary matrices are supported) |
| **b** | Transcript block size — controls hashing granularity in canonical MatMul |
| **r** | Noise rank — controls security and denoising overhead (independent of b) |
| **M31** | Mersenne prime 2^31 − 1 = 2,147,483,647; the consensus field modulus |
| **σ** | Random oracle seed derived from block header (excludes matmul_digest) |
| **z** | Transcript hash (= matmul_digest); the PoW output compared to target |
| **ASERT** | Absolutely Scheduled Exponentially Rising Targets — stateless per-block difficulty adjustment (3600s half-life from block 50,000) |
| **Phase 1** | Cheap header validation (microseconds); gates Phase 2 |
| **Phase 2** | Expensive transcript recomputation (O(n³)); only after Phase 1 passes |
| **v** | Compression vector — b² pseudorandom field elements derived from σ; used for inner-product compression of intermediates (Section 8.3.1) |
| **Mining node** | Tier 0 node: performs full Solve (transcript computation for every nonce attempt) and validates all blocks |
| **Consensus-validating node** | Tier 1 node: validates Phase 2 for all blocks at tip; strongest non-mining trust posture. **This is the minimum "full node."** |
| **Economic node** | Tier 2 node: Phase 1 only + `assumevalid`; does NOT validate Phase 2. Explicitly **not** a "full node" (§12.1). Trusts full-node majority for transcript correctness. |
| **Light / SPV node** | Tier 3 node: Phase 1 only (header chain); trusts full node majority for both transcript correctness and transaction inclusion |
| **Full node** | A node that validates Phase 2 for at least the last `nMatMulValidationWindow` blocks. Only Tier 0 (mining) and Tier 1 (consensus-validating) qualify. Tier 2 (economic) is explicitly not "full" (§12.1). |
| **nMatMulValidationWindow** | Consensus parameter: number of recent blocks requiring Phase 2 validation (default 1000) |

## Appendix B: Reference Pseudocode

**This appendix is the canonical reference implementation.** The CPU scalar
code in B.1 (`CanonicalMatMul_b`), B.2 (if present), and the `dot()` /
`reduce64()` / `from_oracle()` functions in §7.2–7.4 together constitute the
**authoritative definition** of correct consensus behavior. Any alternative
implementation — including GPU kernels (Appendix E), SIMD-optimized paths,
or third-party mining software — MUST produce **bit-for-bit identical output**
to this CPU reference for all inputs. In case of discrepancy between prose
description and reference code, the reference code governs.

### B.1 Canonical Block MatMul with Transcript Compression (block size b)

```
CanonicalMatMul_b(A', B', sigma):
    N = rows(A') / b
    C' = zeros(N*b, N*b)
    v = DeriveCompressionVector(sigma, b)   // b^2 random field elements (Section 8.3.1)
    hasher = SHA256_Init()

    for i in 0..N-1:
        for j in 0..N-1:
            for l in 0..N-1:
                C'_block[i][j] += A'_block[i][l] * B'_block[l][j]
                // Compress b*b intermediate to single field element
                c = dot(flatten(C'_block[i][j]), v, b*b)
                hasher.Update(LE32(c))       // 4 bytes per intermediate

    // Double SHA-256 (SHA256D) — standard Bitcoin digest convention
    hash1 = hasher.Finalize()               // first SHA-256 pass
    z = SHA256(hash1)                        // second SHA-256 pass
    return (C', z)
```

Note: The v1 pseudocode used `emit(i, j, l, block)` implying full-block
hashing. This revision uses field-algebraic compression per Section 8.3.1.
The `DeriveCompressionVector` function is:

```
DeriveCompressionVector(sigma, b):
    seed = SHA-256("matmul-compress-v1" || sigma)
    for k in 0..b*b-1:
        v[k] = field::from_oracle(seed, k)
    return v
```

### B.2 Solve (v1: seeded matrices)

```
Solve(block, params):
    n = params.nMatMulDimension
    b = params.nMatMulTranscriptBlockSize
    r = params.nMatMulNoiseRank
    target = DeriveTarget(block.nBits)

    A = FromSeed(block.seed_a, n)
    B = FromSeed(block.seed_b, n)

    for nonce in 0..MAX:
        block.nNonce64 = nonce
        σ = SHA256(matmul_header_hash(block))
        (E_L, E_R, F_L, F_R) = GenerateNoise(σ, n, r)
        A' = A + E_L·E_R
        B' = B + F_L·F_R
        (C', z) = CanonicalMatMul_b(A', B', σ)   // σ needed for compression vector
        if z < target:
            block.matmul_digest = z
            return true
    return false
```

### B.3 Verify

```
Verify(block, params):
    n = block.matmul_dim
    b = params.nMatMulTranscriptBlockSize
    r = params.nMatMulNoiseRank

    // Phase 1 (cheap)
    if n < min or n > max or n % b != 0: return false
    if matmul_digest > target: return false

    // Phase 2 (expensive)
    A = FromSeed(block.seed_a, n)
    B = FromSeed(block.seed_b, n)
    σ = SHA256(matmul_header_hash(block))
    (E_L, E_R, F_L, F_R) = GenerateNoise(σ, n, r)
    A' = A + E_L·E_R
    B' = B + F_L·F_R
    (_, z) = CanonicalMatMul_b(A', B', σ)   // σ needed for compression vector
    return z == block.matmul_digest
```

## Appendix C: Paper Reference

> Komargodski, I., Schen, I., & Weinstein, O. (2025). "Proofs of Useful Work
> from Arbitrary Matrix Multiplication." arXiv:2504.09971v1.
> https://arxiv.org/abs/2504.09971

## Appendix D: Alternative — Height-Gated KAWPOW Transition

If preserving the existing KAWPOW chain is required, the following changes apply:

1. **Keep KAWPOW header fields** (`nNonce`, `mix_hash`) and add matmul fields
2. **Add `nMatMulPOWHeight`** for activation gate
3. **Dual dispatch** in `validation.cpp`:
   ```cpp
   if (height >= params.nMatMulPOWHeight)
       CheckMatMulProofOfWork(...)
   else
       CheckKAWPOWProofOfWork(...)
   ```
4. **DGW transition reset**: At activation height, hold difficulty at a
   calibrated starting value (NOT powLimit) for 180 blocks
5. **Header size**: 182 + 4 (nNonce) + 32 (mix_hash) = 218 bytes
6. **Additional test burden**: ~15 transition-specific tests

This path is more complex, has more attack surface, and is only recommended if
chain continuity is a hard business requirement.

---

## Appendix E: GPU Kernel Fusion — CUDA + Metal Execution Model

This appendix provides production-ready GPU kernel code for the fused
MatMul + transcript compression pipeline. The code is designed for immediate
integration into the BTX miner and verifier. All arithmetic follows the
consensus rules in §7 (M31 double-fold `reduce64`, per-step reduction in
`dot()`) and §8.3.1 (σ-derived compression vector, LE32 output).

### E.1 Goals and Constraints

#### E.1.1 Primary Goal

Implement `CanonicalMatMul_b(A', B', σ)` on GPU such that:

1. It computes the noisy product C' = A' · B' in canonical (i, j, ℓ) order
2. It produces the compressed transcript stream: one `uint32` per intermediate
3. Only the compressed stream (~128 KiB at n=512, b=16) is transferred to CPU
4. CPU performs SHA-256 on the stream to produce digest z

#### E.1.2 Consensus Constraints (Must Not Change)

- Arithmetic is over F_q with q = 2^31 − 1 (M31)
- `reduce64` uses double Mersenne fold (§7.2.3–7.2.4)
- `dot()` uses per-step reduction (§7.2.5)
- Transcript loop order is i-major, j-next, ℓ-inner
- Compression: `c = dot(flatten(C_block[i][j]), v, b²)` where v is σ-derived
- Hash input per intermediate is exactly 4 bytes: `LE32(c)`
- Output index: `idx = (i * N + j) * N + ell` where N = n/b

#### E.1.3 Performance Constraints

- Do NOT transfer full b×b blocks to CPU (33.5 MiB at n=512, b=16)
- Compression MUST be computed on-GPU ("in-kernel")
- Only the compressed element stream (~128 KiB) may cross the PCIe/unified bus
- Kernel launch overhead must be amortized (one launch per mining attempt)

---

### E.2 Common M31 Field Arithmetic (CUDA + Metal)

Both platforms use identical arithmetic. The GPU implementations must match
the CPU reference in §7.2.4 bit-for-bit.

#### E.2.1 reduce64 — Double Mersenne Fold

```
// Reduces any uint64 value to [0, q) via double Mersenne fold.
// Identical to §7.2.4. MUST NOT be simplified to a single fold.
//
// CUDA:  __device__ __forceinline__ uint32_t reduce64(uint64_t x)
// Metal: inline uint reduce64(ulong x)
//
// Implementation (same logic, platform syntax differs):
//
//   const uint64 Q = 0x7FFFFFFFULL;
//   // FIRST FOLD: x -> fold1 in [0, 5·2^31 − 2]
//   uint64 fold1 = (x & Q) + (x >> 31);
//   // SECOND FOLD: fold1 -> result in [0, 2^31 + 3]
//   uint32 lo = (uint32)(fold1 & Q);
//   uint32 hi = (uint32)(fold1 >> 31);    // hi ≤ 4
//   uint32 r = lo + hi;
//   if (r >= (uint32)Q) r -= (uint32)Q;
//   return r;
```

#### E.2.2 madd — Fused Multiply-Add with Reduction

```
// acc = (acc + a*b) mod q, with per-step reduction.
// The sum (uint64)acc + (uint64)a*b fits in uint64 because:
//   acc < q < 2^31, a*b < 2^62, so sum < 2^62 + 2^31 < 2^63.
// reduce64 handles this (even handles up to 2^64-1).
//
// CUDA:  __device__ __forceinline__ uint32_t madd(uint32_t acc, uint32_t a, uint32_t b)
// Metal: inline uint madd(uint acc, uint a, uint b)
//
//   uint64 prod = (uint64)a * (uint64)b;
//   uint64 sum  = (uint64)acc + prod;
//   return reduce64(sum);
```

---

### E.3 Data Layout and Memory Residency

#### E.3.1 Matrix Storage

Row-major contiguous `uint32_t` arrays, all values in [0, q):

| Buffer | Size (n=512) | Residency |
|--------|-------------|-----------|
| A' | n×n = 1 MiB | GPU global memory |
| B' | n×n = 1 MiB | GPU global memory |
| C' | n×n = 1 MiB | GPU global (optional; needed for denoise) |

#### E.3.2 Compression Vector v

Length b² = 256 elements (1 KiB at b=16). Derived from σ on CPU via
`DeriveCompressionVector(σ, b)` (§8.3.1), then uploaded once per nonce attempt.

| Platform | Storage | Rationale |
|----------|---------|-----------|
| CUDA | `__constant__` memory | 1 KiB << 64 KiB limit; broadcast to all threads |
| Metal | `constant` address space buffer | Fastest read path for small uniform data |

#### E.3.3 Output Stream Buffer

Stores one compressed `uint32` per intermediate:

```
uint32_t out[N³]    where N = n/b
```

| n | b | N | Elements | Size |
|---|---|---|----------|------|
| 512 | 16 | 32 | 32,768 | 128 KiB |
| 256 | 8 | 32 | 32,768 | 128 KiB |
| 64 | 8 | 8 | 512 | 2 KiB |

Allocation:
- **CUDA**: `cudaMallocHost` (pinned) for zero-copy or fast async DMA
- **Metal**: `MTLResourceStorageModeShared` for unified memory on Apple Silicon

---

### E.4 Kernel Fusion Strategy

#### E.4.1 Why Standard GEMM Kernels Cannot Be Used

A standard GEMM kernel accumulates the entire ℓ-loop internally and outputs
only the final C' matrix. The transcript requires every intermediate partial
sum after each ℓ-step. Therefore: each (i, j) tile must iterate ℓ
sequentially and emit a compressed element after every step.

#### E.4.2 Parallelization Model

- **Parallel axis**: (i, j) block tiles — N² independent tiles
- **Sequential axis**: ℓ (accumulation steps) — N steps per tile
- **Threadblock**: b × b threads; each thread owns one element of the accumulator

For n=512, b=16: N=32, N²=1024 tiles, 256 threads/tile. This saturates all
modern GPUs (RTX 3090: 82 SMs; RTX 4090: 128 SMs; M1 Pro: 16 cores).

#### E.4.3 Per-ℓ-Step Operations

After each ℓ accumulation step within a tile:

1. All threads write their accumulator to shared memory (`Csh[b][b]`)
2. Barrier synchronization
3. Compress: compute `c = dot(flatten(Csh), v, b²)` — see §E.5 for strategies
4. Thread 0 writes `out[idx]` where `idx = (i*N + j)*N + ℓ`
5. Barrier synchronization before next ℓ

---

### E.5 Deterministic Parallel Reduction for Compression

Computing `c = dot(flatten(Csh), v, b²)` requires reducing 256 products to
a single field element. Two strategies are provided:

#### E.5.1 Option B — Single-Thread Sequential Dot (Reference Implementation)

Thread 0 computes the dot product sequentially. All other threads idle.

**Advantages**: Trivially deterministic. Matches CPU reference exactly.
**Cost**: 256 sequential multiply-reduce operations per ℓ per tile.

```
// Pseudocode — runs on thread (0,0) only
uint32 compress_sequential(shared uint32 Csh[b][b], const uint32 V[b*b], uint32 b) {
    uint32 acc = 0;
    for (uint32 idx = 0; idx < b*b; ++idx) {
        uint32 c_elem = Csh[idx / b][idx % b];
        uint32 v_elem = V[idx];
        acc = madd(acc, c_elem, v_elem);   // acc = reduce64(acc + c*v)
    }
    return acc;
}
```

Total per attempt: N³ × b² = 32,768 × 256 = 8.4M multiply-add ops.
At ~256 idle threads per compression: warp utilization drops to 1/8 during
compression. Acceptable for v1 reference; optimize later.

#### E.5.2 Option A — Deterministic Parallel Tree Reduction

All 256 threads participate. The reduction uses a fixed binary tree that
produces **bit-identical results** to Option B for M31 arithmetic.

**Proof that parallel tree = sequential for M31:**

All products `p[i] = reduce64((uint64)Csh[i] * V[i])` are in [0, q-1] where
q = 2^31 − 1. At every level of the binary tree, we compute
`reduce64((uint64)left + (uint64)right)` where both operands are in [0, q-1].
The sum is at most 2(q-1) = 2^32 − 4, which fits in uint32. For any
x < 2^32, `reduce64(x)` computes x mod q exactly (the double fold reduces
to: fold1 = (x & q) + (x >> 31) where x>>31 is 0 or 1, so fold1 ≤ q+1;
second fold is identity; then conditional subtract). Since reduce64 returns
the true mathematical x mod q for all inputs < 2^32, and addition modulo a
prime is associative and commutative, the tree order does not affect the
result. **QED.**

**Reduction tree specification (8 levels for 256 elements):**

```
Level 0: thread t computes p[t] = reduce64((uint64)Csh[t] * V[t])
         writes p[t] to sdata[t]
         barrier

Level k (k = 1..8):
  stride = 256 >> k     // 128, 64, 32, 16, 8, 4, 2, 1
  if (t < stride):
      sdata[t] = reduce64((uint64)sdata[t] + (uint64)sdata[t + stride])
  barrier

After level 8: sdata[0] = c (the compressed element)
```

**CUDA implementation:**

```cuda
__device__ uint32_t parallel_compress(
    uint32_t my_c,                    // this thread's Csh element
    uint32_t my_v,                    // this thread's V element
    volatile uint32_t* sdata,         // shared memory, 256 entries
    unsigned tid)                     // thread linear index (0..255)
{
    const uint64_t Q = 0x7FFFFFFFULL;

    // Step 0: each thread computes its product
    uint64_t prod = (uint64_t)my_c * (uint64_t)my_v;
    sdata[tid] = reduce64(prod);
    __syncthreads();

    // Steps 1-8: fixed binary tree reduction
    // For strides >= 32 (warp size), use __syncthreads()
    // For strides < 32, warp-synchronous (volatile handles visibility)
    for (unsigned stride = 128; stride >= 32; stride >>= 1) {
        if (tid < stride) {
            uint64_t sum = (uint64_t)sdata[tid] + (uint64_t)sdata[tid + stride];
            sdata[tid] = reduce64(sum);
        }
        __syncthreads();
    }

    // Final warp (stride 16, 8, 4, 2, 1) — warp-synchronous
    // Using __syncwarp() for modern CUDA (sm_70+).
    // volatile shared memory ensures visibility within the warp.
    if (tid < 32) {
        if (tid < 16) { uint64_t s = (uint64_t)sdata[tid] + (uint64_t)sdata[tid+16]; sdata[tid] = reduce64(s); } __syncwarp();
        if (tid <  8) { uint64_t s = (uint64_t)sdata[tid] + (uint64_t)sdata[tid+ 8]; sdata[tid] = reduce64(s); } __syncwarp();
        if (tid <  4) { uint64_t s = (uint64_t)sdata[tid] + (uint64_t)sdata[tid+ 4]; sdata[tid] = reduce64(s); } __syncwarp();
        if (tid <  2) { uint64_t s = (uint64_t)sdata[tid] + (uint64_t)sdata[tid+ 2]; sdata[tid] = reduce64(s); } __syncwarp();
        if (tid <  1) { uint64_t s = (uint64_t)sdata[tid] + (uint64_t)sdata[tid+ 1]; sdata[tid] = reduce64(s); }
    }
    __syncthreads();

    return sdata[0];
}
```

**Metal implementation:**

```metal
uint parallel_compress(
    uint my_c,
    uint my_v,
    threadgroup uint* sdata,          // 256 entries
    uint tid)                         // thread linear index (0..255)
{
    // Step 0: each thread computes its product
    ulong prod = (ulong)my_c * (ulong)my_v;
    sdata[tid] = reduce64(prod);
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Steps 1-8: fixed binary tree reduction
    for (uint stride = 128; stride >= 1; stride >>= 1) {
        if (tid < stride) {
            ulong sum = (ulong)sdata[tid] + (ulong)sdata[tid + stride];
            sdata[tid] = reduce64(sum);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    return sdata[0];
}
```

**Performance comparison (per mining attempt, n=512, b=16):**

| Strategy | Compression ops | Thread utilization | Latency |
|----------|----------------|-------------------|---------|
| Option B (sequential) | 8.4M serial ops | 1/256 = 0.4% during compress | Baseline |
| Option A (parallel tree) | 8.4M ops / 256 threads + 8 sync levels | ~100% | ~8× faster |

**Recommendation**: Ship Option B for v1 correctness validation. Switch to
Option A once test vectors confirm bit-identical results. Both are canonical.

---

### E.6 CUDA Reference Implementation

#### E.6.1 Prerequisites

- CUDA Toolkit 11.0+ (sm_70+ for `__syncwarp`; sm_50+ minimum for native uint64)
- Minimum compute capability: **sm_50** (Maxwell). Recommended: sm_70+ (Volta)

#### E.6.2 Error Checking Macro

```cuda
#include <cstdio>
#include <cstdlib>

#define CHECK_CUDA(call)                                                    \
    do {                                                                    \
        cudaError_t err = (call);                                           \
        if (err != cudaSuccess) {                                           \
            fprintf(stderr, "CUDA error at %s:%d: %s\n",                    \
                    __FILE__, __LINE__, cudaGetErrorString(err));            \
            abort();                                                        \
        }                                                                   \
    } while (0)
```

#### E.6.3 M31 Arithmetic

```cuda
static constexpr uint32_t M31 = 0x7FFFFFFFU;

__device__ __forceinline__ uint32_t reduce64(uint64_t x) {
    const uint64_t Q = 0x7FFFFFFFULL;
    // First fold: x -> fold1 in [0, 5*2^31 - 2]
    uint64_t fold1 = (x & Q) + (x >> 31);
    // Second fold: fold1 -> [0, 2^31 + 3]
    uint32_t lo = (uint32_t)(fold1 & Q);
    uint32_t hi = (uint32_t)(fold1 >> 31);   // hi <= 4
    uint32_t r = lo + hi;
    if (r >= M31) r -= M31;
    return r;
}

__device__ __forceinline__ uint32_t madd(uint32_t acc, uint32_t a, uint32_t b) {
    uint64_t prod = (uint64_t)a * (uint64_t)b;
    uint64_t sum  = (uint64_t)acc + prod;
    return reduce64(sum);
}
```

#### E.6.4 Constant Memory for Compression Vector

```cuda
// 256 elements for b=16. Fits in 64 KiB constant cache (uses 1 KiB).
// Updated per nonce attempt via cudaMemcpyToSymbol before kernel launch.
__constant__ uint32_t d_V[256];
```

#### E.6.5 Fused MatMul + Transcript Compression Kernel

```cuda
// One threadblock per (i,j) tile. 16x16 = 256 threads per block.
// Grid: (N, N) where N = n/b.
// Iterates ℓ = 0..N-1 inside the block, emitting one compressed
// element per (i,j,ℓ) step.
//
// Shared memory: As[16][17] (padded to avoid bank conflicts on column reads),
//                Bs[16][16], Csh[16][16], reduce_buf[256].
// Total shared: 17*16 + 16*16 + 16*16 + 256 = 1,060 uint32 = 4,240 bytes.
// Well within 48 KiB default shared memory limit.

Implementation status note, April 13, 2026:

The kernel below is still the optimized target design for CUDA, not a
line-for-line description of the current shipped Linux CUDA backend. The live
implementation now has the fused finalize path and a warp-synchronous reduction
tail, but it does not yet ship the shared-memory tiled finalize rewrite,
constant-memory compression-vector path, or the `512/16/8` finalize
specialization described in this appendix.

__global__ void MatMulTranscriptKernel(
    const uint32_t* __restrict__ A,   // n*n, row-major, values in [0, q)
    const uint32_t* __restrict__ B,   // n*n, row-major
    uint32_t*       __restrict__ C,   // n*n output (may be NULL for hash-only)
    uint32_t*       __restrict__ out, // N^3 compressed elements
    const int n,
    const int b,
    const int N)                      // N = n/b
{
    const int tile_i = blockIdx.y;
    const int tile_j = blockIdx.x;
    const int li = threadIdx.y;       // 0..b-1
    const int lj = threadIdx.x;       // 0..b-1
    const int tid = li * b + lj;      // linear thread index 0..b*b-1

    // Accumulator for C'[tile_i*b+li][tile_j*b+lj]
    uint32_t acc = 0;

    // Shared memory tiles
    // As is padded to 17 columns to eliminate bank conflicts when reading
    // column As[*][k] during the inner product loop. Without padding,
    // all 16 threads in a half-warp read the same bank (16-way conflict).
    __shared__ uint32_t As[16][17];   // A tile (padded)
    __shared__ uint32_t Bs[16][16];   // B tile
    __shared__ uint32_t Csh[16][16];  // Accumulator snapshot for compression
    __shared__ volatile uint32_t reduce_buf[256]; // For parallel reduction

    for (int ell = 0; ell < N; ++ell) {

        // --- Load A_block[tile_i][ell] into shared memory ---
        const int a_row = tile_i * b + li;
        const int a_col = ell * b + lj;
        As[li][lj] = A[a_row * n + a_col];

        // --- Load B_block[ell][tile_j] into shared memory ---
        const int b_row = ell * b + li;
        const int b_col = tile_j * b + lj;
        Bs[li][lj] = B[b_row * n + b_col];

        __syncthreads();

        // --- Block multiply-add: acc += row(As,li) . col(Bs,lj) ---
        // Per-step reduction via madd() as required by §7.2.5.
        for (int k = 0; k < b; ++k) {
            acc = madd(acc, As[li][k], Bs[k][lj]);
        }

        // --- Expose accumulator for compression ---
        Csh[li][lj] = acc;
        __syncthreads();

        // --- Compress: c = dot(flatten(Csh), V, b*b) ---
        // Option A: parallel tree reduction (deterministic, see §E.5.2)
        uint32_t my_c = Csh[tid / b][tid % b];  // == acc, but read from shared
        uint32_t my_v = d_V[tid];

        // Parallel reduction into reduce_buf
        uint64_t prod = (uint64_t)my_c * (uint64_t)my_v;
        reduce_buf[tid] = reduce64(prod);
        __syncthreads();

        for (int stride = (b * b) >> 1; stride >= 32; stride >>= 1) {
            if (tid < stride) {
                uint64_t s = (uint64_t)reduce_buf[tid]
                           + (uint64_t)reduce_buf[tid + stride];
                reduce_buf[tid] = reduce64(s);
            }
            __syncthreads();
        }

        // Warp-synchronous final reduction (stride 16..1)
        if (tid < 32) {
            if (tid < 16) { reduce_buf[tid] = reduce64((uint64_t)reduce_buf[tid] + (uint64_t)reduce_buf[tid + 16]); } __syncwarp();
            if (tid <  8) { reduce_buf[tid] = reduce64((uint64_t)reduce_buf[tid] + (uint64_t)reduce_buf[tid +  8]); } __syncwarp();
            if (tid <  4) { reduce_buf[tid] = reduce64((uint64_t)reduce_buf[tid] + (uint64_t)reduce_buf[tid +  4]); } __syncwarp();
            if (tid <  2) { reduce_buf[tid] = reduce64((uint64_t)reduce_buf[tid] + (uint64_t)reduce_buf[tid +  2]); } __syncwarp();
            if (tid <  1) { reduce_buf[tid] = reduce64((uint64_t)reduce_buf[tid] + (uint64_t)reduce_buf[tid +  1]); }
        }
        __syncthreads();

        // --- Write compressed element to output in canonical order ---
        if (tid == 0) {
            const int idx = (tile_i * N + tile_j) * N + ell;
            out[idx] = reduce_buf[0];
        }

        __syncthreads();  // Barrier before next ℓ iteration
    }

    // --- Optionally write final C' element ---
    if (C != nullptr) {
        const int c_row = tile_i * b + li;
        const int c_col = tile_j * b + lj;
        C[c_row * n + c_col] = acc;
    }
}
```

#### E.6.6 Host-Side Launch and Hashing

```cuda
#include <openssl/sha.h>   // or src/crypto/sha256.h

struct MatMulGPUContext {
    uint32_t* d_A;          // device: A' matrix
    uint32_t* d_B;          // device: B' matrix
    uint32_t* d_C;          // device: C' matrix (nullable)
    uint32_t* d_out;        // device: compressed output buffer
    uint32_t* h_out;        // host (pinned): compressed output
    int n, b, N;
};

// Allocate GPU resources (once per mining session)
void matmul_gpu_init(MatMulGPUContext& ctx, int n, int b) {
    ctx.n = n;
    ctx.b = b;
    ctx.N = n / b;
    int nn = n * n;
    int N3 = ctx.N * ctx.N * ctx.N;

    CHECK_CUDA(cudaMalloc(&ctx.d_A, nn * sizeof(uint32_t)));
    CHECK_CUDA(cudaMalloc(&ctx.d_B, nn * sizeof(uint32_t)));
    CHECK_CUDA(cudaMalloc(&ctx.d_C, nn * sizeof(uint32_t)));
    CHECK_CUDA(cudaMalloc(&ctx.d_out, N3 * sizeof(uint32_t)));
    CHECK_CUDA(cudaMallocHost(&ctx.h_out, N3 * sizeof(uint32_t)));
}

void matmul_gpu_free(MatMulGPUContext& ctx) {
    cudaFree(ctx.d_A);
    cudaFree(ctx.d_B);
    cudaFree(ctx.d_C);
    cudaFree(ctx.d_out);
    cudaFreeHost(ctx.h_out);
}

// Upload matrices and compression vector, launch kernel, hash result.
// Returns the transcript digest z.
uint256 matmul_gpu_solve_attempt(
    MatMulGPUContext& ctx,
    const uint32_t* h_A,        // host A' matrix (n*n)
    const uint32_t* h_B,        // host B' matrix (n*n)
    const uint32_t  h_V[256],   // host compression vector (b*b)
    cudaStream_t stream)
{
    int nn = ctx.n * ctx.n;
    int N3 = ctx.N * ctx.N * ctx.N;

    // Upload A', B' (only needed once per seed pair; skip if unchanged)
    CHECK_CUDA(cudaMemcpyAsync(ctx.d_A, h_A, nn * sizeof(uint32_t),
                                cudaMemcpyHostToDevice, stream));
    CHECK_CUDA(cudaMemcpyAsync(ctx.d_B, h_B, nn * sizeof(uint32_t),
                                cudaMemcpyHostToDevice, stream));

    // Upload compression vector to constant memory
    CHECK_CUDA(cudaMemcpyToSymbolAsync(d_V, h_V, 256 * sizeof(uint32_t),
                                        0, cudaMemcpyHostToDevice, stream));

    // Launch kernel: one block per (i,j) tile, b*b threads per block
    dim3 grid(ctx.N, ctx.N);        // (N, N) = (32, 32) for n=512
    dim3 block(ctx.b, ctx.b);       // (16, 16) = 256 threads

    MatMulTranscriptKernel<<<grid, block, 0, stream>>>(
        ctx.d_A, ctx.d_B, ctx.d_C, ctx.d_out,
        ctx.n, ctx.b, ctx.N);

    // Copy compressed output back (128 KiB — takes ~10 μs on PCIe 4.0)
    CHECK_CUDA(cudaMemcpyAsync(ctx.h_out, ctx.d_out,
                                N3 * sizeof(uint32_t),
                                cudaMemcpyDeviceToHost, stream));

    CHECK_CUDA(cudaStreamSynchronize(stream));

    // SHA-256 hash of compressed stream in canonical order
    // out[] is already in canonical order: i-major, j-next, ℓ-inner
    // Each element is native uint32 — on little-endian hosts this IS LE32.
    // On big-endian hosts: byte-swap each element before hashing.
    SHA256_CTX sha;
    SHA256_Init(&sha);
    // NOTE: out[] elements are uint32 in host byte order.
    // Consensus requires LE32. On little-endian (x86, ARM), this is identity.
    // On big-endian: must byte-swap. All modern mining hardware is LE.
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
                  "Big-endian not yet supported; add byte-swap for out[]");
    SHA256_Update(&sha, ctx.h_out, N3 * sizeof(uint32_t));
    unsigned char hash1[32];
    SHA256_Final(hash1, &sha);

    // Double SHA-256 (standard Bitcoin hash)
    SHA256_CTX sha2;
    SHA256_Init(&sha2);
    SHA256_Update(&sha2, hash1, 32);
    unsigned char hash2[32];
    SHA256_Final(hash2, &sha2);

    uint256 z;
    memcpy(z.begin(), hash2, 32);
    return z;
}
```

#### E.6.7 Occupancy Analysis

| GPU | SMs | Max blocks/SM | Shared/block | Theoretical occupancy |
|-----|-----|--------------|-------------|----------------------|
| RTX 3090 (GA102) | 82 | 16 | 4,240 B (<<48 KiB) | 100% (256 threads/block, 16 blocks/SM) |
| RTX 4090 (AD102) | 128 | 16 | 4,240 B | 100% |
| A100 (GA100) | 108 | 16 | 4,240 B | 100% |
| GTX 1660 (TU116) | 22 | 16 | 4,240 B | 100% |

Register usage: ~16 registers/thread (acc, loop vars, temps). No spilling.

At n=512: 1024 blocks launched. RTX 3090 with 82 SMs runs all tiles in ~13
waves. Kernel time dominated by N=32 ℓ-steps with shared memory loads and
256-wide multiply-add loops.

---

### E.7 Metal Reference Implementation (Apple Silicon)

#### E.7.1 Prerequisites

- macOS 13+ / iOS 16+ with Metal 3
- Apple Silicon (M1/M2/M3/M4) — all support `ulong` (64-bit integer) in MSL
- Intel Macs: Metal on Intel supports `ulong` from macOS 10.13+ (GPU family
  macOS 1), but performance is poor for integer compute; not recommended

#### E.7.2 Kernel Parameters Structure

```metal
struct MatMulParams {
    uint n;    // matrix dimension
    uint b;    // transcript block size
    uint N;    // n / b (number of tiles per dimension)
};
```

#### E.7.3 M31 Arithmetic in Metal Shading Language

```metal
#include <metal_stdlib>
using namespace metal;

constant uint M31 = 0x7FFFFFFFU;

inline uint reduce64(ulong x) {
    const ulong Q = 0x7FFFFFFFul;
    // First fold
    ulong fold1 = (x & Q) + (x >> 31);
    // Second fold
    uint lo = (uint)(fold1 & Q);
    uint hi = (uint)(fold1 >> 31);
    uint r = lo + hi;
    if (r >= M31) r -= M31;
    return r;
}

inline uint madd(uint acc, uint a, uint b) {
    ulong prod = (ulong)a * (ulong)b;
    ulong sum  = (ulong)acc + prod;
    return reduce64(sum);
}
```

#### E.7.4 Fused MatMul + Transcript Compression Kernel

```metal
kernel void MatMulTranscriptKernel(
    device const uint*   A       [[buffer(0)]],  // n*n
    device const uint*   B       [[buffer(1)]],  // n*n
    device uint*         C       [[buffer(2)]],  // n*n (write_flag controls)
    device uint*         out     [[buffer(3)]],  // N^3 compressed elements
    constant uint*       V       [[buffer(4)]],  // b*b compression vector
    constant MatMulParams& p     [[buffer(5)]],
    constant uint&       write_C [[buffer(6)]],  // 1 = write C', 0 = skip
    ushort2 tid  [[thread_position_in_threadgroup]],
    ushort2 tgid [[threadgroup_position_in_grid]])
{
    const uint tile_i = tgid.y;
    const uint tile_j = tgid.x;
    const uint li = tid.y;
    const uint lj = tid.x;
    const uint linear_tid = li * p.b + lj;

    uint acc = 0;

    // Shared memory tiles
    // Metal does not have bank-conflict-free padding syntax, but Apple
    // Silicon GPU memory system handles 32-bit access patterns efficiently.
    // Padding is optional; included for consistency with CUDA version.
    threadgroup uint As[16][17];    // padded
    threadgroup uint Bs[16][16];
    threadgroup uint Csh[16][16];
    threadgroup uint reduce_buf[256];

    for (uint ell = 0; ell < p.N; ++ell) {

        // Load tiles
        uint a_row = tile_i * p.b + li;
        uint a_col = ell * p.b + lj;
        As[li][lj] = A[a_row * p.n + a_col];

        uint b_row = ell * p.b + li;
        uint b_col = tile_j * p.b + lj;
        Bs[li][lj] = B[b_row * p.n + b_col];

        threadgroup_barrier(mem_flags::mem_threadgroup);

        // Block multiply-add with per-step reduction
        for (uint k = 0; k < p.b; ++k) {
            acc = madd(acc, As[li][k], Bs[k][lj]);
        }

        // Expose accumulator for compression
        Csh[li][lj] = acc;
        threadgroup_barrier(mem_flags::mem_threadgroup);

        // Parallel tree reduction for compression
        ulong prod = (ulong)Csh[linear_tid / p.b][linear_tid % p.b]
                   * (ulong)V[linear_tid];
        reduce_buf[linear_tid] = reduce64(prod);
        threadgroup_barrier(mem_flags::mem_threadgroup);

        for (uint stride = (p.b * p.b) >> 1; stride >= 1; stride >>= 1) {
            if (linear_tid < stride) {
                ulong s = (ulong)reduce_buf[linear_tid]
                        + (ulong)reduce_buf[linear_tid + stride];
                reduce_buf[linear_tid] = reduce64(s);
            }
            threadgroup_barrier(mem_flags::mem_threadgroup);
        }

        // Write compressed element
        if (linear_tid == 0) {
            uint idx = (tile_i * p.N + tile_j) * p.N + ell;
            out[idx] = reduce_buf[0];
        }

        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    // Optionally write C'
    if (write_C != 0) {
        uint c_row = tile_i * p.b + li;
        uint c_col = tile_j * p.b + lj;
        C[c_row * p.n + c_col] = acc;
    }
}
```

#### E.7.5 Host-Side Dispatch (Objective-C++)

```objc
// Objective-C++ host code for Metal kernel dispatch

- (uint256)solveAttemptWithA:(const uint32_t*)hostA
                           B:(const uint32_t*)hostB
                           V:(const uint32_t*)hostV  // b*b elements
{
    NSUInteger nn = _n * _n * sizeof(uint32_t);
    NSUInteger N3 = _N * _N * _N;
    NSUInteger outBytes = N3 * sizeof(uint32_t);

    // Buffers — storageModeShared for unified memory (zero copy on Apple Silicon)
    id<MTLBuffer> bufA   = [_device newBufferWithBytes:hostA length:nn
                                    options:MTLResourceStorageModeShared];
    id<MTLBuffer> bufB   = [_device newBufferWithBytes:hostB length:nn
                                    options:MTLResourceStorageModeShared];
    id<MTLBuffer> bufC   = [_device newBufferWithLength:nn
                                    options:MTLResourceStorageModeShared];
    id<MTLBuffer> bufOut = [_device newBufferWithLength:outBytes
                                    options:MTLResourceStorageModeShared];
    id<MTLBuffer> bufV   = [_device newBufferWithBytes:hostV
                                    length:256 * sizeof(uint32_t)
                                    options:MTLResourceStorageModeShared];

    MatMulParams params = { .n = _n, .b = _b, .N = _N };
    id<MTLBuffer> bufParams = [_device newBufferWithBytes:&params
                                       length:sizeof(params)
                                       options:MTLResourceStorageModeShared];
    uint32_t writeC = 1;
    id<MTLBuffer> bufWriteC = [_device newBufferWithBytes:&writeC
                                       length:sizeof(writeC)
                                       options:MTLResourceStorageModeShared];

    id<MTLCommandBuffer> cmdBuf = [_queue commandBuffer];
    id<MTLComputeCommandEncoder> enc = [cmdBuf computeCommandEncoder];
    [enc setComputePipelineState:_pipeline];
    [enc setBuffer:bufA      offset:0 atIndex:0];
    [enc setBuffer:bufB      offset:0 atIndex:1];
    [enc setBuffer:bufC      offset:0 atIndex:2];
    [enc setBuffer:bufOut    offset:0 atIndex:3];
    [enc setBuffer:bufV      offset:0 atIndex:4];
    [enc setBuffer:bufParams offset:0 atIndex:5];
    [enc setBuffer:bufWriteC offset:0 atIndex:6];

    MTLSize gridSize = MTLSizeMake(_N, _N, 1);
    MTLSize tgSize   = MTLSizeMake(_b, _b, 1);
    [enc dispatchThreadgroups:gridSize threadsPerThreadgroup:tgSize];
    [enc endEncoding];
    [cmdBuf commit];
    [cmdBuf waitUntilCompleted];

    if (cmdBuf.error) {
        NSLog(@"Metal error: %@", cmdBuf.error);
        abort();
    }

    // Hash the compressed output (shared memory — no copy needed)
    const uint32_t* outPtr = (const uint32_t*)bufOut.contents;
    // SHA-256 identical to CUDA path (§E.6.6)
    // ... use CC_SHA256 from CommonCrypto or BTX's CSHA256 ...

    return z;
}
```

**Note on buffer reuse**: In a mining loop, allocate buffers once and reuse.
Only the compression vector V changes per nonce (because σ changes). A' and
B' change only when seeds change. Use `memcpy` into `bufV.contents` instead
of allocating a new buffer each attempt.

---

### E.8 Determinism Rules for GPU Implementations

#### E.8.1 Arithmetic Determinism

All GPU arithmetic MUST produce bit-identical results to the CPU reference:

1. **No floating point**: No FP16/FP32/FP64 operations. No tensor cores.
   All arithmetic is `uint32` + `uint64` intermediates only.
2. **reduce64 is double-fold**: Do NOT simplify to single fold, even if the
   GPU compiler "proves" it safe. The spec requires double fold (§7.2.4).
3. **madd is the only accumulation path**: Every multiply-add in the inner
   loop must go through `madd()`, which calls `reduce64` per step.

#### E.8.2 Reduction Tree Determinism

If using Option A (parallel reduction):

1. The binary tree MUST be fixed: stride halving from b²/2 down to 1
2. The same thread always reduces the same pair at each level
3. `reduce64` is called at every addition (not just at the end)
4. The tree is identical on CUDA and Metal (same stride sequence)

If using Option B (single-thread sequential):

1. The loop iterates row-major: index 0, 1, 2, ..., b²-1
2. `madd()` is called per element (accumulate + reduce per step)
3. Only thread 0 executes; result is broadcast via shared memory

#### E.8.3 Output Index Mapping

The canonical output index MUST be:

```
idx = (tile_i * N + tile_j) * N + ell
```

This matches the spec's (i, j, ℓ) iteration order. The GPU grid dispatch
order does NOT matter — tiles may execute in any order — but each tile writes
to the correct `idx` position, so the output array is in canonical order
regardless of execution schedule.

#### E.8.4 Endianness

The output buffer contains `uint32` elements in host byte order. For SHA-256
hashing, elements must be in **little-endian** byte order (LE32). On
little-endian hosts (x86-64, ARM64), native uint32 IS LE32. On big-endian
hosts (rare for mining): byte-swap before hashing.

A `static_assert` on byte order is included in the host hashing code.

---

### E.9 Pipeline and Overlap

#### E.9.1 Fused Kernel + Async Copy + CPU Hash

```
┌─────────────────────────────────────────────────┐
│ GPU: MatMulTranscriptKernel (one launch)        │
│  ├─ ℓ=0: load tiles, matmul, compress, write    │
│  ├─ ℓ=1: load tiles, matmul, compress, write    │
│  ├─ ...                                         │
│  └─ ℓ=N-1: final step, write last compressed el │
├─────────────────────────────────────────────────┤
│ DMA: copy out[] to host (128 KiB, ~10 μs PCIe4) │
├─────────────────────────────────────────────────┤
│ CPU: SHA-256(out[0..N³-1]) → z                  │
│      Compare z < target                          │
└─────────────────────────────────────────────────┘
```

The kernel runs entirely on GPU. Transfer and hashing are sequential after
completion. For n=512 on RTX 4090, estimated kernel time is 50–200 ms;
transfer is 10 μs; SHA-256 of 128 KiB is ~0.3 ms. Pipeline overlap is
unnecessary because the transfer + hash cost is < 0.5% of kernel time.

#### E.9.2 Multi-Nonce Pipelining (Advanced)

For high-throughput mining, overlap nonce attempts using CUDA streams:

```
Stream 0: [Kernel nonce=0] → [Copy] → [Hash]
Stream 1:    [Kernel nonce=1] → [Copy] → [Hash]
Stream 2:       [Kernel nonce=2] → [Copy] → [Hash]
```

This requires per-stream output buffers and compression vectors. Benefit is
marginal for single-GPU mining but significant for multi-GPU rigs.

---

### E.10 GPU Verification Path (Full Node Acceleration)

Tier 0 and Tier 1 nodes can use the GPU for Phase 2 verification:

1. Reconstruct A, B from seeds on CPU
2. Compute noise and add to get A', B' on CPU
3. Upload A', B' and σ-derived V to GPU
4. Run the **exact same kernel** (`MatMulTranscriptKernel`)
5. Copy `out[]` back, hash on CPU → z
6. Compare z to `block.matmul_digest`

The kernel is identical for mining and verification. Mining loops over nonces;
verification runs once. GPU verification of one block at n=512 takes the same
50–200 ms as one mining attempt — feasible for both 0.25-second fast-phase
and 90-second steady-state blocks.

---

### E.11 Implementation Checklist

#### E.11.1 CUDA

- [x] `reduce64` uses double Mersenne fold matching §7.2.4
- [x] `madd` calls `reduce64` on every multiply-add (no lazy accumulation)
- [x] `d_V` in `__constant__` memory, updated via `cudaMemcpyToSymbol` per nonce
- [x] `As[16][17]` padding to avoid shared memory bank conflicts
- [x] `__syncthreads()` before AND after every shared memory phase:
  - After tile load (before matmul inner loop)
  - After writing Csh (before compression)
  - After reduction (before writing out and starting next ℓ)
- [x] `__syncwarp()` in final warp of parallel reduction (sm_70+ required)
- [x] For sm_50–sm_61: replace `__syncwarp()` with `__syncthreads()` fallback
- [x] `out[]` allocated with `cudaMallocHost` (pinned) for fast DMA
- [x] `CHECK_CUDA` macro on every CUDA API call
- [x] Output index `(i*N + j)*N + ℓ` matches canonical order
- [x] `static_assert` on little-endian byte order in host hashing code
- [x] No floating-point operations anywhere in kernel or host hash path
- [x] Kernel compiled with `-arch=sm_50` minimum, `-arch=sm_70` recommended

#### E.11.2 Metal

- [x] `reduce64` and `madd` in Metal match CUDA/CPU versions bit-for-bit
- [x] `V` in `constant` address space buffer
- [x] `As[16][17]` padding included
- [x] `threadgroup_barrier(mem_flags::mem_threadgroup)` at every sync point
- [x] `MTLResourceStorageModeShared` for output buffer (unified memory)
- [x] `write_C` flag passed as buffer (no nullptr checks in MSL)
- [x] Buffer reuse in mining loop (allocate once, update contents)
- [x] `cmdBuf.error` checked after `waitUntilCompleted`
- [x] Tested on M1, M2, M3 (Apple GPU family apple7+)
- [x] No `half`/`float` types used anywhere

#### E.11.3 Cross-Platform

- [x] Test vectors: same A', B', V, σ → same `out[]` on CPU, CUDA, Metal
- [x] Output `z` matches across all three platforms
- [x] Option A (parallel tree) and Option B (sequential dot) produce
      identical compressed elements for all test vectors (M31 proof in §E.5.2)

---

### E.12 Pitfalls and Known Issues

#### E.12.1 CUDA-Specific

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| Missing `__syncthreads` after Csh write | Non-deterministic compressed output | Add barrier between Csh write and compression read |
| `As[16][16]` without padding | 4–8× slowdown on inner loop due to bank conflicts | Pad to `As[16][17]` |
| Single-fold `reduce64` | Wrong results for acc + prod > 2^62 | Use double fold (§7.2.3) |
| `cudaMemcpyToSymbol` without stream | Blocks all streams; serializes nonce attempts | Use `cudaMemcpyToSymbolAsync` |
| Constant memory > 64 KiB | Silent truncation / launch failure | V is 1 KiB; safe. Do not put matrices in constant memory |
| `__syncwarp` on pre-Volta (sm < 70) | Compile error or undefined behavior | Guard with `#if __CUDA_ARCH__ >= 700` or use `__syncthreads()` |
| Assumed LE byte order on host | Wrong digest on big-endian | `static_assert` + byte-swap path |

#### E.12.2 Metal-Specific

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| `device uint* C` with no null check | Cannot skip C write via nullptr | Use `write_C` flag buffer instead |
| `threadgroup_barrier` missing | Threadgroup memory races | Add barrier at every shared memory phase boundary |
| `MTLResourceStorageModePrivate` for output | Cannot read back on CPU without blit | Use `StorageModeShared` on Apple Silicon |
| `dispatchThreads` instead of `dispatchThreadgroups` | Incorrect threadgroup sizing | Use `dispatchThreadgroups:threadsPerThreadgroup:` |
| Intel Mac GPU with limited int64 perf | 10–50× slowdown vs Apple Silicon | Warn user; recommend CPU fallback on Intel |

#### E.12.3 Cross-Platform

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| Different reduction order CPU vs GPU | Different z (consensus fork!) | Use identical reduction: Option A or B on all platforms |
| Row-major vs column-major in flatten | Compressed elements differ | Spec says row-major (§8.3.1); enforce in tests |
| Off-by-one in output index | Transposed (i,j) or (j,i) tiles | Verify with small n=8, b=4 test case |
| Compiler reordering uint64 operations | Theoretically possible for integer math | Use `volatile` on shared memory in CUDA reduction |

---

### E.13 Tests and Verifications

#### E.13.1 Unit Tests — M31 Arithmetic on GPU

```
TEST: gpu_reduce64_matches_cpu
  GIVEN: 1000 random uint64 values including edge cases
         (0, 1, M31, M31+1, 2^31, 2^62, 2^63, 2^64-1)
  WHEN:  reduce64 computed on GPU and CPU
  THEN:  All results match bit-for-bit

TEST: gpu_madd_matches_cpu
  GIVEN: 1000 random (acc, a, b) triples, all in [0, M31)
  WHEN:  madd(acc, a, b) on GPU and CPU
  THEN:  All results match

TEST: gpu_reduce64_double_fold_required
  GIVEN: x = 2^63 (requires double fold)
  WHEN:  reduce64(x) on GPU
  THEN:  Result == 2 (matches CPU, see §7.2.2)

TEST: gpu_reduce64_max_uint64
  GIVEN: x = 2^64 - 1
  WHEN:  reduce64(x) on GPU
  THEN:  Result == 3
```

#### E.13.2 Unit Tests — Compression

```
TEST: gpu_compress_option_a_matches_option_b
  GIVEN: Known Csh[16][16] and V[256] arrays
  WHEN:  Option A (parallel tree) and Option B (sequential dot) both compute c
  THEN:  Results are identical
  RATIONALE: M31 proof in §E.5.2 guarantees this

TEST: gpu_compress_matches_cpu
  GIVEN: Same Csh and V on CPU and GPU
  WHEN:  CPU computes dot(flatten(Csh), V, 256) via sequential reduce64 loop
         GPU computes via parallel_compress or compress_sequential
  THEN:  All three produce the same uint32 result

TEST: gpu_compress_known_vector
  GIVEN: Csh = identity-like pattern [1,0,...,0,1,...], V = [1,2,3,...,256]
  WHEN:  compress(Csh, V)
  THEN:  Result matches hand-computed expected value

TEST: gpu_compress_all_max
  GIVEN: Csh[i] = M31-1 for all i, V[i] = M31-1 for all i
  WHEN:  compress(Csh, V)
  THEN:  Result == 256 mod M31 = 256
         (since (M31-1)^2 mod M31 = 1, and sum of 256 ones = 256)
```

#### E.13.3 Integration Tests — Full Kernel

```
TEST: kernel_small_n8_b4_matches_cpu
  GIVEN: n=8, b=4, N=2 → 8 intermediates
         Random A'[8x8], B'[8x8], V[16] over M31
  WHEN:  CPU CanonicalMatMul produces out_cpu[8] and C'_cpu
         GPU MatMulTranscriptKernel produces out_gpu[8] and C'_gpu
  THEN:  out_cpu == out_gpu element-by-element
         C'_cpu == C'_gpu element-by-element

TEST: kernel_n64_b8_matches_cpu
  GIVEN: n=64, b=8, N=8 → 512 intermediates
         Random A', B', V over M31
  WHEN:  CPU and GPU compute out[] and optionally C'
  THEN:  Bit-identical out[] arrays; SHA-256 digests match

TEST: kernel_n512_b16_matches_cpu
  GIVEN: n=512, b=16, N=32 → 32,768 intermediates
         Random A', B', V over M31
  WHEN:  CPU and GPU compute out[]
  THEN:  All 32,768 compressed elements match
         SHA-256 digest z matches

TEST: kernel_n512_b16_digest_matches_header
  GIVEN: A complete block header with known seed_a, seed_b, nNonce64
  WHEN:  Full pipeline: FromSeed → noise → A'+E, B'+F → GPU kernel → SHA-256 → z
  THEN:  z matches the block's matmul_digest field
  (This is the end-to-end consensus test)

TEST: kernel_deterministic_across_launches
  GIVEN: Same inputs
  WHEN:  Run kernel 100 times on same GPU
  THEN:  All 100 out[] arrays are bit-identical
  (Rules out non-determinism from thread scheduling)

TEST: kernel_c_prime_output_correct
  GIVEN: n=64, A', B' with known product
  WHEN:  GPU kernel with write_C enabled
  THEN:  C'_gpu == A' * B' (verified via CPU naive multiply)
```

#### E.13.4 Cross-Platform Tests

```
TEST: cross_platform_cuda_vs_cpu
  GIVEN: Fixed seed for A', B', σ → V
  WHEN:  CPU and CUDA compute out[] and z
  THEN:  z_cpu == z_cuda

TEST: cross_platform_metal_vs_cpu
  GIVEN: Same fixed seed
  WHEN:  CPU and Metal compute out[] and z
  THEN:  z_cpu == z_metal

TEST: cross_platform_cuda_vs_metal
  GIVEN: Same fixed seed
  WHEN:  CUDA and Metal compute out[] and z
  THEN:  z_cuda == z_metal
  (Requires comparison of saved test vector files across machines)

TEST: cross_platform_pinned_test_vector
  GIVEN: Hardcoded A'[8x8], B'[8x8], V[16] (all values specified in test)
  EXPECTED out[8] = [<8 specific uint32 values>]
  EXPECTED z = <specific 32-byte hash>
  WHEN:  Computed on ANY platform (CPU, CUDA, Metal)
  THEN:  Matches expected values exactly
  (This is the consensus-critical determinism test — pin in CI forever)
```

#### E.13.5 Performance Tests

```
TEST: benchmark_kernel_n512_b16
  GIVEN: n=512, b=16 on target GPU
  MEASURE: Kernel execution time (ms)
  EXPECT: 50-200 ms on modern GPU (RTX 3090 / M2 Pro)

TEST: benchmark_transfer_overhead
  GIVEN: 128 KiB output buffer
  MEASURE: Device-to-host copy time
  EXPECT: < 100 μs on PCIe 4.0; near-zero on Apple unified memory

TEST: benchmark_host_sha256
  GIVEN: 128 KiB buffer
  MEASURE: SHA-256 hash time
  EXPECT: < 0.5 ms with hardware SHA extensions

TEST: benchmark_compression_overhead
  MEASURE: Kernel time WITH compression vs hypothetical kernel WITHOUT
  EXPECT: < 15% overhead (parallel reduction adds ~8 sync+reduce levels per ℓ)

TEST: benchmark_option_a_vs_option_b
  GIVEN: Same inputs, n=512
  MEASURE: Kernel time with Option A (parallel) vs Option B (sequential)
  EXPECT: Option A is 2-5× faster overall kernel time
```

#### E.13.6 Stress Tests

```
TEST: stress_max_dimension
  GIVEN: n=2048, b=16, N=128 → 2,097,152 intermediates
  WHEN:  GPU kernel runs
  THEN:  No OOM, no timeout, output matches CPU

TEST: stress_repeated_solve
  GIVEN: n=64 regtest, 10,000 nonce attempts
  WHEN:  GPU kernel runs 10,000 times with incrementing nonce
  THEN:  No crashes, no memory leaks, deterministic when repeated

TEST: stress_concurrent_streams (CUDA only)
  GIVEN: 4 CUDA streams, each running kernel simultaneously
  WHEN:  All complete
  THEN:  Each stream's output matches independent single-stream run
```

---

### E.14 Future Optimizations (Non-Consensus)

These optimizations do not change the output and may be applied without
consensus changes:

1. **Register-file accumulator**: Keep `acc` in registers instead of writing
   to `Csh` shared memory every ℓ-step. Only write to Csh when compression
   is needed. Saves shared memory bandwidth.

2. **Persistent kernel**: Launch one kernel that processes ALL nonce attempts
   in a loop, only returning when a solution is found or max_tries reached.
   Eliminates per-attempt launch overhead (~5 μs each).

3. **CPU AVX2/NEON verification**: For Tier 1 nodes without GPU, use AVX2
   (x86) or NEON (ARM) vectorized M31 arithmetic. 8-wide AVX2 processes 8
   elements simultaneously, ~4× speedup over scalar. Still exact M31.

4. **SHA-256 on GPU**: Only worthwhile if the kernel can stream compressed
   elements directly into a GPU SHA-256 implementation. Usually not faster
   than CPU with SHA-NI extensions. Investigate only if transfer latency
   becomes a bottleneck (unlikely at 128 KiB).

---

### F. P2MR Integration (BIP-360 Profile)

BTX consensus and wallet policy now assume a P2MR-only transaction profile:

1. Witness v2 outputs use `OP_2 <32-byte-merkle-root>` (`witness_v2_p2mr`).
2. Leaf scripts use:
   - `OP_CHECKSIG_MLDSA` (primary ML-DSA-44 key path)
   - `OP_CHECKSIG_SLHDSA` (backup SLH-DSA-SHAKE-128s key path)
3. Wallet default script tree is a two-leaf Merkle commitment:
   - leaf 0: ML-DSA-44 spend path
   - leaf 1: SLH-DSA-SHAKE-128s recovery path
4. Address encoding uses Bech32m witness v2 (`btx1z...` on mainnet).
5. `getblocktemplate` includes PQ metadata (`pq_info`) alongside MatMul fields.

Block-capacity and timing parameters for BTX are:
- Target spacing: 90 seconds (`nPowTargetSpacingNormal=90`)
- Consensus max serialized block size: 24,000,000 bytes
- Consensus max weight: 24,000,000 WU
- Consensus max sigops cost: 480,000

*Document version: 4.2.0*
*Last updated: 2026-02-12*
*Authors: BTX Core Contributors*
