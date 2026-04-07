# MatMul Freivalds Transcript Binding Optimization

**Status**: Historical design and rollout document
**Date**: 2026-04-02

## Current Source Of Truth

This document records the original product-digest rollout plan and the first
implementation pass. It is no longer the authoritative source for the live
post-`61000` mining contract because the initial rollout exposed a separate
miner/validator digest mismatch at the activation boundary.

Use [BTX MatMul Product-Digest Mining Fix](btx-matmul-product-digest-mining-fix-2026-04-03.md)
for the current root-cause analysis, fix design, and regression coverage.

## Implementation Status

This document started as the design plan for the product-committed digest
transition. The branch now carries the implementation. The sections below remain
useful as design context, but the current status is:

- Product-digest activation is height-gated and live-network-aware. Mainnet-style
  enforcement now treats the Freivalds `C'` payload as consensus-required at and
  above `nMatMulProductDigestHeight` even when the legacy static
  `fMatMulRequireProductPayload` flag is `false`.
- Post-activation validation no longer falls back to legacy O(n^3) transcript
  recomputation. Phase 2 gating, IBD counting, and mining policy all short-circuit
  once the product-digest path is active.
- Regtest exposes `-regtestmatmulproductdigestheight` so activation-boundary and
  assumevalid sync behavior can be tested directly.
- Non-Metal builds now implement the async digest submission stubs required by the
  accelerated solver, so `BTX_ENABLE_METAL=OFF` builds link and run correctly.
- Compact-block relay is now explicitly payload-aware. At payload-required heights
  peers no longer announce or serve `cmpctblock` for those blocks, and receivers
  fall back to full-block fetch instead of attempting payload-less reconstruction.
- Targeted coverage now includes unit tests for activation gating and post-activation
  Phase 2 shutdown, backend capability tests for async stub parity, and functional
  tests that mine across the activation boundary and verify live-style peer relay.

## Merge Readiness

This section is historical. The original rollout described here later required
a follow-on mining contract fix so that post-activation nonce scanning targeted
the same product digest validators enforce at `61000`. The fixed contract has
since been proven against the real stalled mainnet datadir by mining live blocks
`61000`, `61001`, and `61002`.

## Problem Statement

Peer nodes on the btx mainnet consistently lag 30-65 blocks behind the mining
node.  Root cause: every block validation runs **both** Freivalds O(n^2) *and*
the full Phase 2 O(n^3) transcript recomputation, making the Freivalds fast-path
dead code in practice.

### Current validation flow (pow.cpp:1899-1974)

```
CheckMatMulProofOfWork_Freivalds(block, params, height)
  1. Reconstruct A', B' from seeds + noise        — O(n^2)
  2. Deserialise C' from block.matrix_c_data       — O(n^2)
  3. Freivalds verify A'*B' == C'  (k=2 rounds)   — O(k*n^2)
  4. IF require_transcript_binding:                 ← ALWAYS true post-binding
       CheckMatMulProofOfWork_Phase2(block, ...)   — O(n^3)  *** redundant ***
```

Step 4 exists because the `matmul_digest` (the PoW hash that must beat the
difficulty target) is defined as the *transcript hash* — a hash over every
intermediate block-level partial sum during the canonical (i,j,ell) accumulation
loop.  Freivalds proves A'\*B'=C' but says nothing about the transcript, so a
miner could submit a valid C' with an arbitrary low digest.

### Impact (n=512, b=16)

| Metric | Value |
|--------|-------|
| Block products per Phase 2 call | (512/16)^3 = 32,768 |
| Estimated Phase 2 wall-time (cloud VPS, no AMX) | 1.5 – 3.0 s |
| Validation window (`nMatMulValidationWindow`) | 1,000 blocks |
| Peer budget (`nMatMulPeerVerifyBudgetPerMin`) | 32/min |
| Time for a 65-block-behind peer to catch up | ~100–200 s compute + budget wait |

The M4 Max mines faster than VPS peers can validate, so the gap widens over
time.

---

## Proposed Solution: Product-Committed Digest

Historical note: the exact digest definition in the section below is the first
rollout design, not the final live fix. That version tried to bind the full
`C'` matrix directly, which later proved to be the wrong mining contract
because it pushed nonce scanning toward a near-canonical per-candidate cost.

The current fix keeps the same activation goals but hashes the sigma-bound
compressed final block image of `C'` instead. See
[BTX MatMul Product-Digest Mining Fix](btx-matmul-product-digest-mining-fix-2026-04-03.md)
for the live design.

Replace the transcript-dependent digest with a **product-committed digest** that
can be verified in O(n^2) using Freivalds, eliminating the need for Phase 2
during verification entirely.

### New digest definition

```
digest = SHA256d(sigma || A'_commitment || B'_commitment || C'_flat || dim_le32)
```

Where:
- `sigma` = existing block header nonce/seed (already binds A', B' via noise
  derivation)
- `A'_commitment`, `B'_commitment` = SHA256 of the serialised perturbed matrices
  (already deterministic from sigma + seed_a + seed_b)
- `C'_flat` = the full n*n product matrix serialised in row-major order (carried
  in `block.matrix_c_data`)
- `dim_le32` = the matrix dimension as a 4-byte LE integer

### Why this is secure

1. **Work binding**: Computing C' = A'\*B' still requires O(n^3) (or
   O(n^{omega}) with fast algorithms).  The noise injection from sigma prevents
   precomputation and easy-matrix attacks — this is the same mechanism used in
   the cuPOW paper (Komargodski et al., 2025, arXiv:2504.09971).

2. **Digest binding**: The digest is a deterministic function of (sigma, A', B',
   C').  A miner cannot vary the digest without changing C', which would fail
   Freivalds.  A miner cannot vary C' without changing the digest, which would
   fail the target check.

3. **No algorithm binding needed**: The current transcript hash forces miners to
   use the specific (i,j,ell) block accumulation order.  This is unnecessarily
   restrictive — PoW security requires that *some* O(n^omega) work was done, not
   that a specific algorithm was used.  Allowing Strassen or other fast
   algorithms is acceptable; the work floor is still superquadratic.

4. **Freivalds sufficiency**: With k=2 rounds over GF(2^31-1), Freivalds error
   probability is < 2^{-62} — cryptographically negligible.  If A'\*B' != C',
   verification fails with overwhelming probability.

### New validation flow

```
CheckMatMulProofOfWork_ProductCommitted(block, params, height)
  1. Reconstruct A', B' from seeds + noise        — O(n^2)
  2. Deserialise C' from block.matrix_c_data       — O(n^2)
  3. Compute digest = SHA256d(sigma || ... || C')   — O(n^2)
  4. Check digest <= target                         — O(1)
  5. Freivalds verify A'*B' == C'  (k=2 rounds)   — O(k*n^2)
  TOTAL: O(n^2)  — 32x faster than current O(n^3) for n=512, b=16
```

---

## Activation Strategy

This is a consensus rule change.  Use a **height-gated activation** consistent
with existing btx activation patterns (cf. `nMatMulFreivaldsBindingHeight`).

### Consensus parameter additions (consensus/params.h)

```cpp
/** Height at which the product-committed digest replaces the transcript
 *  digest for PoW validation.  Below this height the legacy transcript
 *  check remains authoritative. */
int32_t nMatMulProductDigestHeight{std::numeric_limits<int32_t>::max()};
```

### Validation logic (pow.cpp)

```
if (block_height >= params.nMatMulProductDigestHeight) {
    // New path: product-committed digest, O(n^2) verification
    return CheckMatMulProofOfWork_ProductCommitted(block, params, height);
} else {
    // Legacy path: transcript digest, existing Phase 1 + Phase 2 / Freivalds
    return CheckMatMulProofOfWork_Legacy(block, params, height);
}
```

### Mining changes (pow.cpp SolveMatMul)

At or above `nMatMulProductDigestHeight`, the miner:
1. Picks sigma (nonce grinding loop)
2. Derives A', B' from sigma + seeds + noise
3. Computes C' = A' * B' via any algorithm (canonical, Strassen, etc.)
4. Computes digest = SHA256d(sigma || commitments || C'_flat || dim)
5. If digest <= target: solution found
6. Else: increment nonce, goto 1

The C' payload (already present in `block.matrix_c_data`) becomes mandatory for
blocks at the activation height and above.

---

## Implementation Plan

### Phase 1: Core consensus change

| # | Task | Files | Complexity |
|---|------|-------|------------|
| 1.1 | Add `nMatMulProductDigestHeight` to consensus params | `src/consensus/params.h`, `src/kernel/chainparams.cpp` | Low |
| 1.2 | Implement `ComputeProductCommittedDigest()` | `src/matmul/transcript.cpp` | Medium |
| 1.3 | Implement `CheckMatMulProofOfWork_ProductCommitted()` | `src/pow.cpp` | Medium |
| 1.4 | Gate validation: product-committed vs legacy by height | `src/pow.cpp`, `src/validation.cpp` | Medium |
| 1.5 | Update `SolveMatMul()` to use product-committed digest post-activation | `src/pow.cpp` | Medium |
| 1.6 | Make C' payload mandatory at activation height | `src/pow.cpp`, `src/primitives/block.h` | Low |

### Phase 2: Verification budget simplification

| # | Task | Files | Complexity |
|---|------|-------|------------|
| 2.1 | Remove Phase 2 budget tracking for post-activation blocks | `src/pow.cpp` | Low |
| 2.2 | Simplify `ShouldRunMatMulPhase2Validation()` to return false post-activation | `src/pow.cpp` | Low |
| 2.3 | Update IBD validation path — no Phase 2 needed for product-committed blocks | `src/validation.cpp` | Medium |

### Phase 3: Testing

| # | Task | Files | Complexity |
|---|------|-------|------------|
| 3.1 | Unit tests: `ComputeProductCommittedDigest()` round-trip | `src/test/matmul_tests.cpp` | Medium |
| 3.2 | Unit tests: product-committed PoW check accepts valid, rejects invalid C' | `src/test/pow_tests.cpp` | Medium |
| 3.3 | Unit tests: height-gated activation — legacy below, product above | `src/test/pow_tests.cpp` | Medium |
| 3.4 | Unit tests: tampered digest rejected, tampered C' rejected | `src/test/pow_tests.cpp` | Medium |
| 3.5 | Fuzz target: product-committed digest with random matrices | `src/test/fuzz/` | Medium |
| 3.6 | Integration test: mine blocks across activation boundary | `btx-node/test/functional/` | High |
| 3.7 | Integration test: IBD sync across activation boundary | `btx-node/test/functional/` | High |
| 3.8 | Regression test: legacy blocks still validate correctly | `src/test/pow_tests.cpp` | Low |

### Phase 4: Benchmarks

| # | Task | Files | Complexity |
|---|------|-------|------------|
| 4.1 | Benchmark: Phase 2 (legacy) vs product-committed verification wall-time | `src/bench/matmul.cpp` | Medium |
| 4.2 | Benchmark: end-to-end block validation (legacy vs product-committed) | `src/bench/matmul.cpp` | Medium |
| 4.3 | Benchmark: IBD sync rate with product-committed blocks | Manual test | High |
| 4.4 | Benchmark: peer catch-up latency before/after on VPS hardware | Manual test | High |

### Phase 5: Mainnet activation

| # | Task | Description |
|---|------|-------------|
| 5.1 | Set `nMatMulProductDigestHeight` to target height (e.g. current tip + 200) | Params update |
| 5.2 | Deploy updated binary to all known peers | Ops |
| 5.3 | Monitor activation boundary — verify all peers cross cleanly | Ops |
| 5.4 | Verify peer sync lag resolves post-activation | Monitoring |

---

## Security Analysis

### Attack vectors considered

| Attack | Mitigated by |
|--------|-------------|
| Submit valid C' with arbitrary low digest | Digest is SHA256d(... \|\| C'_flat \|\| ...) — changing digest requires changing C', which fails Freivalds |
| Submit invalid C' that happens to hash low | Freivalds rejects with probability > 1 - 2^{-62} |
| Precompute C' for many (A,B) pairs | Noise injection from sigma makes A', B' unpredictable until sigma is chosen |
| Use easy matrices (sparse, zero, identity) | Noise rank r=8 ensures A', B' are dense regardless of base seeds |
| Use fast algorithms (Strassen) to reduce work | Acceptable — work is still O(n^{2.37}) which is superquadratic; PoW security holds |
| Grind sigma to get favourable A', B' | Pre-hash epsilon gate (10 bits) already rate-limits sigma attempts before matmul |

### What changes for miners

- Miners MAY use any correct matrix multiplication algorithm (not forced into
  the specific (i,j,ell) block order)
- Miners MUST include the full C' payload in the block
- The nonce-grinding loop structure remains the same
- Expected mining throughput is unchanged (dominated by the O(n^3) multiply, not
  the O(n^2) digest computation)

### What changes for verifiers

- Verification drops from O(n^3) to O(n^2) — approximately **32x speedup** for
  n=512, b=16
- Legacy blocks (below activation height) continue to use the existing
  validation path unchanged
- No changes to block serialisation format (C' payload field already exists)

---

## References

- Komargodski et al., "Proofs of Useful Work from Arbitrary Matrix
  Multiplication", arXiv:2504.09971, April 2025
- Freivalds' algorithm: O(n^2) probabilistic matrix product verification
- GKR protocol (Goldwasser-Kalai-Rothblum): interactive proofs for arithmetic
  circuits — considered but rejected due to implementation complexity
- zkMatrix (ePrint 2024/161): zk-SNARK for matrix multiplication — considered
  but rejected due to trusted setup requirement and implementation complexity

---

## Open Questions

1. **Activation height**: What lead time do peers need to upgrade?  Suggest
   current tip + 200 blocks minimum.
2. **C' payload size**: At n=512, C' is 512\*512\*4 = 1 MB.  This is already
   carried in blocks with Freivalds payloads.  Confirm this is acceptable as
   mandatory.
3. **Strassen acceptability**: Confirm that allowing fast matrix multiplication
   algorithms is acceptable for the project's goals.  The PoW work floor drops
   from O(n^3) to O(n^{2.37}) but remains superquadratic.
4. **Backward compatibility**: Nodes running old software will reject
   post-activation blocks (different digest computation).  This is a hard fork —
   confirm this is acceptable given the small, controlled network.
