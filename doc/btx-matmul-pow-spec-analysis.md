> **Note**: This document is a historical analysis. Current values: 24 MB serialized, 24 MWU weight, 480k sigops, 90s blocks. See README.md for current parameters.

# BTX MatMul PoW Specification: Deep Analysis Report

**Document analyzed:** `doc/btx-matmul-pow-spec.md`
**Analysis date:** 2026-02-10
**Scope:** Security, scalability, performance, development readiness

---

## Executive Summary

The BTX MatMul PoW specification is an **exceptionally thorough, production-grade engineering document** that translates the academic cuPOW protocol (Komargodski, Schen, Weinstein -- arXiv:2504.09971) into a concrete blockchain implementation. At ~5,000 lines across 18 sections plus appendices, it covers field arithmetic, matrix operations, noise generation, transcript compression, mining integration, two-phase validation with graduated DoS mitigation, difficulty adjustment, monetary policy, a four-tier trust model, block capacity, GPU kernel fusion, and a 168-test verification suite.

### Overall Verdict: **READY FOR DEVELOPMENT with noted caveats**

The specification is development-ready for v1 (seeded matrices). The critical caveats are:

1. **The underlying security conjecture is unproven** -- the "direct-product conjecture for random rank-r matrix products" is novel to the source paper and has not been independently validated by the cryptographic community
2. **No production deployment of MatMul PoW exists anywhere** -- BTX would be first-mover
3. **Cross-platform determinism is the highest implementation risk** -- the spec correctly identifies this but the proof is in the testing
4. **Genesis difficulty calibration** requires empirical benchmarking (acknowledged as open item)

---

## 1. Security Analysis

### 1.1 Foundational Security: The Hardness Assumption

**Finding: HIGH RISK (theoretical), MEDIUM RISK (practical)**

The cuPOW protocol's security rests on Assumption 6.4 from the source paper: the "direct-product conjecture for random rank-r matrix products." This conjecture asserts that computing all intermediate values when multiplying two random n x n rank-r matrices cannot be done faster than O(n^(omega_r+1)/r).

**Assessment:**
- This is a **novel, unproven conjecture** unique to this paper. It does not correspond to any previously named or well-studied hardness assumption
- The paper has **not been published at a peer-reviewed venue** (remains arXiv/IACR preprint as of Feb 2026, ~10 months after initial posting)
- **No independent cryptanalysis** has been published -- neither confirming nor refuting the conjecture
- The authors themselves acknowledge: "we believe our conjecture holds, unless significant algorithmic breakthrough is obtained"

**Practical mitigation in the spec:** The spec correctly positions v1 as using seeded (random) matrices rather than arbitrary matrices. With random matrices, the transcript is computationally indistinguishable from random data, making the security posture closer to a standard hash-based PoW where SHA-256 preimage resistance is the binding mechanism. The noise injection + transcript compression + SHA-256d chain creates a defense-in-depth architecture where an attacker would need to break multiple independent primitives.

**Recommendation:** The spec should explicitly document that v1's security does NOT depend solely on the direct-product conjecture -- it also depends on SHA-256 preimage resistance and the binding properties of Carter-Wegman compression. This layered security argument is implicit in the design but should be made explicit for auditors.

### 1.2 Transcript Compression Security (Carter-Wegman)

**Finding: SOUND**

The compression scheme uses a Carter-Wegman inner product over M31: `c = dot(flatten(C_block), v, b^2)` where v is a sigma-derived pseudorandom vector. This is a well-established construction dating to Carter & Wegman (1979), deployed at internet scale in Poly1305-AES, GMAC, and UMAC.

**Security properties verified:**
- Collision probability per block pair: 1/q = 1/(2^31 - 1) ~= 4.65 x 10^-10 -- adequate for 32,768 intermediates per mining attempt
- The compression vector v depends on sigma (derived from the block header), preventing a miner from pre-selecting a favorable v
- Domain separation via "matmul-compress-v1" prefix prevents cross-contamination with noise derivation
- The spec includes a 10,000-trial collision binding test (Section 8.3.1) -- appropriate for empirical validation

**Concern:** The compression reduces each b x b = 256-element intermediate to a single M31 element (31 bits). This means two distinct intermediates have a ~2^-31 probability of producing the same compressed value. Over 32,768 intermediates per attempt, the probability of ANY collision is ~32,768/2^31 ~= 1.5 x 10^-5 per attempt. This is acceptable for PoW (a collision in compression does not help a miner; the full SHA-256d transcript hash is still 256 bits). The spec correctly analyzes this.

### 1.3 Seed Grinding Analysis

**Finding: CORRECTLY IDENTIFIED AS NON-VULNERABILITY**

Section 18.4 correctly argues that seed grinding (trying different seed_a/seed_b pairs) is equivalent to nonce grinding because:
1. Every seed change requires full O(n^3) recomputation
2. sigma = SHA-256(header) makes seed space unpredictable
3. Both axes (nonce, seed) are equally expensive to explore

This analysis is correct. The two-axis search space is effectively one-dimensional because the cost per exploration step is identical on both axes.

### 1.4 Easy-Matrix Attack (v1 Specific)

**Finding: ADEQUATELY MITIGATED**

In v1, matrices are seed-derived (pseudorandom). A miner could theoretically choose seeds that produce structured matrices (e.g., sparse, low-rank). The noise injection (E = E_L * E_R, F = F_L * F_R with rank r) perturbs the matrices, making the noisy product A' * B' computationally equivalent regardless of the structure of A and B. The transcript of the noisy multiplication is what gets hashed.

**Residual concern:** If a miner finds a seed that produces A = 0 (all zeros), the multiplication reduces to E * B' + noise terms, which costs O(n^2 * r) instead of O(n^3). However, for SHA-256-derived pseudorandom matrices, the probability of producing an all-zero n x n matrix is (1/q)^(n^2) = (1/2^31)^(512^2) -- astronomically unlikely. This is not a practical concern for v1.

### 1.5 Verification Flooding (DoS)

**Finding: EXCELLENT DESIGN**

The two-phase validation with graduated punishment (Section 10) is one of the strongest aspects of the spec:

- **Phase 1 (microseconds):** Checks dimension bounds, digest < target, non-null seeds. Catches trivially invalid blocks before any expensive computation
- **Phase 2 (O(n^3)):** Full transcript recomputation, only after Phase 1 passes
- **Graduated punishment:** disconnect -> discourage -> ban over 24h rolling window
- **Network maturity flag:** `fMatMulStrictPunishment` allows graceful transition from lenient (early network) to strict (mature network) punishment
- **Testnet never bans:** Correct -- testnet exists for finding the bugs that graduated punishment protects against

The rationale in Section 10.2.7 is exceptionally well-argued, citing real-world precedents from Bitcoin, Ethereum, and ProgPoW deployments where early implementation mismatches caused network partitions.

**Minor suggestion:** The per-peer rate limit (`nMatMulPeerVerifyBudgetPerMin`) default value is not specified in the consensus parameters table. It should be pinned (suggested: 6-10 per minute at steady-state 90s blocks).

### 1.6 M31 Field Arithmetic Security

**Finding: SOUND with known implementation pitfalls**

M31 = 2^31 - 1 is a well-studied Mersenne prime used in production by StarkWare (Stwo prover, live on Starknet mainnet) and Polygon Labs (Plonky3). The field size is adequate for the BTX use case because:

- q > n^2 for n <= 46,340 (spec correctly notes this in Section 7.1)
- The Carter-Wegman compression collision bound 1/q ~= 2^-31 is sufficient for PoW (not for general-purpose authentication, but PoW does not require it)
- 32-bit elements enable native uint32 operations on all target architectures, including GPU

**Known implementation pitfalls from production M31 deployments (StarkWare/Polygon):**
1. **Dual-zero representation:** Both 0 and 0x7FFFFFFF represent zero mod M31. The spec's `reduce64` double-fold (Section 7.2.3-7.2.4) correctly handles this by always producing canonical [0, q) output
2. **Overflow in accumulation:** The spec mandates per-step reduction in `dot()` (Section 7.2.5), which prevents accumulator overflow. This is the correct approach -- the spec even includes a test (`naive_accumulation_unsafe`) that demonstrates the failure mode
3. **The Plonky3 FRI verifier vulnerability (GHSA-f69f-5fx9-w9r9, June 2025)** was a protocol-layer bug, not an M31 arithmetic bug. No CVEs exist for M31 field arithmetic implementations

**The spec's arithmetic is correctly specified.** The double Mersenne fold, per-step reduction discipline, and rejection sampling in `from_oracle` are all standard best practices validated by production deployments.

### 1.7 Cross-Platform Determinism

**Finding: CRITICAL IMPLEMENTATION RISK (correctly identified)**

The spec correctly identifies cross-platform determinism as a critical risk (Section 18.2, "Non-determinism from UB/endianness" rated CRITICAL severity). The mitigations are:

- All serialization is little-endian
- All arithmetic is exact F_q (no floating point)
- All types are unsigned with explicit casts
- `from_oracle` uses a byte-exact specification with pinned test vectors (Section 7.4.7)
- Noise derivation has pinned test vectors (Section 8.2.2-8.2.3)

This is the right approach. The spec goes further than most by providing byte-exact derivation specifications with concrete pinned values. The risk is in the implementation, not the specification.

---

## 2. Scalability Analysis

### 2.1 Block Propagation

**Finding: EXCELLENT for v1, MANAGEABLE for v2**

| Phase | Block Size | Bandwidth | Assessment |
|-------|-----------|-----------|------------|
| v1 steady-state (150s) | ~200 KiB | 1.3 KiB/s | Trivial -- works on cellular |
| v1 fast-mining (0.25s) | ~200 KiB | 800 KiB/s (~6.4 Mbps) | Broadband required, but only for ~3.5 hours |
| v2 n=512 (150s) | ~2.2 MiB | 15 KiB/s | Broadband, feasible |
| v2 n=1024 (150s) | ~8.2 MiB | 55 KiB/s | High broadband |

The v1 seeded-matrix design is a major scalability advantage: only 64 bytes of proof data per block (two 32-byte seeds in the header). There is no data availability problem. Any node can reconstruct matrices from seeds.

The 24 MWU consensus weight limit with 8 MWU policy default provides ~4x Bitcoin's transaction capacity at 90s blocks. The analysis in Section 14 is thorough.

### 2.2 Verification Cost Scaling

**Finding: MANAGEABLE with correct tier model**

The O(n^3) verification cost is the fundamental scalability constraint. At n=512:
- ~134M multiply-add operations per block
- 0.5-2.0s on modern single-threaded CPU (Zen 4: ~0.5s, Haswell: ~1.5-2.0s)
- <0.1s with GPU offload

The four-tier trust model (Section 12) correctly addresses this:

| Tier | Phase 2 Cost | Feasibility at 90s blocks | Feasibility at 0.25s blocks |
|------|-------------|---------------------------|-------------------------|
| 0 (Mining) | O(n^3) per attempt | GPU required | GPU required |
| 1 (Consensus) | O(n^3) per block | Any modern CPU | GPU or deferred queue |
| 2 (Economic) | 0 | Any hardware | Any hardware |
| 3 (SPV) | 0 | Mobile-class | Mobile-class |

The `MATMUL_VALIDATION_WINDOW` parameter (default 1000 blocks) correctly bounds the IBD catch-up cost for Tier 1 nodes (~25 minutes on older hardware). The invariant that this must exceed the DGW lookback window (180 blocks) is important and correctly enforced.

### 2.3 Fast-Mining Phase Scalability

**Finding: WELL-DESIGNED with one concern**

The 50,000-block fast-mining phase at 0.25-second intervals is a bold design choice. The spec correctly addresses:
- Phase 2 deferred verification queue (Section 10.3.1)
- Retroactive invalidation for failed deferred verifications
- Queue starvation guard
- Schedule-aware DGW (`ExpectedDgwTimespan`, Section 11.6)
- Smooth difficulty transition at height 50,000

**Concern:** During the fast-mining phase, compact block relay (BIP 152) becomes critical. At 0.25-second block intervals, a block that takes >0.125s to propagate will have a significant orphan rate. The spec mentions compact blocks as a "policy and operational requirement" (Section 14.3.3) but does not quantify the propagation time budget. For a 0.25-second target, the propagation budget is extremely tight.

**Recommendation:** The spec should include a propagation time analysis for the fast-mining phase. At ~200 KiB per block with compact block relay (which transmits only ~10-20 KiB of novel data), propagation should be feasible on broadband. But the analysis should be explicit.

### 2.4 Node Tier Architecture

**Finding: EXCELLENT**

The four-tier model is one of the most thoughtful aspects of the spec. Key strengths:
- Clear terminology with explicit warnings against mislabeling Tier 2 as "full"
- Service bits in P2P `version` message to distinguish tiers
- Detailed IBD behavior per tier (Section 12.4)
- Realistic hardware requirements per tier

The requirement that `MATMUL_VALIDATION_WINDOW >= DGW_PAST_BLOCKS (180)` is a well-motivated invariant -- it ensures Tier 1 nodes independently verify every block that feeds into the active difficulty calculation.

---

## 3. Performance Analysis

### 3.1 Overhead vs. Naive MatMul

**Finding: WELL-BOUNDED**

The spec targets < 15% total protocol overhead at n=512 (Section 15, Milestone 11), broken down as:
- Noise generation: O(n^2 * r) = O(n^2 * 8) -- negligible vs O(n^3) matmul
- Transcript compression: ~6% of matmul time (256 multiply-adds per intermediate, 32,768 intermediates)
- SHA-256d on compressed stream: ~131 KiB input, <0.5ms
- Denoise: O(n^2 * r) -- negligible

The 1+o(1) overhead claim from the source paper is theoretical; the practical overhead is dominated by transcript compression. The spec's target of <15% is realistic and well-justified.

### 3.2 GPU Kernel Fusion

**Finding: PRODUCTION-QUALITY DESIGN**

Appendix E provides detailed CUDA and Metal kernel implementations with:
- Fused MatMul + compression (single kernel launch per mining attempt)
- Shared memory tile decomposition with bank-conflict-avoidant padding (As[16][17])
- Two compression strategies: sequential (trivially correct) and parallel tree reduction (8x faster, proven bit-identical for M31)
- Only ~128 KiB transferred GPU->CPU (compressed stream), not 33.5 MiB (raw intermediates)

The parallel tree reduction proof (Section E.5.2) is correct: since all products are in [0, q-1] and q = 2^31 - 1, the sum of any two elements is at most 2^32 - 4, which fits in uint32. `reduce64` returns the true mathematical x mod q for all inputs < 2^32, and addition mod a prime is associative and commutative. QED.

**Minor concern:** The CUDA kernel uses `volatile uint32_t* sdata` for warp-synchronous reduction. On architectures >= sm_70, `__syncwarp()` is the correct synchronization primitive (which the spec uses). The `volatile` qualifier is a legacy pattern from pre-Volta architectures. The spec correctly uses both, which is the safest approach for broad compatibility.

### 3.3 Comparison to Hash-Based PoW

| Property | SHA-256 (Bitcoin) | KAWPOW (current BTX) | MatMul PoW (proposed) |
|----------|------------------|---------------------|----------------------|
| Core operation | SHA-256d | ProgPoW (mixed ALU/mem) | Dense matrix multiply |
| Verification cost | O(1) per block | O(1) per block | O(n^3) per block |
| ASIC resistance | None (dominated by ASICs) | Strong (saturates GPU) | Structural (commodity GPU alignment) |
| Useful work | None | None | v1: None; v2: Matrix products |
| Hardware alignment | SHA-256 ASICs | GPU | GPU/TPU (AI hardware) |
| Field arithmetic | None | Keccak-f[1600] | M31 (2^31-1) |

The verification asymmetry (O(1) for hash-based vs O(n^3) for MatMul) is the fundamental tradeoff. The spec's two-phase validation, four-tier trust model, and deferred verification queue are all designed to manage this asymmetry. This is the most significant architectural difference from traditional PoW.

### 3.4 ASIC Threat Assessment

**Finding: SPEC'S ANALYSIS IS HONEST AND CORRECT**

Section 18.5 makes no claim of "ASIC resistance" -- only "ASIC economic misalignment." This is the correct framing:
- Dense integer GEMM is the same primitive optimized by Nvidia, AMD, Apple, and Google at $300B+/year R&D investment
- A bespoke mining ASIC for M31 MatMul would need to beat commodity GPU/TPU at their core workload
- The full pipeline (MatMul + SHA-256 + PRNG + noise injection + compression) favors general-purpose architectures
- If an ASIC threat materializes, the protocol can adjust n, switch to M61, or add memory-hard mixing

This is fundamentally different from memory-hardness-based ASIC resistance (which has consistently failed: Ethash, Equihash, Scrypt). Instead of making ASICs expensive, MatMul PoW makes them pointless -- the "ASIC" already exists as commodity AI hardware.

---

## 4. Development Readiness Assessment

### 4.1 Specification Completeness

| Section | Status | Assessment |
|---------|--------|------------|
| Field arithmetic (Section 7) | Complete | Byte-exact spec with pinned test vectors |
| Matrix operations (Section 8) | Complete | Canonical iteration order specified |
| Noise generation (Section 8.2) | Complete | Domain separation, pinned vectors |
| Transcript compression (Section 8.3) | Complete | Carter-Wegman construction fully specified |
| Block header (Section 6) | Complete | 182-byte header, serialization order defined |
| Consensus params (Section 5) | Complete | All parameters with defaults and rationale |
| Mining flow (Section 9) | Complete | Step-by-step with retry axes |
| Validation (Section 10) | Complete | Two-phase with graduated punishment |
| Difficulty adjustment (Section 11) | Complete | Schedule-aware DGW with phase transition |
| Monetary policy (Section 11.4) | Complete | 21M cap, halving schedule, subsidy formula |
| Trust model (Section 12) | Complete | Four tiers with IBD behavior |
| RPC/P2P (Section 13) | Complete | RPC changes specified, P2P v1 unchanged |
| Block capacity (Section 14) | Complete | Weight-based with SegWit accounting |
| GPU kernels (Appendix E) | Complete | CUDA + Metal implementations provided |
| Security audit checklist (Section 17) | Complete | Consolidated invariants for auditors |
| Test matrix (Section 16) | Complete | 168 unit tests + 6 functional tests |

### 4.2 BTX Codebase Integration Feasibility

The existing BTX codebase (forked from Bitcoin Core with KAWPOW additions) provides an excellent template for MatMul integration:

**Key integration points:**
| File | Change Complexity | Description |
|------|------------------|-------------|
| `src/consensus/params.h` | Low | Add ~15 MatMul consensus parameters |
| `src/primitives/block.h` | Moderate | Replace KAWPOW fields with MatMul fields (182-byte header) |
| `src/pow.cpp` | Moderate | Add CheckMatMulProofOfWork (Phase 1 + Phase 2), SolveMatMul |
| `src/validation.cpp` | Moderate | Add MatMul validation conditional branches (~4565) |
| `src/rpc/mining.cpp` | Low | Add MatMul branch in GenerateBlock (~138-191) |
| `src/kernel/chainparams.cpp` | Moderate | Configure MatMul params for all networks |
| `src/crypto/CMakeLists.txt` | Low | Add MatMul source files |
| `src/crypto/matmul/` (new) | High | ~6 new files: field, matrix, noise, transcript, pow, headers |
| `src/test/` (new) | Moderate | ~168 unit tests across 13 test suites |

**DarkGravityWave (pow.cpp:17-60):** Protocol-agnostic, requires zero changes for MatMul integration. The existing 180-block window and clamping bounds work as-is. The only addition is `ExpectedDgwTimespan()` for the schedule-aware fast-mining phase.

**The spec's approach of a fresh genesis (not a KAWPOW transition) significantly reduces integration complexity.** No dual-dispatch logic, no activation height gating, no transition-specific tests.

### 4.3 Milestone Plan Assessment

The 11-milestone plan (Section 15) is well-structured:
- M1-M4 (primitives): Field, Matrix, Noise, Transcript -- zero coupling to consensus code
- M5 (Solve/Verify/Denoise): First integration with pow.cpp
- M6 (Params/Header): Consensus parameter wiring
- M7 (Validation + DoS): Core safety system
- M8 (DGW + Monetary): Difficulty and issuance
- M9 (Mining RPC): External interface
- M10 (E2E tests): Multi-node validation
- M11 (Benchmarks): Genesis calibration

Each milestone has explicit exit criteria with test commands. The dependency chain is correct -- earlier milestones produce testable artifacts that later milestones build on.

### 4.4 Gap Analysis: What's Missing

| Gap | Severity | Impact |
|-----|----------|--------|
| Genesis difficulty calibration values | Medium | Blocks M8/M11; requires hardware benchmarking |
| `nMatMulPeerVerifyBudgetPerMin` default not specified | Low | Needed for M7 implementation |
| Compact block propagation time analysis for fast phase | Medium | Affects orphan rate during 0.25s blocks |
| Stratum V2 extension specification | Medium | Affects mining pool ecosystem |
| Formal verification of `reduce64` / `dot()` | Low | Nice-to-have; pinned test vectors are sufficient for v1 |
| v2 DA layer design | N/A | Explicitly deferred; not needed for v1 |

---

## 5. Risk Matrix

| Risk | Likelihood | Impact | Mitigation in Spec | Residual Risk |
|------|-----------|--------|-------------------|---------------|
| Direct-product conjecture broken | Low | Critical | v1 also secured by SHA-256 preimage resistance; can adjust r via hard fork | Medium |
| Cross-platform determinism failure | Medium | Critical | Byte-exact spec, pinned test vectors, LE serialization | Medium (impl risk) |
| Genesis difficulty miscalibration | Medium | High | Pre-launch benchmarking (M11) | Low after benchmarks |
| Verification flooding DoS | Low | High | Two-phase validation, graduated punishment, rate limiting | Low |
| M31 field too small | Very Low | Medium | q > n^2 for n <= 46K; upgrade path to M61 | Very Low |
| ASIC development | Low | Medium | Commodity GPU alignment; protocol can adjust parameters | Low |
| Fast-phase orphan rate | Medium | Medium | Compact block relay recommended | Medium |
| Network partition from impl bugs | Medium | Critical | Graduated punishment, testnet softfail | Low |

---

## 6. Comparative Assessment

### 6.1 vs. Other PoUW Proposals

| System | Security Basis | Deployment | Overhead | Maturity |
|--------|---------------|------------|----------|----------|
| **cuPOW/BTX MatMul** | Novel conjecture (unproven) | Spec only | 1+o(1) theoretical | Pre-implementation |
| Ofelimos (IOG) | Formal proof (CRYPTO 2022) | Research only | Moderate | Academic |
| Qubic | Ad-hoc | Live mainnet | N/A (PoS+rewards) | Production |
| Primecoin | Ad-hoc difficulty | Live mainnet | Moderate | Legacy |
| Ball et al. (2017) | Fine-grained complexity | Retracted claims | Poly-log | Retracted |

BTX would be the **first blockchain to deploy a MatMul-based PoW system**. This is both a first-mover advantage and a first-mover risk.

### 6.2 vs. Hash-Based PoW (Bitcoin/Litecoin)

**Advantages of MatMul PoW:**
- Commodity GPU/TPU alignment (no special ASICs needed)
- v2 path to genuine useful work
- AI hardware ecosystem alignment

**Disadvantages:**
- O(n^3) verification vs O(1) for hash-based PoW
- Novel, unproven security assumptions
- More complex implementation surface area
- Higher barrier for "full node" operators (Tier 1 requires more hardware than a Bitcoin full node)

### 6.3 vs. KAWPOW (current BTX)

**Advantages over KAWPOW:**
- Stronger ASIC resistance narrative (GPU/TPU alignment vs GPU-only saturation)
- Path to useful work (v2 arbitrary matrices)
- Simpler dependency chain (no ethash/progpow library)

**Disadvantages vs KAWPOW:**
- KAWPOW is battle-tested (5+ years, no known ASICs)
- KAWPOW verification is O(1); MatMul is O(n^3)
- MatMul requires more complex validation infrastructure

---

## 7. Conclusions and Recommendations

### 7.1 Is the Specification Ready for Development Execution?

**Yes, with the following qualifications:**

1. **v1 (seeded matrices) is fully specified** for implementation. Every algorithm, data structure, serialization format, and test case is defined to byte-exact precision. A competent C++ developer can implement each milestone directly from the spec.

2. **The security model is honestly presented.** The spec does not overclaim. It correctly identifies the unproven conjecture, the ASIC economic misalignment (not impossibility), and the v1 limitation of not producing useful output.

3. **The engineering quality is high.** The graduated DoS mitigation, schedule-aware DGW, four-tier trust model, and transcript compression are all well-designed systems that address real operational concerns.

4. **The BTX codebase is structurally ready** for integration. The KAWPOW template provides clear integration patterns, and the fresh-genesis approach eliminates transition complexity.

### 7.2 Recommendations Before Starting Development

1. **Establish cross-implementation test vectors first.** Before writing any C++, generate the full set of pinned test vectors (TV1-TV6 for `from_oracle`, noise derivation vectors, compression vectors) using an independent reference implementation (e.g., Python). These vectors are the ground truth for cross-platform determinism.

2. **Benchmark Phase 2 verification on target hardware** to calibrate genesis difficulty and validate the hardware requirements table (Section 12.2). This is critical for the fast-mining phase feasibility.

3. **Specify `nMatMulPeerVerifyBudgetPerMin` default** (suggest: 6-10 for steady-state, higher for fast phase).

4. **Add explicit compact block propagation time budget** for the fast-mining phase to Section 14.

5. **Consider formal verification of `reduce64`** and `dot()` if resources allow. The Stwo/Plonky3 ecosystem has demonstrated that field arithmetic bugs are rare but consequential when they occur.

### 7.3 What Would Disqualify the Spec

The spec would NOT be ready for development if:
- The direct-product conjecture were publicly broken (currently not the case)
- M31 field arithmetic had known CVEs (none found)
- The transcript compression had demonstrable collision weaknesses (analysis confirms binding)
- The verification cost were infeasible on consumer hardware (it is not -- 0.5-2s at n=512 on a single CPU thread, well within the 90s block interval)

None of these conditions hold. The specification is development-ready.

---

## Sources

### Academic Papers
- Komargodski, Schen, Weinstein. "Proofs of Useful Work from Arbitrary Matrix Multiplication." arXiv:2504.09971 / IACR ePrint 2025/685
- Dikshit et al. "SoK: Is Proof-of-Useful-Work Really Useful?" IACR ePrint 2025/1814
- Bar-On, Komargodski, Weinstein. "Proof of Work With External Utilities." arXiv:2505.21685
- Carter, Wegman. "Universal Classes of Hash Functions." JCSS 18, 1979
- Ren, Devadas. "Bandwidth Hard Functions for ASIC Resistance." IACR ePrint 2017/225

### Production M31 Implementations
- StarkWare. "Stwo Prover" (live on Starknet mainnet). https://starkware.co/blog/stwo-prover-the-next-gen-of-stark-scaling-is-here/
- Polygon Labs. "Plonky3" with Circle STARKs over M31
- Ingonyama. "ICICLE-Stwo: GPU-Accelerated Stwo Prover"
- Plonky3 FRI Verifier Advisory GHSA-f69f-5fx9-w9r9 (June 2025)

### ASIC Resistance History
- ProgPoW ASIC Resistance Analysis (Scitepress, 2020)
- Bitmain Antminer X9 (RandomX ASIC, 2024-2025)
- Zawy12 DGW analysis (GitHub Issues #31, #48)

### Difficulty Adjustment
- DGW technical analysis: https://github.com/zawy12/difficulty-algorithms/issues/31
- DGW oscillation analysis: https://github.com/zawy12/difficulty-algorithms/issues/48
