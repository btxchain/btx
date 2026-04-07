You are implementing MatMul-based Proof-of-Work for the BTX blockchain node.
Work autonomously. Do not ask questions. Make the best decision and move on.
If you need information, read the spec or search online.

The canonical spec is `doc/btx-matmul-pow-spec.md` (~5000 lines, 18 sections).
It is the single source of truth for all consensus-critical behavior.

Your task: implement ALL 11 milestones (M1-M11) defined in Section 15 of the
spec, with full test coverage matching Section 16's test matrix (~168 unit
tests + 6 functional tests). Work continuously through each milestone in
strict order. Build and test after each milestone. Commit after each milestone
passes. Do NOT push to remote until all milestones are complete and all tests
pass.

---

## Reference Documents

Read these before you begin writing code:

| Document | Purpose |
|----------|---------|
| `doc/btx-matmul-pow-spec.md` | Canonical spec (5000 lines, 18 sections) |
| `doc/btx-matmul-pow-spec-analysis.md` | Security/scalability/perf analysis |
| `doc/peer-verify-budget-analysis.md` | DoS parameter justification |
| `test/reference/generate_test_vectors.py` | Independent Python reference implementation |
| `test/reference/test_vectors.json` | 126 pinned test vectors (19 categories) |
| `test/benchmark/matmul_phase2_bench.cpp` | Phase 2 benchmark (confirmed ~556ms at n=512) |

---

## Project Conventions

- **Build system**: CMake 3.22+ / C++20
- **Full build**: `cmake -B build-btx -DBUILD_TESTING=ON && cmake --build build-btx -j$(nproc)`
- **Incremental build**: `cmake --build build-btx -j$(nproc)`
- **Unit tests**: `./build-btx/bin/test_btx --run_test='matmul_*'`
- **Single suite**: `./build-btx/bin/test_btx --run_test=matmul_field_tests`
- **Functional tests**: `python3 test/functional/test_runner.py`
- **Single functional**: `python3 test/functional/mining_matmul_basic.py`
- All new matmul source files go in `src/matmul/` (create the directory)
- All new matmul test files go in `src/test/` following Bitcoin Core convention
- Functional tests go in `test/functional/`
- Field: M31 (q = 2^31 - 1 = 2147483647), all arithmetic uint32/uint64
- NO `__uint128_t`, NO floating point in consensus path
- All serialization is little-endian
- SHA-256 via Bitcoin Core's `hash.h` (`CSHA256`, `CHash256` for SHA-256d)
- Header files use `#ifndef BITCOIN_MATMUL_*_H` include guards

---

## Pinned Test Vectors

The file `test/reference/test_vectors.json` contains independently-generated test
vectors. Your C++ implementation MUST produce bit-for-bit identical results for:

- `from_oracle` outputs (TV1-TV6 in spec §7.4.7)
- `FromSeed` matrix generation
- `reduce64` edge cases
- `dot` products (including all-max-value)
- Noise seed derivation
- Compression vector derivation
- Canonical MatMul transcript hash

When your C++ produces different output from test_vectors.json, the test vectors
are correct. Debug your C++. You can also consult the Python reference
implementation at `test/reference/generate_test_vectors.py` to understand the
expected behavior.

---

## Anti-Patterns to Avoid

- Do NOT use `__uint128_t` -- the spec explicitly forbids it
- Do NOT use lazy accumulation in `dot()` -- per-step `reduce64` is mandatory
- Do NOT confuse `b` (transcript block size) with `r` (noise rank)
- Do NOT include `matmul_digest` in sigma derivation (sigma = SHA256(header \ matmul_digest))
- Do NOT use null terminators in noise domain separation tags (raw ASCII, 18 bytes)
- Do NOT use `nPowTargetSpacing` directly in DGW -- use `GetTargetSpacing(height)`

---

## Decision Making

- If the spec is ambiguous, check `test/reference/test_vectors.json` -- the test
  vectors are canonical.
- If the test vectors don't cover a case, follow Bitcoin Core's existing patterns
  for similar functionality.
- Search online for Bitcoin Core development patterns rather than guessing.
- Never ask the user -- make the best decision and document it in a code comment.

---

## Git Workflow

- Commit after completing each milestone's deliverables AND its tests pass
- Commit message format: `matmul: M{N} - {brief description}`
- Do NOT push until ALL milestones complete and ALL tests pass
- Do NOT amend previous commits -- always create new ones

---

## Working Methodology

1. **Build first**: Before implementing M1, do an initial build to confirm the
   build system works: `cmake -B build-btx -DBUILD_TESTING=ON && cmake --build build-btx -j$(nproc)`

2. **Create src/matmul/ directory**: `mkdir -p src/matmul`

3. **Update CMakeLists.txt**: Add the matmul source files to the build. Look at
   how existing source files are included and follow the same pattern.

4. **Read before writing**: For every milestone, read the full spec sections
   referenced. Do not implement from memory or assumption.

5. **Test-driven**: Write tests alongside implementation. Run them frequently
   during development, not just at the end.

6. **When something fails**: Read the error carefully. Check the spec. Check
   the test vectors. Search online for Bitcoin Core patterns. Do NOT guess.

7. **When stuck**: Re-read the spec section, check the Python reference
   implementation, search online for Bitcoin Core patterns, look at existing
   source for analogous patterns. Make the simplest decision that satisfies
   the spec and move on.

---

## Your Loop

For each milestone M1 through M11:

1. Read the milestone section in `doc/btx-matmul-pow-spec.md` (Section 15)
2. Read all referenced spec sections for that milestone
3. Read relevant test vectors from `test/reference/test_vectors.json`
4. Implement the deliverables
5. Write the unit tests (matching the test count in Section 16.1)
6. Build and run tests
7. Fix any failures -- do NOT move on until all tests pass
8. Commit: `git add src/matmul/{files} src/test/{test_files} && git commit -m "matmul: M{N} - {description}"`
9. Proceed to next milestone

Implementation order is STRICT: M1 -> M2 -> M3 -> M4 -> M5 -> M6 -> M7 -> M8 -> M9 -> M10 -> M11.
Each milestone builds on the previous. Do not skip ahead.

---

## Milestone Implementation Plan

### M1: Finite-Field Arithmetic (M31)

Files: src/matmul/field.h, src/matmul/field.cpp
Tests: src/test/matmul_field_tests.cpp (37 tests)
Spec sections: §7.1-7.4 (field definition, reduce64, dot, from_oracle, FromSeed)
Test vectors: test/reference/test_vectors.json keys: reduce64_edge_cases,
  dot_all_max_len4, from_oracle_extra, from_seed_4x4, from_seed_8x8,
  pinned_tv1 through pinned_tv6

Key requirements:
- reduce64: double Mersenne fold, NOT public API (static/file-internal)
- dot(): per-step reduce64 after every multiply-add, ONLY accumulation path
- from_oracle: SHA-256(seed || LE32(index)), 31-bit mask, rejection if >= q,
  retry with SHA-256(seed || LE32(index) || LE32(retry))
- FromSeed: index = row * n + col (row-major)
- No __uint128_t, no floating point
- Test naive accumulation (without per-step reduce) produces wrong results

### M2: Matrix Type and Operations

Files: src/matmul/matrix.h, src/matmul/matrix.cpp
Tests: src/test/matmul_matrix_tests.cpp (9 tests)
Spec sections: §7.4.3 (FromSeed), §8.1 (block decomposition)

Key requirements:
- Row-major contiguous uint32 storage
- Block decomposition for tile extraction
- Multiplication using field::dot for each output element
- ContentHash for deterministic matrix identity

### M3: Noise Generation (Rank r)

Files: src/matmul/noise.h, src/matmul/noise.cpp
Tests: src/test/matmul_noise_tests.cpp (16 tests)
Spec sections: §8.2 (noise injection), §8.2.1 (domain separation), §8.2.2 (test vectors)
Test vectors: noise_seeds_n8_r2, noise_n8_r2

Key requirements:
- Four domain separation tags: "matmul_noise_EL_v1", "matmul_noise_ER_v1",
  "matmul_noise_FL_v1", "matmul_noise_FR_v1" (18 bytes, raw ASCII, NO null terminator)
- tag_EL = SHA256(tag_string || sigma), etc.
- E_L is n x r (uses r columns), E_R is r x n (uses n columns)
- Index formula uses FACTOR COLUMN COUNT, not global n
- rank(E_L * E_R) <= r

### M4: Canonical MatMul + Transcript Hash (Block size b)

Files: src/matmul/transcript.h, src/matmul/transcript.cpp
Tests: src/test/matmul_transcript_tests.cpp (17 tests)
Spec sections: §8.1 (canonical order), §8.3 (transcript compression), Appendix B
Test vectors: compression_vector_b8, compression_vector_b16, canonical_matmul_n8_b4

Key requirements:
- Strict (i, j, l) iteration order for tiles
- Compression vector: v_seed = SHA256("matmul-compress-v1" || sigma), b^2 elements
- Compressed element: t = dot(v, flatten(C_partial)) for each intermediate
- SHA-256d streaming: feed LE32(t) for each intermediate in canonical order
- Result z = SHA256(SHA256(stream)) is matmul_digest
- b is for transcript blocking, r is for noise -- never confuse them

### M5: Solve, Verify, Denoise

Files: src/matmul/matmul_pow.h, src/matmul/matmul_pow.cpp
Tests: src/test/matmul_pow_tests.cpp (12 tests)
Spec sections: §9 (mining/verification flow), §8.2.3 (denoising)

Key requirements:
- Solve: iterate nonce, compute sigma, generate A/B, compute transcript, check digest < target
- Verify: recompute transcript from header fields, check digest matches and < target
- Denoise: C_clean = C_noisy - E_L*F_R - F_L*E_R, cost O(n^2 * r) not O(n^3)
- sigma = SHA256(serialize(header) excluding matmul_digest)
- seed_a and seed_b are miner-chosen header fields, NOT derived from sigma

### M6: Consensus Parameters and Block Header

Files: modified src/consensus/params.h, src/primitives/block.h, src/chainparams.cpp
Tests: src/test/matmul_params_tests.cpp (10), matmul_header_tests.cpp (7),
       matmul_block_capacity_tests.cpp (6)
Functional: test/functional/feature_btx_block_capacity.py
Spec sections: §5 (params), §6 (header), §14 (block capacity)

Key requirements:
- Header: 182 bytes with seed_a (32B), seed_b (32B), matmul_digest (32B), nNonce64 (8B)
- Remove KAWPOW fields entirely (fresh genesis, no legacy)
- nMaxMoney = 21,000,000 * COIN, nInitialSubsidy = 20 * COIN
- nSubsidyHalvingInterval = 525,000
- nFastMineHeight = 50,000
- nPowTargetSpacingFastMs = 250, nPowTargetSpacingNormal = 90
- nMaxBlockWeight = 16,000,000 WU, WITNESS_SCALE_FACTOR = 4
- Per-network chain params for mainnet, testnet, regtest

### M7: Validation with Two-Phase DoS Mitigation

Files: modified src/pow.h, src/pow.cpp, src/validation.cpp
Tests: src/test/matmul_validation_tests.cpp (14), matmul_trust_model_tests.cpp (6)
Spec sections: §10 (validation), §12 (trust model)

Key requirements:
- Phase 1: dimension bounds, digest < target, non-null seeds (microseconds)
- Phase 2: full transcript recomputation (only if Phase 1 passes)
- Graduated punishment: disconnect (1st fail) -> discourage (2nd) -> ban (3rd+)
- fMatMulStrictPunishment: immediate ban on Phase 2 fail
- Testnet/regtest: threshold = UINT32_MAX (never ban)
- 24h rolling window for phase2_failures
- nMatMulPeerVerifyBudgetPerMin = 8 (per-peer rate limit)
- nMatMulMaxPendingVerifications = 4 (global concurrency cap)
- GetTargetSpacing(h): 0.25 for h < 50000, 90 for h >= 50000

### M8: Difficulty Adjustment (DGW, Fresh Genesis)

Files: modified src/pow.cpp
Tests: src/test/matmul_dgw_tests.cpp (11), matmul_subsidy_tests.cpp (6)
Functional: feature_btx_subsidy_schedule.py, feature_btx_fast_mining_phase.py
Spec sections: §11 (difficulty + monetary policy)

Key requirements:
- DGW uses ExpectedDgwTimespan(h) = sum of GetTargetSpacing(h-k) for k=1..180
- NOT fixed nPowTargetSpacing * 180
- Genesis difficulty calibrated (not powLimit)
- GetBlockSubsidy: 20 * COIN >> (h / 525000)
- Fast phase: 0.25s blocks for h < 50000, then 90s

### M9: Mining RPC

Files: modified src/rpc/mining.cpp, src/miner.h, src/miner.cpp
Tests: src/test/matmul_mining_tests.cpp (5)
Functional: test/functional/mining_matmul_basic.py
Spec sections: §13 (RPC/P2P)

Key requirements:
- getblocktemplate: include matmul_n, matmul_b, matmul_r, seed_a, seed_b fields
- generateblock: produce valid matmul PoW blocks on regtest
- submitblock: validate and accept/reject
- getmininginfo: report "matmul" algorithm

### M10: End-to-End Functional Tests

Files: test/functional/feature_btx_matmul_consensus.py,
       test/functional/p2p_matmul_dos_mitigation.py,
       scripts/matmul_pow_readiness.sh
Spec sections: §10, §12, §16.2

Key requirements:
- Mine 100+ blocks on regtest, verify chain
- Multi-node sync: 2+ nodes agree on tip
- Invalid block rejection with peer penalization
- DoS rate limit testing
- AssumeValid IBD path
- Readiness script: run all matmul tests, report pass/fail

### M11: Performance Benchmarks

Files: scripts/matmul_pow_benchmark.sh, doc/btx-matmul-benchmarks.md
Spec sections: §16 (exit criteria)

Key requirements:
- Benchmark Solve/Verify for n = {64, 128, 256, 512}
- Memory usage confirmation O(n^2)
- Transcript compression overhead breakdown
- Total protocol overhead < 15% at n=512
- Genesis difficulty calibration values from Solve() timings

---

## Critical Spec Details to Internalize

### Field Arithmetic (§7)

- q = 2^31 - 1 = 0x7FFFFFFF
- reduce64(x): fold1 = (x & q) + (x >> 31); lo = fold1 & q; hi = fold1 >> 31;
  s = lo + hi; return s >= q ? s - q : s
- mul(a, b): return reduce64((uint64_t)a * b)
- dot(a, b, n): acc = 0; for i in 0..n-1: acc = reduce64(acc + (uint64_t)a[i] * b[i]); return acc
- from_oracle(seed, index): preimage = seed || LE32(index); h = SHA256(preimage);
  val = LE32(h[0..3]) & 0x7FFFFFFF; if val < q return val;
  else retry with preimage = seed || LE32(index) || LE32(retry++)

### Block Header (§6)

- 182 bytes total
- New fields: seed_a[32], seed_b[32], matmul_digest[32], nNonce64 (uint64)
- sigma = SHA256(serialize(header excluding matmul_digest))
- GetHash() = SHA256d(serialize(full header including matmul_digest))

### Transcript (§8)

- N = n/b tile blocks per dimension
- Iterate (i=0..N-1, j=0..N-1, l=0..N-1)
- For each: C_partial = A_tile(i,l) x B_tile(l,j) [standard i-j-k within tile]
- Compress: t = dot(v, flatten(C_partial)) where v is b^2 elements from sigma
- Hash: SHA256d of concatenated LE32(t) values

### Noise (§8.2)

- E_L(n x r), E_R(r x n): low-rank noise, rank <= r
- F_L(n x r), F_R(r x n): denoising factors
- C_noisy = A*B + E_L*E_R + F_L*F_R
- Denoise: C_clean = C_noisy - E_L*F_R - F_L*E_R (requires r known)

---

## Resume Instructions

If this session is interrupted and you are continuing from a previous session,
check `git log` for the last completed milestone, run its tests to verify they
still pass, then pick up from the next milestone.

---

Now begin. Start with a full build to verify the environment, then implement M1.
Work continuously through all milestones without stopping or asking questions.
