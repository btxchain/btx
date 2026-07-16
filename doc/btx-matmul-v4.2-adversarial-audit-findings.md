# BTX MatMul v4 / v4.2 (ENC-BMX4C) — Adversarial Audit Findings (consolidated)

*Two waves, 11 independent adversarial agents, each finding re-verified by the
lead against the code before acceptance. Scope: the ENC-BMX4C (v4.2) and ENC-S8
(v4.1) committed PoW path, consensus wiring, dispatch/fallback, chainstate
integration, RPC/pool surface, GPU backends, determinism, DoS, and serialization.
Date 2026-07-16. Branch `claude/matmul-v4-design-spec-af23sj` (PR #89).*

## Headline verdict

**The on-chain consensus path is clean under every lens.** No accept-wrong, no
honest-node consensus split, no soundness break, no committed-path overflow/UB,
no payload malleability, and no wrong-but-accepted digest was constructible —
verified analytically AND empirically (an enforcing-config mine→validate round
trip, an independent Python oracle reproducing all golden digests, and compiled
`-fsanitize=undefined,address` determinism probes). The real findings are
**off-consensus**: a header-sync DoS (F1), an RPC profile-interop gap, a GPU
build-integration bug, and defense-in-depth items. Every one is fixed or
documented below.

## Methodology

Wave 1 (6 lenses): E2E enforcing round trip · integer overflow/combine ·
dispatch/fallback/split · determinism/UB · seed/malleability/grinding ·
DoS/ASERT. Wave 2 (5 lenses): ENC-S8 v4.1 batched path · GPU device kernels ·
chainstate reorg/fork integration · full RPC/pool surface · serialization/
conformance/v3-residuals. Grounded in Trail-of-Bits invariant-driven +
independent-oracle differential testing; every claimed finding was reproduced by
the lead against the code (file:line) before being accepted or fixed — several
agent claims were downgraded or corrected in that pass (noted below).

## Findings

| ID | Severity | Class | Status |
|----|----------|-------|--------|
| **F1** header PoW forgeable (self-declared `matmul_digest`) | HIGH | header-sync DoS (NOT a consensus break) | **Fixed (staged mechanism)** `3b88848` + design doc |
| **W-1** ENC-BMX4C seed self-reference | HIGH (latent) | consensus liveness | **Fixed** `80d5f8a` (prior) + E2E test `b5a5c6e` |
| **RPC F-1** service RPCs not BMX4C-aware | Medium | off-consensus pool share verify | **Fixed** `48356e2` |
| **RPC A** GBT/challenge carry no `encoding_profile` | Medium | mining interop | **Fixed** `85c5d0f` |
| **GPU #5** bmx4 accel sources absent from CMake; HIP guard mismatch | High (GPU build only) | build integration | **Documented** (untestable here — no GPU toolchain) |
| **F2** payload cap keyed to max dim not active dim | Low | DoS hardening | **Fixed** `48356e2` |
| **W-2 / ASERT-F1** construction invariants not on all nets; rescale ratio unchecked | Low | misconfig defense-in-depth | **Fixed** `48356e2` |
| **RPC B** `matmul_version` always 4 at v4.2 | Low | cosmetic | **Fixed** `85c5d0f` |
| **chainstate F2** `fSkipMatMulValidation` gating inconsistency | Med (regtest/dev only) | config-split, unmetered verify | **Documented** (prod unaffected; fix risks breaking functional tests) |
| **chainstate F3** ASERT rescale silently skipped on height collision | Low | misconfig | **Documented** (guard reverted — `>=` semantics may be intentional) |
| **ENC-S8 F1** combine-bound docstrings say 8589 | Low | doc accuracy | **Fixed** `48356e2` (true bound 8522) |
| **C2** `DecomposeLimbPlanes*` release-mode silent truncation | Low | latent (non-consensus) | **Documented** (only the report tool + tests call it) |
| **conformance** RPC `nNonce` grind loop is dead (GetHash ignores nNonce) | Low | latent RPC | **Documented** |
| **tooling** report/bench default to ENC-S8 profile | Low | tooling | **Documented** (use `--profile bmx4c` at BMX4C heights) |
| **determinism** v3 `cblas_dgemm` (0,0)-only spot-check | INFO (downgraded) | not a risk | **Documented** — test-only dead code AND exact-by-bound |

## The two HIGH findings (detail)

### F1 — header PoW forgeable → zero-cost header-sync DoS
At v4 heights the only header-level PoW check is `matmul_digest ≤ target`, and
`matmul_digest` is a self-declared header field (proven only when the full block
arrives). An attacker sets it to 0 (free), drives `nBits` hard via ASERT
timestamp manipulation, and floods fabricated high-claimed-work headers →
best-header poisoning / sync stall, defeating MinimumChainWork and headers
anti-DoS (which assume header work is expensive). Full-block verify still rejects
the forgery, so **no consensus break** — a remote liveness/resource DoS. Fixed by
a staged, unit-tested header-hash spam gate `H(GetHash() ‖ nNonce) ≤ spam_target`
using the matmul-decoupled `nNonce` as the grinder (so honest mining is not
taxed). Disabled by default; activation needs the `nNonce` wire-serialization +
testnet burn-in. Full analysis: `doc/btx-matmul-v4.2-header-pow-gate.md`.

### W-1 — ENC-BMX4C seed self-reference (fixed earlier this branch)
`SetDeterministicMatMulSeeds` pinned BMX4C header seeds via
`DeriveOperandSeedBMX4C`, whose operand-B preimage includes `seed_b` → no fixed
point → `bad-matmul-seeds` would reject every honest BMX4C block on an enforcing
net. Fixed by pinning both profiles via the self-reference-free
`DeterministicMatMulSeedV3`; proven by the enforcing-config round-trip test.

## Confirmed-clean (with evidence)

- **Soundness / accept-wrong / split:** the three-layer defense (dispatch
  re-verifies every device result → CPU fallback; winner reseal through the
  single-nonce CPU reference; CPU-only deterministic validation) holds for ENC-S8
  and ENC-BMX4C. No commit-without-verify path; GPU-vs-CPU can only self-DoS.
- **Overflow / UB / determinism:** committed path is pure integer; `Dequant` is a
  multiply not a negative shift; little-endian `static_assert`; no float; base-2⁶
  and base-2⁷ combines total and equal to the direct mod-q combine at every valid
  dim; constant 8,255,455 re-derived independently (the redesign doc's 8,255,527
  is the wrong one). `-O0/-O3/clang/-fsanitize` probes byte-identical.
- **Malleability:** payload not in the block hash but fenced by `BLOCK_MUTATED`
  (never poisons the honest block); `ParseSketch` rejects non-canonical residues;
  word↔byte seam is a canonical bijection.
- **Anti-amortization (B4′/I1′):** ENC-S8 per-nonce work is genuinely Θ(n³/b);
  A/U/V are template-scoped, B/σ nonce-fresh via the shared header hash, so no
  digest-only grinding field exists to amortize.
- **ASERT rescale:** saturating 256-bit arithmetic, double-guarded div-by-zero,
  exact-nBits verifier equality; no overflow/zero-target/boundary-split; `1/1`
  placeholder is behaviorally identical to ordinary re-anchoring.
- **Reorg across the fork:** robust by construction (a block's height is fixed by
  its parent; ASERT is path-independent from ancestry; no cached difficulty).
- **Conformance:** an independent Python oracle reproduced all three committed
  golden digests and the sampler/decomposition totality from the spec.

## Not fixed here, and why

- **GPU #5 (CMake/HIP guard):** real, but the CUDA/Metal/HIP builds cannot be
  compiled or link-tested in this environment. The fixes are coupled (fixing the
  HIP guard alone turns "silently dead" into a link error unless the bmx4 source
  is added simultaneously) and span strong/weak symbol resolution across 3
  backends × enabled/disabled. Blind, unverifiable edits would risk breaking the
  accelerated builds worse. Precise fix: add `{cuda,metal,hip}/matmul_v4_bmx4_accel.*`
  and their stubs to `src/CMakeLists.txt` mirroring `matmul_v4_accel.*` (real
  source when the backend is ON, per-backend stub when OFF, mutually exclusive),
  and reconcile `accel_v4_stub.cpp`'s `BTX_ENABLE_HIP_EXPERIMENTAL` guard with the
  `BTX_ENABLE_HIP` macro CMake defines. Consensus safety is unaffected (CPU
  fallback is always correct); this is GPU-mining-enablement only.
- **chainstate F2 (`fSkipMatMulValidation`):** production hardcodes skip=false so
  all prod nodes agree; the inconsistency is regtest/dev-only, and gating the body
  verify would break the activation functional tests that rely on payload
  rejection under the default (skip=true) config. Recommend instead adding a
  strict-node functional test for the seed rule, and (optionally) aligning the
  net_processing budget accounting.
- **chainstate F3 (ASERT height distinctness):** the existing ordering check
  allows `v4Height == asertHeight` (`>=`), so equality may be intentional; a
  fail-closed distinctness guard could reject a valid config. Left as documented.
