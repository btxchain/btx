> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX MatMul v4 / v4.2 (ENC-BMX4C) — Adversarial Audit Findings (consolidated)

*Three waves, 16 independent adversarial agents, each finding re-verified by the
lead against the code before acceptance. Scope: the ENC-BMX4C (v4.2) and ENC-S8
(v4.1) committed PoW path, consensus wiring, dispatch/fallback, chainstate
integration, RPC/pool surface, GPU backends, determinism, DoS, serialization,
single-flag-day activation, difficulty/ASERT, net_processing, and miner
integration. Date 2026-07-16. Branch `claude/matmul-v4-design-spec-af23sj`
(PR #89). Wave 3 (single-activation, deep-difficulty, net_processing, miner,
completeness) is in §Wave 3 below.*

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

---

## Wave 3 (single-activation, difficulty, network, miner, completeness)

Prompted by the owner directive that the **entire upgrade activates on ONE flag
day** (no multiple activation gates). Five more lenses (two hit Fable's
intermittent AUP safeguard and were re-run on Opus).

### Fixed
- **Single-activation impossible + wrong rescale (HIGH → fixed, `dcad75b`).** A
  startup `assert(bmx4c > v4)` aborted the node, `ValidateMatMulAsertParams`
  fail-closed on `bmx4c <= v4`, and the sequential ASERT cascade fired the v4
  (ENC-S8) rescale first — silently skipping the BMX4C rescale — when heights are
  equal. Fixed: `>=` construction assert, `< v4` param check, cascade guards the
  v4 branch out at equality so the BMX4C rescale (correct for the live profile)
  fires; plus a check that the v4 ratio is inert 1/1 when unified. New suite
  `matmul_unified_activation_tests` (5 cases) pins the correct behaviour.
- **Header-gate enablement footgun (HIGH latent → fixed, `dcad75b`).** Enabling
  the F1 gate (`nMatMulHeaderPoWDiscountBits != UINT32_MAX`) without the `nNonce` wire-serialization
  + miner grind is a reject-all mining halt, with nothing guarding it. Fixed:
  `CBlockHeader::BTX_HEADER_NONCE_ON_WIRE` (false) + a startup assert that the gate
  stays disabled until that wire change lands. The F1 gate was also refolded to
  ride the single v4 fork (no separate height; `bits == 0` disabled sentinel).
- **ASERT anchor shadowing (LOW latent → fixed, `56044aa`).** The half-life-upgrade
  anchor guard omitted the v4/BMX4C rescale heights, so an upgrade at/below a fork
  would silently unwind that fork's rescale. Fixed by folding the fork heights into
  the guard.

### Documented (not code-changed here)
- **F-N1 header-flood → unbounded blockindex growth (HIGH, testnet-v4 / mainnet-v4
  activation gate).** The network realization of F1: forgeable header work lets a
  peer poison `m_best_header` and grow `m_block_index` unboundedly; presync's
  work-based memory bound is defeated because the work is forgeable. The mitigation
  IS the F1 gate — which must be **enabled with wire+miner support at the same
  flag day v4 activates on mainnet** (never activate v4 with the gate off). The net
  lens also recommends enforcing the gate inside presync/`CheckHeadersPoW`, not
  only `ContextualCheckBlockHeader`. **v4 must not be activated on mainnet until
  this lands.**
- **F2b `fSkipMatMulValidation` body verify not gated (MED regtest-only).** The v4
  body verify runs even when the flag skips validation, while net_processing's
  budget accounting assumes it doesn't → unmetered verify. Only reachable on
  regtest/dev (prod hardcodes skip=false). Recommend gating
  `validation.cpp` v4 body verify on `!fSkipMatMulValidation` or keying
  `ShouldRunMatMulExpensiveVerification` on `IsMatMulV4Active`.
- **getblockheader.nonce node-divergent (LOW-MED).** `nNonce` rides the block
  index but not the P2P wire, so a miner reports `low32(nNonce64)` and every
  relaying node reports `0` for the same block; `getblockheader` never exposes the
  real `nNonce64`. Recommend reporting `nNonce64` (as `getblock` does) or a
  `nonce64` field.
- **Flagship activation functional tests run NON-enforcing (MED coverage).**
  `feature_matmul_v4_activation.py` / `feature_matmul_bmx4c_activation.py` run
  without `-matmulstrict` (skip=true), so the `bad-matmul-seeds` / `bad-matmul-dim`
  header enforcement has ZERO end-to-end functional coverage. Recommend adding an
  enforcing variant that submits a wrong-seed / wrong-dim block and asserts
  rejection.
- **S1 relay ceiling < consensus block size (MED).** `MAX_PROTOCOL_MESSAGE_LENGTH`
  = 16 MB but `nMaxBlockSerializedSize` = 24 MB, and the v4 sketch payload is ~8 MB
  — a max consensus block cannot traverse P2P. Recommend an explicit invariant or
  a documented decision.
- **GPU CMake / HIP guard (High, GPU-build-only)** — unchanged from wave 1/2:
  precise fix documented; untestable without a GPU toolchain; consensus-safe.

### Confirmed clean (wave 3, with evidence)
- Freivalds soundness re-derived independently: per-round ≤ 2/q, R=3 ⇒ 2⁻¹⁸⁰;
  σ binds prevblock+nonce64+seeds+round; no cross-round/block challenge reuse;
  `rounds==0` fail-closes both sides.
- Seed derivation across ALL fork boundaries (legacy/V2/V3/v4): a strict priority
  chain with no gap and no overlap; V2/V3 preimages exclude the seed fields
  (idempotent — the W-1 class does not exist in v2/v3).
- ASERT math: `__int128` saturation, `net_shift` clamp, no target rounds to 0 or
  exceeds powLimit on any path; miner-majority cannot drive an exploitable extreme
  (absolute anchoring + BIP94/MTP bounds).
- Compact blocks / mempool / orphan handling: no bypass of the verify budget at
  product-required heights; no mempool coupling; no orphan-header accumulation.
- Deserialization / disk index: payload vectors bounded by the 16 MB message cap;
  `CDiskBlockIndex` rebuild is hash-consistent (GetHash ignores nNonce/mix_hash).
- Miner integration: the normal (gate-disabled) path round-trips; seeds, dim,
  payload channel, and the winner reseal are exactly what validation recomputes;
  the solver picks ENC-BMX4C at the unified fork via the shared profile selector.

### Pre-existing test-harness gap (discovered wave-3, documented — not a consensus issue)

The unit-test mining helpers do not support MatMul v4 blocks: `MineHeaderForConsensus`
call sites (`setup_common.cpp` `CreateBlock`, `miner_tests`, `validation_block_tests`,
`blockfilter_index_tests`, `headers_sync_chainwork_tests`, `peerman_tests`, the
`p2p_headers_presync` fuzzer) do not pass the parent MTP that v4 seed derivation
requires, and the `CBlock` helper populates the v3 Freivalds payload rather than
the v4 product sketch (`matrix_c_data`); the Mining-interface `submitSolution`
does not carry the v4 payload at all. So any fixture that mines past the v4
activation height (e.g. regtest `TestChain100Setup` at height 100) aborts in the
helper. This is **pre-existing** (broken since v4 landed at regtest height 100,
~35 commits before this audit — confirmed by reverting the audit changes) and is
**test-infrastructure only**: no consensus code is involved, and the real miner
(`BlockAssembler` + `SolveMatMul`) produces valid v4 blocks (verified by the
enforcing round-trip test). Fixing it is a bounded but cross-cutting test-infra
task: thread the parent MTP through every `MineHeaderForConsensus` call site,
capture the solved sketch into `matrix_c_data` for v4 (skipping the v3
`PopulateFreivaldsPayload`), and teach `submitSolution` to carry the v4 payload.
Scoped as a follow-up so it does not entangle the consensus-audit fixes.
