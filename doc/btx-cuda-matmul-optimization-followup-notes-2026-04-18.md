# BTX CUDA MatMul Follow-Up Notes (2026-04-18)

This note records the CUDA optimization and cleanup pass on
`codex/cuda-opt-20260418` after the April 13 notes, including:

- which changes were accepted and kept
- which paths were implemented and then reverted
- which fixes were cleanup or correctness work rather than throughput work
- what the current default policy is for larger NVIDIA GPUs

This is an implementation note for the current CUDA mining branch, not a
consensus or protocol document.

It supersedes the default-policy portions of:

- `doc/btx-cuda-matmul-optimization-notes-2026-04-13.md`
- `doc/btx-cuda-matmul-optimization-followup-notes-2026-04-13.md`

## Branch State Covered By This Note

Accepted commits in the current branch state:

- `93e24891` `cuda: auto-enable device-prepared inputs for product digests`
- `03bfad3e` `cuda: consume device-prepared inputs in place`
- `288766d4` `cuda: use shuffle reduction in fused finalize tail`
- `dc8432e2` `cuda: widen feed-side heuristics for larger gpus`
- `35de4356` `cuda: tighten workspace cleanup paths`
- `90d8918b` `cuda: key base-matrix cache reuse by content`

## Test And Bench Context

Unless noted otherwise, the comparisons below were taken on the Linux CUDA
workstation used for this branch:

- GPU: NVIDIA GeForce RTX 5060
- CUDA capability: 12.0
- benchmark shape: `n=512`, `b=16`, `r=8`
- benchmark tool: `build-cuda/bin/btx-matmul-solve-bench --backend cuda`

The validation envelope used for accepted changes in this pass was:

- `build-cuda/bin/test_btx --run_test=matmul_backend_capabilities_tests`
- `build-cuda/bin/test_btx --run_test=matmul_accelerated_solver_tests`
- `build-cuda/bin/test_btx --run_test=pow_tests/matmul_solve_uses_cuda_batch_defaults_when_backend_is_available`
- `build-cuda/bin/test_btx --run_test=pow_tests/matmul_solve_crosses_60999_to_61000_with_product_digest_contract`
- `build-cuda/bin/test_btx --run_test=pow_tests/product_committed_digest_deterministic`

Strict regtest validation was also carried forward from the async-prepare abort
fix and used as a required regression check:

- node shape:
  - `-regtest -test=matmulstrict -test=matmuldgw`
  - height `1507`
- environment:
  - `BTX_MATMUL_BACKEND=cuda`
  - `BTX_MATMUL_PIPELINE_ASYNC=1`
  - `BTX_MATMUL_SOLVER_THREADS=1`
  - `BTX_MATMUL_SOLVE_BATCH_SIZE=1`
- direct tests:
  - `pow_tests/cuda_strict_regtest_warning_repro_solves_without_digest_divergence`
  - `matmul_accelerated_solver_tests/cuda_strict_regtest_warning_repro_direct_and_batch_match_cpu_or_cleanly_falls_back`
  - `matmul_accelerated_solver_tests/cuda_strict_regtest_warning_repro_nonce_scan_matches_cpu_or_cleanly_falls_back`

## Kept Performance Changes

### 1. Product-digest CUDA now defaults to the device-prepared path

Status:

- kept
- commit: `93e24891`

What changed:

- post-`61000` product-digest CUDA mining now auto-enables the
  device-prepared-input path
- transcript-mode / pre-`61000` mining does not widen by default

Why it stayed:

- this was the first real product-mode policy win on the branch
- it turns an already-measured faster path into the default where the branch
  actually needs it

Measured effect on the motivating product-mode solve path:

- before: median `0.072673411s`
- after: median `0.0677498065s`

That is about a `6.8%` improvement on the measured whole-solver product path.

### 2. Device-prepared inputs are consumed in place

Status:

- kept
- commit: `03bfad3e`

What changed:

- the device-prepared CUDA digest path now consumes generated CUDA input
  storage directly instead of repacking through an extra intermediate step

Why it stayed:

- it made the code simpler
- it removed repack overhead
- it did not introduce any observed parity, stability, or throughput regression

Measured effect on the forced device-prepared path:

- before: median `0.011726975s`
- after: median `0.011698915s`

This is only about a `0.2-0.3%` improvement locally, so it is better described
as a cleanup win than a major throughput win.

### 3. Shuffle reduction in the fused finalize tail

Status:

- kept
- commit: `288766d4`

What changed:

- the fused finalize reduction still uses the existing shared-memory/block-sync
  stages for the larger strides
- the tail switches to warp shuffles instead of continuing full shared-memory
  reduction all the way down

Why it stayed:

- it was the largest kernel-side throughput gain found during this branch pass
- it improved both transcript and product modes

Measured effect against the detached pre-change baseline:

- product mode (`61000`)
  - before: median `0.010217697s`
  - after: median `0.0085471665s`
- transcript mode (`60999`)
  - before: median `0.010211025s`
  - after: median `0.00854477s`

That is roughly a `16.3%` improvement on the measured product-mode kernel path.

## Kept Default-Policy Change For Larger GPUs

### 4. Feed-side CUDA heuristics now widen only on higher-SM NVIDIA parts

Status:

- kept
- commit: `dc8432e2`

What changed:

- when overrides are unset, CUDA feed-side defaults now widen by GPU SM tier
  instead of using one shared default across all NVIDIA devices
- the widened path is aimed at larger NVIDIA GPUs, not at forcing more work on
  the local RTX 5060 tier

Current heuristic changes:

- prepare workers:
  - `sm >= 96` and `hw >= 16`: `clamp(hw / 2, 2, 8)`
  - `sm >= 64` and `hw >= 12`: `clamp((hw + 1) / 3, 2, 6)`
  - `sm >= 48` and `hw >= 8`: `clamp((hw + 1) / 4, 2, 5)`
- solver threads:
  - `sm >= 96`: `8` / `6` / `5` for host-concurrency tiers `>=24`, `>=16`, `>=12`
  - `sm >= 64`: `6` / `5` / `4` for host-concurrency tiers `>=16`, `>=12`, `>=8`
  - `sm >= 48`: `5` / `4` / `3` for host-concurrency tiers `>=16`, `>=12`, `>=8`
- prefetch depth:
  - `sm >= 96`: `5` when batch size is `>=6`, otherwise `4`
  - `sm >= 64`: `4` when batch size is `>=4`, otherwise `3`
  - `sm >= 48`: `3`
- product-mode solve batch size:
  - mainnet shape `512/16/8`
    - `sm >= 96`: `8` when solver threads are `>=6`, otherwise `4`
    - `sm >= 64`: `6` when solver threads are `>=5`, otherwise `4`
    - `sm >= 48`: `4` when solver threads are `>=5`, otherwise `2`
  - smaller product shape `256/8/4`
    - `sm >= 64`: `6` when solver threads are `>=5`, otherwise `4`
    - `sm >= 48`: `4` when solver threads are `>=4`, otherwise `2`
- CUDA pool slots:
  - CPU cap tiers: `1 / 2 / 3 / 4 / 6 / 8`
  - GPU cap tiers: `1 / 2 / 4 / 5 / 6 / 7 / 8` as SM count rises through
    `12 / 24 / 48 / 64 / 96 / 128`

Why it stayed:

- the user explicitly wanted the larger-GPU path opened even if the local 5060
  did not show a large win
- on the local machine the effective runtime profile stays unchanged, so the
  accepted bar was "no clear regression" rather than "must get faster here"

Observed local behavior on this `30`-SM RTX 5060:

- effective runtime defaults remained:
  - `parallel_solver_threads=4`
  - `batch_size=2`
  - `prefetch_depth=2`
  - `slot_count=4`
- local product-mode medians during acceptance:
  - `0.0086094255s`
  - `0.0086330105s`
  - `0.008658878s`
- earlier clean baseline in the same comparison flow:
  - `0.008520955s`

This was accepted as larger-GPU enablement because the local tier did not
change behavior and the measurements did not show a clear regression.

## Kept Cleanup And Correctness Changes

### 5. Workspace cleanup paths were centralized

Status:

- kept
- commit: `35de4356`

What changed:

- duplicated CUDA workspace teardown/free logic was consolidated in both
  `src/cuda/matmul_accel.cu` and `src/cuda/oracle_accel.cu`
- stale unused packed-pointer arguments and no-op casts were removed from the
  live CUDA path

Why it stayed:

- this was the right cleanup to salvage from the failed optimization prototypes
- it reduces the chance of future missing-free bugs when new workspace-owned
  buffers are added

Measured local product-mode bench after the cleanup:

- median `0.0085737s`

This was not accepted for throughput; it was accepted because it tightened the
live ownership paths without regressing correctness or local performance.

### 6. Base-matrix cache reuse is now keyed by content

Status:

- kept
- commit: `90d8918b`

What changed:

- the CUDA base-matrix cache is no longer keyed only by raw host pointers
- the CUDA request path now accepts explicit cache keys for `matrix_a` and
  `matrix_b`
- the normal solver path passes stable seed-based keys, so normal mining still
  reuses uploaded bases
- raw low-level callers that do not provide keys now fail closed and re-upload
  instead of risking stale base reuse

Why it stayed:

- a pointer-only cache key was brittle when the caller reused the same storage
  with different contents
- this was a correctness fix discovered during the rejected graph-capture work
- it closed a real latent risk without disturbing the normal seeded solver path

Measured local product-mode bench after the fix:

- median `0.008542629s`

Regression coverage added:

- `cuda_base_matrix_cache_requires_matching_content_keys`
  in `src/test/matmul_backend_capabilities_tests.cpp`

That test mutates matrix contents in place under the same storage, verifies
that changed keys force a miss and still match an uncached recompute, then
verifies that repeated requests with the new keys eventually hit the cache
again.

## Reverted Or Rejected Attempts

### 1. Memory-layout-first finalize rewrites

Status:

- rejected

Variants attempted:

- an earlier transposed-`B'` low-rank finalize rewrite
  - patched serial median `0.0225655945s`
  - clean-tree serial median `0.022613259s`
  - result: too small/noisy to justify keeping
- a more aggressive transposed-`B` memory-layout rewrite
  - product `61000`: median `0.0432127605s`
  - transcript `60999`: median `0.043269293s`
  - result: clear regression
- a narrower `b=16` / `A`-broadcast finalize specialization
  - product baseline: `0.0178700585s`
  - product candidate: `0.018121591s`
  - transcript baseline: `0.0178254315s`
  - transcript candidate: `0.0182995675s`
  - result: slight regression

Reason for rejection:

- none of the memory-layout-first finalize rewrites cleared the acceptance bar
- the aggressive variants were clearly slower, and the narrow variants were too
  small or too noisy to justify extra complexity

### 2. Product-mode CUDA graph / fixed-launch path

Status:

- rejected

What was attempted:

- a product-mode graph-capture path for the fixed `512/16/8` low-rank
  device-prepared CUDA digest flow

Measured result against a clean baseline at `03bfad3e`:

- clean baseline: median `0.008520955s`
- graph candidate: median `0.0085294385s`

Reason for rejection:

- the apparent first "win" did not survive an apples-to-apples rerun
- on this machine the graph path was flat to slightly worse, so it was treated
  as noise and reverted

### 3. Local queue-depth and heuristic retunes for the RTX 5060 tier

Status:

- rejected as local defaults

Rejected local retunes:

- product-mode `BTX_MATMUL_SOLVE_BATCH_SIZE=3`
  - baseline: `0.022613259s`
  - candidate: `0.022882296s`
- `BTX_MATMUL_CUDA_POOL_SLOTS=6`
  - candidate: `0.0101984305s`
- `BTX_MATMUL_SOLVER_THREADS=5` with the implied `batch_size=4`,
  `prefetch_depth=3`
  - candidate: `0.010275142s`
- `BTX_MATMUL_SOLVER_THREADS=5` plus `BTX_MATMUL_CUDA_POOL_SLOTS=6`
  - candidate: `0.010299442s`

Reference clean baseline for the later local retune sweep:

- `0.0101846425s`

Reason for rejection:

- the local 5060 did not benefit from deeper queueing or a wider default solve
  profile
- the later accepted larger-GPU widening was intentionally written so this
  30-SM tier stays on the same effective defaults

### 4. Post-shuffle kernel variants

Status:

- rejected

Rejected variants:

- `b=16` warp-broadcast finalize specialization
  - baseline: `0.0085471665s`
  - candidate: `0.010769312s`
- low-rank build-kernel warp broadcast of shared `noise_left[row, k]`
  - candidate: `0.0086372325s`
  - candidate repeat: `0.0086491005s`
  - baseline: `0.0085471665s`

Reason for rejection:

- after the accepted shuffle-tail change, the remaining easy kernel-side space
  was mostly exhausted on this GPU
- the tested variants were either clearly slower or only flat-to-worse

## Current Resulting CUDA Posture

For the current branch state after this pass:

- post-`61000` CUDA product digests default to the device-prepared path
- transcript-mode CUDA still stays on the staged default path unless explicitly
  overridden
- the best accepted kernel-side win remains the shuffle-tail finalize reduction
- larger NVIDIA GPUs now have a dedicated widening path for feed-side defaults
  when overrides are unset
- the local RTX 5060 tier stays on the same effective `4 / 2 / 2 / 4`
  solver/batch/prefetch/slot profile
- workspace cleanup and cache correctness issues found during failed
  optimization prototypes were kept as standalone cleanup/correctness commits
- strict async regtest validation remains part of the required acceptance
  envelope for future CUDA optimization work

## Most Important Practical Takeaways

- The branch's material throughput wins came from changing the live default
  product-digest policy and from improving the fused finalize reduction, not
  from CUDA graphs or aggressive layout rewrites.
- Larger-GPU default widening is now available without forcing the local
  midrange NVIDIA tier onto a riskier queue profile.
- Cleanup work found during rejected optimization prototypes was still worth
  landing when it removed dead state, tightened ownership, or closed a latent
  correctness risk.
