## BTX CUDA MatMul Follow-Up Notes (2026-04-13)

This note records the second CUDA optimization pass taken from
`../_TODO/cuda-matmul-optimization-roadmap-2026-04-13.md`, including:

- which roadmap items were kept
- which attempted implementations were reverted
- why each decision was made
- the benchmark deltas used for the keep or revert call

This is an implementation note for `codex/cuda-linux`, not a consensus or
protocol document.

Update 2026-04-18:

- the current accepted branch state is now tracked in
  `doc/btx-cuda-matmul-optimization-followup-notes-2026-04-18.md`
- this April 13 note remains useful as historical context, but it no longer
  reflects the latest accepted CUDA defaults or the latest rejected paths

## Test And Bench Context

Unless noted otherwise, the comparisons below were taken on the Linux CUDA
workstation used for this branch:

- GPU: NVIDIA GeForce RTX 5060
- CUDA capability: 12.0
- host CPU: i5-14400F class system
- benchmark shape: `n=512`, `b=16`, `r=8`
- benchmark tool: `build-cuda/bin/btx-matmul-solve-bench --backend cuda`

Correctness checks used during this pass:

- `build-cuda/bin/test_btx --run_test=matmul_accelerated_solver_tests`
- `build-cuda/bin/test_btx --run_test=matmul_backend_capabilities_tests`
- `build-cuda/bin/test_btx --run_test=pow_tests`

## Kept Changes

### 1. Warp-synchronous finalize reduction tail

Status:

- kept
- commit: `5bd26b3e` (`cuda: use warp tail for finalize reduction`)

What changed:

- the finalize kernel now keeps full-block barriers for the larger strides
- the final warp reduction stages use warp-synchronous logic instead of
  `__syncthreads()` on every stride down to 1

Why it stayed:

- it was correct
- it materially improved end-to-end solve latency on the target shape

A/B comparison against the pre-change finalize kernel on the same 12-iteration
bench setup:

- `parallel=1`, `solver_threads=1`
  - before: median `0.0322652745s`
  - after: median `0.019111819s`
- `parallel=2`, `solver_threads=2`, `pool_slots=2`
  - before: median `0.0311276365s`
  - after: median `0.0198863915s`

### 2. Packed digest-owned storage for the device-prepared CUDA path

Status:

- kept as groundwork
- default remains unchanged

What changed:

- the CUDA digest workspace now owns a packed per-request device-input layout
- the copied device-prepared path stages each request with one D2D copy instead
  of five D2D copies
- the low-rank build and finalize path can read compression data from that
  packed digest-owned storage

What did not change:

- this is not the full "generate directly into the final digest slot" design
- `BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS` stays opt-in

Why it stayed:

- it is the right storage shape for a future true direct-slot path
- it removed the worst copied-path overhead without destabilizing the staged
  default
- it recovered most of the earlier regression in the device-prepared path

Device-prepared path benchmark comparison before and after the packed-storage
change:

- `parallel=1`, `solver_threads=1`, `BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS=1`
  - before: median `0.030663383s`
  - after: median `0.0198059235s`
- `parallel=2`, `solver_threads=2`, `pool_slots=2`,
  `BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS=1`
  - before: median `0.0273589945s`
  - after: median `0.0195125625s`

On this 5060, the packed copied path is now close to parity with the staged
default and slightly ahead on the 2-thread benchmark, but not by a wide enough
margin to flip the production default.

### 3. CUDA feed-side autotuning for no-override mining

Status:

- kept

What changed:

- when `BTX_MATMUL_SOLVER_THREADS` is unset and CUDA is the active backend,
  solver threads now scale with host CPU concurrency instead of defaulting to 1
- when `BTX_MATMUL_CUDA_POOL_SLOTS` is unset, the CUDA pool now sizes itself
  from host concurrency plus CUDA SM count instead of defaulting to 1
- CUDA batch size and prefetch depth stay conservative on midrange devices, but
  now scale up for larger concurrency tiers
- pool-slot acquisition now prefers reusing an already-initialized slot before
  consuming a fresh slot, which preserves existing reuse semantics in tests

Why it stayed:

- it is directly relevant to larger-GPU scaling
- it also improves the no-override CUDA path on the local 5060

No-override CUDA benchmark (`--backend cuda --parallel 1`, no solver-thread or
pool-slot override):

- old behavior
  - `parallel_solver_threads=1`
  - `slot_count=1`
  - median `98668.05822019142` nonces/sec
- new behavior
  - `parallel_solver_threads=4`
  - `slot_count=4`
  - median `173767.2950426703` nonces/sec

The current heuristics are still intentionally conservative on batch size and
prefetch depth. On this 5060, deeper prefetch and a larger default batch did
not improve results.

## Reverted Attempts

### 1. Generic shared-memory tiled finalize rewrite

Status:

- reverted

What was attempted:

- stage `A` and `B` tiles in shared memory for each `ell`
- keep the same fused finalize structure and reduction order

Outcome:

- correctness stayed intact
- performance regressed versus the post-item-2 kernel

Measured regression on the same 12-iteration benchmark:

- `parallel=1`, `solver_threads=1`
  - baseline after item 2: median `0.019111819s`
  - tiled attempt: median `0.0300860335s`
- `parallel=2`, `solver_threads=2`, `pool_slots=2`
  - baseline after item 2: median `0.0198863915s`
  - tiled attempt: median `0.023705232s`

Reason for revert:

- the generic shared-memory rewrite did not clear the roadmap acceptance bar
- on this architecture and kernel shape, the added shared-memory structure did
  not beat the simpler global-memory kernel with the warp-tail reduction

### 2. Mainnet-shape finalize specialization (`512/16/8`)

Status:

- reverted

What was attempted:

- a compile-time-specialized finalize kernel for `n=512`, `b=16`, `r=8`
- unrolled hot-loop address arithmetic and fixed thread shape

Outcome:

- correctness stayed intact
- the specialized kernel regressed badly against the generic post-item-3 path

Measured regression:

- `parallel=1`, `solver_threads=1`
  - current baseline before attempt: median about `0.01944s`
  - specialized attempt: median `0.0394377555s`
- `parallel=2`, `solver_threads=2`, `pool_slots=2`
  - current baseline before attempt: median about `0.01979s`
  - specialized attempt: median `0.038177706s`

Reason for revert:

- it clearly failed the roadmap acceptance bar
- the extra code surface was not justified by the measured result

## Current Resulting CUDA Posture

For this branch after the follow-up pass:

- keep the warp-tail finalize reduction
- keep the packed digest-owned storage for the copied device-prepared path
- keep CUDA feed-side autotuning for solver threads and pool slots
- keep the staged path as the production default
- keep `BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS=1` as an explicit opt-in
- do not ship the generic shared-memory tiled finalize attempt
- do not ship the `512/16/8` finalize specialization attempt

## Most Important Practical Takeaways

- The current best kept kernel-side win was the warp-tail reduction, not the
  generic shared-memory tiling rewrite.
- The best storage refactor so far was matching the device-prepared path to a
  digest-owned packed layout; it is useful groundwork even though it is not yet
  the final direct-slot design.
- Feed-side defaults mattered more than expected on this 5060 once the CUDA
  backend stopped forcing the no-override path onto a single solver thread and
  a single pool slot.
