# MatMul Backend Compatibility And Performance Notes

Date: 2026-03-28
Branch: `codex/local-metal-mining-optimizations`
Base commit: `03ab19b53f808b8fd27d06539461012fa3851579`
Scope: Verified backend behavior and performance notes that now accompany the MatMul digest transition work.

## Goals

- Analyze the current BTX mining path for Apple Metal performance bottlenecks.
- Validate which proposed optimizations fit the current architecture and which do not.
- Implement deterministic, regression-safe performance improvements only where correctness can be preserved.
- Add a repeatable benchmark and test workflow to measure improvements or regressions.
- Keep the final local branch build-clean with no warnings or errors in the verified outputs.

## Initial User-Proposed Areas

- Double-buffered GPU pipeline
- Multiple command queues
- Larger solve batches
- `simdgroup_matrix`-style shader optimization
- Barrier minimization
- FP16 usage where valid

## Current Findings

- The current implementation already had more optimization infrastructure than the initial proposal assumed:
  - embedded and standalone Metal kernel sources
  - fused transcript path
  - function-constant specialization
  - batch digest API
  - async CPU prepare within a batch
  - dedicated Metal runtime profiling and benchmark targets
- The build on this machine was originally configured with:
  - `BTX_ENABLE_METAL=OFF`
  - `BUILD_BENCH=OFF`
- A dedicated build tree was created:
  - `build-metal-opt`
- The machine-level Xcode `metal` toolchain component is still broken / unavailable.
  - `xcodebuild -downloadComponent MetalToolchain` fails because local Xcode plugin loading is unhealthy.
  - This branch keeps the CMake escape hatch that allows runtime inline Metal compilation without build-time `metallib`.
- Runtime Metal is available in `build-metal-opt` using inline-source fallback.

## Implemented Work

- Host-side staging reuse for batched digests:
  - `ComputeCanonicalTranscriptDigestBatch` now reuses pooled staging buffers with explicit offsets instead of per-item `newBufferWithLength` churn.
- Solve-loop CPU prefetch:
  - the next nonce window can be prepared while the current batch digests, but only when header refresh would not invalidate the prefetched work.
- Dispatch hot-path cleanup:
  - Metal buffer binding now uses `setBuffers:offsets:withRange:` in the hot encoder path.
  - `commandBufferWithUnretainedReferences` stays in the hot path.
- Deterministic benchmark tooling:
  - `btx-matmul-metal-bench` measures request latency, per-digest latency, aggregate throughput, and buffer-pool behavior.
  - `bench_btx` coverage was expanded for direct Metal digest and solve-throughput measurements.
  - `btx-matmul-solve-bench` now measures repeated live-like `SolveMatMul` runs, supports explicit env-style overrides, and can run synchronized parallel solve rounds to test queue-depth ideas against whole-solver throughput.
- Concurrency instrumentation:
  - the Metal digest path now supports an explicit slot-count override with `BTX_MATMUL_METAL_POOL_SLOTS`.
  - buffer-pool telemetry now reports `slot_count`, `active_slots`, `high_water_slots`, and `wait_events`.
  - `btx-matmul-metal-bench --parallel <threads>` issues synchronized concurrent digest requests so slot-pool experiments are measured honestly.
- Apple Silicon worker tuning:
  - `BTX_MATMUL_PIPELINE_ASYNC=0` now genuinely disables async prepare instead of silently falling back to the default path.
  - default async prepare stays enabled for Metal, including `batch_size=1`, because repeated live-like solve benchmarks showed that the single-nonce prefetch path still improves end-to-end throughput.
  - the async prepare worker auto-count now prefers `hw.perflevel0.logicalcpu - 1` on Apple Silicon, leaving one performance core for the foreground solve loop.
- Regression coverage:
  - batch staging reuse tests
  - single-nonce solve prefetch test
  - concurrent Metal digest correctness and contention-accounting test
  - explicit tests for default single-nonce async behavior, multi-batch async behavior, and `BTX_MATMUL_PIPELINE_ASYNC=0`
  - mainnet-shape GPU-input correctness parity test against CPU oracle generation

## Architectural Assessment

- Good candidates that were worth implementing:
  - reduce repeated batch input buffer allocation in `ComputeCanonicalTranscriptDigestBatch`
  - improve cross-batch CPU/GPU overlap in the solve loop
  - improve benchmark coverage around batch size, transcript path choice, and contention behavior
  - add an opt-in multi-slot staging pool so queue-concurrency assumptions can be tested instead of guessed
- Not sensible to ship as default in this codebase right now:
  - blanket FP16 conversion
    - unsafe for exact 31-bit field arithmetic without a deeper algorithm redesign
  - `simdgroup_matrix` / cooperative tensor rewrite for the current integer mod-field kernel
    - current path is exact `uint32` modular arithmetic, not FP GEMM
  - speculative SIMD-group reduction rewrite for the fused compression kernel
    - a prototype was tried earlier and regressed on this machine
  - multi-slot command queues by default
    - implemented and benchmarked here
    - removes slot-pool waits, but regresses miner-style throughput on this Apple A18 Pro when turned on by default

## External Guidance Notes

- Official Apple guidance reviewed:
  - [Metal Feature Set Tables](https://developer.apple.com/metal/capabilities/)
  - [Advanced Metal Shader Optimization (WWDC16)](https://developer.apple.com/videos/play/wwdc2016/606/)
- Guidance that matched this branch’s direction:
  - reuse queues and buffers
  - avoid unnecessary copies on unified memory
  - put enough work in each compute dispatch to avoid launch overhead
  - use the smallest synchronization scope necessary
- Guidance that did not directly justify a code change here:
  - smaller numeric types only when numerically safe
  - SIMD-group reductions only where they fit the actual arithmetic and launch structure

## Multi-Slot Round Findings

- Added `BTX_MATMUL_METAL_POOL_SLOTS`:
  - default is now `1`
  - values above `1` remain available for explicit local experiments
- Why default stays at `1`:
  - synchronized parallel microbenchmarks show that extra slots eliminate pool waits but do not improve aggregate digest throughput enough to justify the added default complexity on this machine
  - the miner-style solve benchmark regresses sharply when extra slots are enabled by default
- Measured on this Apple A18 Pro machine:
  - microbenchmark, `parallel=2`, `pool-slots=1`:
    - aggregate throughput: `~101.28 digests/s`
    - `wait_events_delta=10`
  - microbenchmark, `parallel=2`, `pool-slots=3`:
    - aggregate throughput: `~101.53 digests/s`
    - `wait_events_delta=0`
    - interpretation: pool contention disappeared, throughput gain was effectively noise-level
  - microbenchmark, `parallel=3`, `pool-slots=1`:
    - aggregate throughput: `~109.72 digests/s`
  - microbenchmark, `parallel=3`, `pool-slots=3`:
    - aggregate throughput: `~108.63 digests/s`
    - interpretation: multi-slot was slightly slower
  - microbenchmark, `parallel=4`, `pool-slots=1`:
    - aggregate throughput: `~116.56 digests/s`
  - microbenchmark, `parallel=4`, `pool-slots=4`:
    - aggregate throughput: `~108.93 digests/s`
    - interpretation: higher slot counts clearly regressed on this workload

## Async / Worker / GPU-Input Round Findings

- Repeated live-like `SolveMatMul` measurements overturned an earlier noisy result:
  - forcing `BTX_MATMUL_PIPELINE_ASYNC=1` for `batch_size=1` is materially faster than sync
  - keeping async enabled by default is the correct choice on this machine
- With the corrected solve benchmark:
  - default single-thread, auto settings:
    - `~0.5603 s / 2048 tries`
    - `~3862 nonces/s`
  - forced sync (`BTX_MATMUL_PIPELINE_ASYNC=0`):
    - `~0.6072 s / 2048 tries`
    - `~3458 nonces/s`
  - interpretation:
    - async default is about `11.7%` faster than sync on this workload
- Prepare worker sweep on this Apple Silicon machine:
  - `workers=1`:
    - `~4408 nonces/s` in the 12-iteration confirmation run
  - `workers=2`:
    - `~3499 nonces/s`
  - `workers=4`:
    - `~3563 nonces/s`
  - interpretation:
    - the old `hardware_concurrency - 1` style auto-count was over-threading the CPU side here
    - one helper worker plus the foreground solver thread best matches the two visible performance cores on this device
- GPU input generation remains a non-default experiment:
  - isolated input-prep benchmarks still show GPU oracle generation faster than CPU oracle generation
  - but the longer live-like solve comparison still favors CPU-generated inputs:
    - default, 24 iterations:
      - `~4252 nonces/s`
    - `BTX_MATMUL_GPU_INPUTS=1`, 24 iterations:
      - `~3872 nonces/s`
  - interpretation:
    - the extra Metal dispatches still cost more than the CPU oracle work they replace in the full solve path
- Larger nonce batches remain a clear loss for this mainnet shape:
  - `batch_size=2`:
    - `~1642 nonces/s`
  - default `batch_size=1`:
    - `~3862 nonces/s`

## Parallel Solve Benchmark Findings

- `btx-matmul-solve-bench --parallel` was added to measure whole-solver concurrency instead of digest-only concurrency.
- On this branch with the new default worker heuristic:
  - `parallel=2`, `pool-slots=1`:
    - `~5074 nonces/s`
    - `wait_events=182`
  - `parallel=2`, `pool-slots=2`:
    - `~4450 nonces/s`
    - `wait_events=0`
  - interpretation:
    - extra slots remove waits but still do not help at low parallelism
  - `parallel=4`, `pool-slots=1`, auto workers:
    - `~5383 nonces/s`
  - `parallel=4`, `pool-slots=4`, auto workers:
    - `~5493 nonces/s`
  - `parallel=4`, `pool-slots=4`, `BTX_MATMUL_PREPARE_WORKERS=4`:
    - `~6375 nonces/s`
  - interpretation:
    - once the process is intentionally running several concurrent solver threads, extra pool slots and more prepare workers can matter
    - that is useful for explicit local experimentation, but it is not the right single-thread default for the main node solve path

## Shared Seed-Matrix Cache Findings

- The first in-process `BTX_MATMUL_SOLVER_THREADS` implementation still lost on this machine because every worker rebuilt the same seed-derived base matrices.
- A shared immutable cache for `matmul::FromSeed(seed, n)` is now wired into the mining and validation paths through `matmul::SharedFromSeed(...)`.
- The cache keeps a small LRU of seed/dimension pairs and returns shared read-only matrices, so solver threads reuse the expensive seed expansion work instead of replaying it.
- This round also cleaned the arm64 build noise by stopping unconditional compilation of `sha256_sse4.cpp` when SSE4 is not enabled.
- After the cache landed, the whole-solver thread fanout results changed materially on this Apple A18 Pro machine:
  - single-thread default, `12 x 2048` tries:
    - `~4571 nonces/s`
    - median `~4078 nonces/s`
  - `solver_threads=2`, `pool_slots=2`, `prepare_workers=2`:
    - `~5280 nonces/s`
    - median `~5325 nonces/s`
  - `solver_threads=4`, `pool_slots=4`, `prepare_workers=4`:
    - `~5377 nonces/s`
    - median `~5246 nonces/s`
- Interpretation:
  - the shared seed cache is a real mining optimization, not just a benchmark artifact
  - the old conclusion that single-thread should always stay default on this MacBook is no longer reliable after removing repeated seed expansion from the threaded path
  - the right strategy is now machine-specific autotuning rather than a fixed branch-wide default

## Branch-Level Performance

- Miner-style benchmark:
  - current branch default, `bench_btx` live-like solve benchmark:
    - `~0.2276 s/op`
  - base worktree at `03ab19b53f808b8fd27d06539461012fa3851579`, same benchmark:
    - `~0.3419 s/op`
- Interpretation:
  - this local optimization branch is now about `33.4%` lower latency than the current main-branch baseline in the same `bench_btx` solve benchmark
  - equivalently, throughput is about `50.2%` higher than the baseline on this machine for that benchmark
  - the meaningful gains are coming from staging reuse, solve-loop prefetch, default-on async prepare, and the new Apple-Silicon worker heuristic
- Single-digest microbenchmarks remain much closer to noise:
  - current branch has only a small edge over base there
  - the end-to-end solve benchmark is the more relevant signal for mining

## Validation Results

- Clean builds completed in `build-metal-opt`:
  - `cmake --build build-metal-opt --target test_btx -j8`
  - `cmake --build build-metal-opt --target bench_btx -j8`
  - `cmake --build build-metal-opt --target btx-matmul-backend-info -j8`
  - `cmake --build build-metal-opt --target btx-matmul-metal-bench -j8`
  - `cmake --build build-metal-opt --target btx-matmul-solve-bench -j8`
  - `cmake --build build-metal-opt --target bitcoind -j8`
- Warning scans on the successful build logs returned no `warning:` / `error:` matches.
- Passed targeted test suites:
  - `./build-metal-opt/bin/test_btx --run_test=matmul_metal_tests`
  - `./build-metal-opt/bin/test_btx --run_test=pow_tests`
  - `./build-metal-opt/bin/test_btx --run_test=matmul_accelerated_solver_tests`
  - `./build-metal-opt/bin/test_btx --run_test=matmul_mining_tests`
  - `./build-metal-opt/bin/test_btx --run_test=matmul_metal_tests,matmul_accelerated_solver_tests,pow_tests`
- Additional validation completed in this round:
  - `./build-metal-opt/bin/test_btx --run_test=pow_tests,matmul_backend_capabilities_tests,matmul_accelerated_solver_tests,matmul_metal_tests`
  - repeated `btx-matmul-solve-bench` runs for:
    - default auto settings
    - forced sync
    - forced GPU inputs
    - forced batch-size `2`
    - parallel solve rounds with `pool-slots=1/2/4`
    - parallel solve rounds with explicit `prepare_workers=4`
- Baseline comparison completed against:
  - `/Users/admin/Documents/GitHub/btx-node-base-metal`
  - `./build-metal-opt-base/bin/bench_btx -filter=MatMulSolveBatchThroughputMainnetLiveLike -min-time=1000`
- Metal backend info confirms runtime availability on this machine via inline-source fallback:
  - `active_backend=metal`
  - `library_source=inline_source_fallback`
  - default `slot_count=1`

## Maintenance Workflow

- Recommended local patch-stack workflow:
  - `git fetch origin`
  - `git switch codex/local-metal-mining-optimizations`
  - `git rebase origin/main`
  - rerun the local validation bundle in `build-metal-opt`
- For patch export on top of updated `main`:
  - `git format-patch origin/main..codex/local-metal-mining-optimizations`
- Local helpers already in place:
  - `git config rerere.enabled true`
  - a separate base worktree at `/Users/admin/Documents/GitHub/btx-node-base-metal` for before/after performance comparisons

## Decisions

- Keep this branch local-only.
- Keep runtime inline-kernel Metal builds on this machine.
- Keep the multi-slot staging path as an experimental, opt-in tuning knob.
- Do not enable multi-slot queueing by default on this hardware.
- Keep async prepare enabled by default for Metal, including `batch_size=1`.
- Keep GPU-generated inputs disabled by default for the mainnet-like solve path.
- Keep `batch_size=1` as the default mainnet solve batch size.
- Use the Apple-Silicon performance-core heuristic for prepare worker auto-sizing.
- Keep optimization scope focused on deterministic, architecture-fitting wins rather than speculative tensor / FP16 rewrites.
