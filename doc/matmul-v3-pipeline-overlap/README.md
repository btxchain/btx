# v3 nonce-seeded solver: pipeline overlap port

Status: BUILD + BYTE-EXACT VALIDATION (Phase 1). NOT deployed. Production solo
(btx-miner container, btx-miner:local image) untouched.

Source base: btxchain/btx v0.32.11, commit 215170f27f7d6889ce34aa7dbba2858ea07a468c
Patch: patches-overlap/v3-pipeline-overlap.patch (applies to a pristine v0.32.11 tree)
Touches: src/pow.cpp only. PoW math, seed derivation, parent_mtp handling unchanged.

## Problem

At v3 (height >= 130500) SolveMatMul routes to SolveMatMulNonceSeeded, which the
upstream dispatch runs strictly SERIAL: per window it does GPU prehash scan ->
single-threaded CPU prepare_inputs (GPU idle) -> one BLOCKING GPU digest (CPU
idle) -> per-candidate CPU confirm (GPU idle). The async/prefetch overlap that
exists and is proven on the legacy v2 path was hard-disabled for v3 at the
dispatch (g_matmul_async_prepare_enabled=false / g_matmul_cpu_confirm_candidates
=false / g_matmul_prefetch_depth=1). Live solo GPU duty cycle ~58%.

## The port (pure scheduling)

1. Dispatch (was the v3 hard-off): replaced the hardcoded
   `g_matmul_async_prepare_enabled.store(false)` / `_prefetch_depth.store(1U)`
   with env-resolved values via a new gate `ShouldEnableNonceSeededPipelineOverlap`
   + the existing `ResolvePreparePrefetchDepth`. SAFE DEFAULT: when
   BTX_MATMUL_PIPELINE_ASYNC is unset the gate returns false, so the OLD serial
   behaviour is preserved exactly. async=1 turns the overlap on. (Deliberately
   does NOT inherit ShouldEnableAsyncPrepare's CUDA-default-true, which would
   silently change behaviour on every Blackwell box.) g_matmul_batch_size still
   carries the GPU-scan window size from ResolveGpuNonceSeedBatchSize (untouched).

2. SolveMatMulNonceSeeded: added a SEPARATE overlap loop, gated on
   `g_matmul_async_prepare_enabled && gpu_nonce_seed_scan_available`, inserted
   immediately before the verbatim serial loop. When the gate is off (default),
   the serial loop runs bit-for-bit unchanged. The overlap loop applies the v2
   prefetch shape to the v3 variable-base path:

     - SUBMIT digest(N) non-blocking via std::async(std::launch::async, ...)
       wrapping ComputeMatMulDigestPreparedVariableBaseBatchForMining (the exact
       same blocking call the serial path makes; the v2 split uses the identical
       std::async wrapper around ComputeCudaDigestsPreparedBatch).
     - While digest(N) runs: BUILD window N+1 (GPU prehash scan) and PREPARE its
       inputs on the EXISTING MatMulPrepareExecutor worker pool (via
       SubmitPreparedBatch / CollectPreparedBatchFutures), then submit digest(N+1).
     - WAIT digest(N) (.get()), CONFIRM its candidates IN ORDER via the existing
       evaluate_batched_digest_result, return the first SOLVED.
     - Hand the already-prepared N+1 stage to the next iteration.

   EXACTLY ONE GPU digest is in flight at a time (same invariant as the v2
   submit -> queue_prefetched_batches -> wait pattern), so the overlap adds no
   concurrent CUDA batch calls and no extra GPU-side contention vs serial. The
   hidden cost is the per-window CPU prepare + the next GPU prehash scan, which
   now overlap the in-flight digest.

3. PoW math / seed derivation / parent_mtp: untouched. The overlap only reorders
   WHEN prepare/scan/confirm run relative to the digest; the inputs to and
   outputs of every PoW call are identical.

## Byte-exactness argument

- Windows are built strictly sequentially from the SAME block cursor state
  (BuildMatMulNonceSeededGpuPreHashBatchWindow is a pure function of the cursor +
  params), so each window covers the identical nonce range the serial loop would.
- digest(N) is fully awaited and its candidates confirmed in scan order BEFORE
  window N+1 is surfaced, so the FIRST solved (nonce, digest) returned is exactly
  the one serial returns.
- max_tries is decremented identically: filtered_nonces per window, 1 per
  confirmed candidate.
- The real `block` cursor is only advanced when a window finishes WITHOUT solving
  (mirrors advance_nonce_window), so a fallthrough to the serial loop (e.g. if the
  GPU scan becomes unavailable mid-run) resumes from the correct nonce.

## Env knobs the v3 path now respects

- BTX_MATMUL_PIPELINE_ASYNC: 0/unset = serial (default), 1 = overlap on.
- BTX_MATMUL_PREPARE_PREFETCH_DEPTH: via ResolvePreparePrefetchDepth (prefetch
  window depth; clamped, default per CUDA SM heuristics).
- BTX_MATMUL_PREPARE_WORKERS: via ResolveMatMulPrepareWorkerCount (the
  MatMulPrepareExecutor pool size that prepares windows).
- BTX_MATMUL_SOLVE_BATCH_SIZE: the GPU-scan window size continues to come from
  ResolveGpuNonceSeedBatchSize (v3 scan path); the env override path is the same
  one the v2 path reads. (The v3 scan batch is intentionally left on its own
  resolver to avoid touching the prehash-scan math.)

This gives a clean A/B and lets prefetch-depth / prepare-workers be swept live via
env with no rebuild.

## Build

Isolated container nvidia/cuda:12.8.0-devel-ubuntu24.04, sm_120, cmake Release,
-DBUILD_TESTS=ON -DBUILD_UTIL=ON. Output to /home/vanities/btx-overlay-out (NOT
btx-miner:local). Targets: btxd, test_btx, btx-matmul-solve-bench, and the A/B
harness btx-matmul-overlap-ab (added as a util target next to the solve-bench).

## Validation

(a) ctest: the CUDA-vs-CPU reference tests in matmul_accelerated_solver_tests
    (cuda_variable_base_device_batch_matches_cpu_product_digest,
     cuda_nonce_seed_v2_mainnet_boundary_variable_base_product_digest_matches_cpu,
     cuda_*_matches_cpu_or_cleanly_falls_back) prove the variable-base digest path
    the overlap drives still matches the CPU reference.

(b) A/B determinism: btx-matmul-overlap-ab solves the SAME fixed v3 job over the
    SAME nonce range twice (serial vs overlap) and asserts the full sequence of
    found (nonce64, digest) pairs is identical. v3 representative: real
    parent-mtp-seed-height / nonce-seed-height / product-digest-height and a real
    parent_mtp, with a relaxed target so the digest gate yields several finds in a
    short run (the per-nonce v3 seed derivation is fully exercised regardless of
    target; only the final acceptance threshold is relaxed).

(Results appended below after the runs.)

---

## VALIDATION RESULTS (2026-06-14)

Build: btx v0.32.11 (215170f2) + patch, CUDA 12.8 devel, sm_120, Release,
BUILD_TESTS=ON BUILD_UTIL=ON. Isolated container; btx-miner:local and the
running btx-miner solo container were NOT touched (verified up throughout).
Binaries: /home/vanities/btx-overlay-out/bin/{btxd,test_btx,btx-matmul-solve-bench,btx-matmul-overlap-ab}

### (a) ctest - CUDA-vs-CPU PoW reference

  ctest -R matmul_accelerated_solver_tests
  1/1 Test #69: matmul_accelerated_solver_tests ... Passed
  100% tests passed, 0 tests failed out of 1

Confirmed the CUDA path is genuinely exercised (not a CPU fallback). Verbose run
of cuda_variable_base_device_batch_matches_cpu_product_digest shows:
  check prepared.cuda_generated_inputs != nullptr   PASS  (device inputs used)
  check batch_results[i].backend == Kind::CUDA       PASS  (CUDA backend, not fallback)
  check batch_results[i].digest == cpu_digest        PASS  (CUDA digest == CPU reference)
=> the variable-base digest path the overlap drives matches the CPU reference byte-exactly.
Log: validation-logs/ctest-matmul-accelerated-solver.log

### (b) A/B determinism - serial vs overlap, SAME v3 job + SAME nonce range

Job (v3 representative): block-height 130600, parent-mtp-seed-height 130500,
nonce-seed-height 125000, product-digest-height 61000, parent-mtp 1781450513
(real mediantime of mainnet block 130599), epsilon-bits 18, backend cuda.
Header reported: parent_mtp_seed_active@height=YES(v3), product_digest_active=yes.
nbits relaxed to 0x207fffff so the digest gate yields a comparable sequence; the
per-nonce v3 seed derivation is fully exercised regardless of target.

Run 1 (defaults):
  serial  found 24 nonce(s)
  overlap found 24 nonce(s)
  RESULT: BYTE-EXACT IDENTICAL (24 found nonces + digests match)

Run 2 (env knobs active: --prefetch-depth 4 --prepare-workers 8 --gpu-inputs 0):
  serial  found 24 nonce(s)
  overlap found 24 nonce(s)
  RESULT: BYTE-EXACT IDENTICAL (24 found nonces + digests match)

Every found nonce64 AND its 256-bit digest is identical between the serial path
(BTX_MATMUL_PIPELINE_ASYNC=0) and the overlap path (=1), in identical order. No
divergence -> no race (no buffer reused before the GPU finished). gpu-inputs=0
(CPU-side input gen, the case the overlap most helps) is also byte-exact.
Logs: validation-logs/ab-serial-vs-overlap-cuda.log,
      validation-logs/ab-prefetch4-workers8-gpuinputs0.log

Cross-check: CPU backend A/B also byte-exact (38/38) at n=64.

### VERDICT

BYTE-EXACT: YES. The v3 overlap produces the SAME found nonces + digests as the
serial path on the real v3 (parent_mtp) seed path, and the CUDA digest still
matches the CPU reference (ctest). Ready for a live throughput test (Phase 2,
handled separately): default stays serial; flip BTX_MATMUL_PIPELINE_ASYNC=1 to
enable the overlap. NOT deployed to production.
