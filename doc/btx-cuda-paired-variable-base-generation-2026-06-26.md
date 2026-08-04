# CUDA Paired Variable-Base Generation

## Summary

This note documents the second CUDA MatMul follow-up optimization on top of the
fused variable-base perturbation change.

The retained change pairs A/B seed-midstate precompute and A/B perturbed matrix
generation in the CUDA variable-base nonce-seed path. On the RTX 5060 benchmark
host, the fixed comparison shape improved by `+0.73%` to `+0.75%` mean
nonces/sec over the fused-perturbation baseline. The scan-heavy factor-64
guardrail was slightly positive at `+0.13%`.

This is a miner-performance change only. It does not change consensus, nonce
validity, MatMul seeds, low-rank noise derivation, product digests, the prehash
gate, or target checks.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-paired-variable-base-generation-2026-06-26/
```

## What Changed

After the fused perturbation optimization, the variable-base CUDA path built a
batch as:

1. Precompute A seed SHA midstates.
2. Generate perturbed A.
3. Precompute B seed SHA midstates.
4. Generate perturbed B.

This optimization changes that to:

1. Precompute A and B seed SHA midstates in one kernel.
2. Generate perturbed A and B in one paired matrix kernel.

The paired generation kernel maps one thread to one matrix element index and
computes the same local element for both A and B. That lets it share the
batch/local index calculation, row/column calculation, and packed input pointer
lookup while emitting both output matrices.

The retained change removes one precompute launch and one matrix-generation
launch per variable-base digest batch. It does not reduce the matrix memory
traffic beyond the fused-perturbation change; it mainly reduces launch overhead
and duplicate per-thread setup.

## Rejected Subtrial

A smaller paired-midstate-only trial was benchmarked first. It paired A/B
midstate precompute but kept separate A and B matrix-generation launches.

That run was noise on the fixed comparison shape:

| Trial | Mean n/s | Mean vs fused-perturbation baseline |
| --- | ---: | ---: |
| Paired midstate only | `53.76M` | `-0.02%` |

The retained unit is therefore the paired midstate plus paired A/B generation
change, not the midstate-only change.

## Kernel Resource Notes

`cuobjdump --dump-resource-usage` for the retained build reported:

| Kernel | Registers | Stack | Local | Shared |
| --- | ---: | ---: | ---: | ---: |
| `PrecomputeSeedPairMidstatesKernel` | `40` | `0` | `0` | `0` |
| `GeneratePerturbedMatrixPairFromSeedMidstatePackedPointersKernel` | `95` | `0` | `0` | `0` |

The paired matrix-generation kernel retained the same `95` register count as
the single-matrix fused generator from the previous optimization and did not add
stack or local-memory spills.

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

The baseline for this note is the fused-perturbation commit:

- Fixed comparison mean: `53.77M` nonces/sec
- Fixed comparison median: `53.78M` nonces/sec
- Factor-64 mean: `603.15M` nonces/sec
- Factor-64 median: `610.26M` nonces/sec

| Case | Mean n/s | Median n/s | Mean vs fused baseline | Active power | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| Fixed comparison run 1 | `54.18M` | `54.21M` | `+0.75%` | `101.31 W` | Positive |
| Fixed comparison repeat | `54.17M` | `54.20M` | `+0.73%` | `102.48 W` | Positive |
| Factor-64 scan-heavy guardrail | `603.93M` | `611.13M` | `+0.13%` | `96.43 W` | Neutral-positive |

The retained fixed-shape average is `54.17M` mean nonces/sec, which is
`+3.28%` over the final PR #278 fixed-shape baseline of `52.45M` mean
nonces/sec. The sampled board-power readings increased versus the immediately
prior fused-perturbation run, so this should be treated as a small throughput
optimization rather than a power-reduction change.

Fixed comparison command:

```bash
build-cuda/bin/btx-matmul-solve-bench \
  --backend cuda \
  --iterations 5 \
  --tries 200000000 \
  --n 512 \
  --b 16 \
  --r 8 \
  --nbits 0x1d01433a \
  --epsilon-bits 18 \
  --block-height 142340 \
  --nonce-seed-height 125000 \
  --parent-mtp-seed-height 130500 \
  --parent-mtp 1782494892 \
  --product-digest-height 61000
```

Factor-64 guardrail command:

```bash
build-cuda/bin/btx-matmul-solve-bench \
  --backend cuda \
  --iterations 20 \
  --tries 600000000 \
  --n 512 \
  --b 16 \
  --r 8 \
  --nbits 0x1c04e984 \
  --epsilon-bits 18 \
  --block-height 142378 \
  --nonce-seed-height 125000 \
  --parent-mtp-seed-height 130500 \
  --parent-mtp 1782498541 \
  --product-digest-height 61000
```

## Hardware Scaling Estimate

This optimization has no operator setting. It should remain valid on larger
CUDA GPUs because the paired kernel did not increase register count or spill to
local memory.

Expected scaling:

| Hardware class | Expected setting change | Reason |
| --- | --- | --- |
| RTX 5060 | none | Measured positive on the current `512x16x8` shape. |
| 5090-class CUDA GPU | none | CUDA batch sizing already scales separately; paired generation has no tuning knob. |

The percentage gain may be smaller on a 5090-class GPU if its larger batch size
makes launch overhead a smaller share of total work. The benefit also shrinks
when the nonce-seed scan dominates runtime, as shown by the factor-64 guardrail.
No default setting needs to change for more capable GPUs.

Review this optimization if future CUDA compilers raise the paired generator's
register count enough to reduce occupancy or introduce local-memory spills. For
the current build, resource usage stayed flat against the single-generator
baseline.

## Validation

Build:

```bash
/usr/bin/time -p cmake --build build-cuda --target btx-matmul-solve-bench test_btx -j$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l)
```

Focused tests passed:

```bash
build-cuda/bin/test_btx --run_test=matmul_accelerated_solver_tests/cuda_variable_base_device_batch_matches_cpu_product_digest
build-cuda/bin/test_btx --run_test=matmul_accelerated_solver_tests/cuda_nonce_seed_v2_mainnet_boundary_variable_base_product_digest_matches_cpu
build-cuda/bin/test_btx --run_test=matmul_accelerated_solver_tests/cuda_strict_regtest_warning_repro_nonce_scan_matches_cpu_or_cleanly_falls_back
build-cuda/bin/test_btx --run_test=pow_tests/MatMulParentMtpSeed_cuda_solver_uses_gpu_scan_and_variable_base_batch
build-cuda/bin/test_btx --run_test=pow_tests/MatMulNonceSeed_cuda_prehash_scan_matches_cpu_gate
build-cuda/bin/test_btx --run_test=pow_tests/MatMulParentMtpSeed_cuda_prehash_scan_matches_cpu_gate
build-cuda/bin/test_btx --run_test=pow_tests/MatMulNonceSeed_cuda_batch_override_accepts_large_batch
```

`git diff --check` passed.
