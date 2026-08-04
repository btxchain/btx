# CUDA Factored Words 2x4 Tile Trial

## Summary

This note documents a rejected MatMul product-final kernel trial.

The retained CUDA product-final path already uses factored compression:

```text
D[j][x][m] = sum_y W[x,y] * B'[m,j,y]
word(i,j) = sum_x sum_m A'[i,x,m] * D[j,x,m]
```

The current word kernel uses one warp per `2x2` output tile. This trial added a
`2x4` tile kernel so each warp reused the same two A rows across four RHS
columns and emitted eight output words instead of four.

The trial was correct and did not increase register count or spill to local
memory, but benchmark results were too small and mixed to justify retaining
another kernel variant. The trial code was reverted.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-factored-words-2x4-trial-2026-06-26/
```

## Trial Details

The experimental kernel:

- used one warp per `2x4` output tile
- required `blocks_per_axis % 4 == 0`
- kept the existing `2x2` kernel as fallback
- reduced tile count by half for the current `512/16` shape
- accumulated eight output words per warp instead of four

`cuobjdump --dump-resource-usage` reported:

| Kernel | Registers | Stack | Local | Shared |
| --- | ---: | ---: | ---: | ---: |
| Existing `ComputeFactoredWordsKernel` (`2x2`) | `40` | `0` | `0` | `0` |
| Trial `ComputeFactoredWords2x4Kernel` | `40` | `0` | `0` | `0` |

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

Baseline for this note: deferred GPU scan prehash confirmation commit.

Fixed comparison shape:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Deferred-confirmation baseline average | `54.35M` | `54.37M` | baseline | baseline |
| `2x4` tile average | `54.42M` | `54.44M` | `+0.13%` | `+0.12%` |

Factor-64 scan-heavy guardrail:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Deferred-confirmation baseline | `603.66M` | `611.08M` | baseline | baseline |
| `2x4` tile | `603.27M` | `610.33M` | `-0.07%` | `-0.12%` |

## Decision

Reject the `2x4` tile kernel for now.

The fixed-shape gain was only `+0.13%` mean and the scan-heavy guardrail moved
slightly negative. That does not justify adding another product-final kernel
variant and another dispatch branch.

## Hardware Scaling Estimate

A 5090-class GPU may have enough bandwidth and scheduling headroom for wider
tiles to behave differently, but the current result does not provide a
portable default. If this area is revisited on larger hardware, benchmark
`2x4`, `4x2`, and possibly `4x4` variants together and include register count,
occupancy, and factor-64 guardrails. Do not assume the RTX 5060 result scales
monotonically because the trial changes per-warp arithmetic intensity and tile
parallelism at the same time.

## Validation

The trial build passed:

```bash
cmake --build build-cuda --target btx-matmul-solve-bench test_btx -j$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l)
```

Focused correctness tests passed before benchmarking:

```bash
build-cuda/bin/test_btx --run_test=matmul_accelerated_solver_tests/cuda_variable_base_device_batch_matches_cpu_product_digest
build-cuda/bin/test_btx --run_test=matmul_accelerated_solver_tests/cuda_nonce_seed_v2_mainnet_boundary_variable_base_product_digest_matches_cpu
```

The experimental code was reverted after benchmarking.
