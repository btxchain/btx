# CUDA Pinned Product Digest Copyback Trial

## Summary

This note documents a rejected CUDA product digest copyback trial.

The retained product-digest CUDA path copies one `uint256` digest per survivor
from device to host using a small pageable `std::vector<DeviceDigestBytes>`.
The trial reused the existing CUDA digest workspace pinned host staging buffer
for that copyback, avoiding a per-batch host vector allocation and making the
digest D2H copy target pinned.

The change was correct, but benchmark results did not support retaining it. The
code was reverted.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-pinned-product-digest-copyback-2026-06-26/
```

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

Baseline for this trial: retained CUDA direct seed/sigma copy.

Fixed current-difficulty comparison:

| Case | Mean n/s | Median n/s | Mean vs baseline |
| --- | ---: | ---: | ---: |
| Direct seed/sigma copy average | `59.25M` | `59.25M` | baseline |
| Pinned product digest copyback average | `59.24M` | `59.26M` | `-0.01%` |

Factor-64 scan-heavy guardrail:

| Case | Mean n/s | Median n/s | Mean vs baseline |
| --- | ---: | ---: | ---: |
| Direct seed/sigma copy average | `696.74M` | `705.36M` | baseline |
| Pinned product digest copyback | `696.17M` | `704.27M` | `-0.08%` |

## Decision

Do not retain this change.

The digest copyback is only `32` bytes per survivor, so the pinned staging
target did not offset the added workspace use and aliasing complexity on the RTX
5060. The current pageable vector copyback is simple and measured slightly
better in this trial.

This may be worth revisiting only if a future path batches much larger digest
copybacks or uses asynchronous overlap where pinned host memory is required for
correct overlap. With the current synchronous mining batch flow, keep the
existing copyback.

## Validation

Trial build:

```bash
cmake --build build-cuda --target btx-matmul-solve-bench test_btx -j$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l)
```

Focused tests during the trial:

```bash
build-cuda/bin/test_btx --run_test='matmul_accelerated_solver_tests/cuda_*'
build-cuda/bin/test_btx --run_test='pow_tests/*cuda*'
```

`git diff --check` passed before benchmarking.
