# CUDA Single-Copy Compact Scan Trial

## Summary

This note documents a rejected CUDA nonce-seed prehash scan pipeline trial.

The existing compact scan path copies the compact pass count back to the host,
synchronizes, then copies exactly the pass offsets that survived the prehash
gate. The trial changed compact mode to use one device buffer where word `0`
held the pass count and words `1..scan_count` held the offsets. The host then
copied the full bounded output buffer in one transfer and synchronized once.

The goal was to remove one host synchronization and one small device-to-host
copy per scan window. Benchmarking did not support retaining the change, so the
code was reverted.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-single-copy-compact-scan-2026-06-26/
```

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

Baseline for this trial: retained batched CUDA device input generation.

Fixed current-difficulty comparison:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Batched device input generation average | `55.89M` | `55.92M` | baseline | baseline |
| Single-copy compact scan average | `55.19M` | `55.23M` | `-1.25%` | `-1.23%` |

Factor-64 scan-heavy guardrail:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Batched device input generation | `607.24M` | `614.18M` | baseline | baseline |
| Single-copy compact scan | `537.63M` | `544.10M` | `-11.46%` | `-11.41%` |

## Decision

Do not retain this change.

The saved synchronization did not offset the changed copyback behavior on the
RTX 5060. In particular, the scan-heavy guardrail regressed sharply. The
existing two-step compact path remains preferable because it reads the count
first and copies only the survivor offsets.

This may be worth revisiting only if a future scan path keeps compact offsets
entirely on-device or consumes them in a following CUDA stage without a host
round trip. As long as the host needs the survivor headers, this one-copy
layout should stay rejected.

## Validation

Build:

```bash
cmake --build build-cuda --target btx-matmul-solve-bench test_btx -j$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l)
```

Focused tests run during the trial:

```bash
build-cuda/bin/test_btx --run_test='pow_tests/*cuda*'
```
