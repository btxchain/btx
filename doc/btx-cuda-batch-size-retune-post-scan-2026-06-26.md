# CUDA Batch Size Retune After Scan Optimizations

## Summary

This note documents a retained CUDA nonce-seed mining batch-size retune.

An earlier post-fusion batch-size sweep kept the RTX 5060-class product-digest
CUDA default at `256`. Since then, the scan path changed substantially:
prehash scan midstates are now computed once per scan request, survivor records
avoid host seed/sigma recomputation, and the scan launch was retuned to
`256` threads. Those changes reduce scan-side overhead and make larger survivor
digest batches worth retesting.

This retune changes the product-digest CUDA default for `24..63` SM devices at
the current `n=512`, `b=16`, `r=8` shape from `256` to `512`. Larger CUDA SM
tiers keep their existing scaling behavior.

On the RTX 5060 benchmark host, the no-override confirmation selected batch
size `512` and improved fixed current-difficulty throughput by `+0.44%` mean
versus the prior `256` default. The factor-64 scan-heavy guardrail improved by
`+0.55%` mean.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-batch-size-resweep-post-scan-retune-2026-06-26/
```

## What Changed

`ResolveCudaNonceSeedBatchSize` now raises the CUDA product-digest batch size to
at least `512` when all of the following are true:

- product digest is active
- `n >= 512`
- `b >= 16`
- `r >= 8`
- the primary CUDA device has at least `24` and fewer than `64` SMs

The existing memory cap still applies. The existing `64+` SM tier scaling is
unchanged.

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Driver: `595.58.03`
- SM count: `30`
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

Baseline for this note: retained CUDA 256-thread scan retune with default batch
size `256`.

Fixed current-difficulty sweep:

| Batch size | Mean n/s | Median n/s | Digest batches | Mean vs 256 |
| ---: | ---: | ---: | ---: | ---: |
| `128` | `58.96M` | `58.99M` | `125` | `-0.43%` |
| `256` | `59.21M` | `59.25M` | `62` | baseline |
| `512` | `59.35M` | `59.35M` | `31` | `+0.24%` |

No-override fixed confirmation after the heuristic change:

| Case | Mean n/s | Median n/s | Selected batch | Mean vs prior default |
| --- | ---: | ---: | ---: | ---: |
| Default `512` confirmation | `59.53M` | `59.58M` | `512` | `+0.44%` |

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

Factor-64 scan-heavy guardrail:

| Case | Mean n/s | Median n/s | Selected batch | Mean vs prior default |
| --- | ---: | ---: | ---: | ---: |
| Prior `256` default average | `699.75M` | `709.11M` | `256` | baseline |
| `512` override | `702.80M` | `712.66M` | `512` | `+0.44%` |
| Default `512` confirmation | `703.59M` | `715.36M` | `512` | `+0.55%` |

Factor-64 command:

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

This retune is intentionally scoped to the RTX 5060-class `24..63` SM tier.
More capable GPUs such as an RTX 5090 already use the higher SM-tier scaling
path, so this change does not raise their existing default.

For the current product-digest shape, the defaults remain:

| CUDA SM tier | Product-digest batch behavior |
| ---: | --- |
| `<24` | lower memory/concurrency default |
| `24..63` | `512` after this retune |
| `64..95` | existing `512` tier |
| `96..127` | existing `1024` tier |
| `128..159` | existing `1536` tier |
| `>=160` | existing `2048` tier |

The memory cap still clamps the selected value. A 5090-class GPU should not need
a different setting from this change alone. Revisit the larger tiers only after
direct 5090 measurements, because larger batches trade fewer launches against
larger matrix buffers and possible memory pressure.

## Validation

Build:

```bash
cmake --build build-cuda --target btx-matmul-solve-bench test_btx -j$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l)
```

Focused tests:

```bash
build-cuda/bin/test_btx --run_test='matmul_accelerated_solver_tests/cuda_*'
build-cuda/bin/test_btx --run_test='pow_tests/*cuda*'
```

`git diff --check` passed.
