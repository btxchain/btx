# CUDA Survivor Record Hydration

## Summary

This note documents a retained CUDA mining pipeline optimization for the
nonce-seeded prehash survivor path.

The compact CUDA prehash scanner already computes `seed_a`, `seed_b`, and
`sigma` while testing each nonce against the prehash gate. Before this change,
the scanner returned only survivor offsets. The host then rebuilt each survivor
header by recomputing the deterministic MatMul seeds and later derived `sigma`
again while preparing CUDA digest inputs.

This change adds an optional compact survivor-record mode for CUDA prehash
scans. After the compact scan finds survivor offsets, CUDA hydrates one record
per survivor containing the offset, `seed_a`, `seed_b`, and `sigma`. The solver
uses those records to populate survivor headers and passes the precomputed
sigmas into batched CUDA digest-input preparation.

On the RTX 5060 benchmark host, the fixed current-difficulty comparison showed
a small `+0.42%` mean and `+0.44%` median nonces/sec improvement versus the
previous retained product-digest-finalization baseline. The factor-64
scan-heavy guardrail was effectively neutral at `-0.11%` mean and `-0.12%`
median.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-survivor-record-hydration-2026-06-26/
```

## What Changed

`btx::cuda::ScanMatMulNonceSeedPreHashGPU` now accepts
`compact_pass_records` when `compact_pass_offsets` is enabled. The old compact
offset behavior remains unchanged for callers that do not request records.

The CUDA implementation keeps the original scan kernel result layout, then
optionally launches a survivor hydration kernel over the compact offset list.
That kernel recomputes the same nonce-seed prehash material for surviving
offsets only and writes:

```text
offset || seed_a || seed_b || sigma
```

The host sorts returned records by offset, matching the existing sorted compact
offset list. `BuildMatMulNonceSeededGpuPreHashBatchWindow` validates that the
record offsets match the compact offsets before using the records.

`matmul::accelerated::PrepareMatMulDigestInputsBatchForBackend` now has an
overload that accepts a vector of precomputed sigmas. Existing callers still use
the previous overload, which derives sigmas from headers.

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Driver: `595.58.03`
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

Baseline for this note: retained CUDA product digest finalization.

Fixed current-difficulty comparison:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Product digest finalization average | `58.26M` | `58.31M` | baseline | baseline |
| Survivor record hydration aggregate | `58.50M` | `58.57M` | `+0.42%` | `+0.44%` |

The survivor record fixed comparison used two five-iteration runs and one
ten-iteration run. The mean reports the iteration-weighted aggregate; the
median reports the average of the three run medians.

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

The extended fixed pass used the same command with `--iterations 10`.

Factor-64 scan-heavy guardrail:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Product digest finalization | `610.43M` | `617.96M` | baseline | baseline |
| Survivor record hydration | `609.76M` | `617.20M` | `-0.11%` | `-0.12%` |

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

This optimization has no operator setting. It trades one small CUDA hydration
kernel and about `100` bytes of device-to-host data per survivor for removing
host recomputation of two deterministic MatMul seeds plus `sigma` per survivor.

The 5060 result is intentionally modest because the existing path was already
mostly GPU-bound after the earlier compact scan, batched input generation, and
product digest finalization work. Faster GPUs such as an RTX 5090 should not
need a different tuning value for this change. The record payload scales with
survivor count, and the CUDA hydration work is tied to the same compact offsets
that the solver already consumes.

The likely 5090 behavior is neutral to slightly better than the 5060 result:
as digest throughput rises, host-side seed and sigma reconstruction can become
a larger fraction of the survivor path. Review this area if 5090 measurements
show the fixed-difficulty path regressing beyond normal benchmark noise, or if
future changes keep survivor headers fully on-device and make this host record
copy unnecessary.

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
