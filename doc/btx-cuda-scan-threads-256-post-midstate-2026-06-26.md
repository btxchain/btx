# CUDA 256-Thread Scan Retest After Midstate Setup

## Summary

This note documents a retained CUDA nonce-seed prehash scan launch-geometry
change.

An earlier trial rejected `ORACLE_SCAN_THREADS = 256` because the 256-thread
scan launch was slightly slower than the 128-thread default. That result was
measured before the prehash scanner moved nonce-independent SHA-256 midstate
setup into a once-per-scan setup kernel.

After the midstate setup change, the scan kernel no longer pays the same
serialized SHA setup cost in every CUDA block. This retest changes
`ORACLE_SCAN_THREADS` from `128` to `256`. On the RTX 5060 benchmark host, the
fixed current-difficulty comparison was effectively neutral-positive at
`+0.04%` mean and `+0.15%` median nonces/sec, while the factor-64 scan-heavy
guardrail improved by `+0.43%` mean and `+0.53%` median.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-scan-threads-256-post-midstate-2026-06-26/
```

## What Changed

The CUDA oracle scan launch geometry changed from:

```text
ORACLE_SCAN_THREADS = 128
```

to:

```text
ORACLE_SCAN_THREADS = 256
```

The generic oracle kernels still use their existing thread geometry. This
constant only affects the nonce-seed prehash scan kernel and the optional
survivor-record hydration kernel.

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Driver: `595.58.03`
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

Baseline for this note: retained CUDA direct seed/sigma copy with the
post-midstate `128`-thread scan default.

Fixed current-difficulty comparison:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| 128-thread scan post-midstate | `59.25M` | `59.25M` | baseline | baseline |
| 256-thread scan post-midstate | `59.27M` | `59.33M` | `+0.04%` | `+0.15%` |

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

The fixed comparison was repeated once; the table reports the average of the
two five-iteration runs.

Factor-64 scan-heavy guardrail:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| 128-thread scan post-midstate | `696.74M` | `705.36M` | baseline | baseline |
| 256-thread scan post-midstate | `699.75M` | `709.11M` | `+0.43%` | `+0.53%` |

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

The factor-64 guardrail was repeated once; the table reports the average of the
two twenty-iteration runs.

## Hardware Scaling Estimate

This optimization has no operator setting. It changes a compile-time CUDA
kernel launch geometry.

The result is expected to remain reasonable on more capable GPUs such as an RTX
5090 because the scan kernel now has less per-block serialized setup work and
can use fewer, larger blocks for the same scan window. The exact best thread
count is still hardware- and compiler-sensitive. Larger GPUs may benefit from
additional launch geometry retesting, especially if future CUDA compiler
resource allocation changes scan occupancy.

Review this setting if future profiling shows lower occupancy, register
pressure regressions, or materially different scan-heavy behavior on 5090-class
hardware. The prior 128-thread default was correct before midstate setup; this
change should be understood as dependent on the current scan kernel shape.

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
