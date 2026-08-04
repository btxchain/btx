# CUDA Specialized Nonce-Seed Prehash Scan

## Summary

This note documents the CUDA nonce-seed prehash scan follow-up optimization on
top of the compact pass-offset scan and the default
`BTX_MATMUL_NONCE_SEED_SCAN_MULTIPLIER=1`.

The retained change specializes the scan kernel's fixed SHA-256 message layout
and launches the scan kernel with 128 threads per block. On the RTX 5060
benchmark host, the high-difficulty factor-64 case improved from `551.45M` to
`600.48M` mean nonces/sec, a `+8.89%` gain.

This is a miner-performance change only. It does not change consensus, nonce
validity, the prehash gate, MatMul seeds, digest calculation, or target checks.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-specialized-scan-sha-followup-2026-06-26/
```

## What Changed

The previous CUDA scan path built full per-thread byte messages for:

- seed-v2 messages
- seed-v3 messages
- header-hash messages
- the final fixed 32-byte SHA-256 over the header hash

The optimized path builds the fixed SHA-256 block words directly. The
nonce-independent first-block midstates are still computed once per CUDA block
and shared by all threads in that block, but each thread no longer materializes
the full seed/header message arrays.

The scan kernel now uses a dedicated launch width:

```cpp
constexpr uint32_t ORACLE_THREADS = 256;
constexpr uint32_t ORACLE_SCAN_THREADS = 128;
```

The general oracle generation kernels continue to use `256` threads per block.
Only the register-heavy nonce-seed prehash scan uses `128`.

## Kernel Resource Tradeoff

`cuobjdump --dump-resource-usage` showed this scan-kernel change:

| Kernel state | Registers | Stack | Shared |
| --- | ---: | ---: | ---: |
| Compact pass-offset path before this change | `113` | `152` | `1088` |
| Specialized SHA path after this change | `124` | `0` | `1088` |

The optimization removes local stack traffic at the cost of higher register
pressure. The 128-thread scan launch recovered throughput on the RTX 5060
despite the higher register count. A 64-thread launch reduced power but lost too
much throughput and was rejected.

## Benchmark Results

Benchmark shape:

- GPU: NVIDIA GeForce RTX 5060
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`
- Synthetic factor-64 difficulty: `bits=0x1c04e984`
- Iterations: `20`
- Tries: `600,000,000`

Command shape:

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

| Case | Mean n/s | Median n/s | Mean vs baseline | Active power | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| Prior compact-offset, multiplier `1` baseline | `551.45M` | `557.19M` | - | `109.66 W` steady | Baseline |
| Specialized SHA, 256-thread scan | `580.24M` avg | `587.17M` avg | `+5.22%` | `92.7 W` avg | Positive |
| Folded header SHA, 256-thread scan | `579.88M` | `587.07M` | `+5.16%` | `93.6 W` | Neutral |
| Specialized SHA + folded header, 128-thread scan | `600.48M` avg | `607.48M` avg | `+8.89%` | `97.6 W` avg | Retained |
| Specialized SHA + folded header, 64-thread scan | `508.29M` | `514.37M` | `-7.83%` | `90.8 W` | Rejected |

The retained setting is the specialized SHA scan path with a 128-thread scan
launch. The active-power samples are not a perfect apples-to-apples power
profile against the earlier steady-power summary, but the retained candidate did
not need higher sampled power to produce the throughput gain.

## Hardware Scaling Estimate

The scan multiplier and the batch size scale differently:

- `BTX_MATMUL_NONCE_SEED_SCAN_MULTIPLIER` is a statistical scan-window safety
  factor. It controls how far the miner scans ahead for a requested batch of
  passing nonces.
- `BTX_MATMUL_NONCE_SEED_BATCH_SIZE` controls how many passing nonces the miner
  tries to digest in one nonce-seed batch.
- CUDA batch size already auto-scales by detected SM count and memory cap when
  the batch-size environment variables are unset.

For the current `512x16x8` product-digest shape, CUDA starts from a base
nonce-seed batch of `256`. The SM-tier resolver then scales this base:

| CUDA SM tier | Auto batch for this shape |
| ---: | ---: |
| `<24` SMs | `128` |
| `24..63` SMs | `256` |
| `64..95` SMs | `512` |
| `96..127` SMs | `1024` |
| `128..159` SMs | `1536` |
| `>=160` SMs | `2048` |

The RTX 5060 benchmark host selected the `256` batch tier. A 5090-class device
that reports at least `160` SMs should auto-select `2048`, assuming memory does
not cap it lower.

Memory should not be the limiting factor for that shape. One nonce-seed batch
entry is approximately:

```text
2 * 512 * 512 * sizeof(uint32_t) +
(4 * 512 * 8 + 16 * 16) * sizeof(uint32_t)
= 2,163,712 bytes
```

At batch `2048`, that is about `4.13 GiB`. With the default
`BTX_MATMUL_CUDA_NONCE_SEED_MEMORY_PERCENT=25`, a 32 GiB GPU has about `8 GiB`
of nonce-seed batch budget, so the `2048` SM-tier batch remains under the memory
cap. The global maximum remains `4096`.

## 5060 To 5090 Setting Estimate

The current estimate is:

| Setting | RTX 5060 result | 5090-class estimate | Reason |
| --- | ---: | ---: | --- |
| `BTX_MATMUL_NONCE_SEED_SCAN_MULTIPLIER` | `1` | `1` | Larger batches reduce relative pass-count variance, while multiplier `2` still does extra scan work that is often discarded. |
| CUDA nonce-seed batch | `256` auto | `2048` auto if `>=160` SMs and not memory-capped | Already handled by SM-tier auto sizing. |
| Scan launch width | `128` threads | Start with `128` threads | Same CUDA architecture class and same register-heavy kernel shape; benchmark `128` vs `256` on real hardware before changing. |
| CUDA memory percent | `25` default | `25` default | Batch `2048` fits comfortably on a 32 GiB-class card for the current shape. |

The main reason multiplier `1` is still expected to hold on larger GPUs is that
the batch-size scaling already gives the larger GPU more useful work per
window. At multiplier `1`, the expected number of prehash passes in the scan
window equals the requested batch size. The relative statistical shortfall
shrinks as the batch grows:

| Batch | Approximate relative shortfall at multiplier `1` |
| ---: | ---: |
| `256` | `~2.5%` |
| `512` | `~1.8%` |
| `1024` | `~1.2%` |
| `2048` | `~0.9%` |

So a 5090-class batch of `2048` should need less multiplier headroom, not more.
Multiplier `2` would double the scan window while the host still stops after
filling the digest batch, recreating the overscan pattern seen on the RTX 5060.

## Review Points

At the factor-64 benchmark point (`bits=0x1c04e984`), the measured multiplier-1
scan window for batch `256` was `218,587,904` nonces. Scaling only the batch to
`2048` gives an estimated scan window of:

```text
218,587,904 * (2048 / 256) = 1,748,703,232 nonces
```

That remains under the current 32-bit scan-count ceiling. At the same point,
multiplier `2` would estimate about `3.50B` scanned nonces, close to the
ceiling and still mostly extra scan work.

For a 5090-class `2048` batch, remeasure before changing defaults when either
of these becomes true:

- multiplier `1` scan windows approach the 32-bit scan-count ceiling
- observed pass batches are frequently underfilled even though `max_tries` is
  not capping the scan window

Using the factor-64 scan count above as a rough scale, the multiplier-1
32-bit-ceiling point for batch `2048` is around `157x` the 2026-06-26 base
difficulty used in these sweeps. Multiplier `2` would reach the same ceiling
around `79x`.

These are remeasurement triggers, not predicted crossover points. The RTX 5060
data did not show multiplier `2` becoming better. If very high difficulty makes
the scan window too large, the more likely next optimization is adaptive scan
continuation or wider scan-count plumbing, not a default return to multiplier
`2`.

## Validation

Build:

```bash
/usr/bin/time -p cmake --build build-cuda --target btx-matmul-solve-bench test_btx -j$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l)
```

Focused tests:

```bash
build-cuda/bin/test_btx --run_test=pow_tests/MatMulNonceSeed_cuda_prehash_scan_matches_cpu_gate
build-cuda/bin/test_btx --run_test=pow_tests/MatMulParentMtpSeed_cuda_prehash_scan_matches_cpu_gate
build-cuda/bin/test_btx --run_test=pow_tests/MatMulParentMtpSeed_cuda_solver_uses_gpu_scan_and_variable_base_batch
build-cuda/bin/test_btx --run_test=pow_tests/MatMulNonceSeed_cuda_batch_override_accepts_large_batch
build-cuda/bin/test_btx --run_test=matmul_accelerated_solver_tests/cuda_nonce_seed_v2_mainnet_boundary_variable_base_product_digest_matches_cpu
build-cuda/bin/test_btx --run_test=matmul_accelerated_solver_tests/cuda_strict_regtest_warning_repro_nonce_scan_matches_cpu_or_cleanly_falls_back
```

`git diff --check` passed.
