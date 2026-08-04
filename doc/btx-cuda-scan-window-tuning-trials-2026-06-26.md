# CUDA Scan Window Tuning Trials

## Summary

This note documents two rejected CUDA nonce-seed tuning trials performed after
the paired variable-base generation optimization:

- changing the default nonce-seed digest batch/window size
- changing the CUDA prehash scan launch from 128 to 256 threads

Neither trial showed a reliable improvement on the RTX 5060 benchmark host, so
no default was changed.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-followup-batch-size-sweep-2026-06-26/
../_audit/benchmarks/cuda-scan-threads-256-trial-2026-06-26/
```

## Batch Size Sweep

The CUDA nonce-seed scan window uses:

```text
scan_count = batch_size * estimated_pre_hash_spacing * BTX_MATMUL_NONCE_SEED_SCAN_MULTIPLIER
```

The default batch size on the RTX 5060 host is `256` for the current
`n=512`, `b=16`, `r=8`, product-digest-active shape. Larger batch sizes reduce
the number of scan/digest submissions but increase the per-batch matrix and
input working set.

Fixed comparison shape:

- `n=512`, `b=16`, `r=8`
- bits: `0x1d01433a`
- epsilon bits: `18`
- block height: `142340`
- nonce-seed height: `125000`
- parent-MTP seed height: `130500`
- parent MTP: `1782494892`
- product digest height: `61000`

| Batch size | Mean n/s | Median n/s | Mean vs 256 |
| ---: | ---: | ---: | ---: |
| `128` | `54.03M` | `54.06M` | `-0.31%` |
| `256` | `54.20M` | `54.21M` | baseline |
| `512` | `54.18M` | `54.16M` | `-0.05%` |
| `1024` | `53.75M` | `53.63M` | `-0.83%` |

Result: keep the existing RTX 5060-class default of `256`.

## Scan Thread Trial

The CUDA prehash scanner currently launches `128` threads per block. A trial
changed `ORACLE_SCAN_THREADS` to `256`.

Fixed comparison result:

| Scan threads | Mean n/s | Median n/s | Mean vs 128-thread default |
| ---: | ---: | ---: | ---: |
| `128` | `54.20M` | `54.21M` | baseline |
| `256` | `54.05M` | `54.06M` | `-0.28%` |

Result: keep `ORACLE_SCAN_THREADS = 128`.

## Hardware Scaling Estimate

The rejected batch-size result is specific to this RTX 5060 host and current
shape. More capable GPUs such as a 5090-class card may tolerate or prefer a
larger batch size because they have more SMs and memory bandwidth, but the
existing code already scales CUDA nonce-seed batch size by SM tier and memory
cap. This sweep does not justify raising the RTX 5060-tier default.

The rejected 256-thread scan launch is less likely to become a 5090-specific
default because it changes per-block SHA occupancy and shared-midstate reuse
rather than increasing queue depth. Revisit only if a future CUDA compiler or
scan-kernel rewrite changes register pressure or occupancy.

## Validation

Both trials were built with:

```bash
cmake --build build-cuda --target btx-matmul-solve-bench test_btx -j$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l)
```

The 256-thread scan trial was reverted after benchmarking and is not retained.
