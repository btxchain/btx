# CUDA Deferred GPU Scan Prehash Confirmation

## Summary

This note documents a small retained optimization in the nonce-seeded CUDA
mining path.

After the GPU prehash scan returns compact pass offsets, the host previously
recomputed the prehash gate for every passed nonce before sending the batch to
the digest backend. This change trusts the GPU scan for batch construction and
moves the CPU prehash confirmation to the rare accepted-digest path. A CUDA
false positive can therefore waste a digest slot, but it still cannot be
returned as a solved block because the CPU prehash gate is checked before
acceptance.

On the RTX 5060 benchmark host, the fixed comparison shape improved by `+0.32%`
mean and `+0.32%` median nonces/sec over the paired-generation baseline. The
factor-64 scan-heavy guardrail was flat at `-0.05%` mean and `-0.01%` median.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-deferred-gpu-scan-prehash-confirm-2026-06-26/
```

## What Changed

In `BuildMatMulNonceSeededGpuPreHashBatchWindow`, GPU scan pass offsets now
only rebuild the nonce-specific seeds and header needed by the variable-base
digest batch. The per-offset host call to `CheckMatMulPreHashGate` was removed.

In `SolveMatMulNonceSeeded`, `evaluate_batched_digest_result` now calls
`CheckMatMulPreHashGate` after a digest meets the effective target and before
the digest is accepted.

This preserves the important safety property: a GPU scan false positive cannot
produce an accepted block candidate. The only behavior change for a false
positive is that it may be digested before being rejected.

Consensus validation is unchanged. Validators still run the normal prehash
gate and digest checks.

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

Baseline for this note: paired variable-base generation commit.

Fixed comparison shape:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Paired-generation baseline average | `54.17M` | `54.20M` | baseline | baseline |
| Deferred confirmation average | `54.35M` | `54.37M` | `+0.32%` | `+0.32%` |

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

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Paired-generation baseline | `603.93M` | `611.13M` | baseline | baseline |
| Deferred confirmation | `603.66M` | `611.08M` | `-0.05%` | `-0.01%` |

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

This optimization has no operator setting and does not require different
defaults for larger CUDA GPUs. It removes host-side SHA work proportional to
the number of GPU scan pass offsets. A 5090-class GPU should still benefit from
the same logic, but the percentage gain may be smaller if GPU digest work or
scan throughput becomes a larger share of total runtime.

Review this if the GPU prehash scanner becomes less trusted operationally, or
if a future solver path accepts CUDA digests without the CPU prehash check on
the accepted-digest path. The retained code depends on that final CPU check to
preserve acceptance safety.

## Validation

Build:

```bash
cmake --build build-cuda --target btx-matmul-solve-bench test_btx -j$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l)
```

Focused tests:

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
