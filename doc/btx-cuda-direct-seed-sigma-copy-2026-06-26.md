# CUDA Direct Seed and Sigma Copy

## Summary

This note documents a retained CUDA variable-base request staging cleanup.

The CUDA variable-base digest path receives MatMul seeds and sigmas as
`uint256` arrays. Before this change, the host copied each `uint256` into a
temporary `DeviceSeedBytes` vector before issuing the CUDA host-to-device
copies. `uint256` is already a 32-byte trivially copyable byte blob, matching
the device seed layout, so the extra CPU staging vectors were redundant.

This change copies the `uint256` arrays directly to the existing device seed
and sigma buffers. Static assertions document and enforce the layout
assumption.

On the RTX 5060 benchmark host, throughput was effectively unchanged versus the
previous retained prehash-midstate baseline: fixed current difficulty moved
`+0.01%` mean / `-0.02%` median, and the factor-64 scan-heavy guardrail moved
`+0.01%` mean / `+0.04%` median. The change is retained because it removes
redundant host allocations and byte copies without a measured throughput cost.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-direct-seed-sigma-copy-2026-06-26/
```

## What Changed

The variable-base CUDA paths now copy directly from:

```text
request.matrix_a_seeds
request.matrix_b_seeds
request.sigmas
```

to the existing device buffers:

```text
workspace.device_seed_a
workspace.device_seed_b
workspace.device_sigma
```

The device kernels and device memory layout are unchanged. The compressed-word
variable-base path also skips the temporary seed staging vectors.

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Driver: `595.58.03`
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

Baseline for this note: retained CUDA prehash midstate setup.

Fixed current-difficulty comparison:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Prehash midstate setup average | `59.24M` | `59.26M` | baseline | baseline |
| Direct seed/sigma copy average | `59.25M` | `59.25M` | `+0.01%` | `-0.02%` |

Factor-64 scan-heavy guardrail:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Prehash midstate setup average | `696.68M` | `705.09M` | baseline | baseline |
| Direct seed/sigma copy average | `696.74M` | `705.36M` | `+0.01%` | `+0.04%` |

Commands used the same fixed and factor-64 shapes documented in
`doc/btx-cuda-prehash-midstate-setup-2026-06-26.md`.

## Hardware Scaling Estimate

This optimization has no operator setting. It removes host CPU staging work
that scales with survivor batch size, but the bytes are small compared with the
matrix and digest kernels. Larger GPUs such as an RTX 5090 should not need
different settings. If larger batches become common, the cleanup may save a
little more CPU time, but it should not be expected to materially change GPU
throughput by itself.

Review this area only if `uint256` layout changes or if the device seed format
changes. The static assertions are intended to fail the build before an unsafe
copy could be introduced.

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
