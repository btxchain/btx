# CUDA Batched Device Input Generation

## Summary

This note documents a retained CUDA mining pipeline optimization for the
nonce-seeded prehash path.

After the GPU prehash scanner returns surviving nonce headers, the miner
previously prepared CUDA oracle inputs one survivor at a time. Each survivor
submitted its own device input generation work: one noise kernel and one
compression-vector kernel. This change batches those survivors and prepares the
device-resident oracle inputs with one batched noise launch and one batched
compression-vector launch per survivor window.

The optimization keeps the existing digest path unchanged: each prepared item
still carries a `MatMulGeneratedInputsDevice` handle, and variable-base digest
evaluation consumes those handles as before. If batched CUDA input generation
fails, the solver falls back through the existing single-input preparation
path.

On the RTX 5060 benchmark host, the fixed current-difficulty comparison
improved by `+2.84%` mean and `+2.83%` median nonces/sec versus the previous
retained baseline. The factor-64 scan-heavy guardrail improved by `+0.59%`
mean and `+0.51%` median.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-batched-device-input-generation-2026-06-26/
```

## What Changed

`btx::cuda::GenerateMatMulInputsGPUDeviceBatch` accepts a batch of `sigma`
values with a shared `n`, `b`, and `r` shape. The CUDA workspace now keeps
device arrays for the per-survivor oracle seeds and output pointers.

The new batched kernels map a flat thread index across
`batch_size * words_per_input`, derive the survivor index and local word index,
and write directly into each survivor's existing device input buffers.

`matmul::accelerated::PrepareMatMulDigestInputsBatchForBackend` provides a
solver-level wrapper around the CUDA batch API. It preserves the existing
policy checks, runtime counters, and fallback behavior.

`SolveMatMulNonceSeeded` now uses the batch preparation helper for GPU prehash
survivor windows before submitting the variable-base digest batch.

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Driver: `595.58.03`
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

Baseline for this note: CUDA deferred GPU scan prehash confirmation.

Fixed current-difficulty comparison:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Deferred-confirmation baseline average | `54.35M` | `54.37M` | baseline | baseline |
| Batched device input generation average | `55.89M` | `55.92M` | `+2.84%` | `+2.83%` |

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
| Deferred-confirmation baseline | `603.66M` | `611.08M` | baseline | baseline |
| Batched device input generation | `607.24M` | `614.18M` | `+0.59%` | `+0.51%` |

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

This optimization has no new operator setting. It reduces per-survivor CUDA
kernel submissions from two tiny launches per survivor to two launches per
survivor window. That launch-count reduction should remain appropriate on more
capable GPUs such as an RTX 5090.

The percentage gain may differ on a 5090-class card. If digest kernels become
faster, fixed CPU/driver launch overhead can become a larger share of the
survivor path, making batching more valuable. If scan throughput dominates the
benchmark, the percentage gain can shrink. The existing survivor window size is
still the main scaling knob; this change automatically follows that window and
does not need a separate 5060-vs-5090 default.

Review this area if future 5090 measurements show survivor windows frequently
reaching the configured batch cap with digest kernels underfed. In that case,
the setting to revisit is the existing CUDA nonce-seed batch/window sizing, not
the batched device input generation itself.

## Validation

Build:

```bash
cmake --build build-cuda --target btx-matmul-solve-bench test_btx -j$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l)
cmake --build build-cuda --target test_btx -j$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l)
```

Focused tests:

```bash
build-cuda/bin/test_btx --run_test='matmul_accelerated_solver_tests/cuda_*'
build-cuda/bin/test_btx --run_test='pow_tests/*cuda*'
```

`git diff --check` passed.
