# CUDA Prehash Midstate Setup

## Summary

This note documents a retained CUDA nonce-seed prehash scan optimization.

The CUDA prehash scanner needs two nonce-independent SHA-256 midstates for each
scan window: one for deterministic MatMul seed derivation and one for the block
header `sigma` prehash. Before this change, thread `0` in every CUDA block
rebuilt those midstates before scanning its nonce range. That kept the per-nonce
work much lower than the original implementation, but still left serialized
SHA-256 setup work in every scan block.

This change adds a tiny CUDA setup kernel that computes the two midstates once
per scan request into device memory. The scan kernel and survivor-record
hydration kernel copy those 16 words into shared memory instead of recomputing
SHA block 0 in each CUDA block.

On the RTX 5060 benchmark host, the fixed current-difficulty comparison
improved by `+1.27%` mean and `+1.18%` median nonces/sec versus the previous
retained survivor-record baseline. The factor-64 scan-heavy guardrail improved
by `+14.25%` mean and `+14.24%` median.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-prehash-midstate-setup-2026-06-26/
```

## What Changed

`ScanMatMulNonceSeedPreHashGPU` now allocates a one-entry device midstate
buffer in the CUDA oracle workspace.

Each scan request launches:

```text
BuildNonceSeedPreHashMidstatesKernel
ScanNonceSeedPreHashKernel
optional HydrateNonceSeedPreHashPassRecordsKernel
```

The setup kernel computes:

```text
seed block-0 midstate
header block-0 midstate
```

The main scan and hydration kernels then copy those precomputed words into
shared memory at the start of each CUDA block. This preserves the existing
per-block shared-memory shape while removing repeated SHA compression setup.

No public API or operator setting changed.

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Driver: `595.58.03`
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

Baseline for this note: retained CUDA survivor record hydration.

Fixed current-difficulty comparison:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Survivor record hydration aggregate | `58.50M` | `58.57M` | baseline | baseline |
| Prehash midstate setup average | `59.24M` | `59.26M` | `+1.27%` | `+1.18%` |

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
| Survivor record hydration | `609.76M` | `617.20M` | baseline | baseline |
| Prehash midstate setup average | `696.68M` | `705.09M` | `+14.25%` | `+14.24%` |

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

This optimization has no operator setting. It removes work that scaled with the
number of CUDA scan blocks and replaces it with one setup kernel per scan
request. That should continue to scale well on larger GPUs such as an RTX 5090.

The gain should be most visible when mining is scan-heavy: higher difficulty,
larger scan windows, or fewer survivors per scanned nonce. In that regime, the
scanner launches many CUDA blocks and digest work is a smaller share of total
time. The fixed current-difficulty path still improved, but less dramatically
because digest preparation and variable-base MatMul work remain a larger share
of runtime.

Review this area if future tuning creates very small scan windows. For tiny
scan windows, the extra setup-kernel launch could matter more. At the current
window sizing and current mainnet shape, the setup launch is more than paid
back by removing repeated per-block SHA setup.

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
