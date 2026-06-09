# CUDA Nonce-Seed Mining Optimization Notes

Date: 2026-06-08

## Context

At `nMatMulNonceSeedHeight` the MatMul PoW solver switches from the legacy
shared-base matrix path to nonce-bound seed derivation. This is separate from
the shielded C-002 activation at height 123000.

The nonce-seeded PoW rule is consensus-correct, but it broke the performance
shape that CUDA mining depended on before the activation:

- Pre-activation mining can reuse one A/B matrix pair across a batch of nonce
  candidates.
- Post-activation mining derives `seed_a` and `seed_b` from the candidate
  nonce, so every passing nonce has its own A/B matrix pair.
- The initial post-activation implementation therefore fed CUDA one candidate
  at a time after CPU-side seed and matrix generation.

On the observed Linux CUDA miner, this left the GPU mostly idle while one CPU
core fed small digest submissions.

## Baseline Finding

Using `btx-matmul-solve-bench` with CUDA, mainnet-like 512x16x8 product-digest
shape, `--block-height 125000 --nonce-seed-height 125000`, and the live
mainnet compact target for height 125000 (`--nbits 0x1d0b8746`):

- Post-activation throughput was about 14.1k nonces/sec.
- GPU utilization was about 1%.
- CPU utilization was about one saturated core.

Pre-activation at height 124999, using the live mainnet compact target for that
height (`--nbits 0x1d0b5997`), was still healthy:

- Throughput was about 3.30M nonces/sec.
- GPU utilization averaged about 91%, with 100% peaks.
- CPU utilization was about 5.8 to 6.2 cores due to the existing parallel,
  shared-base pipeline.

## What Changed

The update keeps the activation gate and adds a CUDA-specific path for
post-`nMatMulNonceSeedHeight` mining:

1. CUDA pre-hash scan

   A CUDA scanner computes nonce-seeded `seed_a`, `seed_b`, header hash, and
   sigma for a nonce window. It returns only the candidates that pass the
   consensus pre-hash gate.

2. Target-aware scan sizing

   The scan window estimates the actual pre-hash gate spacing from
   `target << epsilon` instead of blindly using `batch_size * 2^epsilon`.
   This avoids overscanning when the block target is already far below
   `powLimit`.

3. Variable-base CUDA digest batch

   A new CUDA batch API accepts candidate-specific A/B seeds plus the existing
   device-generated noise/compression inputs. CUDA generates each candidate's
   base A/B matrices on device, applies the low-rank perturbations, and runs
   the existing compressed-word finalization in one batch.

4. Miner loop routing

   The post-activation CUDA miner now batches the CUDA-scanned candidates
   through the variable-base digest path. It no longer calls CPU
   `SharedFromSeed()` for every candidate before submitting tiny CUDA jobs.

5. Batch sizing

   The post-activation CUDA nonce-seed path has a separate default batch
   resolver. For the 512x16x8 product-digest shape, low and midrange CUDA
   GPUs start from the RTX 5060-tested default batch of 256. Larger devices
   scale from the first selected CUDA device's SM count, then clamp the auto
   batch to a conservative fraction of that device's reported global memory.

   The nonce-seed CUDA path is intentionally single-device for now. If
   `BTX_MATMUL_CUDA_DEVICES` lists more than one device, nonce-seed pre-hash
   scan, device input generation, and variable-base digest batching use the
   first selected visible CUDA ordinal.

   Operators can force an exact nonce-seed batch with:

   ```bash
   BTX_MATMUL_NONCE_SEED_BATCH_SIZE=128
   ```

   Values up to 4096 are accepted. The existing `BTX_MATMUL_SOLVE_BATCH_SIZE`
   override is still honored if the nonce-seed-specific override is unset.
   The auto memory budget can be adjusted with:

   ```bash
   BTX_MATMUL_CUDA_NONCE_SEED_MEMORY_PERCENT=25
   ```

   The memory percentage only caps the auto default. It does not override an
   explicit `BTX_MATMUL_NONCE_SEED_BATCH_SIZE`.

## Result

After the update, the same post-activation benchmark reached:

- About 2.47M nonces/sec.
- Average GPU utilization about 91.7%.
- Peak GPU utilization 100%.
- CPU utilization about one saturated core.

For comparison, the same run immediately before the activation boundary still
used the legacy path:

- About 3.30M nonces/sec.
- Average GPU utilization about 91.4%.
- Peak GPU utilization 100%.
- CPU utilization about 5.9 cores.

The post-activation path is still slower than the legacy shared-base path, but
it now keeps the GPU busy and is no longer bottlenecked by one-candidate CPU
matrix generation.

The activation-boundary comparison uses the live mainnet targets at the two
heights being compared:

```bash
# Pre nonce-seed activation.
BTX_MATMUL_CUDA_DEVICES=0 \
BTX_MATMUL_CUDA_NONCE_SEED_MEMORY_PERCENT=25 \
build-cuda-regtest/bin/btx-matmul-solve-bench \
  --backend cuda \
  --iterations 3 \
  --tries 4194304 \
  --n 512 --b 16 --r 8 \
  --nbits 0x1d0b5997 \
  --block-height 124999 \
  --nonce-seed-height 125000 \
  --product-digest-height 125000

# Post nonce-seed activation.
BTX_MATMUL_CUDA_DEVICES=0 \
BTX_MATMUL_CUDA_NONCE_SEED_MEMORY_PERCENT=25 \
build-cuda-regtest/bin/btx-matmul-solve-bench \
  --backend cuda \
  --iterations 3 \
  --tries 4194304 \
  --n 512 --b 16 --r 8 \
  --nbits 0x1d0b8746 \
  --block-height 125000 \
  --nonce-seed-height 125000 \
  --product-digest-height 125000
```

A rerun on the current CUDA branch with those inputs produced:

| Case | `nbits` | Mean nonces/sec | Median nonces/sec | GPU max |
|---|---:|---:|---:|---:|
| Height 124999, legacy shared-base path | `0x1d0b5997` | 3.15M | 3.33M | 98% |
| Height 125000, nonce-seed path | `0x1d0b8746` | 2.45M | 2.48M | 100% |

## Validation

Focused validation performed:

- `cmake --build build-cuda-regtest --target btx-matmul-solve-bench test_btx -j$(nproc)`
- `test_btx --run_test=matmul_accelerated_solver_tests/cuda*`
- `test_btx --run_test=pow_tests/MatMulNonceSeed*`
- `test_btx --run_test=pow_tests/e1_v2*`
- `git diff --check`

New direct coverage:

- CUDA nonce-seeded pre-hash scan matches the CPU consensus gate.
- CUDA variable-base device batch matches the CPU product digest.

## Notes

This optimization should remain gated by `nMatMulNonceSeedHeight`. It is not a
replacement for the pre-activation shared-base CUDA path, which remains faster
because it can reuse one base A/B matrix pair across the batch.

The current implementation still uses the CPU to build candidate headers,
verify the pre-hash gate after the CUDA scan, and evaluate final digest results.
The heavy per-candidate base matrix generation and digest batching are now on
CUDA, which was enough to restore high GPU utilization on the tested miner.

`btx-matmul-solve-bench` throughput is sensitive to `nbits`. The reported
`nonces/sec` includes pre-hash scanning plus digest work for the candidates that
pass the pre-hash gate, so different compact targets change how much expensive
digest work each nonce window produces. Do not compare absolute throughput
numbers across different `nbits` values without recording the target. For
example, the benchmark default `0x1e063c74` produces far more pre-hash pass
candidates than the live height-124999/125000 targets above and is therefore not
comparable to the activation-boundary figures.
