# Metal Nonce-Seed Mining Optimization Notes

Date: 2026-06-08

## Context

At `nMatMulNonceSeedHeight` the MatMul PoW solver switches from the legacy
shared-base matrix path to nonce-bound seed derivation. This is separate from
the shielded C-002 activation at height 123000.

The nonce-seeded PoW rule is consensus-correct, but it changes the performance
shape that Metal mining used before activation:

- Pre-activation mining can reuse one A/B matrix pair across a batch of nonce
  candidates.
- Post-activation mining derives `seed_a` and `seed_b` from the candidate
  header, so every passing nonce has its own A/B matrix pair.
- The initial post-activation implementation therefore fed Metal one
  candidate at a time after CPU-side seed and matrix generation.

On Apple Silicon this left the GPU underfed in the same class of failure that
the CUDA follow-up fixed.

## What Changed

The update keeps the activation gate and adds a Metal-specific path for
post-`nMatMulNonceSeedHeight` mining:

1. Metal pre-hash scan

   A Metal scanner computes nonce-seeded header hashes and sigma gate results
   for a nonce window. It returns the candidates that pass the consensus
   pre-hash gate.

2. Variable-base Metal digest batch

   A new Metal batch API accepts candidate-specific A/B seeds. Metal generates
   each candidate's base A/B matrices on device, applies the low-rank
   perturbations, and runs the product-committed digest path for the batch.

3. Miner loop routing

   The post-activation Metal miner now batches Metal-scanned candidates through
   the variable-base digest path. It no longer relies on one CPU-prepared
   base-matrix instance per nonce candidate before submitting small Metal jobs.

4. GPU-core-scaled batch sizing

   Metal has a separate nonce-seed batch resolver because Apple GPU core counts
   vary widely across Mac mini, MacBook Pro, and Mac Studio models. The resolver
   reads the Metal GPU core count from IORegistry and scales the default batch
   size from that value.

   For the mainnet-like 512x16x8 product-digest shape:

   | Detected Metal GPU cores | Default nonce-seed batch |
   |---:|---:|
   | fewer than 10 | 32 |
   | 10-17 | 64 |
   | 18-29 | 128 |
   | 30-59 | 192 |
   | 60 or more | 256 |

   Operators can override the nonce-seed batch with:

   ```bash
   BTX_MATMUL_NONCE_SEED_BATCH_SIZE=64
   ```

   The existing `BTX_MATMUL_SOLVE_BATCH_SIZE` override is still honored if the
   nonce-seed-specific override is unset.

5. Device reporting

   `btx-matmul-backend-info --backend metal` and `btx-matmul-solve-bench` now
   report the detected Metal device name, GPU core count, and core-count source.
   A field/debug override is available for machines where IORegistry does not
   expose the expected property:

   ```bash
   BTX_MATMUL_METAL_GPU_CORES_OVERRIDE=20
   ```

## Benchmarks

Benchmarks were run on a Mac mini M4 with a 10-core Apple GPU. The runtime
probe reported:

```json
{
  "device_name": "Apple M4",
  "gpu_core_count": 10,
  "gpu_core_count_source": "io_registry_gpu_core_count"
}
```

The benchmark shape matched the live mainnet MatMul dimensions and hardened
pre-hash setting:

- `n=512`
- `b=16`
- `r=8`
- `epsilon_bits=18`
- `nbits=0x1e063c74`

`btx-matmul-solve-bench` has live-like defaults for the shape, `nbits`, and
epsilon value, but the activation-boundary comparison explicitly set the
heights:

```bash
# Pre nonce-seed activation.
./build/bin/btx-matmul-solve-bench \
  --backend metal \
  --block-height 124999 \
  --nonce-seed-height 125000

# Post nonce-seed activation.
./build/bin/btx-matmul-solve-bench \
  --backend metal \
  --block-height 125000 \
  --nonce-seed-height 125000
```

Post-activation, on the optimized nonce-seed Metal path:

| Requested batch | Selected batch | Median nonces/sec |
|---:|---:|---:|
| default | 64 | 2305 |
| 16 | 16 | 2316 |
| 32 | 32 | 2305 |
| 64 | 64 | 2287 |
| 128 | 128 | 2266 |

Metal fallbacks to CPU were zero in the sweep. On this 10-core M4, batches 16,
32, and 64 were effectively tied; the default of 64 keeps enough work queued
without materially hurting throughput.

For comparison, the pre-activation shared-base path with the same shape
measured:

| Requested batch | Selected batch | Median nonces/sec |
|---:|---:|---:|
| default | 2 | 2139 |
| 1 | 1 | 4687 |
| 16 | 16 | 3533 |
| 32 | 32 | 3546 |

The post-activation path is still slower than the legacy shared-base path
because base A/B matrices must be regenerated per nonce seed. The update closes
the GPU-underutilization issue by moving the expensive variable-base work into
Metal batches.

## Validation

Focused validation performed:

- `cmake --build build --target test_btx btx-matmul-backend-info btx-matmul-solve-bench -j2`
- `test_btx --run_test=matmul_metal_tests,pow_tests/MatMulNonceSeed*`
- `test_btx --run_test=pow_tests`
- `test_btx --run_test=matmul_accelerated_solver_tests`
- `git diff --check`

New direct coverage:

- Metal nonce-seeded pre-hash scan matches the CPU consensus gate.
- Metal variable-base device batch matches the CPU product digest.
- The post-activation Metal solver uses the GPU scan and variable-base batch
  path.
- Metal nonce-seed batch defaults scale from GPU core-count tiers.

## Notes

This optimization remains gated by `nMatMulNonceSeedHeight`. It is not a
replacement for the pre-activation shared-base Metal path, which remains faster
because it can reuse one base A/B matrix pair across the batch.

The current implementation still uses the CPU to build candidate headers,
verify final digest results, and maintain the mining loop. The heavy
per-candidate base matrix generation and digest batching are now on Metal.
