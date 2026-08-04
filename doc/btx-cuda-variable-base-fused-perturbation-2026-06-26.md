# CUDA Variable-Base Fused Perturbation

## Summary

This note documents a CUDA MatMul follow-up optimization on top of the nonce-seed
scan changes from PR #278.

The retained change fuses variable-base matrix generation with low-rank
perturbation for CUDA nonce-seed product-digest batches. On the RTX 5060
benchmark host, the fixed PR #278 comparison shape improved from `52.45M` to
`53.77M` mean nonces/sec, a `+2.52%` gain, while sampled active board power fell
from about `102.36 W` to `100.16 W`.

This is a miner-performance change only. It does not change consensus, nonce
validity, MatMul seeds, low-rank noise derivation, product digests, the prehash
gate, or target checks.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-variable-base-fused-perturbation-2026-06-26/
```

## What Changed

The CUDA variable-base nonce-seed product path previously built each batch as:

1. Precompute A seed SHA midstate.
2. Generate the base A matrix.
3. Precompute B seed SHA midstate.
4. Generate the base B matrix.
5. Apply low-rank perturbation to A.
6. Apply low-rank perturbation to B.

The optimized path builds the perturbed matrices directly:

1. Precompute A seed SHA midstate.
2. Generate perturbed A from the A midstate and packed noise inputs.
3. Precompute B seed SHA midstate.
4. Generate perturbed B from the B midstate and packed noise inputs.

This removes two kernel launches and two full matrix read/write passes from the
variable-base device-input path. The shared-base path still uses the existing
shared base matrix plus perturbation kernels.

For the current `n=512`, `b=16`, `r=8`, batch `256` CUDA shape, this removes
about one GiB of matrix traffic per full variable-base digest batch:

```text
2 matrices * 256 batch entries * 512 * 512 elements * 4 bytes * read+write
= 1,073,741,824 bytes
```

The fused kernel does more work per matrix element, but it writes the final
field element once instead of writing the base matrix and then reading and
writing it again for perturbation.

## Kernel Resource Notes

`cuobjdump --dump-resource-usage` for the retained build reported:

| Kernel | Registers | Stack | Local | Shared |
| --- | ---: | ---: | ---: | ---: |
| `GeneratePerturbedMatrixFromSeedMidstatePackedPointersKernel` | `95` | `0` | `0` | `0` |

The register count is higher than a pure perturbation or pure base-generation
kernel would be, but the fused path avoids global-memory traffic and launch
overhead that dominate this stage at the current shape.

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

| Case | Mean n/s | Median n/s | Mean vs baseline | Active power | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| PR #278 fixed comparison baseline | `52.45M` | `52.47M` | - | `102.36 W` | Baseline |
| Fused variable-base perturbation, same fixed shape | `53.77M` | `53.78M` | `+2.52%` | `100.16 W` | Retained |
| PR #278 factor-64 scan-heavy baseline | `600.48M` | `607.48M` | - | `97.64 W` | Baseline |
| Fused variable-base perturbation, factor-64 scan-heavy | `603.15M` | `610.26M` | `+0.45%` | `95.96 W` | Neutral-positive |
| Fused variable-base perturbation, live tip `142449` / bits `1d010e95` | `63.07M` | `62.89M` | no direct baseline | `100.17 W` | Context |

The high-difficulty factor-64 run is expected to show a smaller percentage gain
because nonce scanning dominates that benchmark. The fixed comparison shape is
the better measurement for this candidate because it matches the final PR #278
mainnet-shape benchmark command.

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

Factor-64 guardrail command:

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

This optimization has no operator setting. It removes work from the CUDA
variable-base product-digest path, so it should remain favorable on larger GPUs.

The absolute matrix traffic removed scales with:

```text
batch_size * n * n
```

For the same `512x16x8` shape:

| CUDA nonce-seed batch | Approximate removed traffic per digest batch |
| ---: | ---: |
| `256` | `1.00 GiB` |
| `512` | `2.00 GiB` |
| `1024` | `4.00 GiB` |
| `2048` | `8.00 GiB` |

A 5090-class GPU is expected to use a larger auto-selected nonce-seed batch than
the RTX 5060, assuming memory does not cap it lower. That makes the absolute
traffic reduction larger. The percentage gain may still shrink at very high
difficulty when the scan kernel dominates total runtime, as shown by the
factor-64 guardrail.

The current estimate is:

| Hardware class | Expected setting change | Reason |
| --- | --- | --- |
| RTX 5060 | none | Measured positive at current shape. |
| 5090-class CUDA GPU | none | Batch sizing already scales separately; this change removes per-batch matrix traffic and does not require tuning. |

Review this optimization only if future shapes substantially increase `r` or if
resource usage from the fused kernel starts reducing occupancy enough to offset
the saved memory traffic. For the current `r=8` shape, the RTX 5060 data shows
the fusion is positive.

## Validation

Build:

```bash
/usr/bin/time -p cmake --build build-cuda --target btx-matmul-solve-bench test_btx -j$(lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l)
```

Focused tests passed:

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
