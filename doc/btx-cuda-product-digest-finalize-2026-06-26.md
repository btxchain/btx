# CUDA Product Digest Finalization

## Summary

This note documents a retained CUDA mining pipeline optimization for the
post-product-digest nonce-seeded path.

The previous CUDA variable-base digest path computed the compressed final block
words on the GPU, copied every compressed word back to the host, and finalized
the product-committed digest on the CPU. At the current mainnet shape
`n=512`, `b=16`, that copied `1024` field words, or `4096` bytes, per survivor.

This change adds a product-digest CUDA path for variable-base device-generated
inputs. CUDA still computes the same compressed final block words, but then
hashes those words and applies the product digest wrapper on-device. The host
receives only one `uint256` digest per survivor.

On the RTX 5060 benchmark host, the fixed current-difficulty comparison
improved by `+4.24%` mean and `+4.29%` median nonces/sec versus the previous
retained batched-input baseline. The factor-64 scan-heavy guardrail improved
by `+0.52%` mean and `+0.61%` median.

Raw benchmark records are under:

```text
../_audit/benchmarks/cuda-product-digest-finalize-2026-06-26/
```

## What Changed

`btx::cuda::ComputeProductDigestsLowRankVariableBaseDeviceBatch*` was added for
the product-committed CUDA mining path. The new API accepts the existing
variable-base matrix seeds, per-survivor sigmas, and device-generated input
handles, then returns final digests instead of compressed word vectors.

The CUDA implementation reuses the existing variable-base matrix build and
compressed final-word kernels. After final words are available in device
memory, a CUDA hash kernel computes:

```text
SHA256d(compressed_final_blocks(C'))
SHA256d("matmul-product-digest-v3" || sigma || hash || dim_le32 || b_le32)
```

`ComputeCudaVariableBaseDigestsPreparedBatch` now uses this direct digest path
when `DigestScheme::PRODUCT_COMMITTED` is active. Transcript mode still uses
the existing compressed-word result path.

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Driver: `595.58.03`
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Product digest active: height `61000`
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`

Baseline for this note: retained batched CUDA device input generation.

Fixed current-difficulty comparison:

| Case | Mean n/s | Median n/s | Mean vs baseline | Median vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Batched device input generation average | `55.89M` | `55.92M` | baseline | baseline |
| CUDA product digest finalization average | `58.26M` | `58.31M` | `+4.24%` | `+4.29%` |

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
| Batched device input generation | `607.24M` | `614.18M` | baseline | baseline |
| CUDA product digest finalization | `610.43M` | `617.96M` | `+0.52%` | `+0.61%` |

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

This optimization has no new operator setting. It reduces host copyback from
`4 * (n / b)^2` bytes per survivor to `32` bytes per survivor for the
product-committed variable-base CUDA path. At the current `512/16` shape, that
is `4096` bytes down to `32` bytes per survivor.

The benefit should generally scale to larger GPUs such as an RTX 5090. Faster
digest kernels make host copyback and CPU finalization a larger fraction of the
remaining survivor path, so keeping finalization on-device should remain useful.
The percentage gain may shrink if scan throughput dominates, and it may grow if
larger windows or higher survivor counts make host transfer more visible.

Review this area if transcript-mode mining becomes active again for CUDA, or if
future consensus shapes reduce `(n / b)^2` enough that the extra CUDA hash
kernel outweighs the saved copyback.

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
