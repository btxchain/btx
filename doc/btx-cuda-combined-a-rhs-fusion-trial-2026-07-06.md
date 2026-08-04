# CUDA Combined A/RHS Fusion Trial

## Summary

This note documents a rejected CUDA product-digest fusion trial on
`research/matmul-combined-a-rhs-fusion`.

The trial tested whether the stream-A product-digest path could remove the
large global factored-RHS staging buffer by fusing A-row reconstruction and RHS
slab generation into one finalizer kernel. Two orientations were tested:

- `BTX_MATMUL_CUDA_COMBINED_A_RHS_FUSION=1`: j-major. One CTA builds a RHS
  slab for a j-pair and all i-pairs consume it.
- `BTX_MATMUL_CUDA_COMBINED_A_RHS_FUSION=2`: i-major. One CTA caches an A row
  block and builds a small RHS j-group slab.

Both variants were correctness-valid and dramatically reduced the per-slot CUDA
buffer-pool footprint. Neither variant was competitive with the current default
throughput path. The prototype code was removed from `src/cuda/matmul_accel.cu`
before this note was retained, so there is no compiled or runtime-activatable
combined A/RHS fusion path in this branch.

## Why It Regressed

The low result is not mainly because the code is new and unoptimized. Some
implementation tuning is possible, but the main loss is structural.

The current default stream-A path pays global memory to preserve both major
reuse properties:

- reconstruct each A row block once per survivor batch
- build the B-derived factored RHS once per survivor batch and reuse it across
  all row blocks

The combined kernels remove the large factored-RHS buffer, but each orientation
gives up one of those reuse properties:

- j-major keeps RHS slab reuse within a j-pair, but recomputes A work across
  every j-pair
- i-major caches an A row block, but repeats B/RHS reconstruction across row
  blocks

That trade lowers memory movement but adds enough duplicated seed-midstate,
oracle fallback, low-rank, and dot-product setup work that throughput falls
well below the staged RHS design.

## Reconstruction Notes

These notes are intentionally documentation-only. Recreate this prototype only
on a new experiment branch if explicitly instructed.

The prototype was implemented only in `src/cuda/matmul_accel.cu`, on top of the
stream-A rank-8 product-digest path. It did not change consensus code,
serialization, prepared-input generation, or CPU validation.

### Runtime Gate

Add a local helper next to `ShouldUseStreamARowPairWords()`:

```c++
uint32_t ResolveCombinedARhsProductDigestFusionMode(uint32_t n,
                                                    uint32_t b,
                                                    uint32_t r,
                                                    bool stream_a_words,
                                                    bool split_b_low_rank_rhs)
```

The helper reads `BTX_MATMUL_CUDA_COMBINED_A_RHS_FUSION` and returns:

- `0` when unset, unsupported, or not on the exact supported shape
- `1` for j-major fusion
- `2` for i-major fusion

The shape guard was strict:

- `stream_a_words == true`
- `split_b_low_rank_rhs == true`
- `n == 512`
- `b == 16`
- `r == 8`

### Shared Setup

In `FinalizeProductDigestsPackedPointerBatch`, after computing
`split_b_low_rank_rhs`, resolve the fusion mode before `slabbed_split_b_words`.
When the mode is non-zero:

- set `sample.mode` to the mode-specific historical string
- allocate `workspace.device_matrix_b` for only the split-B low-rank transform
- do not allocate or fill `workspace.device_factored_rhs`
- launch `BuildRhsLowRankRightTransformPackedPointersKernel<16, 512, 8>`
  into `workspace.device_matrix_b`
- launch one of the combined finalizer kernels below

The transform size is:

```text
blocks_per_axis = n / b
transform_elements = blocks_per_axis * b * r
total_transform_elements = batch_size * transform_elements
```

The transform pointer for a batch and j-word is:

```text
transform_batch + batch_index * transform_elements + j * b * r
```

### Mode 1, J-Major Kernel

Historical mode string: `product_digest_stream_a_combined_rhs_j_major`.

The prototype kernel was:

```c++
template <uint32_t BLOCK_SIZE, uint32_t MATRIX_N, uint32_t RANK, uint32_t SLAB_M>
__global__ __launch_bounds__(SLABBED_RHS_THREADS, 1)
void ComputeFactoredWordsStreamACombinedRhsSlabbedKernel(...)
```

Template constants used by the launch:

```text
BLOCK_SIZE = 16
MATRIX_N = 512
RANK = 8
SLAB_M = 128
threads = SLABBED_RHS_THREADS
grid = batch_size * ((MATRIX_N / BLOCK_SIZE) / 2)
```

The CTA layout was one block per `(batch_index, j_pair)`.

```text
blocks_per_axis = 32
j_pairs_per_request = 16
batch_index = blockIdx.x / j_pairs_per_request
j_pair = blockIdx.x % j_pairs_per_request
j0 = j_pair * 2
warp = threadIdx.x >> 5
lane = threadIdx.x & 31
i0 = warp * 2
```

The shared RHS slab was static:

```text
rhs_slab[2 * BLOCK_SIZE * SLAB_M]
```

For each `slab_base` in `0, 128, 256, 384`, threads `0..255` built the two
j-word RHS slabs. For each `(rel_j, local_m)`:

- load `noise_f_left[m * RANK + k]`
- for each compressed column `y`, derive B with
  `CandidateFromMidstateScalars(midstate_b, m * MATRIX_N + col)` and fall back
  to `FromOracle(seed_b, matrix_index)` when the candidate is outside the field
- accumulate the compressed base contribution for each local row `x`
- add the low-rank contribution
  `sum_k noise_f_left[m,k] * transform[j,x,k]`
- store `rhs_slab[(rel_j * BLOCK_SIZE + x) * SLAB_M + local_m]`

All warps then consumed that RHS slab. Each warp handled one i-row-pair:

```text
row0 = i0 * BLOCK_SIZE + x
row1 = row0 + BLOCK_SIZE
```

For each `x` and lane-strided `local_m`, it reconstructed A directly with:

```c++
PerturbedElementFromSeedMidstatePackedPointerRank8<MATRIX_N>(
    seed_a,
    midstate_a,
    packed_inputs,
    noise_e_left_offset_words,
    noise_e_right_offset_words,
    row,
    m,
    row * MATRIX_N + m)
```

It accumulated the four products for `(row0,row1) x (j0,j0+1)`, reduced with
`Reduce64`, folded the warp with `__shfl_down_sync`, and wrote:

```text
output[batch * words_per_request + i0 * blocks_per_axis + j0]
output[batch * words_per_request + i0 * blocks_per_axis + j0 + 1]
output[batch * words_per_request + (i0 + 1) * blocks_per_axis + j0]
output[batch * words_per_request + (i0 + 1) * blocks_per_axis + j0 + 1]
```

The structural problem is that A reconstruction repeats for every j-pair.

### Mode 2, I-Major Kernel

Historical mode string: `product_digest_stream_a_combined_rhs_i_major`.

The prototype kernel was:

```c++
template <uint32_t BLOCK_SIZE,
          uint32_t MATRIX_N,
          uint32_t RANK,
          uint32_t SLAB_M,
          uint32_t J_PAIR_GROUP>
__global__ __launch_bounds__(WORKSPACE_THREADS, 1)
void ComputeFactoredWordsStreamARowBlockCombinedRhsGroupKernel(...)
```

Template constants used by the launch:

```text
BLOCK_SIZE = 16
MATRIX_N = 512
RANK = 8
SLAB_M = 128
J_PAIR_GROUP = 2
threads = WORKSPACE_THREADS
```

The CTA layout was one block per `(batch_index, i_block, j_group)`:

```text
blocks_per_axis = 32
j_pairs_per_request = 16
j_groups_per_request = ceil(j_pairs_per_request / J_PAIR_GROUP) = 8
groups_per_batch = blocks_per_axis * j_groups_per_request
batch_index = blockIdx.x / groups_per_batch
local_group_index = blockIdx.x % groups_per_batch
i = local_group_index / j_groups_per_request
j_group = local_group_index % j_groups_per_request
j0 = j_group * J_PAIR_GROUP * 2
```

The kernel used static shared memory for one A row block:

```text
a_block[BLOCK_SIZE * MATRIX_N]
```

It used dynamic shared memory for the RHS slab:

```text
rhs_slab[J_PAIR_GROUP * 2 * BLOCK_SIZE * SLAB_M]
dynamic_rhs_slab_bytes = J_PAIR_GROUP * 2 * 16 * 128 * sizeof(Element)
```

The launch had to set:

```c++
cudaFuncSetAttribute(
    ComputeFactoredWordsStreamARowBlockCombinedRhsGroupKernel<16, 512, 8, 128, 2>,
    cudaFuncAttributeMaxDynamicSharedMemorySize,
    dynamic_rhs_slab_bytes)
```

The kernel first filled `a_block` for one 16-row block using
`PerturbedElementFromSeedMidstatePackedPointerRank8`. For each `slab_base`, it
then built a grouped RHS slab for four j-words (`J_PAIR_GROUP * 2`) using the
same B-midstate, oracle fallback, compressed base, and split-B low-rank formula
as mode 1.

Warps `0..3` were active output warps, one warp per j-word in the group. Each
active warp multiplied every local A row `x` against the corresponding RHS row,
lane-striding over `SLAB_M`, then reduced and wrote:

```text
output[batch * words_per_request + i * blocks_per_axis + j0 + warp]
```

The structural problem is that B/RHS reconstruction repeats for every i-row
block.

### Historical Finalizer Branch

The branch in `FinalizeProductDigestsPackedPointerBatch` was ordered before
`slabbed_split_b_words`:

```text
if combined mode:
  build split-B right transform into workspace.device_matrix_b
  if mode 2:
    set dynamic shared-memory attribute
    launch i-major grouped kernel
  else:
    launch j-major slabbed kernel
else if slabbed_split_b_words:
  existing slabbed path
else:
  existing default paths
```

No other source file was required.

## Benchmark Results

Benchmark environment:

- GPU: NVIDIA GeForce RTX 5060
- Shape: `n=512`, `b=16`, `r=8`
- Epsilon bits: `18`
- Backend: CUDA, `BTX_MATMUL_REQUIRE_BACKEND=cuda`,
  `BTX_MATMUL_CUDA_DEVICES=0`
- Product digest active
- Nonce-seed active: height `125000`
- Parent-MTP seed active: height `130500`
- Current-style block height: `142340`
- Current-style parent MTP: `1782494892`

Current mainnet-like difficulty, `nbits=0x1d01433a`:

| Case | Mean n/s | Median n/s | Pool slot bytes | CUDA fallbacks | Mean vs default |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default stream-A | `85.49M` | `85.65M` | `547,491,840` | `0` | baseline |
| Fusion mode 1, j-major | `13.13M` | `13.07M` | `10,620,928` | `0` | `-84.64%` |
| Fusion mode 2, i-major short probe | `5.22M` | `5.22M` | `10,620,928` | `0` | `-93.89%` |

The i-major current-difficulty row is a one-iteration, `20,000,000`-try probe.
A longer 3-iteration run was interrupted after it was already clearly too slow
for the retained benchmark set.

Factor-64 difficulty, `nbits=0x1c04e984`:

| Case | Mean n/s | Median n/s | Pool slot bytes | CUDA fallbacks | Mean vs default |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default stream-A | `728.76M` | `747.30M` | `273,745,920` | `0` | baseline |
| Fusion mode 1, j-major | `425.46M` | `430.13M` | `5,310,464` | `0` | `-41.62%` |
| Fusion mode 2, i-major | `245.21M` | `245.76M` | `5,310,464` | `0` | `-66.35%` |

## Commands

Current mainnet-like default:

```bash
BTX_MATMUL_REQUIRE_BACKEND=cuda \
BTX_MATMUL_CUDA_DEVICES=0 \
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
  --parent-mtp 1782494892
```

During the removed prototype trial, a fusion variant was selected by adding:

```bash
BTX_MATMUL_CUDA_COMBINED_A_RHS_FUSION=1
```

or:

```bash
BTX_MATMUL_CUDA_COMBINED_A_RHS_FUSION=2
```

Factor-64 runs used the same command shape with:

```bash
--iterations 10 --nbits 0x1c04e984
```

## Validation

Build:

```bash
cmake --build build-cuda -j$(nproc) --target btx-matmul-solve-bench test_btx
```

Focused CUDA parity tests run during the removed prototype trial:

```bash
BTX_MATMUL_CUDA_COMBINED_A_RHS_FUSION=1 \
BTX_MATMUL_REQUIRE_BACKEND=cuda \
BTX_MATMUL_CUDA_DEVICES=0 \
build-cuda/bin/test_btx \
  --run_test=matmul_accelerated_solver_tests \
  --catch_system_error=no \
  --log_level=test_suite

BTX_MATMUL_CUDA_COMBINED_A_RHS_FUSION=2 \
BTX_MATMUL_REQUIRE_BACKEND=cuda \
BTX_MATMUL_CUDA_DEVICES=0 \
build-cuda/bin/test_btx \
  --run_test=matmul_accelerated_solver_tests \
  --catch_system_error=no \
  --log_level=test_suite
```

Both focused test runs passed.

## Decision

Do not make either combined A/RHS fusion variant default.

The memory reduction was real, but the current staged-RHS stream-A path is
faster because it preserves both A reuse and RHS reuse. Do not carry this code
as a dormant env-gated path. A future low-memory fallback should be recreated
from the reconstruction notes on a new branch only if that is explicitly
requested. The next throughput-oriented direction should preserve both reuse
properties rather than trading one away inside a single CTA-local fusion.
