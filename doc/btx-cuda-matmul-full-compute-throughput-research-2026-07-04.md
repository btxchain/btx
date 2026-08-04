# CUDA MatMul Full-Compute Throughput Research

Branch: `research/matmul-full-compute-throughput`

Date: 2026-07-04

## Scope

This note tracks research for improving CUDA throughput after the nonce-seed
prehash gate. The target path is the expensive survivor path: nonces that pass
the prehash scan and must compute the product-committed MatMul digest before a
miner can compare against the effective target.

The live product-digest contract is unchanged:

```text
SHA256d("matmul-product-digest-v3" || sigma ||
        SHA256d(compressed_final_blocks(C')) || dim_le32 || b_le32)
```

For mining, "full compute" means exact computation of the compressed final
block image of `C' = A' * B'`. It does not require materializing the full `C'`
matrix for every survivor. Full `C'` materialization remains a winning-candidate
or validation concern.

## Current CUDA Survivor Path

For nonce-seed product-digest survivors, the current CUDA path is:

1. CUDA prehash scan returns compact survivor offsets and optional records
   containing `seed_a`, `seed_b`, and `sigma`.
2. Batched CUDA oracle input generation creates device-resident low-rank noise
   and compression vectors for each survivor.
3. `ComputeProductDigestsLowRankVariableBaseDeviceBatchOnDevice()` copies
   seeds/sigmas/pointers, precomputes A/B seed midstates, then launches
   `GeneratePerturbedMatrixPairFromSeedMidstatePackedPointersKernel`.
4. That kernel materializes full `A'` and `B'` matrices for every survivor in
   `workspace.device_matrix_a` and `workspace.device_matrix_b`.
5. `FinalizeProductDigestsPackedPointerBatch()` computes factored compressed
   final words:

   ```text
   D[j][x][m] = sum_y W[x,y] * B'[m,j*b+y]
   word(i,j) = sum_x sum_m A'[i*b+x,m] * D[j][x][m]
   ```

6. `ComputeProductDigestsKernel` hashes the 1024 compressed words per survivor
   and copies one 32-byte digest per survivor to the host.

At the current `n=512`, `b=16`, `r=8`, batch `512` shape, the full A/B matrix
buffers alone are:

```text
2 * 512 survivors * 512 * 512 elements * 4 bytes = 1,073,741,824 bytes
```

The generated input buffers, factored RHS, output words, and digest buffers are
much smaller. This makes full A/B materialization the main implementation target
for both memory footprint and global-memory traffic.

## Prior Paths To Avoid Repeating

These are already documented in `doc/` and/or `../_audit/benchmarks/`.

Rejected or reverted:

- Generic shared-memory tiled finalize rewrite: correct, but slower.
- Mainnet-shape `512/16/8` finalize specialization: clear regression.
- Memory-layout-first finalize rewrites, including transposed-B and A-broadcast
  variants: flat to worse, with aggressive variants clearly slower.
- Product-mode CUDA graph/fixed-launch path: flat to slightly worse on rerun.
- Local RTX 5060 queue-depth retunes: `batch_size=3`, pool slots `6`, solver
  threads `5`, and combinations did not improve local defaults.
- Post-shuffle kernel variants: `b=16` warp-broadcast finalize and low-rank
  build-kernel warp broadcast were flat to worse.
- Paired-midstate-only trial: noise-level result; only the paired midstate plus
  paired A/B generation unit was retained.
- `2x4` factored-word tile kernel: tiny fixed-shape gain, slight scan-heavy
  regression, reverted.
- Pinned product-digest copyback: copyback is only 32 bytes per survivor; pinned
  staging was slightly worse.
- Single-copy compact scan output: sharply regressed scan-heavy throughput.
- Scan multiplier `2`: high-tries sweep showed extra overscan without useful
  candidate work through the factor-64 guardrail.

Conditional retunes:

- Batch size and scan-thread retunes are kernel-shape dependent. A `256`-thread
  scan was rejected before prehash midstate setup, then retained after the scan
  kernel changed. Batch size `512` was retained after scan retuning. Revisit
  these only after the full-compute path changes enough to alter the balance.

Retained work that is already part of the baseline:

- Device-prepared product-digest path default.
- Device-prepared inputs consumed in place.
- Shuffle-tail reduction in fused finalize.
- Fused variable-base perturbation and paired A/B generation.
- Batched CUDA device input generation.
- On-device product digest finalization.
- Survivor record hydration.
- Prehash midstate setup.
- Direct seed/sigma copy cleanup.
- CUDA batch-size retune to `512` for the current RTX 5060-class post-scan
  default.

## Highest-Value Consensus-Neutral Candidates

### 1. Stream B directly into factored RHS

Prototype a replacement for `BuildFactoredRhsPackedPointersKernel` that does
not read `workspace.device_matrix_b`.

For each `(survivor, j, m)`, generate the `b` values:

```text
B'[m, j*b + y], y in 0..b-1
```

once into registers, then compute all `x` outputs:

```text
D[j][x][m] = sum_y W[x,y] * B'[m,j*b+y]
```

This preserves the existing reuse of each B element across all compression rows
`x`; the naive version that maps one thread to `(j,x,m)` would recompute each
B element `b` times and should be avoided.

Expected benefit:

- eliminates `device_matrix_b` allocation, full-batch B writes, and later B
  reads;
- keeps exact product-digest semantics;
- keeps the current factored `D`/word pipeline shape.

Main risk:

- register pressure from holding the B row block and multiple D accumulators;
- less parallelism if one thread does too much serial work per `(j,m)`.

Prototype result:

- implemented behind `BTX_MATMUL_CUDA_STREAM_B_RHS=0` as the disable switch;
  default behavior streams B for compatible product-digest shapes;
- adds a single-matrix seed-midstate perturbation kernel for A and a `b=16`
  streamed-B factored-RHS builder that writes the existing `[j][x][m]` RHS
  layout;
- leaves compressed-word paths unchanged.

Same-binary A/B benchmark on RTX 5060, stored in
`../_audit/benchmarks/cuda-full-compute-throughput-research-2026-07-04/raw/`:

| Shape | Off mean n/s | On mean n/s | Mean delta | Off median n/s | On median n/s | Median delta | Prepared | Digest requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Current | `107.11M` | `134.49M` | `+25.56%` | `108.26M` | `136.27M` | `+25.87%` | `7,960` | `16` |
| Fixed comparison | `59.40M` | `75.84M` | `+27.69%` | `59.48M` | `75.93M` | `+27.64%` | `15,298` | `31` |
| Factor64 | `763.09M` | `781.14M` | `+2.37%` | `768.23M` | `786.87M` | `+2.43%` | `360` | `1` |

The current and fixed-comparison shapes both exercise enough digest batches to
confirm this as a real survivor full-compute improvement. Factor64 remains a
small positive guardrail but is less diagnostic here because it only produced one
batched digest request in this run. GPU memory returned to `1740 MiB` after the
benchmark sequence.

### 1b. Split B-side low-rank algebra inside streamed RHS

Follow-up prototype: keep B streaming, but stop forming each perturbed B element
as `B_base + F_L * F_R` before compression. Instead precompute the small exact
right-side transform:

```text
T[j][x][k] = sum_y W[x,y] * F_R[k,j*b+y]
```

and build the factored RHS as:

```text
D[j][x][m] =
    sum_y W[x,y] * B_base[m,j*b+y]
  + sum_k F_L[m,k] * T[j][x][k]
```

This is byte-identical field algebra. It keeps the existing factored RHS layout
and word kernel, but replaces repeated `F_R` reads inside every `(j,m,y)` B
perturbation with a small per-survivor transform (`32 * 16 * 8` field elements
at the production shape).

Prototype result:

- retained as the default for compatible `512/16/8` product-digest CUDA mining
  shapes;
- disabled with `BTX_MATMUL_CUDA_SPLIT_B_LOWRANK_RHS=0`;
- uses the skipped `device_matrix_b` buffer as an 8 MiB scratch transform for a
  batch of 512 survivors, not as a full B matrix.

Same-binary A/B benchmark on RTX 5060, stored in
`../_audit/benchmarks/cuda-matmul-rethink-candidates-2026-07-04/raw/`:

| Shape | Off mean n/s | On mean n/s | Mean delta | Off median n/s | On median n/s | Median delta | Prepared | Digest requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Current | `134.44M` | `139.61M` | `+3.84%` | `136.29M` | `141.54M` | `+3.85%` | `7,960` | `16` |
| Fixed comparison | `75.89M` | `78.94M` | `+4.02%` | `76.14M` | `79.05M` | `+3.82%` | `15,298` | `31` |
| Factor64 | `783.50M` | `784.39M` | `+0.11%` | `788.66M` | `789.70M` | `+0.13%` | `360` | `1` |

No-env confirmation on the current shape produced `139.49M` mean and `141.48M`
median n/s, matching the enabled path. GPU memory returned to `1740 MiB` after
the benchmark sequence; a resident non-mining `btxd` process was using about
`1698 MiB` during these measurements.

### 1c. Slabbed RHS word finalizer

Follow-up prototype: keep the successful split-B transform, but stop
materializing the full factored RHS `D[j][x][m]` for the whole batch. Instead,
for each `(survivor, j-pair)` CUDA block:

- build a two-`j` RHS slab for `128` adjacent `m` values in shared memory;
- compute all `16` `i`-pair word tiles from that slab;
- advance to the next `m` slab and keep accumulating the same output words.

This keeps the exact product-digest algebra and preserves the current `2x2`
word reuse pattern, but replaces the full `device_factored_rhs` allocation with
a per-block shared-memory slab. The path is disabled by default and enabled with
`BTX_MATMUL_CUDA_SLAB_RHS_WORDS=1`.

Same-binary A/B benchmark on RTX 5060, stored in
`../_audit/benchmarks/cuda-slabbed-rhs-words-2026-07-04/raw/`:

| Shape | Off mean n/s | On mean n/s | Mean delta | Off median n/s | On median n/s | Median delta | Prepared | Digest requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Current | `139.47M` | `139.45M` | `-0.01%` | `141.47M` | `141.48M` | `+0.01%` | `7,960` | `16` |
| Fixed comparison | `79.42M` | `79.43M` | `+0.01%` | `79.86M` | `79.86M` | `+0.01%` | `15,273` | `31` |
| Factor64 | `787.87M` | `772.80M` | `-1.91%` | `793.34M` | `776.49M` | `-2.13%` | `360` | `1` |

Buffer-pool capacity check on the current shape:

| Mode | Device capacity | Max slot capacity |
| --- | ---: | ---: |
| Full RHS | `1,084,362,752` bytes | `1,084,362,752` bytes |
| Slabbed RHS | `547,491,840` bytes | `547,491,840` bytes |

Decision: retain as an opt-in memory-efficiency path, not as the default
throughput path. It removes about `512 MiB` of CUDA digest workspace capacity
for production-shape full batches and is throughput-neutral on the current and
fixed comparison shapes, but the one-digest-request factor64 guardrail regresses
about `2%`.

Rejected follow-up:

- a `256`-wide `m` slab used `32 KiB` shared memory and half as many slab
  barriers, but regressed current by `14.64%`, fixed comparison by `15.70%`,
  and factor64 by `2.07%`. It was removed.

### 1d. Rejected A-row slab word finalizer

Follow-up prototype: avoid materializing the full perturbed A matrix by
generating two adjacent A block rows into a shared-memory slab inside the word
finalizer. One CUDA block handled `(survivor, i-pair)`, generated a 128-wide
`m` slab of A for both rows, and reused that slab across all `j` pairs before
moving to the next `m` slab.

This preserved exact product-digest algebra and reduced full-batch workspace
capacity by about `512 MiB`, but the fused generation/finalize kernel lost too
much occupancy and scheduling efficiency.

Same-binary A/B benchmark on RTX 5060, stored in
`../_audit/benchmarks/cuda-slabbed-a-words-2026-07-04/raw/`:

| Shape | Off mean n/s | On mean n/s | Mean delta | Off median n/s | On median n/s | Median delta | Prepared | Digest requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Current | `139.45M` | `127.06M` | `-8.88%` | `141.49M` | `128.51M` | `-9.18%` | `7,960` | `16` |
| Fixed comparison | `79.68M` | `71.92M` | `-9.74%` | `80.24M` | `72.21M` | `-10.00%` | `15,273` | `31` |
| Factor64 | `784.51M` | `776.63M` | `-1.01%` | `789.50M` | `782.08M` | `-0.94%` | `360` | `1` |

Buffer-pool capacity check on the current shape:

| Mode | Device capacity | Max slot capacity |
| --- | ---: | ---: |
| Full A | `1,084,362,752` bytes | `1,084,362,752` bytes |
| Slabbed A | `547,491,840` bytes | `547,491,840` bytes |

Decision: rejected and removed. The memory reduction is real, but the current
and fixed comparison throughput regressions are too large to retain as a mining
path.

### 1e. Rejected shared-RHS word fusion prototypes

Two shared-memory RHS fusion variants were tested and rejected:

- **Single-j shared RHS word kernel**: builds one `D[j]` slice in shared memory
  and computes all `i` words for that `j`. It avoids global RHS traffic, but
  loses the current `2x2` word tile's A reuse across two adjacent `j` columns.
- **Paired-j shared RHS word kernel**: builds two adjacent `D[j]` slices in
  dynamic shared memory to preserve the `2x2` reuse. It avoids global RHS
  traffic, but the 64 KiB shared slab reduces occupancy enough to lose.

Results in
`../_audit/benchmarks/cuda-matmul-rethink-candidates-2026-07-04/raw/`:

| Prototype | Shape | Off mean n/s | On mean n/s | Mean delta | Off median n/s | On median n/s | Median delta |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Single-j shared RHS | Current | `134.32M` | `115.75M` | `-13.83%` | `136.29M` | `117.18M` | `-14.02%` |
| Single-j shared RHS | Fixed comparison | `76.04M` | `64.74M` | `-14.86%` | `76.22M` | `64.78M` | `-15.01%` |
| Paired-j shared RHS | Current | `134.30M` | `117.54M` | `-12.48%` | `136.26M` | `118.93M` | `-12.72%` |

Both prototypes were removed after benchmarking.

### 1f. Rejected 4x2 factored-word tile

Follow-up prototype: widen the factored word kernel from the retained `2x2`
warp tile to a `4x2` tile. Each warp computed four adjacent `i` block rows by
two adjacent `j` block columns, increasing reuse of the two RHS rows at the cost
of eight accumulators per lane instead of four.

The path preserved exact product-digest algebra and passed CUDA/CPU parity, but
the extra accumulator/register pressure offset the lower RHS traffic.

Same-binary A/B benchmark on RTX 5060, stored in
`../_audit/benchmarks/cuda-factored-words-4x2-2026-07-04/raw/`:

| Shape | Off mean n/s | On mean n/s | Mean delta | Off median n/s | On median n/s | Median delta | Prepared | Digest requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Current | `139.42M` | `139.17M` | `-0.18%` | `141.48M` | `140.92M` | `-0.39%` | `7,960` | `16` |
| Fixed comparison | `79.52M` | `79.12M` | `-0.51%` | `79.87M` | `79.52M` | `-0.44%` | `15,273` | `31` |
| Factor64 | `783.41M` | `781.45M` | `-0.25%` | `788.01M` | `784.62M` | `-0.43%` | `360` | `1` |

Decision: rejected and removed. The regression is small, but there is no memory
benefit and no throughput upside.

### 1g. Rejected vec2 A materialization

Follow-up prototype: keep full A materialization, but have each CUDA thread
generate two adjacent perturbed A elements instead of one. This reduced the
number of A-build threads and attempted to amortize per-thread overhead in the
materialization phase.

The path preserved exact product-digest algebra and passed CUDA/CPU parity, but
it reduced parallelism in a stage that is already throughput-sensitive.

Same-binary A/B benchmark on RTX 5060, stored in
`../_audit/benchmarks/cuda-vec2-a-build-2026-07-04/raw/`:

| Shape | Off mean n/s | On mean n/s | Mean delta | Off median n/s | On median n/s | Median delta | Prepared | Digest requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Current | `139.17M` | `128.64M` | `-7.57%` | `141.30M` | `129.97M` | `-8.01%` | `7,960` | `16` |
| Fixed comparison | `79.44M` | `72.64M` | `-8.56%` | `79.88M` | `72.97M` | `-8.66%` | `15,273` | `31` |
| Factor64 | `784.85M` | `778.20M` | `-0.85%` | `789.63M` | `783.29M` | `-0.80%` | `360` | `1` |

Decision: rejected and removed. The one-element-per-thread A materialization
remains better for the full-compute mining path.

### 1h. Rejected A-side low-rank split

An exact A-side version was also tested:

```text
word(i,j) =
    sum_x,m A_base[i*b+x,m] * D[j][x][m]
  + sum_x,k E_L[i*b+x,k] * (sum_m E_R[k,m] * D[j][x][m])
```

The prototype generated base A only, built an `E_R * D` transform, and added the
low-rank correction in an alternate word kernel. It passed CPU/CUDA parity, but
regressed the current shape because the extra projection and correction cost
more than skipping A perturbation.

Result in
`../_audit/benchmarks/cuda-matmul-rethink-candidates-2026-07-04/raw/`:

| Shape | Off mean n/s | On mean n/s | Mean delta | Off median n/s | On median n/s | Median delta | Prepared | Digest requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Current | `139.50M` | `136.74M` | `-1.98%` | `141.49M` | `138.46M` | `-2.15%` | `7,960` | `16` |

The A-side prototype was removed after benchmarking.

### 1i. Rethinks considered but not prototyped

- **Fuse word production directly into product-digest SHA**: rejected at design
  stage. The digest needs the 1024 compressed words in canonical order, while
  the current word stage gets its throughput from many independent warps/blocks.
  A fused one-block-per-survivor SHA path would serialize the dominant work; a
  multi-block path still needs an ordered word buffer or an additional
  synchronization stage.
- **Generate A on demand inside word tiles**: rejected at design stage. Each A
  row value is reused across many `j` tiles. Direct on-demand generation inside
  the current word tiles would rerun base-A SHA work per `j` tile; the tested
  A-side low-rank split was the exact algebraic way to avoid that recomputation,
  and it still regressed.

### 2. Stream or slab A into factored words

Eliminating `device_matrix_a` is harder because each A row value is reused
across many `j` tiles in `ComputeFactoredWordsKernel`. A naive on-the-fly A
lookup inside the current `2x2` word tile would recompute A for each `j` tile.

Possible prototypes:

- process a fixed `(survivor, i tile)` over several `j` tiles so generated A row
  values are reused before being discarded;
- generate A in row slabs, compute all needed word tiles for the slab, then
  discard the slab;
- keep A materialized for the first experiment while eliminating B, then retune
  once the impact is measured.

Expected benefit:

- removes the second large matrix buffer only if reuse is preserved;
- may improve memory footprint more than throughput if recomputation is high.

Main risk:

- this overlaps with already-rejected wider tile/finalize variants unless the
  new kernel avoids full A materialization rather than only widening output
  tiles.

### 3. Exact low-rank algebra path

Use the structure:

```text
A' = A_base + E_L * E_R
B' = B_base + F_L * F_R
```

inside the compressed final-block computation instead of first constructing
`A'` and `B'`.

For B-side RHS:

```text
D[j][x][m] =
    sum_y W[x,y] * B_base[m,j*b+y]
  + sum_k F_L[m,k] * (sum_y W[x,y] * F_R[k,j*b+y])
```

For A-side words:

```text
word(i,j) =
    sum_x,m A_base[i*b+x,m] * D[j][x][m]
  + sum_x,k E_L[i*b+x,k] * (sum_m E_R[k,m] * D[j][x][m])
```

This is exact field algebra, not a probabilistic shortcut.

Follow-up status:

- B-side RHS split was retained (see section 1b).
- A-side word split was rejected (see section 1d).
- A full low-rank rewrite that avoids both materialized A and factored RHS was
  not prototyped in this sweep; the retained/rejected halves show that the B
  side has exploitable reuse while the A side is balanced too closely against
  the existing word kernel.

Expected benefit:

- can avoid materializing low-rank perturbations into full matrices;
- may reduce global memory traffic and make the math more cacheable;
- exposes smaller intermediate transforms tied to `r=8`.

Main risk:

- base A/B oracle generation is still required;
- arithmetic count may be similar unless the implementation reuses base and
  low-rank transforms well;
- needs tight CPU/GPU parity tests because reassociation must stay exact in
  M31 arithmetic.

### 4. Add true CUDA event timings before judging small wins

Current profiling fields record host-side launch/copy submission timing, not
true kernel elapsed time. Before accepting or rejecting sub-5% candidates, add
CUDA event timings for at least:

- seed midstate precompute;
- perturbed matrix generation;
- streamed/factored RHS;
- factored words;
- product digest hash;
- D2H digest copy and stream sync.

This should be a measurement aid, not a behavior change.

### 5. Retune batch size after matrix materialization changes

Current batch-size evidence reflects the full-A/B-matrix path. If one or both
matrix buffers are removed, larger survivor batches may become faster because
the memory cap and global-memory pressure change. Re-run the existing fixed and
factor-64 benchmark shapes only after the computation path changes.

## Algorithm And Consensus-Changing Ideas

These are not drop-in CUDA optimizations.

- Changing the prehash gate or epsilon to reduce survivor count would change
  consensus mining economics and target distribution.
- Replacing product digest computation with a probabilistic verifier-style
  shortcut would change what miners are proving and needs a security proof.
- Changing the digest commitment, sigma derivation, or adding coinbase/header
  commitments reopens the circularity discussed in
  `doc/btx-matmul-product-digest-mining-fix-2026-04-03.md`.
- Any exact algorithm that computes the live compressed product image faster is
  consensus-compatible, but if it is asymptotically or materially cheaper than
  intended, it is also a PoW security finding and should be reviewed as such.

## Proposed Order

1. Add CUDA event timing or collect an Nsight trace for the current batch-512
   survivor path.
2. Prototype streamed-B factored RHS while keeping A materialized.
3. Benchmark against the existing fixed current-difficulty and factor-64 shapes.
4. If B streaming wins, prototype A streaming/slabbing or the explicit low-rank
   algebra path.
5. Only then retune survivor batch size and scan/window parameters.
