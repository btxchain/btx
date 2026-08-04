# CUDA MatMul Gating/MatMul Rethink Notes - 2026-07-06

Branch: `research/matmul-gating-radical-rethink`

Host GPU: NVIDIA GeForce RTX 5060, CUDA 13.2 runtime, driver 595.58.03.
An idle `btxd` process held about 1.2 GiB of device memory during these runs.

## Baselines

`main` was built from a clean release worktree at
`fcc201340d6acd680e76e095ce74410c4a9b5a26` into `./build-cuda-main`.
The comparison branch baseline was `4f340060c43d362f82c628453616833c94b5cc04`
before the exploratory edits in this branch.

All benchmarks used `n=512`, `b=16`, `r=8`, post-product-digest height
`61000`, nonce-seed height `125000`, and parent-MTP-seed height `130500`.

| Build/path | Difficulty case | Mean nonces/s | Median nonces/s | Batch | Max slot memory |
|---|---:|---:|---:|---:|---:|
| `main` / `build-cuda-main` | current mainnet-like, `nbits=0x1d01433a` | 44,210,770.884 | 44,775,641.316 | 256 | not reported on main |
| `main` / `build-cuda-main` | factor-64, `nbits=0x1c04e984` | 202,908,036.039 | 203,260,152.462 | 256 | not reported on main |
| current branch default | current mainnet-like | 78,569,787.121 | 79,027,313.835 | 512 | 1,084,362,752 bytes |
| current branch default | factor-64 | 732,017,158.694 | 743,049,798.312 | 512 | 1,084,362,752 bytes |

## Stream-A Prototype

The first-pass opt-in path was enabled with:

```bash
BTX_MATMUL_CUDA_STREAM_A_WORDS=1
```

The retained-A product-digest path materializes both the full perturbed A batch
and the factored RHS batch. The prototype skips the full A allocation and
reconstructs A row pairs in the word kernel from the seed midstate and
device-generated low-rank inputs. For the mainnet shape it uses a 64 KiB dynamic
shared-memory row-pair kernel and falls back to a 32 KiB row-block kernel if the
device rejects the shared-memory attribute.

| Path | Difficulty case | Mean nonces/s | Median nonces/s | Batch | Max slot memory |
|---|---:|---:|---:|---:|---:|
| stream-A row-pair | current mainnet-like | 68,892,167.553 | 68,964,813.253 | 512 | 547,491,840 bytes |
| stream-A row-pair | factor-64 | 718,849,951.954 | 728,215,035.832 | 512 | 547,491,840 bytes |
| stream-A row-pair, `--parallel 4` short probe | current mainnet-like | 69,201,060.267 | 69,726,399.702 | 512 | 2,189,967,360 bytes total |

Other explored variants:

| Path | Current mean nonces/s | Factor-64 mean nonces/s | Max slot memory | Result |
|---|---:|---:|---:|---|
| retained A + slabbed split-B RHS | 65,417,345.860 | 712,672,821.028 | 547,491,840 bytes | lower memory, slower than row-pair stream-A |
| stream-A row-block, one output per warp | 54,572,328.530 | 690,204,783.135 | 547,491,840 bytes | too much A/read recompute overhead |
| stream-A row-block, two adjacent outputs per warp | 67,960,788.636 | 717,653,943.553 | 547,491,840 bytes | close to row-pair, slightly slower |
| stream-A row-block, four adjacent outputs per warp | 67,267,285.587 | not retained | 547,491,840 bytes | register/scheduling pressure regressed |

## Follow-Up: Occupancy-Capped Row-Block

The row-pair kernel improved A reuse but carried about 170 registers/thread and
used 64 KiB dynamic shared memory, limiting occupancy. Retesting the 32 KiB
row-block kernel with `__launch_bounds__(WORKSPACE_THREADS, 3)` reduced its
resource profile to 80 registers/thread with a small stack frame. That changed
the result from a memory-only tradeoff into a faster default path.

Policy after this follow-up:

- stream-A is default-on for the compatible `512/16/8` product-digest CUDA path;
- `BTX_MATMUL_CUDA_STREAM_A_WORDS=0` disables it and returns to retained A;
- `BTX_MATMUL_CUDA_STREAM_A_ROW_PAIR=1` forces the older row-pair stream-A
  variant for comparison.

Same-binary benchmarks after the launch-bound retune:

| Path | Difficulty case | Mean nonces/s | Median nonces/s | Batch | Max slot memory |
|---|---:|---:|---:|---:|---:|
| retained A fallback, `BTX_MATMUL_CUDA_STREAM_A_WORDS=0` | current mainnet-like | 78,824,862.925 | 79,009,927.328 | 512 | 1,084,362,752 bytes |
| stream-A row-block default | current mainnet-like | 85,300,632.561 | 85,458,784.459 | 512 | 547,491,840 bytes |
| stream-A row-block default | factor-64 | 738,664,609.376 | 750,661,972.426 | 512 | 547,491,840 bytes |
| stream-A row-block, `--batch-size 768` | current mainnet-like | 85,316,917.097 | 85,602,471.741 | 768 | 821,237,760 bytes |
| stream-A row-block, `--batch-size 1024` | current mainnet-like | 85,567,970.583 | 85,722,262.930 | 1024 | 1,094,983,680 bytes |
| stream-A row-block, `--batch-size 1024` | factor-64 | 744,306,664.116 | 747,126,990.615 | 1024 | 810,544,560 bytes |

Batch `512` remains the default: larger batches were only marginally faster on
mean current-difficulty throughput and spent much more device memory. Batch
`1024` also lowered factor-64 median throughput versus the default run.

## Follow-Up: Fixed Rank-8 Stream-A Perturbation

The row-block stream-A kernel only dispatches for the production `512/16/8`
shape. Specializing its A reconstruction helper for `r=8` removes the generic
pending-counter reduction loop and emits the exact two four-product reduction
groups used by `REDUCE_INTERVAL=4`. The retained version keeps the same row-block
resource profile:

```text
ComputeFactoredWordsStreamARowBlockKernel<16,512,8>:
  REG:80 STACK:184 SHARED:33792
```

Benchmarks after retaining that helper:

| Path | Difficulty case | Mean nonces/s | Median nonces/s | Batch | Max slot memory |
|---|---:|---:|---:|---:|---:|
| stream-A row-block + rank-8 A helper | current mainnet-like, 5 iterations | 85,598,756.913 | 85,802,565.240 | 512 | 547,491,840 bytes |
| stream-A row-block + rank-8 A helper | current mainnet-like, 10 iterations | 85,727,614.514 | 85,893,090.921 | 512 | 547,491,840 bytes |
| stream-A row-block + rank-8 A helper | factor-64 | 740,505,798.230 | 751,386,418.039 | 512 | 547,491,840 bytes |

Compared with the prior default row-block measurements, this is a small
instruction-count win without changing the memory footprint or occupancy target.

Rejected follow-up candidates in this pass:

| Candidate | Current mean nonces/s | Factor-64 mean nonces/s | Result |
|---|---:|---:|---|
| row-block thread-count sweep, best `320`-thread run | 85,550,119.806 over 10 iterations | 738,383,335.782 | current-only noise-level gain; factor-64 neutral/slightly lower |
| A-left-factor shared overlay inside row-block | 85,378,932.588 | 736,911,407.750 | extra barriers outweighed fewer left-factor reads |
| row-wise warp-broadcast A-left factors | 83,913,738.102 | not run | reduced repeated reads but changed scheduling/locality badly |
| row-block `__launch_bounds__(WORKSPACE_THREADS, 2)` | 84,986,862.475 | not run | compiler moved to `REG:125 STACK:0`, losing the 3-block occupancy target |
| split-B RHS rank-8 low-rank dot specialization | 86,502,134.186 | 738,902,778.533, then 737,864,016.672 | current looked better, but repeated factor-64 guardrail was lower than A-helper-only |
| four-output row-block word tile under launch bounds | 84,839,929.991 | not run | more accumulators reduced scheduling efficiency |
| split-B RHS builder launch bound | 84,585,089.452 | not run | reduced registers but added stack and regressed throughput |
| fixed-shape perturbation helper without explicit rank-8 reduction groups | 85,392,095.681 | not run | resource profile unchanged and no clear throughput signal |

## Takeaways

The first-pass row-pair stream-A result looked like a memory-pressure escape
hatch. The occupancy-capped row-block result is stronger: on this RTX 5060 it
beats the retained-A fallback by about 8 percent at current mainnet-like
difficulty while cutting per-slot device memory almost exactly in half. The
fixed rank-8 A helper nudges that path slightly higher without changing its
resource profile. The factor-64 guardrail is also slightly positive on mean and
median throughput.

The profiling fields added to `btx-matmul-solve-bench` make future runs identify
the path via `cuda_profiling_stats.last_mode`, including
`product_digest_stream_a` for this prototype.
