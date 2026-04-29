# BTX Metal Mining Tuning

This document describes the current Apple Metal mining defaults and the
supported tuning overrides for `btxd`, `btx-matmul-solve-bench`, and related
Metal benchmarking tools.

Unless you are benchmarking or debugging a specific host, the recommended
operator policy is simple:

- set `BTX_MATMUL_BACKEND=metal` if you want to force the Metal backend
- leave the rest of the Metal tuning variables unset
- let the node use the validated auto-tuned policy

Metal-dependent benchmarks must run on the host with GPU access. Do not use
results from restricted sandboxes or containers that cannot see the Metal
device.

## Recommended Default

Recommended daemon launch on Apple Silicon:

```bash
BTX_MATMUL_BACKEND=metal ./build-btx/bin/btxd -server=1
```

Recommended readiness check:

```bash
./build-btx/bin/btx-matmul-backend-info --backend metal
```

Recommended throughput benchmark for the current production product-digest
mining path:

```bash
./build-btx/bin/btx-matmul-solve-bench \
  --backend metal \
  --block-height 61000
```

`block_height=61000` is important for benchmarking because it exercises the
current production product-digest path rather than the older transcript-only
path.

## Current Auto Policy

The current Metal policy is intentionally narrow. It is designed around the
current production path, not every possible MatMul shape.

| Area | Current behavior |
|---|---|
| Backend request | If `BTX_MATMUL_BACKEND` is unset, Apple builds request `metal` by default. If Metal is unavailable, runtime falls back to CPU. |
| Parallel solve enable | Auto Metal fanout only enables for product-digest, mainnet-like shapes: `n >= 512`, `b >= 16`, `r >= 8`, with product digest active. |
| Solver threads | On Apple, high-tier hosts with `hw.perflevel0.logicalcpu >= 10` auto-resolve to `6`. Conservative 4-perf-core hosts auto-resolve to `1` to avoid recurrent Metal hang/recovery fallbacks. Other Apple hosts still use the perf-core split. |
| Prepare workers | `BTX_MATMUL_PREPARE_WORKERS` uses the same Apple perf-core split by default, then clamps to the selected solver-thread count when Metal fanout is active. High-tier Apple hosts now auto-resolve to `5`. |
| Metal pool slots | If `BTX_MATMUL_METAL_POOL_SLOTS` is unset and `BTX_MATMUL_SOLVER_THREADS` is explicitly set, pool slots mirror that value. Otherwise they follow the same Apple host-class policy as solver auto-tuning: `5` on high-tier hosts, `1` on conservative 4-perf-core hosts, and the perf-core split elsewhere. |
| Batch size | `BTX_MATMUL_SOLVE_BATCH_SIZE` auto-resolves to `2` on the current production Metal product-digest path when parallel solve support is active. Otherwise it stays at `1`. |
| Digest slice size | `BTX_MATMUL_DIGEST_SLICE_SIZE` stays at `1` for batch sizes `1` and `2`. It only widens automatically for larger forced batches. |
| GPU-generated inputs | `BTX_MATMUL_GPU_INPUTS` stays auto-off on Metal. |
| Async prepare | `BTX_MATMUL_PIPELINE_ASYNC` defaults to on for Metal. |
| Prefetch depth | `BTX_MATMUL_PREPARE_PREFETCH_DEPTH` auto-resolves to `1` on Metal. Deeper queues remain available as explicit benchmarking overrides. |
| CPU confirmation | Accelerated candidates are CPU-confirmed by default via `BTX_MATMUL_CPU_CONFIRM`. |

On the local Apple M4 Max Mac Studio reference host with
`hw.perflevel0.logicalcpu=10`, the validated auto policy now resolves to:

- `solver_threads=6`
- `prepare_workers=5`
- `pool_slots=5`
- `batch_size=2`
- `digest_slice_size=1`
- `prefetch_depth=1`
- `gpu_inputs=auto/off`

Measured on that host with `btx-matmul-solve-bench --backend metal --block-height 61000`:

- old conservative auto tuple (`4/4/4/2`, solver/pool/prepare/prefetch):
  about `95.5k` nonces/s mean before the April 20 code-level optimization pass
- same conservative tuple after the kernel reduction rewrite:
  about `142.1k` nonces/s mean
- new M4 Max auto policy:
  about `163.1k` nonces/s mean

So the current M4 Max auto policy is both materially faster than the old
conservative Apple heuristic and effectively identical to the explicit local
`6/5/5/1` tuned tuple on that host.

## Override Model

All Metal tuning overrides are process-level environment variables.

- Set them before launching `btxd`.
- Restart the process after changing them.
- Explicit values override the auto policy.
- If you pin `BTX_MATMUL_SOLVER_THREADS` above `1`, you should usually pin
  `BTX_MATMUL_METAL_POOL_SLOTS` to the same value.
- `btx-matmul-solve-bench` exposes matching one-shot CLI flags for the common
  tuning knobs, so you do not need to export environment variables just to run
  a benchmark.

Example: force the old single-solver baseline:

```bash
BTX_MATMUL_BACKEND=metal \
BTX_MATMUL_SOLVER_THREADS=1 \
BTX_MATMUL_METAL_POOL_SLOTS=1 \
BTX_MATMUL_SOLVE_BATCH_SIZE=1 \
./build-btx/bin/btxd -server=1
```

Example: explicitly pin the current validated M4 Max tuple:

```bash
BTX_MATMUL_BACKEND=metal \
BTX_MATMUL_SOLVER_THREADS=6 \
BTX_MATMUL_PREPARE_WORKERS=5 \
BTX_MATMUL_METAL_POOL_SLOTS=5 \
BTX_MATMUL_SOLVE_BATCH_SIZE=2 \
BTX_MATMUL_PREPARE_PREFETCH_DEPTH=1 \
./build-btx/bin/btxd -server=1
```

Equivalent benchmark command:

```bash
./build-btx/bin/btx-matmul-solve-bench \
  --backend metal \
  --block-height 61000 \
  --solver-threads 6 \
  --prepare-workers 5 \
  --pool-slots 5 \
  --batch-size 2 \
  --prefetch-depth 1
```

## Common Overrides

These are the overrides most operators and benchmark users should care about.

| Variable | Default / auto behavior | When to override | Example |
|---|---|---|---|
| `BTX_MATMUL_BACKEND` | Apple default request is `metal`; other hosts default to `cpu` | Force a specific backend or verify fallback behavior | `BTX_MATMUL_BACKEND=metal` |
| `BTX_MATMUL_SOLVER_THREADS` | Apple auto policy uses the host perf-core count | Pin solve fanout for controlled benchmarking or to cap CPU/GPU pressure | `BTX_MATMUL_SOLVER_THREADS=1` |
| `BTX_MATMUL_PREPARE_WORKERS` | Auto uses the Apple perf-core split, then clamps to solver threads when Metal fanout is active | Lower host CPU usage or benchmark a specific prepare/solve ratio | `BTX_MATMUL_PREPARE_WORKERS=2` |
| `BTX_MATMUL_METAL_POOL_SLOTS` | Auto mirrors explicit solver threads or uses the same perf-core split | Keep pool depth aligned with a manual solver-thread override | `BTX_MATMUL_METAL_POOL_SLOTS=5` |
| `BTX_MATMUL_SOLVE_BATCH_SIZE` | Auto is `2` on the current production Metal product path, otherwise `1` | Compare the current default against `1`, or force larger experimental windows | `BTX_MATMUL_SOLVE_BATCH_SIZE=1` |
| `BTX_MATMUL_DIGEST_SLICE_SIZE` | Auto is `1` for batch sizes `1-2` | Only for controlled batching experiments | `BTX_MATMUL_DIGEST_SLICE_SIZE=2` |
| `BTX_MATMUL_GPU_INPUTS` | Auto-off on Metal | Force GPU-generated inputs on or off for host-specific testing | `BTX_MATMUL_GPU_INPUTS=1` |
| `BTX_MATMUL_PIPELINE_ASYNC` | Auto-on on Metal | Disable only to isolate overlap/pipelining effects | `BTX_MATMUL_PIPELINE_ASYNC=0` |
| `BTX_MATMUL_PREPARE_PREFETCH_DEPTH` | Auto is `1` on Metal | Fine-tune overlap depth during benchmarking | `BTX_MATMUL_PREPARE_PREFETCH_DEPTH=1` |
| `BTX_MATMUL_CPU_CONFIRM` | Auto-on for accelerated backends | Keep enabled in normal operation; disable only for controlled experiments | `BTX_MATMUL_CPU_CONFIRM=0` |

## Advanced And Benchmark-Only Overrides

These exist, but they are not the normal production mining knobs.

| Variable | Scope | Notes |
|---|---|---|
| `BTX_MATMUL_METAL_FUNCTION_CONSTANTS=auto|0|1` | Metal kernel specialization policy | Relevant to Metal kernel microbenchmarks and transcript-path tuning. Not a normal product-mining tuning knob. |
| `BTX_MATMUL_METAL_PIPELINE=auto|legacy|fused` | Transcript-only Metal pipeline choice | Useful for transcript microbenchmarks and non-product paths. The current production mining path is product digest, not transcript digest. |
| `BTX_MATMUL_METAL_POOL_PREWARM=0|1` | Metal pool startup behavior | Defaults to on. Usually only touched for startup-latency experiments. |
| `BTX_MATMUL_DIAG_COMPARE_CPU_METAL=0|1` | CPU vs Metal digest comparison | Diagnostic only. Increases work. |

## Benchmark CLI Flags

`btx-matmul-solve-bench` accepts one-shot flag versions of the common tuning
overrides:

- `--backend`
- `--async`
- `--gpu-inputs`
- `--batch-size`
- `--digest-slice-size`
- `--prefetch-depth`
- `--prepare-workers`
- `--pool-slots`
- `--solver-threads`

Useful examples:

```bash
./build-btx/bin/btx-matmul-solve-bench \
  --backend metal \
  --block-height 61000

./build-btx/bin/btx-matmul-solve-bench \
  --backend metal \
  --block-height 61000 \
  --solver-threads 1 \
  --pool-slots 1 \
  --batch-size 1

./build-btx/bin/btx-matmul-solve-bench \
  --backend metal \
  --block-height 61000 \
  --solver-threads 3 \
  --prepare-workers 3 \
  --pool-slots 3 \
  --batch-size 2
```

For lower-level digest microbenchmarks, use `btx-matmul-metal-bench`. That tool
is useful for transcript-pipeline and function-constant experiments, but it is
not the primary end-to-end mining-throughput benchmark.

## Practical Guidance

- For production Apple Metal mining, prefer `BTX_MATMUL_BACKEND=metal` and
  otherwise leave the tuning variables unset.
- If you override `solver_threads`, usually override `pool_slots` to match.
- Treat `BTX_MATMUL_GPU_INPUTS=1` as experimental until it wins on your actual
  host.
- Treat `BTX_MATMUL_METAL_PIPELINE` and
  `BTX_MATMUL_METAL_FUNCTION_CONSTANTS` as transcript-path or microbenchmark
  knobs, not current product-mining defaults.

## Evaluated But Not Promoted

The current defaults already reflect one completed optimization round. Several
other paths were benchmarked and intentionally not promoted into production
defaults.

### GPU-Generated Inputs Stayed Auto-Off

On the current M4 reference host, after the landed fanout and pair-batching
changes:

| Configuration | Median throughput |
|---|---:|
| current default | `~44.42k` nonces/s |
| `BTX_MATMUL_GPU_INPUTS=1` | `~44.14k` nonces/s |
| `BTX_MATMUL_GPU_INPUTS=1 BTX_MATMUL_PREPARE_WORKERS=1` | `~44.70k` nonces/s |

Conclusion:

- forcing GPU-generated inputs was flat to slightly worse on this host
- the best forced variant was only about `+0.6%`, which was too small and noisy
  to justify changing the default
- `BTX_MATMUL_GPU_INPUTS` remains a host-specific experiment, not a production
  auto-on setting

### Product Function-Constant Policy Stayed On Auto

Current product-mining path benchmark on the same host:

| Configuration | Median throughput |
|---|---:|
| auto | `~44.14k` nonces/s |
| `BTX_MATMUL_METAL_FUNCTION_CONSTANTS=1` | `~44.45k` nonces/s |
| `BTX_MATMUL_METAL_FUNCTION_CONSTANTS=0` | `~36.00k` nonces/s |

Supporting product-digest microbenchmark:

| Configuration | Median latency |
|---|---:|
| auto | `~4814.5` us/digest |
| `BTX_MATMUL_METAL_FUNCTION_CONSTANTS=1` | `~4769.4` us/digest |
| `BTX_MATMUL_METAL_FUNCTION_CONSTANTS=0` | `~5063.0` us/digest |

Conclusion:

- forcing function constants off is clearly worse
- forcing them on is only marginally better than auto on this host
- the gain was not large or robust enough to replace the existing auto policy

### Transcript Pipeline Policy Was Left Alone

Transcript-only digest microbenchmarks with enough warmup converged to:

| Configuration | Median latency |
|---|---:|
| auto | `~2759.4` us/digest |
| `BTX_MATMUL_METAL_PIPELINE=legacy` | `~2751.5` us/digest |
| `BTX_MATMUL_METAL_PIPELINE=fused` | `~28096.3` us/digest |

Conclusion:

- `fused` is decisively wrong for the tested `n=512` transcript shape
- `auto` and `legacy` were effectively tied once warmup was sufficient
- there was no strong case to change the current transcript pipeline policy

### Correctness-Losing Or High-Risk Paths Remain Rejected

- `BTX_MATMUL_NONCE_PREFILTER`-style lossy screening is not a production
  mining optimization. Any returned nonce would still be checked with the real
  digest, but skipped nonces are never evaluated, so the search becomes
  non-exhaustive. That may be acceptable for tooling such as genesis search,
  but not for normal mining.
- FP16, tensor-style, or approximate arithmetic rewrites are not current
  candidates for the production MatMul path. The mining kernels operate on
  exact `uint32` finite-field arithmetic, so these paths would carry much
  higher correctness and stability risk than the measured policy-level gains.

## Possible Future Work: Apple Silicon Class Calibration

The current Metal defaults are still a heuristic host policy, not a true
processor-class calibration system.

Current state:

- the shipped fanout defaults are driven mainly by host capacity, especially
  `hw.perflevel0.logicalcpu`, plus shape gating for the current production
  Metal path
- this is enough to choose a safe default tuple on the current validated M4
  reference host
- it is not the same as saying "all M1", "all M2", "all M3", or "all M4"
  systems have been measured and assigned validated class-specific defaults

Possible future direction:

- treat Apple processor class only as a coarse starting bucket:
  - `M1`
  - `M2`
  - `M3`
  - `M4`
  - and, where distinguishable, tier variants such as `Pro`, `Max`, or
    `Ultra`
- add a short cached calibration pass keyed by:
  - `MTLDevice.name`
  - `hw.perflevel0.logicalcpu`
  - build/version
- search only a small bounded tuple set per host, for example:
  - `1/1/auto`
  - `2/2/2`
  - `3/3/3`
  - optional `4/4/4`
- cache the best measured tuple and reuse it for mining instead of retuning
  during live block solving
- keep explicit env overrides intact so operators can still force known-good
  values

Important distinction:

- the current policy says "this host has this many performance cores, so use
  the matching heuristic tuple"
- a calibration cache would say "this exact host/device/build combination was
  measured, and this tuple was best"

Validation note:

- this can be designed and implemented from a single M4 development host
- but processor-class-specific claims should not be made until at least one
  real host or trusted benchmark artifact exists for each target Apple Silicon
  class/tier
