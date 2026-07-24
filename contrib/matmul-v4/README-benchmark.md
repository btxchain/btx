# BTX MatMul v4.6 ENC_RC — turnkey benchmark

`run-full-benchmark.py` is the **one** benchmark to run for current proof-of-work
performance. It measures the real ENC_RC episode (the workload a miner actually
runs) and is verbose by design: it describes the full workload, states which
kernel each component uses (optimized vs fallback) on your hardware, decides
resident-vs-streamed from your actual VRAM and explains why, and reports every
phase separately and combined.

## Run it

```sh
# fast sanity pass (toy shape, no GPU needed)
contrib/matmul-v4/run-full-benchmark.py --quick

# the real thing (production dims)
cmake --build build --target matmul-v4-rc-harness
contrib/matmul-v4/run-full-benchmark.py --shape production --json report.json
```

It auto-locates `matmul-v4-rc-harness` under `build*/`. Pass `--harness PATH` to
point at a specific binary. Even with no binary built, it still prints the
hardware analysis and the optimized/fallback backend map.

## What it tells you

- **Workload description** — the five phases of an episode, in execution order,
  and which are compute-dominant (FFN) vs hash-bound (XOF/attention).
- **Backend map** — per component (`Operand XOF`, `FFN int8 recompute`,
  `SV attention recompute`, GPU tensor path): `[OPTIMIZED]`, `[FALLBACK]`, or
  `[baseline]`. A `[FALLBACK]` is a performance gap **to fix on that hardware**,
  not a wrong result — every path is gated byte-exact to the int64 reference.
- **Memory regime** — for production it compares your free VRAM to the ~48 GiB
  resident working set. If VRAM is insufficient it **forces streamed and says
  so**, and notes that a ≥64 GiB card (e.g. B200) would run resident.
- **Native FP4 status** — whether the native MXFP4/FP8 tensor path is active, or
  declined by the byte-exact self-qual (with the reason), or not built in. A
  declined native path is reported loudly, never hidden behind INT8 numbers.
- **Numbers** — per-phase walls (separate) and the combined total; streamed vs
  resident wall ratio when both regimes ran.

## Why the old benchmarks were removed

The previous `btx-matmul-{cost,solve,metal}-bench` binaries and the
`src/bench/matmul_*` microbenchmarks measured superseded workloads (v3 solve,
v4.1 batched, v4.2/v4.4, BMX4, LT). They reported "MatMul PoW" numbers that no
longer reflect the shipping workload (ENC_RC v4.6), so `bench_btx -filter=MatMul*`
was actively misleading. They were deleted; this tool replaces them.

Nothing here changes consensus or activation — heights remain `INT32_MAX`.
