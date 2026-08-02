# BTX MatMul v4.7 — benchmark entry points

The MatMul v4.7 Epoch-A candidate is **Profile 1 with complete ExactReplay**.
The canonical transition and activation gates are documented in
`doc/btx-matmul-v4.7-transition-roadmap.md`. Profile 2 is reserved for the
later proof-authoritative Epoch D and is not an ExactReplay launch candidate.

`run-full-benchmark.py --shape production` now selects Profile 1 and is an alias
for `--shape profile1-production`. Historical Profile-2/proof research requires
the explicit `--shape profile2-production` spelling and must not be cited as
Epoch-A acceptance evidence.

## Run it

```sh
# fast sanity pass (toy shape, no GPU needed)
contrib/matmul-v4/run-full-benchmark.py --quick

# MatMul v4.7 Epoch-A Profile-1 full Metal campaign
cmake --build build --target matmul-v4-rc-harness
contrib/matmul-v4/run-full-benchmark.py --shape production --episodes 100 \
  --backend metal --json profile1-metal-100.json

# historical Profile-2/proof-development measurement
contrib/matmul-v4/run-full-benchmark.py --shape profile2-production \
  --backend cuda --json profile2.json
```

It auto-locates `matmul-v4-rc-harness` under `build*/`. Pass `--harness PATH` to
point at a specific binary. Even with no binary built, it still prints the
hardware analysis and the optimized/fallback backend map.

Production shapes require an explicit backend. This prevents `auto` from
silently starting a multi-hour serial-CPU campaign. Use `--backend cpu` for a
deliberate reference measurement, or `--allow-production-cpu-auto` when testing
automatic resolution itself. The wrapper exits nonzero for invocation errors,
timeouts, harness failures, malformed/incomplete reports, or a failed
self-qualification, and writes `--json` only after the report passes validation.

## What it tells you

- **Workload description** — the five phases of an episode, in execution order,
  and which are compute-dominant (FFN) vs hash-bound (XOF/attention).
- **Backend map** — per component (`Operand XOF`, `FFN int8 recompute`,
  `SV attention recompute`, GPU tensor path): `[OPTIMIZED]`, `[FALLBACK]`, or
  `[baseline]`. A `[FALLBACK]` is a performance gap **to fix on that hardware**,
  not a wrong result — every path is gated byte-exact to the int64 reference.
- **Memory regime** — for the historical Profile-2/coupled production shape it
  compares your free VRAM to the ~48 GiB
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
longer reflect either the historical ENC_RC v4.6 construction or the MatMul
v4.7 Epoch-A candidate, so `bench_btx -filter=MatMul*` was actively misleading.
They were deleted.

Nothing here changes consensus or activation. Optional shadow proofs,
sampled/Freivalds carriers, and local evidence cannot authorize blocks.
Mainnet Epoch A activates at height 181'894; every other public epoch height
remains disabled.
