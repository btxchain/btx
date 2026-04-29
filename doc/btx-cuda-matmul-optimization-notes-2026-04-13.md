# BTX CUDA MatMul Optimization Notes (2026-04-13)

This note records the CUDA MatMul optimization work that is now present on
`codex/cuda-linux`, what is enabled by default, and which experimental path was
intentionally left disabled after benchmarking.

It is a Linux CUDA implementation note, not a protocol or consensus document.

Update 2026-04-18:

- current accepted CUDA defaults and later keep/revert decisions are tracked in
  `doc/btx-cuda-matmul-optimization-followup-notes-2026-04-18.md`
- the statements in this note about device-prepared inputs staying non-default
  are no longer current for the post-`61000` product-digest CUDA mining path

## Scope

The current CUDA backend is functionally complete for Linux MatMul mining:

- CUDA runtime probing is real.
- `btxd` can mine regtest blocks with `BTX_MATMUL_BACKEND=cuda`.
- `btx-matmul-backend-info --backend cuda` reports runtime/device readiness.
- `btx-matmul-solve-bench` reports CUDA buffer-pool stats.

The optimization work below focuses on the backend implementation in:

- `src/cuda/oracle_accel.cu`
- `src/cuda/matmul_accel.cu`
- `src/matmul/accelerated_solver.cpp`

## Optimizations Now In Place

### 1. Stream-scoped CUDA submission

The CUDA digest and oracle paths now use nonblocking per-workspace CUDA streams
instead of broad `cudaDeviceSynchronize()` behavior.

This matters because:

- one CUDA submission no longer stalls unrelated CUDA work
- multiple pool slots can overlap useful work
- the solver can keep async prepare enabled without forcing global device stalls

### 2. Fused compressed-word finalize kernel

The digest path no longer materializes an intermediate contribution buffer for
compressed-word finalization.

The current implementation:

- fuses contribution accumulation and finalize work into one kernel
- removes one kernel launch from the hot path
- removes one full device global-memory write/read pass

### 3. Pinned host staging

The staged host/device transfer path now uses pinned host buffers for both:

- the host-returning CUDA oracle path
- the staged CUDA digest path

This keeps the current production path fast without requiring a larger solver
refactor. If pinned allocation fails, the code falls back to pageable host
memory instead of failing the solve path.

### 4. Shared CUDA digest buffer pool

CUDA now uses a shared slot pool similar to the Metal backend instead of
per-thread caches.

The pool currently supports:

- reusable base-matrix uploads
- reusable digest work buffers
- pool-slot wait/reuse accounting
- bench/backend-info observability

Relevant runtime knobs:

- `BTX_MATMUL_CUDA_POOL_SLOTS`

Relevant observability:

- `btx-matmul-backend-info --backend cuda`
- `btx-matmul-solve-bench --backend cuda`

### 5. Device-generated prepared inputs with ready-event handoff

CUDA can generate prepared noise/compression inputs on-device and hand them to
the digest path through a device handle.

The handoff now uses a ready event instead of synchronizing the prepare stream
before returning, which keeps the prepare side cheaper and preserves a correct
dependency edge into the digest stream.

This path remains available, but it is not the production default. See
"Current Production Default" below.

## Current Production Default

The current production-oriented CUDA default is:

- use the staged CUDA digest path
- keep pinned host staging enabled
- keep shared buffer-pool reuse enabled
- leave device-resident prepared-input mode disabled unless explicitly forced

The runtime switch for the experimental device-prepared path is:

- `BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS=1`

If that variable is unset, the solver uses the staged path even when CUDA is
selected.

This is intentional. The staged path is currently faster on the benchmarked
production-like shape than the device-prepared path.

## Why Device-Prepared Inputs Are Not Default

Two variants of "remove the extra device-to-device staging copies" were tested:

- direct per-buffer pointer indirection
- a reduced-overhead single-storage-pointer indirection path

Both variants were correct, but neither beat the staged path on the local CUDA
workstation.

Clean sequential benchmark comparison on `n=512`, `b=16`, `r=8`,
`solver_threads=2`, `parallel=2`, `pool_slots=2`:

- staged path, `BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS=0`
  - median `0.0052142205s`
- reduced-overhead no-copy path, `BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS=1`
  - median `0.005774869s`

That is still a regression of roughly 11% on median latency, so the no-copy
path was not kept as the default.

The most likely reason is that simple pointer indirection removes the D2D copy
cost, but gives back too much in:

- extra pointer-table setup
- less contiguous memory access
- weaker hot-kernel locality than the staged contiguous layout

## Bench Context

The optimization measurements cited in this note were taken on the Linux CUDA
development workstation used for this branch:

- GPU: NVIDIA GeForce RTX 5060
- CUDA toolkit: 13.2 (`/usr/local/cuda`, `nvcc release 13.2, V13.2.51`,
  current CUDA Toolkit documentation line as of April 2026)
- driver series: 595.xx

Representative current results on the staged default path:

- single solver (`solver_threads=1`, `parallel=1`)
  - median `0.0021317335s`
- two solver threads (`solver_threads=2`, `parallel=2`, `pool_slots=2`)
  - median `0.005398241s` on the branch validation run

These numbers are bench guidance, not protocol targets.

## Validation Performed

The optimization work described here was revalidated with:

- `build/bin/test_btx --run_test=matmul_backend_capabilities_tests,matmul_accelerated_solver_tests`
- `build/bin/test_btx --run_test=pow_tests`
- `build-btx/bin/test_btx --run_test=matmul_backend_capabilities_tests`

The broader CUDA mining path had already been validated earlier on this branch
through:

- full `ctest` on `build-btx`
- full `ctest` on `build`
- regtest daemon mining with `BTX_MATMUL_BACKEND=cuda`

## Recommended Operator Settings

For normal CUDA mining on Linux:

```bash
BTX_MATMUL_BACKEND=cuda ./build/bin/btxd -server=1
```

For benching with two CUDA pool slots:

```bash
BTX_MATMUL_CUDA_POOL_SLOTS=2 \
./build/bin/btx-matmul-solve-bench \
  --backend cuda \
  --solver-threads 2 \
  --parallel 2 \
  --pool-slots 2
```

Do not enable `BTX_MATMUL_CUDA_DEVICE_PREPARED_INPUTS=1` in production by
default at this stage. It remains an experimental knob for further development.

## Next Plausible Optimization Step

The next likely win is not "more pointer indirection." It is a larger storage
ownership refactor:

- generate directly into a digest-owned workspace slot, or
- otherwise unify prepare and digest storage so the digest path keeps contiguous
  memory access without paying for extra staging copies

That is a larger change than the staged-transfer optimizations already merged,
and it should clear a measurable performance bar before being kept.
