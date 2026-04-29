# MatMul External Miner Backend Tracking (Metal + CUDA Scaffold)

## Scope
Land full in-tree MatMul solve backend acceleration with:
- Metal/MLX full transcript-digest solve path enabled on supported Apple hosts.
- Node mining (`SolveMatMul`) and `btx-genesis` using shared backend-selected solve code.
- CUDA path present but disabled by default (code path + tests remain scaffolded).

## Why This Exists
This tracker started when node mining was CPU-only and Metal support was utility-scoped.
That gap is now closed for Metal full-digest solving while preserving deterministic
CPU parity and CPU fallback semantics.

## Constraints
- Keep consensus validation unchanged.
- Keep non-Apple and non-CUDA hosts green.
- Keep CUDA disabled by default until validated hardware/CI coverage exists.
- Preserve deterministic digest equivalence between accelerated and CPU paths.

## Execution Board
- [x] Create branch `codex/matmul-metal-cuda-external-miner`.
- [x] Write this tracking file in-repo.
- [x] Add backend capability module (`cpu`, `metal`, `cuda-disabled`) under `src/matmul/`.
- [x] Add build flags and compile-time guards (`BTX_ENABLE_METAL`, `BTX_ENABLE_CUDA_EXPERIMENTAL`).
- [x] Add utility binary for backend capability reporting (external miner integration point).
- [x] Add unit tests for backend capability and selection behavior.
- [x] Gate CUDA tests/code paths off by default; document opt-in path.
- [x] Run local build + targeted tests.
- [x] Commit first slice.
- [x] Implement next execution slice toward full external miner workflow.
- [x] Wire backend selection telemetry into miner/pool readiness artifact flow.
- [x] Add/extend unit tests for backend telemetry integration in readiness tooling.

## Delivered Backend Solve Slice
1. Added shared solver module: `src/matmul/accelerated_solver.{h,cpp}`.
2. Added full Metal digest backend: `src/metal/matmul_accel.{h,mm}` (+ non-Metal stub).
3. Wired `src/pow.cpp::SolveMatMul` to backend-selected digest solving.
4. Wired `src/btx-genesis.cpp` to shared backend-selected digest solving.
5. Added deterministic parity tests: `src/test/matmul_accelerated_solver_tests.cpp`.
6. Kept CUDA scaffold behavior explicit (`disabled_by_build` unless opt-in).

## Verification
- Build:
  - `cmake --build build-btx --target btx-genesis btx-matmul-backend-info test_btx -j8`
- Unit/CTests:
  - `build-btx/bin/test_btx --run_test=matmul_accelerated_solver_tests,matmul_backend_capabilities_tests --catch_system_error=no --log_level=test_suite`
  - `ctest --test-dir build-btx --output-on-failure -j8`
- Script regressions:
  - `bash test/util/m11_metal_mining_validation_test.sh`
  - `bash test/util/m5_verify_genesis_freeze_test.sh`
  - `python3 test/util/m7_miner_pool_e2e-test.py`
- Runtime probe:
  - `build-btx/bin/btx-matmul-backend-info --backend metal`

Observed on this host:
- `metal` compiled + runtime available, selected as active backend when requested.
- `cuda` remains compiled=false/available=false (`disabled_by_build`).
- Full-suite ctest and targeted BTX script gates pass.
