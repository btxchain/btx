# CUDA / runtime GPU qualification

GPU runtime qualification is **not** a proof of model usefulness or safety.
`capabilities.cuda_qualification=true` means an **isolated worker** exists
(`QualifyFile` never `cudaSetDevice`). Default `-modelruntimecheck=0` is
still `NOT_RUN_CUDA_ISOLATION`. A live `GPU-01 RUNTIME_OBSERVED` is
`contrib/modelnet/cuda-isolated-e2e.sh`. The packaged bar is
`planning/acceptance-matrix.csv`.

## Policy

- Static qualification (`btx-modelcheck` / `QualifyFile`) never launches
  CUDA kernels. It reads SafeTensors/GGUF **headers** vs filesystem size.
- Pickle / `.pt` / Python / `.so` are rejected before any runtime.
- Default `-modelruntimecheck=0` returns `NOT_RUN_CUDA_ISOLATION` and does
  not load libcuda.
- When `-modelruntimecheck=1`, `QualifyRuntime` posix_spawns
  `BTX_CUDA_QUAL_WORKER` or PATH `cuda_qual_worker` with `--gpu=N` and
  optional `--allow-shared-gpu` from `BTX_ALLOW_SHARED_GPU`. `btxd` never
  `cudaSetDevice` for model qualification.
- Process proof: `CUDA_HOST=<cuda-workstation> contrib/modelnet/cuda-isolated-e2e.sh`.
  Do not set `BTX_LIVE_ATTESTOR=1`. Never SIGKILL production `btxd.real`.
- Shared validation GPUs remain B0-restricted: model qualification must
  not starve ExactReplay.

Do not treat a `STRUCTURE_VERIFIED` shard as “it runs on this GPU.”

Current evidence: the RTX workstation CUDA qualification worker compiles
successfully with `nvcc -c`, and the production validator remains the only
GPU process. Runtime kernel execution is intentionally still `NOT_RUN` until
a separate GPU or explicit operator authorization permits sharing the live
device.
