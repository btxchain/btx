Linux Release Build Variants
============================

BTX Linux releases publish separate x86_64 archives for CPU-only mining and
CUDA mining. The CUDA archives are prepackaged release builds: users do not need
to install the CUDA Toolkit on the target machine, but they do need a compatible
NVIDIA driver and a supported NVIDIA GPU.

## Release asset matrix

| Platform id | Archive suffix | Build flavor | CUDA runtime |
|---|---|---|---|
| `linux-x86_64` | `x86_64-linux-gnu` | CPU-only | None |
| `linux-x86_64-cuda12` | `x86_64-linux-gnu-cuda12` | CUDA 12 | CUDA 12.9.1 |
| `linux-x86_64-cuda13` | `x86_64-linux-gnu-cuda13` | CUDA 13 | CUDA 13.2.0 |

The CUDA runtime is statically linked into the CUDA archives when the toolkit
provides `CUDA::cudart_static`. Native CUDA tarballs should be built with
`-DBTX_CUDA_RUNTIME_LIBRARY=Static` (the experimental CUDA backend now
auto-selects Static when that target exists; Shared remains an explicit
override). That removes `libcudart.so.13` (and any `libcudart.so.*`) from the
loader path. The NVIDIA driver is still required (`libcuda.so.1`).

Guix CUDA builds already pass `-DCMAKE_CUDA_RUNTIME_LIBRARY=Static
-DBTX_CUDA_RUNTIME_LIBRARY=Static`. Packaged binaries should not have dynamic
`libcudart.so`, `libcuda.so`, or CUDA `RPATH`/`RUNPATH` entries from the
link step. `libcublasLt` remains a dynamic dependency of the experimental
MatMul CUDA backend and is **not** part of the NVIDIA driver. A CUDA
tarball that ships only `btxd` fails at launch with
`libcublasLt.so.13: cannot open shared object file`. Native CUDA
archives must run `scripts/release/bundle_cuda_runtime_libs.py` so
`libcublasLt` (and its CUDA-toolkit siblings) sit next to `btxd` with
`$ORIGIN` rpath. `python3 scripts/release/verify_release_btxd.py` then
executes `btxd -version` and requires exit 0; that is the gate that
catches a missing CUDA runtime.

The NVIDIA driver is still required on the target (`libcuda.so.1`). Do
not bundle `libcuda.so.*`.

All three Linux/macOS release flavors (CPU, CUDA, Metal) must configure
`-DWITH_ZMQ=ON`. After linking, `python3 scripts/release/verify_release_btxd.py`
must pass against the **real binary**: `build/bin/btxd` in a build tree, or
`libexec/btxd.real` in a published tarball (`ldd` shows `libzmq` on Linux;
macOS uses static `libzmq.a`). Since 0.34.1, packaged `bin/btxd` is a
`#!/bin/sh` wrapper — `ldd bin/btxd` / `otool -L bin/btxd` return nothing
and are not a verification. CMake must print
`ZeroMQ .............................. ON`. A `btxd` that still
contains `-zmqpubhashblock` strings without linking libzmq must not ship.

`cudaRuntimeGetVersion()` reports the statically linked CUDA runtime line, while
`cudaDriverGetVersion()` reports the installed NVIDIA driver API level. These
values can differ; for example, the CUDA 12 build can report runtime `12.9`
while the installed driver reports CUDA driver API `13.2`.

## Hardware support

| Build flavor | Supported hardware |
|---|---|
| CPU-only | x86_64 Linux hosts supported by the normal release build. No NVIDIA GPU or NVIDIA driver is required. |
| CUDA 12 | NVIDIA GPUs with compute capability 8.0 or newer, when the build contains a matching binary image or usable PTX. The Guix CUDA 12 build currently embeds `sm_80`, `sm_86`, `sm_89`, `sm_90`, `sm_100`, `sm_101`, `sm_103`, `sm_120`, and `sm_121`, plus PTX for `compute_80`, `compute_100`, and `compute_120`. Use this archive for Ampere, Ada, Hopper, and the currently targeted Blackwell families; this includes RTX 4090-class `sm_89` hardware. |
| CUDA 13 | NVIDIA GPUs covered by the CUDA 13 release target set in the Guix build. The Guix CUDA 13 build currently embeds `sm_100`, `sm_103`, `sm_110`, `sm_120`, and `sm_121`, plus PTX for `compute_100` and `compute_120`. This archive is intended for the targeted Blackwell-era GPUs. It does not include Ampere/Ada/Hopper images such as `sm_80`, `sm_86`, `sm_89`, or `sm_90`; use the CUDA 12 archive for those GPUs. |

The BTX CUDA runtime probe rejects devices below compute capability 8.0, but
the embedded CUDA image list is still the final build-time compatibility
boundary. If a GPU is visible but no kernel image is available for it, the CUDA
backend can fail when a mining kernel is launched even if basic device probing
succeeds.

Run these checks on the target host:

```bash
nvidia-smi -L
./bin/btx-matmul-backend-info --backend cuda
./bin/btx-matmul-solve-bench --backend cuda --iterations 1 --tries 256
```

The backend-info command confirms driver visibility and the selected device.
The solve benchmark is the stronger smoke test because it launches the CUDA
MatMul kernels from the archive.

## Driver support

| Build flavor | Required target-host driver |
|---|---|
| CPU-only | No NVIDIA driver required. |
| CUDA 12 | NVIDIA Linux x86_64 driver compatible with CUDA 12.x. NVIDIA documents the CUDA 12.x minor-compatibility floor as `>= 525.60.13`; the driver paired with CUDA 12.9 Update 1 is `>= 575.57.08`. Newer drivers are supported by CUDA driver backward compatibility. |
| CUDA 13 | NVIDIA Linux x86_64 driver compatible with CUDA 13.x. NVIDIA documents the CUDA 13.x minor-compatibility floor as `>= 580`; the driver paired with CUDA 13.2 GA is `>= 595.45.04`. If the release is later moved to CUDA 13.2 Update 1, the corresponding toolkit driver floor becomes `>= 595.58.03`. |

The CUDA archives do not package or install an NVIDIA driver. Driver selection
is outside the Guix build and release-asset process; operators must install a
driver that supports their GPU and the selected CUDA runtime line.

## Selecting an archive

Use the CPU archive when the host has no NVIDIA GPU, when the installed driver
cannot be upgraded, or when reproducible CPU-only operation is preferred.

Use the CUDA 12 archive for currently deployed Ampere/Ada/Hopper systems and
for any Blackwell systems that need CUDA 12.9 compatibility. This is the
expected archive for RTX 4090 testing.

Use the CUDA 13 archive for systems that have a CUDA 13-capable driver and one
of the CUDA 13 target architectures listed above.

The fast-start installer can select these platform ids explicitly:

```bash
python3 contrib/faststart/btx-agent-setup.py --platform linux-x86_64-cuda12 ...
python3 contrib/faststart/btx-agent-setup.py --platform linux-x86_64-cuda13 ...
```

## References

- NVIDIA CUDA 12.9 Update 1 release notes:
  <https://docs.nvidia.com/cuda/archive/12.9.1/cuda-toolkit-release-notes/index.html>
- NVIDIA CUDA 13.2 release notes:
  <https://docs.nvidia.com/cuda/archive/13.2.0/cuda-toolkit-release-notes/index.html>
- NVIDIA CUDA compatibility guide:
  <https://docs.nvidia.com/deploy/cuda-compatibility/minor-version-compatibility.html>
- NVIDIA CUDA 12.9 NVCC architecture documentation:
  <https://docs.nvidia.com/cuda/archive/12.9.1/cuda-compiler-driver-nvcc/index.html>
- NVIDIA CUDA 13.2 NVCC architecture documentation:
  <https://docs.nvidia.com/cuda/archive/13.2.0/cuda-compiler-driver-nvcc/index.html>
