# BTX CUDA MatMul Mining Troubleshooting

This guide helps diagnose the case where a GPU that was previously mining via the
experimental CUDA MatMul backend silently stops engaging the GPU after a version
bump, and the node quietly continues solving on the CPU at a small fraction of
the throughput.

> **Status of the CUDA backend.** The CUDA MatMul backend is **experimental** and
> compiled **OFF by default** (`BTX_ENABLE_CUDA_EXPERIMENTAL=OFF` in
> `src/CMakeLists.txt`). When compiled in, it is selected **at runtime** via
> `BTX_MATMUL_BACKEND=cuda`. On **any** CUDA error — runtime unavailable, kernel
> load failure, unsupported device, shape mismatch, exception — the solver
> **silently falls back to CPU and keeps producing valid digests**. Mining never
> stops; it just gets ~20x slower with no hard error. The logging described below
> is the only way the fallback surfaces.

---

## 1. Symptom

Typical report (RTX 3080, `sm_86`, CUDA 13.x, WSL2 Ubuntu 24.04, i7-10700K),
after updating to a new node version:

- MatMul throughput collapses (e.g. ~1.3 MN/s -> ~67 KN/s).
- GPU utilization drops to a few percent (`nvidia-smi` shows ~3%).
- CPU is pinned (e.g. 400% — i.e. the CPU is now silently doing all the solving).
- Zero shares found over many minutes despite being fully synced to tip.

This pattern — high CPU, idle GPU, valid-but-slow mining — is the signature of a
**silent CUDA -> CPU fallback**, not a crash and not a consensus problem.

---

## 2. Confirm which backend is actually active

All evidence lives in `debug.log`. Two lines matter.

### 2a. The resolved-backend line (emitted once, at first solve)

```
grep "MatMul mining backend" debug.log
```

- Healthy GPU mining:

  ```
  MatMul mining backend: CUDA (requested=CUDA, requested_backend_available)
  ```

- Silent fallback (the case this doc is about):

  ```
  MatMul mining backend: CPU [WARNING: requested CUDA but it is unavailable -> <reason>]
  ```

  The `<reason>` is the verbatim probe reason and tells you exactly why. Common
  values:
  - `device_compute_capability_too_old:sm_XX` — the compute-capability gate
    rejected the card (see §4d).
  - `cuda_runtime_unavailable:<cudaError string>` — the CUDA runtime/driver could
    not be queried (driver/toolkit/WSL2 mismatch; see §4b/§4c).
  - `no_supported_device` — no visible device passed the gate.
  - `cuda_driver_probe_faulted` — the driver faulted inside the probe (e.g. a
    PTX JIT crash on an unsupported arch) and was caught by the backstop.

This line comes from `ResolveMiningBackendFromEnvironment()` in
`src/matmul/accelerated_solver.cpp`. The resolution logic is in
`backend::ResolveRequestedBackend()` /  `CapabilityFor(Kind::CUDA)` in
`src/matmul/backend_capabilities.cpp`.

### 2b. The per-error fallback warning

```
grep "MATMUL WARNING" debug.log
```

You will see one of:

```
MATMUL WARNING: CUDA backend fallback to CPU (<concrete error>)
MATMUL WARNING: CUDA backend still falling back to CPU (<N> total fallbacks; last reason: <error>)
```

The first is logged once; the second is re-logged at most every 5 minutes so a
node mining silently on CPU keeps reminding you. The `<error>` here is the
runtime CUDA error that triggered the fallback (e.g. a kernel-launch error string,
`cuda_digest_failed`, `cuda_backend_exception:...`, `cuda_prepared_inputs_shape_mismatch`).
These come from `RecordCudaFallback()` / `LogBackendFallbackOnce()` /
`LogBackendFallbackSustained()` in `src/matmul/accelerated_solver.cpp`; the last
reason is also retained in `g_last_cuda_fallback_error` and counted in
`g_cuda_fallbacks_to_cpu` (surfaced via the mining RPC backend stats).

### 2c. Utilization cross-check

- **GPU engaged:** `nvidia-smi` shows sustained high GPU utilization; CPU is
  modest; throughput is in the MN/s range.
- **Fallen back to CPU:** GPU near-idle (single-digit %), CPU pinned across cores,
  throughput in the tens of KN/s. If `debug.log` shows the WARNING lines above,
  this confirms it.

---

## 3. Why this commonly appears right after a version bump

A version bump replaces the binary. If the new binary was built with a **different
CUDA toolkit** or a **different architecture list** than the one you were running,
a card that worked before can start failing the runtime kernel load even though
nothing about your GPU or driver changed. The fallback is silent, so the only
visible change is the throughput/utilization collapse.

---

## 4. Most likely root causes of a silent CUDA -> CPU fallback

### 4a. Prebuilt binary / cubin built for an arch list that omits `sm_86`

The CUDA targets are compiled for exactly the architectures in
`BTX_CUDA_ARCHITECTURES` (wired to `CMAKE_CUDA_ARCHITECTURES` and the target's
`CUDA_ARCHITECTURES` property in `src/CMakeLists.txt`). If the build that shipped
in the new version did **not** include `86` (Ampere consumer / RTX 30-series),
the kernels for your card are absent. Depending on whether embedded PTX is present
and JIT-compilable, this surfaces at runtime as a kernel-load / launch error and
triggers the fallback. **This is the most likely cause for an `sm_86` card whose
gate clearly passes** (sm_86 >= sm_80). Fix: rebuild with `86` in the arch list
(§5).

### 4b. CUDA 12-built binary run against a CUDA 13 runtime (or vice versa)

The experimental build links the CUDA runtime (`CUDA::cudart` shared, or
`CUDA::cudart_static`, per `BTX_CUDA_RUNTIME_LIBRARY`). A binary built against one
major CUDA toolkit and then run against a mismatched driver/runtime can fail to
initialize or to load modules. This typically shows as
`cuda_runtime_unavailable:<cudaError string>` on the resolved-backend line, or a
CUDA error string in the MATMUL WARNING line. Fix: rebuild against the same CUDA
toolkit major version that matches your installed driver/runtime.

### 4c. WSL2 driver / `libcuda` mismatch

On WSL2 the CUDA driver (`libcuda.so` / `libnvidia-ptxjitcompiler`) is provided by
the Windows-side NVIDIA driver and surfaced into the WSL distro; the CUDA
**toolkit** is installed inside Ubuntu. After a Windows driver update or a distro
change these can drift out of step, producing `cuda_runtime_unavailable:...`,
`cuda_driver_probe_faulted`, or PTX-JIT failures. Note the node already forces
`CUDA_MODULE_LOADING=EAGER` during the probe to surface such incompatibilities as
ordinary error codes (and has a SIGSEGV/SIGILL backstop) rather than crashing —
see `ProbeCudaHardwareTopology()` / `CachedCudaHardwareTopology()` in
`src/cuda/cuda_context.cpp`. Fix: align the Windows NVIDIA driver and the in-WSL
CUDA toolkit, then rebuild if you changed the toolkit.

### 4d. The compute-capability gate rejecting an older card

The bundled kernels are validated for `sm_80+` (Ampere). The gate lives in
`src/cuda/cuda_context.cpp`:

```cpp
constexpr int DEFAULT_MIN_SUPPORTED_COMPUTE_CAPABILITY_MAJOR{8};   // sm_80+
```

A device with `major < 8` is marked unsupported with reason
`device_compute_capability_too_old:sm_XX`, and the backend reports
`no_supported_device`. **This does not apply to `sm_86`** — major version 8
passes the gate. If your resolved-backend reason is
`device_compute_capability_too_old` on an RTX 3080, that would contradict the gate
and should be investigated; for `sm_86` the failure is almost always 4a/4b/4c, not
the gate.

---

## 5. Rebuild from source with the correct architecture

The CUDA backend must be explicitly enabled and given an architecture list. For an
RTX 3080 (`sm_86`) include `86`; add other archs you also run (e.g. `80;86;89`).
The toolkit you build with should match the CUDA runtime/driver on the mining host.

```sh
# From the repo root, using clang for the host compiler:
cmake -B build \
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON \
  -DBTX_CUDA_ARCHITECTURES="86" \
  -DCMAKE_CUDA_COMPILER=/usr/local/cuda/bin/nvcc \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++

cmake --build build -j"$(nproc)"
```

Notes:
- `BTX_ENABLE_CUDA_EXPERIMENTAL=ON` **requires** `BTX_CUDA_ARCHITECTURES` to be set
  explicitly; CMake errors out otherwise (`src/CMakeLists.txt`). If you leave
  `BTX_CUDA_ARCHITECTURES` empty but have already set `CMAKE_CUDA_ARCHITECTURES`,
  the build adopts that value.
- Multiple archs are semicolon-separated, e.g.
  `-DBTX_CUDA_ARCHITECTURES="80;86;89"`.
- `nvcc` (the CUDA toolkit) must match the installed driver/runtime major version
  (see §4b/§4c). On WSL2 install the CUDA toolkit inside Ubuntu and keep the
  Windows NVIDIA driver current.
- Runtime linkage is controlled by `-DBTX_CUDA_RUNTIME_LIBRARY=Shared` (default) or
  `Static`.

After rebuilding, run with `BTX_MATMUL_BACKEND=cuda` and re-check the two log lines
in §2 to confirm `MatMul mining backend: CUDA (... requested_backend_available)`.

---

## 6. `BTX_CUDA_ALLOW_OLDER_GPUS` (opt-in; does NOT help an `sm_86` card)

`BTX_CUDA_ALLOW_OLDER_GPUS` lowers the compute-capability floor from `sm_80` to
`sm_60` (Pascal), per `src/cuda/cuda_context.cpp`:

```cpp
constexpr int OPT_IN_MIN_SUPPORTED_COMPUTE_CAPABILITY_MAJOR{6};   // sm_60+
```

- It is **opt-in**. Set `BTX_CUDA_ALLOW_OLDER_GPUS=1` (any value other than
  `0`/`false`/`no`/`off`) to enable; unset/`0` keeps the default `sm_80` floor.
- When set, the node logs a `MATMUL NOTE:` line announcing the lowered gate.
- It exists because a pool independently validated GPU-vs-CPU digest equivalence
  on Pascal (`sm_6x`). It only **lowers a gate**; you must still have kernels built
  for those archs (add e.g. `60` to `BTX_CUDA_ARCHITECTURES`) and validate digest
  equivalence for your own hardware.
- **It does NOT help an `sm_86` card.** `sm_86` already passes the default
  `sm_80` gate, so lowering the floor changes nothing for an RTX 3080. If an
  `sm_86` card is falling back, the cause is a kernel-load / runtime / arch-list
  problem (§4a–§4c), not the gate.

---

## 7. Pool / share mining note (`share_target_override`)

Pool operators who want a higher per-share hit rate can use the
`share_target_override` path on the MatMul solvers (`SolveMatMul` /
`SolveMatMulNonceSeeded` / `SolveMatMulParallel` in `src/pow.h` / `src/pow.cpp`).
A non-null override supplies an **easier (larger) share target** that is used
**only** for the digest early-exit comparison, so the solver returns nonces that
meet the share target. Consensus is unaffected: the **block-tier pre-hash gate**
(`CheckMatMulPreHashGate`) is still computed against the real block target derived
from `nBits` (`DeriveTarget`). The share target is purely a pool-side knob for
share frequency; ensuring share target >= block target is the pool's
responsibility. This is independent of the CUDA fallback issue above — it does not
affect which backend runs.

---

## 8. Quick diagnostic checklist / decision tree

1. **Is mining slow + GPU idle + CPU pinned?** -> suspect a silent CUDA->CPU
   fallback. Continue.
2. `grep "MatMul mining backend" debug.log`
   - `... CUDA (... requested_backend_available)` -> GPU is the intended backend;
     if it's still slow, check `grep "MATMUL WARNING"` for **runtime** fallbacks
     (per-digest errors after a successful resolve).
   - `CPU [WARNING: requested CUDA but it is unavailable -> <reason>]` -> read
     `<reason>`:
     - `device_compute_capability_too_old:sm_XX` ->
       - card is `< sm_80` and you accept it -> set `BTX_CUDA_ALLOW_OLDER_GPUS=1`
         **and** build kernels for that arch (§6).
       - card is `sm_86` (should pass) -> unexpected; investigate driver/probe.
     - `cuda_runtime_unavailable:...` / `cuda_driver_probe_faulted` -> driver /
       toolkit / WSL2 mismatch (§4b/§4c). Align driver+toolkit; rebuild if needed.
     - `no_supported_device` -> GPU not visible to CUDA (check `nvidia-smi`,
       `BTX_MATMUL_CUDA_DEVICES`, WSL2 GPU passthrough).
3. **Did this start right after a version bump, on an `sm_86` card whose gate
   passes?** -> most likely the new build omits `86` from the arch list or was
   built against a mismatched CUDA toolkit. Rebuild from source with
   `-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON -DBTX_CUDA_ARCHITECTURES="86"` against the
   matching toolkit (§5).
4. **Re-verify:** restart with `BTX_MATMUL_BACKEND=cuda`, then confirm
   `MatMul mining backend: CUDA (... requested_backend_available)` and that no
   new `MATMUL WARNING: CUDA backend ... fallback to CPU` lines appear, GPU
   utilization is high, and throughput is back in the MN/s range.
