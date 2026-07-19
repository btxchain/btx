# MatMul v4 GPU Backends — Build & Hardware-Verification Runbook

**Status:** normative for mainnet activation. This runbook is the operational
form of the design spec's cross-vendor determinism requirements
(`doc/btx-matmul-v4-design-spec.md` §B.6 determinism argument, §S.1–§S.3
INT8-tensor-path eligibility, §N.3-v determinism risk register, Appendix C-3
cross-vendor test vectors). **No GPU backend may be flagged mining-capable —
and v4 must not activate on mainnet — until every backend intended to mine has
passed the checklist below on real hardware.**

---

## 1. The contract every backend must satisfy

The pure-integer CPU implementation (`matmul_v4::ComputeDigest`,
`src/matmul/pow_v4.h`) **is the consensus definition**. For every
`(header, n)` input, an accelerated backend must produce a `(digest, sketch
payload)` pair that is **byte-identical** to the CPU reference:

- same 32 digest bytes (`H(sigma || Chat)`, §E.1), and
- same `8·(n/8)²` sketch payload bytes (canonical little-endian F_q words,
  fixed serialization order).

This is achievable exactly because the v4 field is engineered for it (§B.6):
`s8×s8→s32` MMA is exact two's-complement arithmetic with no rounding, the
§B.4 bound guarantees no accumulator wrap, and integer addition is associative
— so IMMA, MFMA, Apple integer TensorOps, and AVX-512 VNNI all produce the
identical INT32 product regardless of tiling, warp mapping, or split-K.
**Any single differing bit is a consensus fork**: the backend would mine
digests the rest of the network rejects (or accept blocks it should reject).
There is no tolerance, no epsilon, no "close enough."

What can still go wrong — and what this runbook exists to catch — are
*library/toolchain* bugs (§N.3-v): saturating instead of wrapping arithmetic,
hidden quantization pre-passes, sparsity flags, FP-path fallbacks in a GEMM
library, wrong-order payload serialization.

### Eligibility (which silicon may mine at all — §S.1)

Admission is decided by `matmul_v4::backend::EligibilityFor` /
`ResolveBackend` (`src/matmul/backend_capabilities_v4.h`), which the v4
dispatch layer (`matmul/accel_v4.h`, `matmul_v4::accel::ResolveBackend`)
delegates to:

| Backend | Admissible silicon | Excluded (verification-only) |
|---|---|---|
| CPU | always (consensus reference) | — |
| CUDA | IMMA-capable, compute capability ≥ 7.5: Turing sm_75, Ampere sm_80/86, Ada sm_89, Hopper sm_90, Blackwell sm_10x/12x | Volta sm_70/72 (FP16-only tensor cores), all pre-tensor parts (Pascal, CMP 30HX/TU116-class) |
| HIP/ROCm | CDNA MFMA: gfx908 (MI100), gfx90a (MI200), gfx940/941/942 (MI300), gfx950 (MI350) | GCN/Vega (gfx900/906 — no matrix cores), RDNA gfx10xx/11xx/12xx (WMMA not qualified pending golden vectors) |
| Metal | Apple M5-class GPU Neural Accelerator with Metal 4 INT8 TensorOps (OS 26.4+) | Every pre-M5 GPU; the ANE (its "INT8" dequantizes to FP16 — no exact integer path) |

FP-anything (FP16/BF16/FP8, or any floating accumulate) is **never**
admissible — floating accumulation rounds per partial sum and is not
bit-reproducible (§B.1, §K.4).

Admissibility is necessary, not sufficient: per §N.3-v each backend must also
**pass the determinism harness on the physical device class it will mine on**
before being flagged mining-capable. Eligibility must be machine-checked, not
vendor-claimed (§S.3-6).

---

## 2. The determinism harness

`src/test/matmul_v4_backend_determinism_tests.cpp`
(suite `matmul_v4_backend_determinism_tests`) does, per run:

1. computes the CPU reference `(digest, payload)` for a fixed vector set
   (n = 256 and n = 512; the same header constants as the pinned golden-vector
   table in `matmul_v4_determinism_vectors.cpp`);
2. re-runs CPU and requires byte-identity, and round-trips every payload
   through the consensus verifier `matmul_v4::VerifySketch`;
3. for **each backend compiled into the binary**, runs the accelerated digest
   path (`matmul_v4::accel::ComputeDigestAccel`) over the same vectors and
   **hard-fails** (`BOOST_REQUIRE`, message prefixed `CONSENSUS SPLIT`) on any
   digest or payload byte difference;
4. emits a loud `BOOST_WARN` (`SKIPPED-PENDING-HARDWARE: ...`) for every GPU
   row that could not run — backend not compiled in, dispatch header absent,
   no admissible device — so a green CPU-only run can never be mistaken for
   hardware verification. Set `BTX_REQUIRE_GPU_GOLDEN=1` to turn those skips
   (and empty `kHardwareVectors` digest slots in
   `matmul_v4_determinism_vectors`) into hard failures for a certification
   lane — **never invent digests**; leave schema rows empty until silicon
   fills them;
5. additionally pins the pure eligibility classifiers (§1 table) so the
   admission rule itself is regression-tested on every platform, GPU or not.

Run it (any build):

```sh
build/bin/test_btx --run_test=matmul_v4_backend_determinism_tests \
  --log_level=warning
# or: ctest --test-dir build -R "^matmul_v4" --output-on-failure

# Silicon / release lane (fails if any GPU row would have been skipped):
BTX_REQUIRE_GPU_GOLDEN=1 build/bin/test_btx \
  --run_test=matmul_v4_backend_determinism_tests,matmul_v4_determinism_vectors \
  --log_level=warning
```

`--log_level=warning` (or lower) is required to see the
`SKIPPED-PENDING-HARDWARE` / `UNPINNED` warnings; do not certify a backend
from output that hides them.

### Multi-arch CPU containers (no GPU)

Use `contrib/docker/Dockerfile.tests` (Ubuntu 24.04). See header comments
there and `doc/btx-matmul-v4.4-multiarch-qemu-status.md` for amd64/arm64/riscv64
buildx + `matmul*` run commands.

**Pass criterion for a backend on a given device:** the suite is green **and**
the log contains
`v4 backend '<name>': N cross-backend vectors byte-identical to CPU reference`
— i.e. zero `SKIPPED-PENDING-HARDWARE` warnings for that backend. Record the
device, driver/library versions, and the log in the verification matrix (§7).

The GPU rows compile only when (a) the backend's own CMake define is set
(`BTX_ENABLE_CUDA_EXPERIMENTAL` / `BTX_ENABLE_METAL` / `BTX_ENABLE_HIP`,
forwarded to the harness by `src/test/CMakeLists.txt`) and (b) the v4 dispatch
header `src/matmul/accel_v4.h` is present in the tree. A CPU-only container
build therefore compiles and passes with three loud skip-warnings — that is
the expected CI state, not a certification.

---

## 3. CUDA backend (NVIDIA IMMA)

### Build

Requires the CUDA toolkit (`nvcc`) matching the host driver, and an explicit
SM architecture list. Include every architecture you will certify — the
harness must run on a binary built for the device's native arch (no PTX JIT
surprises).

```sh
# Repo root. Example arch list covers Turing/Ampere/Ada/Hopper/Blackwell:
cmake -B build-cuda \
  -DCMAKE_BUILD_TYPE=Release \
  -DBTX_ENABLE_CUDA_EXPERIMENTAL=ON \
  -DBTX_CUDA_ARCHITECTURES="75;80;86;89;90;100;120" \
  -DCMAKE_CUDA_COMPILER=/usr/local/cuda/bin/nvcc \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++

cmake --build build-cuda -j"$(nproc)" --target test_btx
```

Notes:
- `BTX_ENABLE_CUDA_EXPERIMENTAL=ON` **requires** `BTX_CUDA_ARCHITECTURES`
  (semicolon-separated); CMake errors out otherwise (`src/CMakeLists.txt`).
  Single-device certification runs may build just that arch (e.g. `"90"` for
  H100).
- `nvcc` major version must match the driver/runtime on the mining host (see
  `doc/btx-cuda-mining-troubleshooting.md` §4).
- The v4 kernel path must use integer tensor ops only: IMMA
  (`mma.sync.*.s32.s8.s8.s32` / cuBLASLt `CUBLASLT_COMPUTE_32I` /
  CUTLASS int8×int8→int32). Any FP path anywhere in the digest pipeline is a
  spec violation (§B.1) and will be caught as a byte mismatch.

### Verify on hardware

```sh
CUDA_VISIBLE_DEVICES=0 build-cuda/bin/test_btx \
  --run_test=matmul_v4_backend_determinism_tests --log_level=warning
```

Repeat per device class. **Required device matrix before mainnet** (§K.3,
§N.3-v; datacenter + consumer + oldest-admissible):

| Class | Device | Arch |
|---|---|---|
| Datacenter Hopper | H100 (and/or H200) | sm_90 |
| Datacenter Blackwell | B200 | sm_100 |
| Consumer Blackwell | RTX 5090 or 5080 | sm_120 |
| Consumer Ada/Ampere | RTX 4090 / 3090 | sm_89 / sm_86 |
| Oldest admissible (boundary) | any Turing IMMA card (e.g. RTX 2080 / CMP 50HX-class with IMMA exposed) | sm_75 |

Also confirm the negative boundary: on a Volta (sm_70) or pre-tensor host the
harness must log `inadmissible`/skip for CUDA, never run it —
`ResolveBackend("cuda")` must fall back to CPU with
`cuda_inadmissible_fallback_to_cpu:volta_fp16_tensor_only_inadmissible:sm_70`
(or `pre_tensor_no_int8_mma:*`).

---

## 4. Metal backend (Apple M5-class INT8 TensorOps)

### Build

Requires macOS 26.4+ (first OS exposing Metal 4 INT8 TensorOps), Xcode with
command-line tools (`xcrun`/`xcodebuild` supply the `metal` shader compiler),
and an M5-class machine to certify.

```sh
# On the Mac, repo root:
xcode-select --install            # once; provides xcrun + metal toolchain
cmake -B build-metal \
  -DCMAKE_BUILD_TYPE=Release \
  -DBTX_ENABLE_METAL=ON \
  -DBTX_MATMUL_METAL_PRECOMPILE_KERNELS=ON   # precompile .metallib via xcrun metal

cmake --build build-metal -j"$(sysctl -n hw.ncpu)" --target test_btx
```

Notes:
- `BTX_ENABLE_METAL` defaults ON for Apple builds; it is stated explicitly
  here because certification must record the exact configure line.
- If `xcrun` is unavailable the backend compiles kernels at runtime; for
  certification prefer the precompiled `.metallib` so the shader binary is
  pinned and archivable alongside the run log.
- The v4 kernel path must use Metal 4 TensorOps INT8 (s8×s8→s32) — the
  M5 GPU Neural Accelerator path — not MPS FP16/FP32 GEMM and not the ANE.

### Verify on hardware

```sh
build-metal/bin/test_btx \
  --run_test=matmul_v4_backend_determinism_tests --log_level=warning
```

**Required device matrix:** at least one of each — base M5, M5 Pro/Max — on
OS 26.4+. On any pre-M5 machine (M1–M4) the required result is the loud skip:
Metal classifies `no_integer_tensor_path_verification_only` and
`ResolveBackend("metal")` falls back to CPU. Pre-M5 passing as *admissible* is
itself a harness failure (§O.1: M4-class devices are verification-only).

---

## 5. HIP backend (AMD CDNA MFMA)

### Build

Requires ROCm (`hipcc`) on a CDNA host. The HIP backend is the newest of the
three; `BTX_ENABLE_HIP` gates it identically to the other backends and the
harness rows are already wired to it.

```sh
# Repo root, ROCm >= 6.x:
cmake -B build-hip \
  -DCMAKE_BUILD_TYPE=Release \
  -DBTX_ENABLE_HIP=ON \
  -DBTX_HIP_ARCHITECTURES="gfx908;gfx90a;gfx942;gfx950" \
  -DCMAKE_HIP_COMPILER=/opt/rocm/bin/hipcc \
  -DCMAKE_C_COMPILER=/opt/rocm/llvm/bin/clang \
  -DCMAKE_CXX_COMPILER=/opt/rocm/llvm/bin/clang++

cmake --build build-hip -j"$(nproc)" --target test_btx
```

Notes:
- Build only the gfx targets you will certify; ROCm feature suffixes
  (`:sramecc+:xnack-`) are handled by the eligibility classifier.
- **Production ExactGemm (v4.4 LT):** prefer hipBLASLt with
  `HIPBLAS_COMPUTE_32I` (s8×s8→s32); fall back to rocBLAS `gemm_ex`
  i8×i8→i32. `IsLtMfmaGemmAvailable()` is true only after bit-exact match vs
  `ExactGemmS8S8` on square + MatExpand panel shapes. Device scalar tiles are
  `IsLtDeviceAluGemmAvailable` only — never labeled MFMA.
- **Arch list:** `gfx942` (MI300) and `gfx950` (MI350) are the primary CDNA
  targets for PR #89; include older CDNA (`gfx90a` / `gfx908`) when certifying
  instruction-generation coverage. Example:
  `-DBTX_HIP_ARCHITECTURES="gfx942;gfx950"`.
- The v4 BMX4-C kernel path may also use MFMA integer intrinsics
  (`v_mfma_i32_16x16x32_i8`-family / `__builtin_amdgcn_mfma_i32_*`). No FP path,
  no XDLOPS-FP16 for ExactGemm.
- RDNA cards (gfx10xx/11xx/12xx) are **not** certifiable for mining even if
  the backend happens to run on them: the classifier reports
  `rdna_wmma_not_qualified_verification_only` and `ResolveBackend("hip")`
  falls back to CPU. Qualifying RDNA WMMA would require extending §S.1 plus a
  full golden-vector pass — a spec change, not a runbook change.
- When `BTX_ENABLE_HIP` is OFF, all HIP ExactGemm symbols fail closed (stub).

### Verify on hardware

```sh
HIP_VISIBLE_DEVICES=0 build-hip/bin/test_btx \
  --run_test=matmul_v4_backend_determinism_tests --log_level=warning
```

**Required device matrix:** MI300X (gfx942) plus at least one older CDNA part
(MI250/gfx90a or MI100/gfx908) to cover both MFMA instruction generations.

---

## 6. Full-dimension and golden-vector cross-checks (release gate)

The unit harness uses n = 256/512 for suite speed. Before mainnet activation,
additionally run on each certified device:

1. **Mainnet dimension:** the same harness comparison at n = 4096 (the §0.7
   production dimension) — exercise via the bench/QA lane or a temporary
   vector entry; the §B.4 bound (`4096·125² ≪ 2³¹`) holds, so any mismatch
   that appears only at large n indicates a tiling/split-K library bug, which
   is exactly the §N.3-v class of failure this gate exists for.
2. **Pinned golden vectors:** `matmul_v4_determinism_vectors` must be green
   with its TV table **pinned** (no `UNPINNED` warnings) and the hardware
   `(backend, driver, digest, payload_sha256)` tuples recorded in that file's
   hardware-vector table. The harness proves backend == CPU *on this machine*;
   the pinned vectors prove every machine agrees with the *committed* bytes.
3. **Cross-vendor sweep (Appendix C-3):** identical digest hex across all
   vendors' logs for the same vector set — NVIDIA (H100, B200, ≥1 consumer),
   AMD CDNA, Apple M5, and the CPU reference on x86-64 **and** arm64. Any
   two logs differing anywhere = activation blocker.

## 7. Verification matrix (gates mainnet — keep updated in review)

Record one row per (device, driver/OS, build) certification run. A backend is
mining-eligible only for device classes with a green row; v4 mainnet
activation requires green rows for every class marked *required*.

| Backend | Device | Required | Driver / OS / toolkit | Harness (n=256/512) | n=4096 | Golden vectors | Date | Log |
|---|---|---|---|---|---|---|---|---|
| CPU (x86-64) | reference | yes | — | pending | pending | pending (pin TVs) | — | — |
| CPU (arm64) | reference | yes | — | pending | pending | pending | — | — |
| CUDA | H100 (sm_90) | yes | — | pending | pending | pending | — | — |
| CUDA | B200 (sm_100) | yes | — | pending | pending | pending | — | — |
| CUDA | RTX 5090 (sm_120) | yes | — | pending | pending | pending | — | — |
| CUDA | RTX 4090 (sm_89) | yes | — | pending | pending | pending | — | — |
| CUDA | Turing sm_75 (boundary) | yes | — | pending | pending | pending | — | — |
| Metal | Apple M5 | yes | — | pending | pending | pending | — | — |
| Metal | Apple M5 Pro/Max | yes | — | pending | pending | pending | — | — |
| HIP | MI300X (gfx942) | yes | — | pending | pending | pending | — | — |
| HIP | MI250/MI100 (gfx90a/908) | yes | — | pending | pending | pending | — | — |

**Failure protocol:** any `CONSENSUS SPLIT` failure on any row is a
consensus-critical bug — file it against the backend, mark the backend
inadmissible for that device class (do **not** work around it by widening
tolerances; there are none), and re-run the full matrix for that backend after
the fix. The CPU reference is only changed by consensus spec revision, never
to match a GPU library.
