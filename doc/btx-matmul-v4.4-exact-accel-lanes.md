# MatMul v4.4 — Exact Accelerator Lanes (miner-local)

Status: **software-complete on `feat/bmx4c-exact-accel-lanes`** (portable exact MXFP4 + device hot paths; CUTLASS/FP8/AMD-native remain hardware-gated swaps). Branched from PR #89 (`claude/matmul-v4-design-spec-af23sj`). Mainnet activation remains **inert** (`INT32_MAX` / `ratification = false`). Floating lanes are **not** separate consensus activations.

## Thesis

Consensus sees only canonical integer sketch bytes. The optimal design is **one canonical integer workload** served by several **provably exact** accelerator lanes (CPU/SIMD, INT8, MXFP4, FP8). FP4/FP8/INT8, batching, kernel choice, and GPU model remain miner-local.

## Highest-value redesigns (implementation map)

| # | Redesign | Status in tree |
|---|---|---|
| 1 | Replace 16-GEMM combine with **Karatsuba-9** + fused M61 epilogue | **Done** (CPU + CUDA `Bmx4BuildKaratsubaPlanesKernel` + HIP + Metal) |
| 2 | **Scale-partitioned grouped MXFP4** projection (total K = n, not 4n) | **Done (exact, software-complete)**: CPU reference + portable exact grouped path (`cuda/matmul_v4_bmx4_cutlass_mxfp4.h`, byte-identical to dense) + CUDA native FP4 tier (hand-written scalar / cuBLASLt, M-t24 gated; C6: scalar never sets `used_tensor_path`) + INT8 tier. Hardware-gated: CMake `BTX_BMX4C_CUTLASS_MXFP4` + CUTLASS headers; `IsGroupedMxfp4TensorKernelLinked()` true only after self-qual |
| 3 | Entire nonce loop **device-resident** | **Done**: real device kernels in `ComputeDigestsBMX4CAccel` (CUDA/HIP/Metal) run projection + Karatsuba-9 combine + limb decompose/fold on-device and are the dispatched hot path (per-digest re-verify + CPU fail-closed fallback); `PersistentSketchMinerBMX4C` triple-buffer is the cross-call host template cache / fallback. Remaining (perf only): bind CUDA graphs to the device stages |
| 4 | **Stop returning loser payloads** | **Done** — streaming `ComputeSketchDigestFromFq`; no 8 MiB loser alloc; CUDA `ComputeDigestsOnlyBMX4CAccel` drops loser payloads device-side |
| 5 | Future **FP8 five-limb** combine lane | **CPU reference done (exact)**; planner selects for `"rubin"`. Device path: fail-closed API (`IsDeviceFp8FiveLimbAvailable`, `LaunchDeviceFp8FiveLimbCombine`) with transparent CPU fallback via `ComputeCombineFp8FiveLimbDeviceOrCpu` — no Rubin silicon headers in default builds |

## Hardware portfolio (planner)

| Hardware | Projection | Combine |
|---|---|---|
| H200 / default | Canonical INT8 | Karatsuba-9 INT8 |
| B200 / SM120 / MI350 | Scale-partitioned MXFP4 | Karatsuba-9 INT8 |
| Rubin-class | Exact FP8 | Five-limb FP8 |
| CPU | Canonical INT8 | Canonical integer |

## Design-limit analysis: do AI chips win more blocks?

### What the measurements already showed (PR #89)

- At ENC-BMX4C `n=4096`, **B200 ≈ 2× RTX 5090** on the small per-nonce GEMM shapes — not the 4–6× dense INT8 peak ratio.
- **FP4 does not tilt datacenter further**; consumer Blackwell’s FP4/INT8 ratio was *higher* than B200’s in the reported sweep.
- **cuBLASLt does not serve OCP MXFP4**; native MXFP4 needs CUTLASS / tcgen05.
- Historical H100/5090 ≈ **0.40×** was SHA-floor + skinny GEMMs — the batched/dense redesign flipped ordering on B200 vs 5090 for the *compute* profile, but **cost/nonce still favors retail** on rental/acquisition dollars.

### Have we hit a design ceiling?

**Not a consensus ceiling — a utilization ceiling.** Consensus cannot force “AI chips win”; it can only make the committed work **map onto the ops those chips accelerate** while staying exact. The remaining gap is almost entirely **miner-local schedule**, not the integer rule.

| Lever | Effect on DC vs retail | Status |
|---|---|---|
| Larger dense batched GEMMs (Q, stacked combine) | Moves along the 2×→4–6× B200/5090 axis | Available; needs sustained large Q |
| Karatsuba-9 (−35% combine MAC) | Helps both; slightly more on H200 (tensor-heavier share) | **Done** |
| Remove host XOF / H2D / loser 8 MiB / alloc | Attacks the **non-tensor floor** (the part that flattens $/nonce) | **Done**: device kernels are the hot path; loser payloads dropped device-side. Remaining: bind CUDA graphs (per-launch overhead only) |
| Scale-partitioned MXFP4 (K=n not 4n) | Raises tensor intensity on B200 | Exact software-complete (CPU + portable grouped + CUDA FP4/INT8 tiers); CUTLASS tensor kernel hardware-gated |
| FP8 five-limb (Rubin) | Future INT8 drought hedge | CPU exact; no Rubin silicon yet |
| One nonce / multi-GPU | Spec correctly rejects — NVLink does not help EPP search | Policy |

### Closing the cost-per-nonce gap (honest bound)

Even with a perfect device-resident loop:

1. **SHA/XOF remains class-flat.** Portable XOF moves SHA *off the host PCIe path*, but SHA throughput/$ across GPU classes is much flatter than dense tensor throughput/$. As long as ~tens of percent of wall time is SHA, retail clocks stay competitive on $/nonce.
2. **Small-GEMM shape still strands DC SMs** unless Q (and combine width) stay large. Karatsuba reduces MAC count but does not enlarge tiles by itself.
3. **Acquisition/$ and power/$** are outside consensus. A design can make B200 *faster per card* and still lose to a 5090 fleet on *blocks per dollar*.
4. **FP4/FP8 exact lanes** raise peak tensor opportunity on Blackwell/Rubin, but only after qualification and only for the projection/combine alphabets that fit. They do not erase the SHA floor.

**Verdict:** The integer + exact-lane design has **not** exhausted the levers that favor high-end AI silicon, but it **has** hit the limit of what consensus bytes can do. Further DC advantage is almost all:

- sustained large-Q dense GEMMs,
- device-resident XOF/hash (now scheduled; needs CUDA graph bind),
- real MXFP4 grouped kernels,
- and fleet economics — not another consensus encoding.

If after those miner-local steps B200 still loses on $/nonce to 5090, that is an **economic** outcome, not a missing consensus feature. Future-proofing (FP8 lane) keeps the workload on whichever exact low-precision unit vendors ship; it cannot guarantee datacenter always beats retail.

## Remaining (silicon-bound — every item has a complete, exact software path today)

All correctness-bearing device stages are implemented and are the dispatched
hot path (CUDA/HIP/Metal `ComputeDigestsBMX4CAccel`, per-digest re-verify + CPU
fail-closed fallback). What remains is either a throughput lever or a
vendor-tensor-kernel swap that only *replaces* an already-exact software path:

1. **CUDA graphs** bound to the device stages — per-launch overhead only; the
   kernels themselves already run on-device.
2. **CUTLASS grouped MXFP4** tensor kernel on qualified Blackwell (`BTX_BMX4C_CUTLASS_MXFP4`
   + `BTX_CUTLASS_INCLUDE_DIR`). `IsGroupedMxfp4TensorKernelLinked()` requires real TU
   headers **and** self-qual; portable exact grouped path is always available.
3. **Device FP8 five-limb** behind planner + qualification; fail-closed launch +
   `ComputeCombineFp8FiveLimbDeviceOrCpu` CPU fallback is complete today.
4. **LT ExactGemm tensor preference** — IMMA (cuBLASLt) / MFMA / Metal TensorOps
   Try* hooks with bit-exact self-test; scalar/ALU tiles remain the fallback.
   Metal TensorOps recipe still declines until factored from BMX4C M5 path.
5. **AMD native block-scaled MXFP4** (HIP tier (a)) — gated off pending real MI300/
   MI355 + ROCm; the INT8 MFMA tier (b) is fully implemented and bit-exact.
6. B200 / H200 / 5090 / MI350 soak + cost/nonce accounting (measurement, not code).

## Key symbols

- `src/matmul/matmul_v4_bmx4_pipeline.{h,cpp}` — persistent triple-buffer miner
- `src/cuda/matmul_v4_bmx4_context.{h,cpp}` — cross-call template context
- `ExpandMantissaStreamPortable` / `ComputeSketchDigestFromFq` — device-portable XOF + streaming digest
- `ComputeCombineKaratsuba9BMX4C` / CUDA Karatsuba-9 combine
- `src/cuda/matmul_v4_bmx4_accel.cu` — CUDA device backend (INT8 IMMA + native FP4 tiers, Karatsuba-9 combine)
- `src/hip/matmul_v4_bmx4_accel.hip` — HIP device backend (INT8 MFMA tier complete; native MXFP4 tier hardware-gated)
- `src/metal/matmul_v4_bmx4_accel.mm` — Metal device backend (ALU + M5 tensor-ops GEMM, self-test gated)
- `matmul_v4_bmx4_cutlass_mxfp4.h` — complete portable exact scale-partitioned grouped MXFP4 projection (`LaunchGroupedMxfp4Projection`); CUTLASS tensor kernel is the hardware-gated swap
