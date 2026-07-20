# MatMul v4.4 — Exact Accelerator Lanes (miner-local)

Status: **portable exact integer / software fallback paths are in tree**.
“MXFP4” in a portable path or planner enum describes grouping/layout intent,
not an issued native instruction. Native CUTLASS/tcgen05 MXFP4 and device FP8
remain hardware-gated or fail-closed. LT CUDA/HIP consume logical MX components
through four exact INT8 IMMA/MFMA (or exact device-ALU fallback) partitions by
default on every supported architecture. A one-GEMM dense INT8 projection is a
diagnostic opt-out, not the production default. Mainnet activation remains
**inert**.

**Economic rule:** more capable AI hardware earns greater *expected* share via exact seal throughput only; per-block subsidy is hardware-independent.

## Thesis

Consensus sees only canonical integer sketch bytes. The optimal design is **one canonical integer workload** served by several **provably exact** accelerator lanes (CPU/SIMD, INT8, MXFP4, FP8). FP4/FP8/INT8, batching, kernel choice, and GPU model remain miner-local.

## Highest-value redesigns (implementation map)

| # | Redesign | Status in tree |
|---|---|---|
| 1 | Replace 16-GEMM combine with **Karatsuba-9** + fused M61 epilogue | **Done** (CPU + CUDA `Bmx4BuildKaratsubaPlanesKernel` + HIP + Metal) |
| 2 | **Contraction-aligned MX projection** (one E8M0 code per 32 K elements and output coordinate) | The pre-activation A/B scale-axis correction is implemented in the exact CPU reference, CUDA masked-plane consumers, and portable **integer emulation**, all byte-identical to dense. That makes a future one-pass native MXFP4 projection structurally possible; it does not mean one is wired. CUTLASS/tcgen05 hardware execution remains fail-closed until self-qualified; LT has its own already-contraction-aligned B layout. |
| 2b | Adaptive base-256 / two-limb exact combine | **Done (miner-local)**: `ComputeCombineAdaptiveLimbBMX4C` + deferred `__int128` `ComputeCombineModQ` + classical oracle; tournament harness under `bench/` |
| 3 | Entire nonce loop **device-resident** | **Implemented for the provenance-qualified CUDA/HIP full-header Q* path**: nonce-fresh W generation, direct/radix-lowered GEMMs, Karatsuba-9 combine, and SHA256d(Chat) stay on-device; one digest/status batch is copied at completion with no per-candidate synchronization. Cold template binding and self-tests are outside that steady-state claim. Exact logical-MX partitioning is the default projection; `BTX_MATMUL_V4_LT_DENSE_BHAT=1` is the one-GEMM dense diagnostic. Metal/Ascend and native MXFP4 do not yet make this resident-Q* claim. |
| 4 | **Stop returning loser payloads** | **Done** — LT CUDA/HIP full-header batches return digest/status only, and dispatch CPU-reseals payloads solely for target candidates. Losing slots remain payload-empty. The streaming digest also avoids the historical 8 MiB loser allocation. |
| 5 | Future **FP8 five-limb** combine lane | **CPU reference done (exact)**; planner selects for `"rubin"`. Device path: fail-closed API (`IsDeviceFp8FiveLimbAvailable`, `LaunchDeviceFp8FiveLimbCombine`) with transparent CPU fallback via `ComputeCombineFp8FiveLimbDeviceOrCpu` — no Rubin silicon headers in default builds |

## Hardware portfolio (planner intent, not runtime evidence)

| Hardware | Projection | Combine |
|---|---|---|
| H200 / B200 / SM120 / MI300 / MI350 | Logical MX lowered through four exact INT8 tensor/device-ALU GEMMs by default; one dense INT8 GEMM only with `BTX_MATMUL_V4_LT_DENSE_BHAT=1`; native MXFP4 remains intent | Karatsuba-9 INT8 |
| Rubin-class | Exact FP8 | Five-limb FP8 |
| CPU | Canonical INT8 | Canonical integer |

## Design-limit analysis: do AI chips win more blocks?

### What the measurements already showed (PR #89)

- At ENC-BMX4C `n=4096`, **B200 ≈ 2× RTX 5090** on the small per-nonce GEMM shapes — not the 4–6× dense INT8 peak ratio.
- **FP4 does not tilt datacenter further**; consumer Blackwell’s FP4/INT8 ratio was *higher* than B200’s in the reported sweep.
- **cuBLASLt does not serve OCP MXFP4**; native MXFP4 needs CUTLASS / tcgen05.
- Historical H100/5090 ≈ **0.40×** was SHA-floor + skinny GEMMs — the batched/dense redesign flipped ordering on B200 vs 5090 for the *compute* profile, but **cost/nonce still favors retail** on rental/acquisition dollars.

An externally supplied RTX 5090 data point at commit `695dd45` (`n=512`, `Q=64`,
SM120, CUDA 13) isolates the current LT parameter and Extract changes. These are
**host-CPU stage timers**, not device nonce-throughput measurements:

| Stage | w=128 | w=1024 | w=1024 + MX Extract |
|---|---:|---:|---:|
| S0 template | 181.8 ms | 488.3 ms | 416.5 ms |
| S1 MatExpand-B | 135.5 ms | 445.0 ms | 370.0 ms |
| S2 `Bhat·V` | 42.6 ms | 43.5 ms | 43.2 ms |
| S3 combine | 29.6 ms | 30.0 ms | 30.2 ms |
| Marginal / nonce | 209.9 ms | 520.7 ms | 445.6 ms |
| Tensor-stage share | 84.9% | 93.8% | 92.7% |

Lever-B PRF dilution reduced total S1 by about **17%** versus the w=1024
pre-MX Extract, rather than 32×, because the two `MatExpandCore` GEMMs plus the
host G/H/W projector expansion still dominate this CPU-reference stage. The
report emitted `device_nonce_per_s = null` for
these runs, so they cannot satisfy the LT G2 throughput ratio. A separate
Extract performance model estimates B200:5090 near **2.3×** at w=1024; treat
that as a rough upper bound, not byte-exact silicon evidence. It remains below
the 4× gate and, under the contributor-supplied ~15× rental-price assumption,
would still favor the 5090 per dollar. Rental prices are operator inputs, not a
pinned protocol fact.

### 1ca87fb Q*=128 trace: a host/launch measurement, not a silicon ratio

Byte-exact reports collected at commit `1ca87fb` (`n=512`, consensus `Q*=128`)
initially printed RTX 5090 **77.08**, B200 **118.92**, and CPU-reference **2.24 / 4.35**
nonce/s. With operator-supplied VAST rates of $0.50/h and $7.00/h, the old gate
therefore printed a 1.54× B200:5090 ratio and a 9.1× consumer nonce/$ advantage.
Those arithmetic results describe the report's wall timer, not the GPUs.

An `nsys` trace on a 5060 Ti found about **11.2 ms wall time per nonce** but only
**169 us of GPU kernels (1.5%)**, approximately **53 serialized launches per
nonce**, and 13,406 launches / 43 ms total GPU execution over the run. At
`1ca87fb`, the raw ABI could not batch seed-complete headers: it invoked each Q*
separately, expands nonce-fresh W on one host thread, transfers it, launches and
synchronizes the device work, copies the sketch back, then digests on the host.
An indicative locally instrumented 5060 Ti rate of **95.68 nonce/s** exceeding
the 5090 by 24% is consistent with host/NUMA and launch latency dominating.

Accordingly, **118.92 / 77.08 must not be called a B200:5090 silicon ratio and
must not calibrate ASERT**. Current gating treats reports with that historical
provenance only as `host_orchestrated_nonce_per_s`; `device_nonce_per_s` remains
null and `device_rate_valid=false`. The newer CUDA/HIP full-header entry can
establish resident-batch telemetry after it proves a single device-resident
consensus-Q* batch with nonce-fresh W generation and digest on-device and no
per-nonce synchronization. It can publish `device_nonce_per_s` for G2/G3 only
after it additionally proves a qualified native path, device-event timing, and
host independence. Reports record CPU model and CPU/NUMA affinity for diagnosis,
but G2 deliberately does not require the GPU classes to use identical CPUs: an
accepted device-domain rate must not depend on the host model.
`cpu_reference_tensor_share_pct` (called `tensor_share_pct` in
the historical report) remains a CPU-reference composition metric,
not evidence of tensor-core utilization and not a G1 pass. G1 requires a
qualified native tensor path plus independent device-side timing and hardware
counters with `device_tensor_share_pct > 50`; absent any part of that tuple it
fails closed. The reported 0.0032% B200 utilization
was likewise an ops/wall-rate diagnostic and is no longer published as device
tensor utilization without silicon-rate provenance.

### d4f5577 resident-window trace: batching alone did not isolate silicon

Same-tip production-shape (`n=4096`, `Q*=256`) host-wall telemetry measured an
RTX 5090 at 1.70 nonce/s with daemons active, 2.21 with them paused, and about
2.36 when NUMA-pinned. A separate RTX 5060 Ti host measured about 3.50 nonce/s.
The 5060 Ti host's 3.70 GHz single-thread clock versus the dual-socket 5090
host's 2.25 GHz clock tracked the 1.48× throughput inversion closely. This is
strong evidence that the resident API removed the old per-nonce orchestration
but not all serial per-window host sensitivity. These values are now
`resident_batch_wall_nonce_per_s` diagnostics, not a consumer-GPU silicon
ranking, B200/5090 G2 evidence, or ASERT input. Device events around the actual
GPU work plus a controlled host-sensitivity check are required before the
silicon-rate fields become valid.

There was also a separate standalone-harness defect in every pre-fix CPU
number: `matmul-v4-report` did not construct `kernel::Context` or call
`SHA256AutoDetect()`, so its host digests used the portable SHA implementation.
Those CPU nonce/s, S0–S4 timings, derived composition shares, and Lever-B stage
ratios must all be re-measured. Digest bytes remain valid. The tool now selects
SHA before timing, records `sha256_implementation`, and hashes a little-endian
`vector<Fq>` as one contiguous LE64 stream (with an explicit portable endian
fallback) instead of one eight-byte `CSHA256::Write` per word.

### Have we hit a design ceiling?

**Not a consensus ceiling — a utilization ceiling.** Consensus cannot force “AI chips win”; it can only make the committed work **map onto the ops those chips accelerate** while staying exact. The remaining gap is almost entirely **miner-local schedule**, not the integer rule.

| Lever | Effect on DC vs retail | Status |
|---|---|---|
| Larger dense batched GEMMs (Q, stacked combine) | Moves along the 2×→4–6× B200/5090 axis | Available; needs sustained large Q |
| Karatsuba-9 (−35% combine MAC) | Helps both; slightly more on H200 (tensor-heavier share) | **Done** |
| Remove host XOF / H2D / loser payload / alloc | Attacks the **non-tensor floor** (the part that flattens $/nonce) | **Implemented, silicon re-measure pending**: CUDA/HIP accept complete seed-bound Q* headers, generate W and SHA256d(Chat) on-device, return digest/status only, and have no per-candidate synchronization. The steady-state call synchronizes at completion; cold binding/self-tests may synchronize separately. CUDA bounds Chat staging to 128 MiB; HIP overlaps an eight-slot ring. Per-candidate GEMM launches and serial SHA/prefix work remain profiling targets. |
| Logical scale partition | Exposes committed mantissa/scale tensors without dense dequantization | Exact CPU path plus default CUDA/HIP four-pass INT8 lowering complete; `BTX_MATMUL_V4_LT_DENSE_BHAT=1` retains the one-GEMM A/B diagnostic; CUTLASS/tcgen05 native kernel hardware-gated |
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
- device-resident W generation/hash (implemented for the CUDA/HIP full-header
  path; further graph/launch fusion is a throughput optimization),
- real, self-qualified MXFP4 grouped kernels (not planner labels),
- and fleet economics — not another consensus encoding.

If after those miner-local steps B200 still loses on $/nonce to 5090, that is an **economic** outcome, not a missing consensus feature. Future-proofing (FP8 lane) keeps the workload on whichever exact low-precision unit vendors ship; it cannot guarantee datacenter always beats retail.

## Remaining (silicon-bound — every item has a complete, exact CPU fallback)

The LT CUDA/HIP full-header APIs implement the resident digest/status path and
publish that fact only through per-call provenance. Other vendor lanes remain
at the explicitly documented scope below, and every decline or mismatch falls
back to the canonical CPU transcript. The remaining work is qualification,
measurement, launch amortization, or a vendor-tensor-kernel swap:

1. **CUDA graphs** bound to the device stages — per-launch overhead only; the
   kernels themselves already run on-device.
2. **CUTLASS grouped MXFP4** tensor kernel on qualified Blackwell (`BTX_BMX4C_CUTLASS_MXFP4`
   + `BTX_CUTLASS_INCLUDE_DIR`). `IsGroupedMxfp4TensorKernelLinked()` requires real TU
   headers **and** self-qual; portable exact grouped path is always available.
3. **Device FP8 five-limb** behind planner + qualification; fail-closed launch +
   `ComputeCombineFp8FiveLimbDeviceOrCpu` CPU fallback is complete today.
4. **LT ExactGemm tensor preference** — CUDA IMMA and HIP MFMA are wired for
   direct s8 stages, radix-lowered `Y·H`, and Karatsuba-9 combine. Frontier
   default exact projection consumes logical MX components through four exponent partitions;
   this is real INT8 tensor execution, not native MXFP4. Metal TensorOps remains
   self-qualification gated.
5. **AMD native block-scaled MXFP4** (HIP tier (a)) — gated off pending real MI300/
   MI355 + ROCm; the INT8 MFMA tier (b) is fully implemented and bit-exact.
6. B200 / H200 / 5090 / MI350 soak + cost/nonce accounting (measurement, not code).

## Key symbols

- `src/matmul/matmul_v4_bmx4_pipeline.{h,cpp}` — persistent triple-buffer miner
- `src/cuda/matmul_v4_bmx4_context.{h,cpp}` — cross-call template context
- `ExpandMantissaStreamPortable` / `ComputeSketchDigestFromFq` — device-portable XOF + streaming digest
- `ComputeCombineKaratsuba9BMX4C` / CUDA Karatsuba-9 combine
- `src/cuda/matmul_v4_bmx4_accel.cu` — CUDA device backend (INT8 + portable/native-FP4 tiers; native admission separately gated)
- `src/cuda/matmul_v4_lt_tensor_gemm.cu` — LT cuBLASLt IMMA ExactGemm + arch probe
- `src/cuda/matmul_v4_lt_accel.cu` — LT resident IMMA path (exact logical-MX partition by default, dense diagnostic opt-out, plus direct/radix/Karatsuba stages; no native MXFP4)
- `src/hip/matmul_v4_bmx4_accel.hip` — HIP device backend (INT8 MFMA tier complete; native MXFP4 tier hardware-gated)
- `src/hip/matmul_v4_lt_tensor_gemm.hip` — LT hipBLASLt/rocBLAS MFMA ExactGemm
- `src/hip/matmul_v4_lt_accel.hip` — LT resident MFMA path (exact logical-MX partition by default, dense diagnostic opt-out, plus direct/radix/Karatsuba stages; no native MXFP4)
- `src/metal/matmul_v4_bmx4_accel.mm` — Metal device backend (ALU + M5 tensor-ops GEMM, self-test gated)
- `matmul_v4_bmx4_cutlass_mxfp4.h` — portable exact grouped integer emulation behind MXFP4-shaped APIs; CUTLASS tensor kernel is a separate hardware-gated swap
