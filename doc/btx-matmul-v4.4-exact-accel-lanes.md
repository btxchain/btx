# MatMul v4.4 — Exact Accelerator Lanes (miner-local)

Status: **implementation in progress on `feat/bmx4c-exact-accel-lanes`**, branched from PR #89 (`claude/matmul-v4-design-spec-af23sj`). Mainnet activation remains **inert** (`INT32_MAX` / `ratification = false`). Floating lanes are **not** separate consensus activations.

## Thesis

Consensus sees only canonical integer sketch bytes. The optimal design is **one canonical integer workload** served by several **provably exact** accelerator lanes (CPU/SIMD, INT8, MXFP4, FP8). FP4/FP8/INT8, batching, kernel choice, and GPU model remain miner-local.

## Highest-value redesigns (implementation map)

| # | Redesign | Status in tree |
|---|---|---|
| 1 | Replace 16-GEMM combine with **Karatsuba-9** + fused M61 epilogue | **Done** |
| 2 | **Scale-partitioned grouped MXFP4** projection (total K = n, not 4n) | **CPU reference done**; CUTLASS stub inert until silicon |
| 3 | Entire nonce loop **device-resident** | **Done on host (normative schedule)** — `PersistentSketchMinerBMX4C` triple-buffer (XOF → Karatsuba-9 → streaming digest), portable two-pass XOF, cross-call template reuse via `Bmx4CudaTemplateContext`. CUDA graphs/buffers bind to the same stages on bring-up |
| 4 | **Stop returning loser payloads** | **Done** — streaming `ComputeSketchDigestFromFq`; no 8 MiB loser alloc |
| 5 | Future **FP8 five-limb** combine lane | **CPU reference done**; planner selects for `"rubin"` |

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
| Remove host XOF / H2D / loser 8 MiB / alloc | Attacks the **non-tensor floor** (the part that flattens $/nonce) | **Host schedule done**; device graphs still to bind |
| Scale-partitioned MXFP4 (K=n not 4n) | Raises tensor intensity on B200 | CPU exact; CUTLASS pending silicon |
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

## Remaining (silicon-bound)

1. Bind CUDA graphs / device buffers to the triple-buffer stages (host schedule is normative).
2. CUTLASS grouped MXFP4 on qualified Blackwell.
3. Device FP8 five-limb behind planner + qualification.
4. B200 / H200 / 5090 / MI350 soak + cost/nonce accounting.

## Key symbols

- `src/matmul/matmul_v4_bmx4_pipeline.{h,cpp}` — persistent triple-buffer miner
- `src/cuda/matmul_v4_bmx4_context.{h,cpp}` — cross-call template context
- `ExpandMantissaStreamPortable` / `ComputeSketchDigestFromFq` — device-portable XOF + streaming digest
- `ComputeCombineKaratsuba9BMX4C` / CUDA Karatsuba-9 combine
- `matmul_v4_bmx4_cutlass_mxfp4.h` — CUTLASS stub
