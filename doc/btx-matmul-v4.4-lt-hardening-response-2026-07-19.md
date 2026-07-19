# BTX v4.4-LT hardening response (2026-07-19)

Response to the external deficiency report. Recommendations were verified against the tree before acting. Public activation remains **inert** (`INT32_MAX`). Subsidy stays **hardware-independent**.

## Economic framing (accepted; no code change to subsidy)

Progressively more capable AI-native hardware receives progressively greater **expected** mining opportunity through higher exact seal throughput. Per-block subsidy and total issuance remain hardware-independent. No GPU-model fields, tensor attestations, FP4/FP8 bonus multipliers, or hardware-specific targets.

## Verified and acted on

| Report item | Verdict | Action |
|---|---|---|
| §1 Hardware subsidy multipliers | Correct — do not implement | Documented |
| §17 `BTX_MATMUL_LT_BATCH` alters seal Q* | **Confirmed** | Split `consensus_Qstar` vs `execution_chunk` in `SolveMatMulV4LT` |
| §18 LT pool share target | **Confirmed** | Pass `effective_target` into LT solve |
| §11 Accel nonce-only API | **Confirmed** (fail-closed before) | Batch only when seeds match; else per-complete-header device calls |
| §10 Phase-B regenerates template | **Confirmed** | `ComputeSealDigestBMX4CLT` uses prepared `WindowSketchMinerLT` + `MineSlot` |
| §7 Per-MAC Fq reduction | **Confirmed worthwhile** | `ComputeCombineModQ` deferred `__int128` + one reduce (byte-identical) |
| §15 Sync EncDr on msg thread | **Confirmed** | Saturated queue: defer/drop; never `ProcessBlockSync` EncDr |
| §16 Best-header raw chainwork | **Confirmed** | Trust-adjusted selection + descendant auth-work propagation |
| IBD unbounded expensive budget | **Confirmed** | Global leaf-unit budget always charged; IBD/fast-phase uses finite elevated ceiling (≥256) |
| Q* charged as 1 verification | **Confirmed** | `MatMulEncDrWorkUnits` = Q* in seal mode; pending/budget consume leaf units |
| V2-only blocktxn ceiling | **Confirmed** | Prefer full `BLOCK` fallback when blocktxn exceeds V2 payload; NOTFOUND only if BLOCK also too large |
| §3 Unified public activation | **Confirmed useful** | Public nets require `v4==bmx4c==drlt` + `seal_as_pow` when DRLT live |
| §13 Metal ARC `id<MTLBuffer>&` | **Confirmed** | `__strong&` ownership fix |
| §19 `VerifyWindowSlotFreivalds` | **Confirmed** unsafe as general API | Marked test/diagnostic-only |
| §5 / §25 C-15 / overclaims | **Confirmed** | Docs corrected (below) |

## Verified but deferred (not yet better as consensus changes)

| Report item | Why deferred |
|---|---|
| §4 Header-PoW wire redesign | Real malleability risk with compile flag; redesign needs versioned activation + identity commit. Flag stays default-OFF. |
| §5 Cryptographic extractor replacement | SplitMix is weak as a PRF story; swapping extractor is a consensus transcript change — needs golden vectors + external review before activation. |
| §6 / §8 Adaptive limbs / Strassen tournament | Plausible private miner advantage; publish as miner-local exact algs + calibrate ASERT to fastest known — do **not** change the integer transcript until measured. |
| §9 Q* algorithm enforcement | Correct: Q* is aggregate commitment only. Document; no fake tensor consensus rule. |
| §12–14 Native IMMA/MFMA/MXFP4/Metal MPP | Real gaps; keep fail-closed stubs; do not mislabel scalar kernels. Full tensor residency is Phase 3. |
| Full 256-bit slot IDs | Low-64 slot nonce + uniqueness reject is an interim harden; full ID binding later. |

## Documentation posture

Prefer: exact reference available · scalar device fallback · native tensor unimplemented/qualified · C-15 external review open · direct-product assumption open · fastest-known-as-of-date · activation inert.

Remove/qualify: “C-15 closed”, “no cheaper mathematical path”, “12.5% shortcut cap”, “software-complete” for native tensor lanes, “device-resident” without “scalar GEMM today”.
