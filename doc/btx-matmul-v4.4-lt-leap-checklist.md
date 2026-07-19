# V4.4-LT leap checklist (living)

Branch: `feat/bmx4c-exact-accel-lanes` → PR #89 (`claude/matmul-v4-design-spec-af23sj`).

**Invariant:** public nets remain fail-closed (`nMatMulV4Height` / `nMatMulDRLTHeight` = `INT32_MAX`; ASERT rescale `1/1` until measured silicon JSON).

| # | Criterion | Code status | Gate |
|---|---|---|---|
| 1 | Q* verify bounded + async | Phase-B seal MTP threaded into `MatMulVerifyWorker` + Classify | Tip-verify soak at Q*∈{128,256,512}; regtest Phase B live |
| 2 | Header admission + chainwork auth | HeaderPoW bit-26 self-describing wire **withdrawn** (`f21a282`); commitment-format HeaderPoW activation remains **hard NO-GO**; public discount `UINT32_MAX` (disabled) | Separate calibrated HeaderPoW design + finite public heights (orthogonal to C-15) |
| 3 | Persistent device-resident GPU | LT CUDA/HIP: Lever-B **MX Extract** device twin + prefer **scale-partitioned B̂·V** when `PlanLTAccel`→`ScalePartitionedMxfp4` (Blackwell/MI350); else dense IMMA/MFMA on dequantized Bhat; s32xs8 scalar. Chat still D2H | Device SHA256d + B200/5090/MI350 **re-measure after Lever B** (do not claim ≥4×) |
| 4 | FP4/FP8/Tensor genuinely wired | Portable exact MXFP4; CUTLASS/device FP8 **fail-closed**; LT MX scale layout ≠ BMX4C row-block scales; never `used_tensor_path` on scalar | sm_100a / MI350 M-t24 qualified |
| 5 | Cross-vendor exactness | Harness schema + `BTX_REQUIRE_GPU_GOLDEN`; Dockerfile.tests Ubuntu | H100/B200/M5/MI350 PASS |
| 6 | Production benchmarks | `--profile bmx4c-lt` in report + measure-hardware; lt-gate device JSON | ≥4× nonce/s / nonce/$ against **fastest known exact** baseline (not naive GEMM; see FMM/ASERT calibration note) |
| 7 | Adversarial shortcut resistance | Lever-B **MX-block Extract** landed (consensus digest hard fork of LT transcript) + internal non-affinity/goldens; external C-15 packet **hardened draft (falsifiable §0.1 game; OPEN — not closed)**; ~32× PRF dilution ≠ C-15 closure; public exact combine baselines + CPU tournament harness | Independent cryptanalyst PASS on packet game + measured tournament vs silicon (**orthogonal** to FMM); **re-measure after Lever B — do not claim ≥4×** |
| 8 | Consensus safety (2026-07-19 harden) | Q* env invariance; prepared seal template; trust-adjusted best-header; no sync EncDr on msg-thread saturation; complete-header accel batching | Activation still NO-GO until full checklist |

## Explicitly NOT claimed

- K.2b GO/NO-GO
- External C-15 closed (OPEN; MX Extract / PRF ≠ work lower bound)
- Finite activation heights (`nMatMulDRLTHeight` / `nMatMulV4Height` = `INT32_MAX`)
- HeaderPoW bit-26 wire live (withdrawn)
- Tensor MXFP4 / device FP8 as production-trusted without self-qual
- “No cheaper exact mathematical path” (**retired** — adaptive limbs / Strassen / LCMA remain open *efficiency* work; public baselines + tournament published; calibrate to fastest known exact)
- Hardware-dependent per-block subsidy (forbidden; throughput share only)

## Calibration cross-link (ASERT vs HonestMAC operator hygiene)

Hardness (C-15 / `HonestMAC` MAC count) vs efficiency (ASERT / Strassen–Winograd
~n^{2.807} on combine/sketch; MatExpand stays `O(n²·w)`):
`doc/btx-matmul-v4.4-lt-c15-asert-fmm-calibration-2026-07-19.md`.

| Operator rule | Pin |
|---|---|
| **Tournament baseline** | **Fastest known exact** identity-PASS path (CPU combine tournament + measured ExactGemm / device lanes) — **not** naive schoolbook GEMM / invented `n³` |
| **Row 6 (≥4×)** | Measure vs that fastest-exact baseline; invent **no** silicon nonce/s in docs |
| **Row 7 / G5** | External C-15 packet game — **orthogonal to FMM** efficiency; tournament speedup ≠ C-15 PASS |
| **C-15 status** | **OPEN**; public heights remain `INT32_MAX` |
| **Non-reduction** | LT-C15 does **not** follow from SETH/OV/APSP/3SUM/BMM/ω/KW/PRF/Freivalds — packet §0.3 + fold `doc/btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md` |

> **C-15 prices shortcuts in MAC count; ASERT prices the fastest honest exact
> wall-clock path.** Do not conflate the two.