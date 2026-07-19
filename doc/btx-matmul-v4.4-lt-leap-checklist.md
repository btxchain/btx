# V4.4-LT leap checklist (living)

Branch: `feat/bmx4c-exact-accel-lanes` → PR #89 (`claude/matmul-v4-design-spec-af23sj`).

**Invariant:** public nets remain fail-closed (`nMatMulV4Height` / `nMatMulDRLTHeight` = `INT32_MAX`; ASERT rescale `1/1` until measured silicon JSON).

| # | Criterion | Code status | Gate |
|---|---|---|---|
| 1 | Q* verify bounded + async | Phase-B seal MTP threaded into `MatMulVerifyWorker` + Classify | Tip-verify soak at Q*∈{64,128} |
| 2 | Header admission + chainwork auth | HeaderPoW bit-26 self-describing wire **withdrawn** (`f21a282`); commitment-format HeaderPoW activation remains **hard NO-GO**; public discount `UINT32_MAX` (disabled) | Separate calibrated HeaderPoW design + finite public heights (orthogonal to C-15) |
| 3 | Persistent device-resident GPU | LT CUDA: persistent MatExpand + IMMA scratch; **s8xs8 IMMA** (`TryLaunchLtImmaGemmS8S8Device`) after multi-shape ExactGemm self-qual (square + MatExpand panels); **s32xs8 scalar only** (no IMMA recipe); scalar graphs on IMMA decline. **HIP MFMA wired**: hipBLASLt `HIPBLAS_COMPUTE_32I` \| rocBLAS `gemm_ex`, multi-shape self-qual incl. MatExpand panel, device-pointer resident path; else honest ALU (never labeled MFMA). Chat still D2H (`device_hashing=false`) | Device SHA256d + B200/5090/MI350 perf proof |
| 4 | FP4/FP8/Tensor genuinely wired | Portable exact MXFP4; CUTLASS/device FP8 **fail-closed**; cuBLASLt MXFP4 no-algo on sm_100/sm_120 (PR #89); hand PTX sm_120a ≠ sm_100a; never `used_tensor_path` on scalar | sm_100a / MI350 M-t24 qualified |
| 5 | Cross-vendor exactness | Harness schema + `BTX_REQUIRE_GPU_GOLDEN`; Dockerfile.tests Ubuntu | H100/B200/M5/MI350 PASS |
| 6 | Production benchmarks | `--profile bmx4c-lt` in report + measure-hardware; lt-gate device JSON | ≥4× nonce/s / nonce/$ against **fastest known exact** baseline (not naive GEMM; see FMM/ASERT calibration note) |
| 7 | Adversarial shortcut resistance | ChaCha20-PRF MatExpand candidate + internal non-affinity/goldens; external C-15 packet **hardened draft (falsifiable §0.1 game; candidate selected; OPEN — not closed)**; public exact combine baselines published (`ComputeCombineModQ` deferred, adaptive limb, Karatsuba-9) + CPU tournament harness | Independent cryptanalyst PASS on packet game + measured tournament vs silicon (**orthogonal** to FMM efficiency calibration) |
| 8 | Consensus safety (2026-07-19 harden) | Q* env invariance; prepared seal template; trust-adjusted best-header; no sync EncDr on msg-thread saturation; complete-header accel batching | Activation still NO-GO until full checklist |

## Explicitly NOT claimed

- K.2b GO/NO-GO
- External C-15 closed (OPEN; ChaCha-PRF ≠ work lower bound)
- Finite activation heights (`nMatMulDRLTHeight` / `nMatMulV4Height` = `INT32_MAX`)
- HeaderPoW bit-26 wire live (withdrawn)
- Tensor MXFP4 / device FP8 as production-trusted without self-qual
- “No cheaper exact mathematical path” (**retired** — adaptive limbs / Strassen / LCMA remain open *efficiency* work; public baselines + tournament published; calibrate to fastest known exact)
- Hardware-dependent per-block subsidy (forbidden; throughput share only)

## Calibration cross-link

Hardness (C-15 / HonestMAC) vs efficiency (ASERT / Strassen–Winograd ~n^{2.807} on combine/sketch; MatExpand stays `O(n²·w)`):  
`doc/btx-matmul-v4.4-lt-c15-asert-fmm-calibration-2026-07-19.md`.