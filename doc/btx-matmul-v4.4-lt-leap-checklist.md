# V4.4-LT leap checklist (living)

Branch: `feat/bmx4c-exact-accel-lanes` → PR #89 (`claude/matmul-v4-design-spec-af23sj`).

**Invariant:** public nets remain fail-closed (`nMatMulV4Height` / `nMatMulDRLTHeight` = `INT32_MAX`; ASERT rescale `1/1` until measured silicon JSON).

| # | Criterion | Code status | Gate |
|---|---|---|---|
| 1 | Q* verify bounded + async | Phase-B seal MTP threaded into `MatMulVerifyWorker` + Classify | Tip-verify soak at Q*∈{64,128} |
| 2 | Header admission + chainwork auth | HeaderPoW `nNonce` opt-in via `BTX_ENABLE_HEADER_NONCE_ON_WIRE` (default OFF); public discount `UINT32_MAX` | Wire ON + calibrated discount |
| 3 | Persistent device-resident GPU | LT CUDA path expanded (persistent buffers / graph-oriented stages); host ExactGemm fail-closed | B200/5090 perf proof |
| 4 | FP4/FP8/Tensor genuinely wired | Portable MXFP4 always; CUTLASS option + honesty stubs; FP8 device fail-closed | sm_100a / MI350 M-t24 |
| 5 | Cross-vendor exactness | Harness schema + `BTX_REQUIRE_GPU_GOLDEN`; Dockerfile.tests Ubuntu | H100/B200/M5/MI350 PASS |
| 6 | Production benchmarks | `--profile bmx4c-lt` in report + measure-hardware; lt-gate device JSON | ≥4× nonce/s / nonce/$ |
| 7 | Adversarial no cheaper path | Internal MatExpand closed; external C-15 packet **drafted (not closed)**: `doc/btx-matmul-v4.4-lt-external-c15-packet.md` | Independent cryptanalyst |

## Explicitly NOT claimed

- K.2b GO/NO-GO
- External C-15 closed
- Finite activation heights
- Tensor MXFP4 / device FP8 as production-trusted without self-qual
