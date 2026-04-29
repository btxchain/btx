> **Note**: This document is from the original design phase. References to 150-second block times reflect the initial target; the current mainnet target is 90 seconds. See README.md for current parameters.

# BTX MatMul PoW Benchmarks

Generated: 2026-02-19 23:24:24 JST
Host: `cybook.local`
Platform: `macOS-15.0-arm64-arm-64bit-Mach-O`
CPU: `arm`
Peak RSS (full benchmark run): `5.11 MiB`

## Method

- Benchmark source: `test/benchmark/matmul_phase2_bench.cpp`
- Build command: `c++ -O3 -std=c++20 -I src test/benchmark/matmul_phase2_bench.cpp build-btx/lib/libbitcoin_crypto.a -o build-btx/bin/matmul_phase2_bench`
- Solve timing is **per attempt** (`A/B` precomputed once, nonce-loop path only).
- Verify timing includes two `FromSeed` reconstructions plus noise + transcript path.

## Solve/Verify Timing

| n | MatMul (ms) | Solve/attempt (ms) | Verify (ms) | CPU @150s | CPU @0.25s |
|---|---:|---:|---:|---:|---:|
| 64 | 0.75 | 1.22 | 2.87 | 0.001% | 0.3% |
| 128 | 6.88 | 8.13 | 14.71 | 0.008% | 2.8% |
| 256 | 63.10 | 68.00 | 94.34 | 0.070% | 25.2% |
| 512 | 487.91 | 516.93 | 622.29 | 0.542% | 195.2% |

## n=512 Overhead Breakdown

| Component | Time (ms) | % of MatMul |
|---|---:|---:|
| Noise generation | 3.39 | 0.69% |
| Transcript compression (dot) | 25.63 | 5.25% |
| Rolling SHA-256 (compressed stream 128 KiB) | 0.054 | 0.011% |
| Denoise (O(n^2*r)) | 2.05 | 0.42% |
| Total protocol overhead (noise+compression+sha+denoise) | 31.12 | 6.38% |

## Compression Hash-Input Reduction

- Compressed transcript bytes at n=512,b=16: `131072` bytes (128 KiB)
- Naive full-block hash bytes at n=512,b=16: `33554432` bytes (32.00 MiB)
- Byte reduction factor: `256.0x`
- SHA-256 median time on naive stream: `13.982 ms`
- SHA-256 median time on compressed stream: `0.054 ms`

## Memory Scaling (O(n^2))

| n | Matrices A/B/C (MiB) | Noise factors (KiB) | Transcript stream (KiB) | Estimated working set (MiB) | Matrix growth vs previous |
|---|---:|---:|---:|---:|---:|
| 64 | 0.047 | 8.0 | 0.2 | 0.055 | - |
| 128 | 0.188 | 16.0 | 2.0 | 0.205 | 4.00x |
| 256 | 0.750 | 32.0 | 16.0 | 0.797 | 4.00x |
| 512 | 3.000 | 64.0 | 128.0 | 3.188 | 4.00x |

The dominant matrix term quadruples on each doubling of `n`, confirming `O(n^2)` memory behavior.

## Genesis Difficulty Calibration (Fast Phase: 0.25s target)

Derived from measured Solve() attempt timings with `target = powLimit * solve_seconds`.

| n | Solve/attempt (s) | Attempts per 0.25s block | Target scale vs powLimit | Suggested genesis nBits |
|---|---:|---:|---:|---:|
| 64 | 0.001224 | 204.280 | 0.004895 | `0x1c0140d0` |
| 128 | 0.008128 | 30.758 | 0.032512 | `0x1c0852b2` |
| 256 | 0.067999 | 3.677 | 0.271995 | `0x1c45a176` |
| 512 | 0.516930 | 0.484 | 1.000000 | `0x1d010000` |

## Milestone 11 Exit-Criteria Check

- [PASS] Solve/Verify timings captured for n={64,128,256,512}
- [PASS] Memory growth follows O(n^2)
- [PASS] Compression dot overhead at n=512 <= 10%
- [PASS] Rolling SHA-256 on compressed stream < 0.5 ms
- [PASS] Compression + SHA overhead < 10%
- [PASS] Denoise overhead < 2% at n=512
- [PASS] Total protocol overhead < 15% at n=512

## Raw Artifacts

- Raw benchmark output: `/Users/admin/Documents/btxchain/btx-node/.btx-production-readiness/matmul_phase2_bench.out`
- Timing output: `/Users/admin/Documents/btxchain/btx-node/.btx-production-readiness/matmul_phase2_bench.time`
