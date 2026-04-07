# PQ Benchmark Results (Revision 7d)

This document records local benchmark evidence for the Revision 7d validation
weight calibration and CI smoke checks.

## Environment

- Date: 2026-02-16
- Host: `Darwin 24.0.0` (arm64)
- CPU: `Apple M1 Max` (`10` logical CPUs)
- RAM: `64 GiB`
- Build: `cmake -B build && cmake --build build -j$(sysctl -n hw.ncpu)`

## Commands

```bash
./build/bin/bench_btx \
  -priority-level=all \
  -min-time=3000 \
  -filter="^(bench_mldsa_verify|bench_schnorr_verify|bench_slhdsa_verify|bench_worst_case_p2mr_block|bench_worst_case_tapscript_block)$"
```

Tier-1 CI smoke command (wired in `scripts/ci/run_ci_target.sh`):

```bash
build-btx/bin/bench_btx -min-time=5 -filter="^(bench_mldsa_verify|bench_slhdsa_verify)$"
```

## Results

| Benchmark | ns/op | op/s | Notes |
|---|---:|---:|---|
| `bench_schnorr_verify` | 26,756.27 | 37,374.42 | tapscript baseline primitive |
| `bench_mldsa_verify` | 51,983.79 | 19,236.76 | ML-DSA verification |
| `bench_slhdsa_verify` | 202,605.31 | 4,935.70 | SLH-DSA verification |
| `bench_worst_case_tapscript_block` | 26,493.73 | 37,744.77 | baseline block simulation |
| `bench_worst_case_p2mr_block` | 65,517.77 | 15,263.03 | P2MR weighted block simulation |

Derived ratios on this host:

- `ML-DSA / Schnorr`: `1.94x`
- `SLH-DSA / Schnorr`: `7.57x`
- `Worst-case P2MR / Worst-case tapscript`: `2.47x`

## Notes

- These are local development measurements, not release-gating reference
  machine numbers.
- Release gating remains fail-closed: if reference-machine benchmarks exceed
  accepted limits, validation-weight constants must be adjusted before release.
