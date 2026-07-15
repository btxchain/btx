# MatMul v4 — Activation Readiness Tracker

This file tracks the path from the current reference implementation to a
mainnet hard-fork activation. **`nMatMulV4Height` is deliberately UNSET on
mainnet** — v4 is enabled only on regtest/testnet for testing. Two gates:

- **Gate A — merge to `main` (after public review).** The fork lands
  *disabled*; inert until a height is set. Near-term.
- **Gate B — activate on mainnet.** Gated on calibration + audit + testnet +
  coordinated upgrade. Weeks–months; some items require real GPU hardware
  this repo cannot provide.

Design source of truth: `doc/btx-matmul-v4-design-spec.md`. Per-backend
hardware runbook: `doc/matmul-v4-gpu-backends.md`.

---

## Gate A — merge to main (disabled)

| # | Item | Status |
|---|---|---|
| A1 | CPU consensus core (`int8_field`, `matmul_v4`, `pow_v4`) — compiles | ✅ done |
| A2 | Height-gated dispatch + one-time ASERT rescale (`pow.cpp`, `validation.cpp`) | ✅ done |
| A3 | Chainparams: regtest/testnet v4 params; **mainnet unset** | ✅ done |
| A4 | GPU backends (CUDA/Metal/HIP) + dispatch + capabilities — host side compiles | ✅ done |
| A5 | Dispatch re-verifies every accelerated result vs CPU, falls back | ✅ done |
| A6 | Miner seals `header.matmul_digest` (mining-flow correctness) | ⏳ in progress |
| A7 | Fix `matmul_v4_pow_tests` / `matmul_v4_determinism_vectors` digest-seal bug | ⏳ in progress |
| A8 | CPU unit suite builds + **runs green** (resolve `test_btx` wallet-link) | ⏳ in progress |
| A9 | Pin golden determinism vectors (CPU) — currently empty placeholders | ☐ todo |
| A10 | DoS verify-budget params + min/max dimension bounds (§G.2/§I.5) | ⏳ in progress |
| A11 | Pooled-mining / challenge-header RPC paths (still v3-only) | ☐ todo |
| A12 | Optimal-miner `(U·A)(B·V)` path in CPU `ComputeDigest` (currently forms full C; correct but Θ(n³)) | ☐ todo (perf) |
| A13 | Public code review of design spec + implementation | ☐ todo |

Exit criterion: A1–A11 done, CPU suite green, reviewed → merge to `main`
with `nMatMulV4Height` unset.

---

## Gate B — mainnet activation

### B1. GPU miner backends — hardware bring-up (needs real silicon)
The kernels are written bit-exact-by-construction and compile behind their
toolchain guards, but **cannot be compiled or run in this environment**
(no CUDA toolkit, no macOS/Metal, no ROCm). For each backend, on real
hardware: build (`nvcc`/`xcodebuild`/`hipcc`), run the determinism harness,
and confirm the digest is **bit-for-bit identical to the CPU reference**.

| Backend | Build | Verify (diff vs CPU) |
|---|---|---|
| CUDA (Turing→Blackwell, sm≥75) | `-DBTX_ENABLE_CUDA_EXPERIMENTAL=ON` | ☐ H100, B200, RTX 5090/4090, sm_75 |
| Metal (Apple M5-class) | `-DBTX_ENABLE_METAL=ON` (Xcode 26+) | ☐ M5, M5 Max |
| HIP/ROCm (CDNA MFMA) | `-DBTX_ENABLE_HIP=ON -DBTX_HIP_ARCHITECTURES=gfx942` | ☐ MI300X, MI250 |

Pass = `matmul_v4_backend_determinism_tests` green with **zero**
skip-pending-hardware warnings for that backend. A one-bit divergence is a
chain split — hard fail. Details in `doc/matmul-v4-gpu-backends.md`.

### B2. Appendix-C calibration (consensus-critical)
| # | Item | Needs |
|---|---|---|
| B2a | Cross-vendor INT8 determinism golden vectors — generate on H100/B200/consumer/Apple-M5/CDNA and confirm identical | **real GPUs** |
| B2b | One-time ASERT rescale `Num/Den` — benchmark real v3→v4 throughput on reference hardware and set empirically | reference GPU |
| B2c | b=8 roofline confirmation on real IMMA/MFMA/Metal kernels | real GPUs |
| B2d | Operand XOF regen timing envelope (15–35 ms); s8 operand + U/V sampling vectors | CPU/GPU |
| B2e | n=4096 verify-budget confirmation on reference CPUs (<1 s single-thread) | CPU |

### B3. Security audit
External consensus/security audit. Focus: verifier DoS surface (payload
parser fuzzing, oversized/malformed sketches), the ASERT rescale, the
v3→v4 dispatch boundary, and the GPU-vs-CPU verify/fallback path.

### B4. Public testnet burn-in
Deploy on testnet, mine across `nMatMulV4Height` with **diverse hardware**,
confirm zero splits over a sustained window. This is where determinism
problems surface in the wild.

### B5. Coordinated activation
- Choose a mainnet height with **weeks** of lead time (not days).
- Prefer a miner/version **signaling/readiness gate** so activation only
  proceeds once a supermajority has upgraded — a flag-day with no adoption
  check risks a split.
- Ship a release with the height set; drive node/miner/pool/exchange
  upgrades *before* the height.
- Rewrite mining guides + pool software (§N.2 — Freivalds-verified shares).

Exit criterion: B1–B4 green, height set with lead time + signaling,
supermajority upgraded → activate.

---

## Hard dependencies this repo cannot satisfy
- **Real GPUs** (H100/B200/RTX/Apple-M5/CDNA) for B1 and B2a–B2c.
- **External audit** (B3).
- **Public testnet operators + time** (B4).

Everything else (Gate A, the code for B1, the calibration harnesses) is in
this branch.
