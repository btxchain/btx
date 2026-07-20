# ENC_RC finish-to-production status (2026-07-20)

*Tip: Succinct-proof audit-hardening M6–M11 on M1–M5 base (`0bbd060`+).
*Public activation: **NO-GO** (`nMatMulRCHeight = INT32_MAX`).*
*Companion: `doc/btx-matmul-v4.5-enc-rc-final-form-spec-2026-07-20.md`.*
*Soundness: `doc/btx-matmul-v4.5-rc-succinct-proof-soundness-2026-07-20.md`.*
*Arithmetization: `doc/btx-matmul-v4.5-rc-arithmetization-completeness-2026-07-20.md`.*
*PCS alt: `doc/btx-matmul-v4.5-rc-succinct-proof-pcs-alternative-2026-07-20.md`.*
*M9 cost: `doc/btx-matmul-v4.5-rc-succinct-proof-cost-m9-2026-07-20.md`.*
*M11 FRI gap: `doc/btx-matmul-v4.5-rc-fri-proximity-gap-m11-2026-07-20.md`.*

This note tracks Amendments **1.A / 1.B / 1.C / 1.CORRECT / 1.SCOPE / 1.D / GKR guardrail**
against Stages §§1–5. It does **not** raise height.

---

## §1 — Amendments

### 1.CORRECT — `peak_ready` / `blocks_device_resident` are DERIVED

| Item | Status |
|---|---|
| Rule | **Never hand-set.** `DeriveLtPeakMxFlags`: `peak_ready = peak_capable && resident_native_mx_wired && (mxfp4\|\|fp8)`; `blocks_device_resident = peak_required && !peak_ready` (deficit flag) |
| On oracle pass | Set **only** `resident_native_mx_wired` (+ qual flags); let the two derive |
| On ready path | `blocks_device_resident` **MUST be false** |
| Code | `matmul_v4_lt_mx_exact.h::DeriveLtPeakMxFlags`; CUDA/HIP `ProbeLtPeakMxPathStatus` |

### 1.SCOPE — native-MX qual is PER-ARCH

| Item | Status |
|---|---|
| Rule | Record qual under `arch_key` (`sm_120`, `sm_100`, `gfx950`, …) — not per-card |
| Observed (consumer Blackwell) | MXFP4 standalone may qualify across **sm_120** generally (5090 + 5060 Ti); FP8 declines; **resident-native unwired** on all → §1.A is class-wide consumer-Blackwell work |
| B200 | **sm_100** needs its **own** qualification (≠ sm_120) |
| Report | `lt.arch_key` emitted in `matmul-v4-report.cpp` |

### 1.A — LT resident native MX device-pointer path

| Item | Status |
|---|---|
| Goal | `TryLaunchResidentNativeMxProjectedRightDevice` stays on-device (pack + cuBLASLt on same stream); no full-tensor D2H/H2D hot path |
| CUDA | Device-pointer path landed; call from `EnqueueOneHeader` before INT8 fallback |
| HIP / Metal | **Fail-closed** device-pointer entries |
| Residual | Silicon re-qual at production dims + actual resident layouts for `peak_ready` |

### 1.B / 1.RC-vs-LT — RC ≠ LT for native FP4 (Ozaki)

| Item | Status |
|---|---|
| Why | LT bounds &lt; 2^24 do **not** transfer to RC Z≈2^30.76 / wgrad on **any** vendor |
| Plan | `doc/btx-matmul-v4.5-rc-native-fp4-ozaki-plan-2026-07-20.md` |
| Scaffold | `src/matmul/matmul_v4_rc_mx_ozaki.{h,cpp}` — fail-closed; `IsRcOzakiMxfp4Qualified() == false` |
| Status | **PARKED / scaffolded** — no RC `native_mxfp4` flip until Ozaki quals vs int64 at consensus dims |

### 1.C — Staging telemetry diagnosis

| Item | Status |
|---|---|
| Emit | ROOT keys already present; nulls ⇒ artifact/revision mismatch — **no new emit keys** |

### 1.D — AMD / HIP build + guard correctness (Amendment v3)

| Item | Status |
|---|---|
| **D1** HIPCXX = clang | **DONE** — resolve before `enable_language(HIP)`; reject g++ |
| **D2** Isolate `hip::device` | **DONE** — `btx_hip_device` only; no `-x hip` on g++ TUs |
| **D3** Strip host CET from amdgcn | **DONE** — `btx_hip_device` overrides `-fcf-protection=none` for `COMPILE_LANGUAGE:HIP` (hardening stays on CXX host TUs) |
| **D4** `__HIP_PLATFORM_AMD__` reach | **DONE** — PUBLIC on `btx_hip_device` + `btx_matmul_backend` when HIP on (reaches bitcoin_common HIP includes); non-HIP builds unpoisoned |
| **D5** Self-contained `device_mx.h` | **DONE** — `matmul_v4_lt_device_mx.h` includes `hip_runtime.h` / `cuda_runtime.h` under platform guards |
| **D-MFMA** K16 / K32 / RDNA4 | **DONE (code)** — `btx_hip_mfma_guard.h` + `btx_hip_mfma_i8_gemm.h`; gfx908/90a → `mfma_i32_16x16x16i8`; gfx940/941/942/950 → `mfma_i32_16x16x32_i8` (K=16 removed on CDNA3/4); gfx1200 → scalar. Kernels in `matmul_v4_accel.hip` / `bmx4` call shared helper. **Silicon compile-gate** via D7 still required on ROCm box |
| **D6** Scripts + library discovery | **DONE** — `measure-hardware.sh` + `verify-backend.sh`; distro `/usr` hipBLASLt/rocBLAS hints |
| **D7** Isolated MFMA compile-gate | **DONE** — `contrib/matmul-v4/hip-mfma-compile-gate.sh` (PASS/FAIL per arch; COMPILE ≠ gfx1200 runtime qual) |
| Fail-closed | **Standing** — never label unqualified AMD path native-MX / peak-ready |

---

## §2 — Succinct proof production-harden (M1–M11)

| Gate | Status |
|---|---|
| **M1 REAL FRI** | **DONE (code)** — LDE blowup=16, multi-layer fold openings; forge rejects |
| **M2 ALL-PHASE** | **DONE (code)** — every round × QKt/SV/Fwd/Bwd/Wgrad + LogUp + `round_seeds`; **no shrink-to-toy**; proof v4 |
| **M3 Fp2 + bound** | **DONE (writeup)** — challenges in Fp2; composed bound in soundness note. **External audit OPEN** |
| **M4 / M9 cost** | **DONE (instrument)** — `MeasureWinnerGkrToyMedium` / CSV; CI=toy; off-CI `BTX_RC_GKR_MEASURE_LADDER=1` (b_seq=256) + `BTX_RC_GKR_MEASURE_MEDIUM=1` (b_seq=8192). Soft over_budget → ExactReplay (tested). **No invented silicon rates**. Consensus-dim HBM vs shrink needs datacenter GPU (OUT OF SCOPE) |
| **M5 shadow** | **Intact** — shadow ON, arbiter OFF, ExactReplay decides |
| **M6 FRI params** | **DONE (Fable)** — unique-decoding **Q=116**, blowup=**16**, g=**40**, Fp2; `FriSoundnessBoundBits()=65`; conjectured ρ^Q gated OFF; Fp3 / DEEP-OOD documented as future/OPEN |
| **M7 under-constraint** | **DONE (audit+tests)** — wire→constraint; LogUp `(in,out)`; adversarial (a)–(g). **OPEN G1–G5** block arbiter. **Decision:** ship k=40/Fp2; Fp3 not built |
| **M8 soundness note** | **DONE** — Fable table + composed bound + DEEP/OOD OPEN + EXTERNAL AUDITOR CHECKLIST |
| **M10 PCS alt** | **DONE (recommend)** — hand-rolled-but-audited FRI; no consensus vendor dep |
| **M11 proximity gap** | **DONE (option)** — BCIKS20 Q≈53 documented; **not** shipped; Q=116 default |

| Item | Detail |
|---|---|
| Reality Guardrail | Still REJECTS HBM/production-complete until audit + silicon cost close |
| Consensus | ε=0 ExactReplay; `nMatMulRCHeight=INT32_MAX` |
| Soft budget | over_budget → ExactReplay recommendation (**shipping**), not toy arithmetization |

**Honest residual:** M7 G1–G5; DEEP/OOD exact-eval binding OPEN; consensus-dim
prove cost on CPU likely over soft budget (ExactReplay ships until silicon M4);
**independent human crypto audit** required before arbiter ON (OUT OF SCOPE).
Fable IOP reference remains scratchpad-only (never merge as consensus).

---

## §3 — Coupled inert wire

| Item | Status |
|---|---|
| Profile | `ENC_RC_COUPLED` + `nMatMulRCCoupledHeight = INT32_MAX` (public inert) |
| Oracle | Toy + medium; 4 exec modes digest-identical (`matmul_v4_rc_coupled.*`) |
| Device | ExactGemm s8×s8 only — **never** sets native MXFP4 |
| Status | **DONE (inert)** — GPU coupled ExactGemm still SILICON-GATED |

---

## §4 — F axes (three-axis schedule)

| Item | Status |
|---|---|
| Code | `matmul_v4_rc_scale_axes.{h,cpp}` — dials `W_state`, `C_local`, `X_exchange` |
| Enable | `kRCThreeAxisScheduleEnabled = false` (always epoch-0 dials) |
| Brake | F6 omitted (height/epoch-only; no chainwork brake) |
| Caps | Streamed peak + transcript hard caps with prior-dim fallback |
| Status | **DONE (PROVISIONAL, inert)** — ratios freeze only after Stage G silicon |

Independent of parked §R.7 `kRCGrowthScheduleEnabled=false`.

---

## §5 — Tests (scaffolding)

| Suite | Coverage |
|---|---|
| `matmul_v4_rc_tests` | V1 golden, modes, self-qual fail-closed, P1.2 layouts, Stage F inert, **Ozaki native_* lock** |
| `matmul_v4_rc_coupled_tests` | Toy/medium, modes, device probe skip, **native_* stay false** |
| `matmul_v4_rc_gkr_tests` | ALL-PHASE toy prove/verify; M2+M7 adversarial rejects (claim/sumcheck, drop layer, round_seed, pow_bind/digest, logup_sum, trace_fri, lookup_fri/Extract proxy); no shrink-from-shape; Fp2/FRI; shadow; Reality Guardrail |
| `matmul_v4_lt_tests` | `DeriveLtPeakMxFlags` ready/deficit invariants |
| D7 gate | `contrib/matmul-v4/hip-mfma-compile-gate.sh` (ROCm box) |
| Gates | `contrib/matmul-v4/rc-golden-gate.py`, `rc-gate.py` (offline GO tally ≠ height raise) |

---

## Definition of CODE-COMPLETE (this tip) vs OPEN-by-nature

### CODE-COMPLETE (achieved on tip — CPU-green; fail-closed where not silicon-qualified)

| Path | Status |
|---|---|
| LT device-pointer MX (CUDA) | **code-complete**; peak_ready fail-closed until resident oracle at prod dims |
| HIP D1–D7 + D-MFMA | **code-complete**; native-MX fail-closed until compile-gate + oracle |
| Metal resident MX | **fail-closed** stub entry |
| RC Ozaki | **scaffolded / fail-closed** until consensus-dim qual |
| Succinct proof (Fp2+FRI+LogUp+real episode+shadow+shrink) | **code-complete scaffold**; NOT production-complete / NOT audited |
| Coupled + Stage F | **inert / provisional** behind INT32_MAX / `kRCThreeAxisScheduleEnabled=false` |
| Stage H CPU suites | **green** (115 cases in RC/GKR/coupled/LT aggregate run) |

### STILL OPEN BY NATURE (do not claim done)

1. Production-scale prover cost on datacenter silicon → HBM vs shrink decision
2. Native FP4 + RC Ozaki qualification on real 5090/B200/MI300/MI355X/RDNA4
3. Independent cryptographic AUDIT before proof-as-arbiter cutover
4. Stage G economic + PCIe-vs-NVLink campaign; activation-height decision

**Do not** invent silicon rates from toy runs. **Do not** copy LT native flags into RC.
**Do not** claim HBM GKR production-complete under the Reality Guardrail.
