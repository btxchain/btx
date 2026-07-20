# ENC_RC finish-to-production status (2026-07-20)

*Tip: Amendment **v2** (§1.CORRECT / SCOPE / 1.D / GKR Reality Guardrail) on finish-to-production tip.
*Public activation: **NO-GO** (`nMatMulRCHeight = INT32_MAX`).*
*Companion: `doc/btx-matmul-v4.5-enc-rc-final-form-spec-2026-07-20.md`.*

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

### 1.D — AMD / HIP build + guard correctness (Amendment v2)

| Item | Status |
|---|---|
| **D1** HIPCXX = clang | **DONE** — resolve before `enable_language(HIP)`; reject g++ |
| **D2** Isolate `hip::device` | **DONE** — `btx_hip_device` only; no `-x hip` on g++ TUs |
| **D3** `__HIP_PLATFORM_AMD__` | **DONE** — target define on `btx_hip_device` |
| **D4** MFMA vs WMMA | **DONE** — `src/hip/btx_hip_mfma_guard.h`; MFMA only on CDNA; RDNA4/gfx1200 → scalar/INT8 (WMMA path future); `#error` if both classes defined |
| **D5** Library discovery | **DONE** — distro `/usr` hints; ExactGemm MFMA chain intact |
| **D6** Scripts | **DONE** — `measure-hardware.sh` + `verify-backend.sh` |
| **D7** Fail-closed | **Standing** — never label unqualified AMD path native-MX / peak-ready |

---

## §2 — GKR + Reality Guardrail

| Item | Status |
|---|---|
| Decision | Winner-only **direction** locked; scaffold is **NOT** production-complete |
| Reality Guardrail | `kRCGkrRealityGuardrail` — REJECT HBM/production-complete until actual-episode + succinct + no-rerun verify + formal ≤2^{-64}-after-grinding. Current: synth 32×32, non-succinct, verify re-runs, single Goldilocks insufficient |
| Fallback | `VerifyBoundedExactReplay` / ExactReplay (expect this to fire) |
| Consensus today | ExactReplay; GKR env-gated OFF by default |
| Height | `INT32_MAX` |

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
| `matmul_v4_rc_gkr_tests` | Winner GKR / ExactReplay dual path + Reality Guardrail strings |
| `matmul_v4_lt_tests` | `DeriveLtPeakMxFlags` ready/deficit invariants |
| Gates | `contrib/matmul-v4/rc-golden-gate.py`, `rc-gate.py` (offline GO tally ≠ height raise) |

Full production-size / cross-vendor / malformed-proof / silicon suites remain OPEN.

---

## Remaining silicon / audit gates

Keep `nMatMulRCHeight = INT32_MAX` until **all** hold:

1. **1.A silicon** — CUDA device-pointer path is code-complete; re-qual on peak silicon **per arch** (`sm_120` vs `sm_100`); HIP/Metal fail-closed until twins land.
2. **1.B closed** — RC Ozaki MXFP4 quals vs int64 at consensus dims before any RC `native_mxfp4_qualified` (every vendor).
3. **1.D D4 silicon** — gfx1200 build compiles clean with MFMA fenced; CDNA MFMA path oracle-qualifies separately.
4. Stage A hazards closed (goldens versioned; no half-wired growth/brake).
5. 8 GiB Streamed/Checkpointed identical-episode completion.
6. Native accel without CPU masking (A5 / C / D).
7. Stage G measured interconnect (≥7× NVLink-vs-PCIe) + GPU rates — CPU campaigns alone are NOT EVIDENCE.
8. GKR Reality Guardrail gates closed (or ExactReplay retained as consensus).
9. Same-tip economic / audit review; clean flag-day cutover only.

**Do not** invent silicon rates from toy runs. **Do not** copy LT native flags into RC.
**Do not** claim HBM GKR production-complete under the Reality Guardrail.
