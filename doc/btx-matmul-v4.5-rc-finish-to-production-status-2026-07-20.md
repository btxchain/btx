# ENC_RC finish-to-production status (2026-07-20)

*Tip: post-`ea9b167` finish-to-production amendment 1.A/1.B/1.C + §§2–5 WIP.
*Public activation: **NO-GO** (`nMatMulRCHeight = INT32_MAX`).*
*Companion: `doc/btx-matmul-v4.5-enc-rc-final-form-spec-2026-07-20.md`.*

This note tracks Amendments **1.A / 1.B / 1.C** against Stages §§1–5 WIP and the
remaining silicon/audit gates. It does **not** raise height.

---

## §1 — Amendments

### 1.A — LT resident native MX device-pointer path

| Item | Status |
|---|---|
| Goal | `TryLaunchResidentNativeMxProjectedRightDevice` stays on-device (pack + cuBLASLt on same stream); no full-tensor D2H/H2D hot path |
| CUDA (WIP) | **Device-pointer path landed:** `LaunchResidentNativeMxDeviceCore` + on-device pack kernels (`PackMuE2M1KMajorKernel` / …); hot path no longer D2H-packs; self-qual uses the same core (fixture upload only for oracle compare). Call site: `LtCudaResidentPool::EnqueueOneHeader` before INT8 fallback. sm_120 (5090) ≠ sm_100 (B200) — separate codegen/qual |
| HIP | **Fail-closed** — deficit `"device-pointer resident pack not wired"` |
| Metal | **Fail-closed** — `TryLaunchResidentNativeMxProjectedRightDeviceLT` returns false; INT8 scale-partition remains |
| No GPU / stub | `g_resident_native_mx_wired=false` with deficit — do not fake true |
| Preserve | INT8 scale-partition fail-closed fallback; never label INT8 as native-MX; never call host `TryLaunchNativeMxfp4ProjectedRight` from resident pool |
| Residual | Silicon re-qual at production dims + actual resident layouts still required for `peak_ready`; CI CPU stubs stay green |

### 1.B — RC ≠ LT for native FP4 (Ozaki)

| Item | Status |
|---|---|
| Why | LT 5090 qual (bounds &lt; 2^24) does **not** carry to RC. Z=S·V ~2^30.76; wgrad &gt; 2^24 |
| Plan | `doc/btx-matmul-v4.5-rc-native-fp4-ozaki-plan-2026-07-20.md` |
| Scaffold | `src/matmul/matmul_v4_rc_mx_ozaki.{h,cpp}` — `TryRcOzakiMxfp4GemmS8S8Int64` **fail-closed**; CPU limb-split reference matches int64 on small panels; `IsRcOzakiMxfp4Qualified() == false` |
| Wiring | Comments at Phase-1 Z / wgrad in `matmul_v4_rc.cpp`; `ProbeRCSelfQual` keeps `native_mxfp4_qualified=false` |
| Tests | `rc_ozaki_mxfp4_fail_closed_until_wired`; coupled probe asserts native_* stay false |
| Status | **PARKED / scaffolded** — no RC `native_mxfp4` flip until Ozaki quals vs int64 at consensus dims |

### 1.C — Staging telemetry diagnosis

| Item | Status |
|---|---|
| Emit sites | **Already present at ROOT** in `src/matmul-v4-report.cpp` (~1944–1951 and ~2431–2440): `throughput_chat_staging_slots` / `throughput_chat_staging_chunks` |
| Nulls | JSON `null` when `chat_staging_slots == 0` means **provenance/artifact mismatch or staging unused**, **not** missing emit code |
| Change this wave | One-line Amendment 1.C comments at both emit sites; **no new emit keys** |

---

## §2 — GKR + VerifyBoundedExactReplay

| Item | Status |
|---|---|
| Decision | Stage E **DECIDED**: winner-only GKR/sumcheck (`doc/btx-matmul-v4.5-rc-stage-e-winner-gkr-decision-2026-07-20.md`) |
| Code | `matmul_v4_rc_gkr.{h,cpp}` — serializable proof, dual-path verifier, soundness ≤ 2^{-64} after PoW grinding (computational, not ε=0) |
| Fallback | `VerifyBoundedExactReplay` — ε=0 STREAMED ExactReplay (dispute/oracle) |
| Consensus today | `CheckMatMulProofOfWork_RC` ExactReplay; GKR optional behind `BTX_RC_VERIFY_GKR=1` (default OFF) via `VerifyRCWinnerOrExactReplay` |
| Residual | Medium/HBM prove-cost may PARK HBM-scale GKR; ship both verifiers; do not raise height on decision alone |

---

## §3 — Coupled inert wire

| Item | Status |
|---|---|
| Profile | `ENC_RC_COUPLED` + `nMatMulRCCoupledHeight = INT32_MAX` (public inert) |
| Oracle | Toy + medium; 4 exec modes digest-identical (`matmul_v4_rc_coupled.*`) |
| Device | `MakeResolvedExactGemmBackendForRC` after `ProbeRCSelfQual`; ExactGemm s8×s8 only — **never** sets native MXFP4 |
| PoW | `CheckMatMulProofOfWork_RCCoupled` / regtest enable only |
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
| `matmul_v4_rc_gkr_tests` | Winner GKR / ExactReplay dual path |
| `matmul_v4_rc_distributed_tests` | Topology parity scaffold |
| `matmul_v4_rc_transcript_tests` | Resident/Streaming sinks |
| `matmul_v4_rc_verify_bakeoff_tests` | Stage E bake-off scaffolding |
| Gates | `contrib/matmul-v4/rc-golden-gate.py`, `rc-gate.py` (offline GO tally ≠ height raise) |

Full production-size / cross-vendor / malformed-proof / silicon suites remain OPEN.

---

## Remaining silicon / audit gates

Keep `nMatMulRCHeight = INT32_MAX` until **all** hold:

1. **1.A silicon** — CUDA device-pointer path is code-complete; re-qual on peak silicon + keep HIP fail-closed until twin lands.
2. **1.B closed** — RC Ozaki MXFP4 quals vs int64 at consensus (or production-representative) dims before any RC `native_mxfp4_qualified`.
3. Stage A hazards closed (goldens versioned; no half-wired growth/brake).
4. 8 GiB Streamed/Checkpointed identical-episode completion.
5. Native accel without CPU masking (A5 / C / D).
6. Stage G measured interconnect (≥7× NVLink-vs-PCIe) + GPU rates — CPU campaigns alone are NOT EVIDENCE.
7. Stage E verify cost ≤ fraction of block interval (GKR) with ExactReplay dispute path retained.
8. Same-tip economic / audit review; clean flag-day cutover only.

**Do not** invent silicon rates from toy runs. **Do not** copy LT native flags into RC.
