> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# ENC_RC / ENC_RC_COUPLED datacenter-advantage defaults — 2026-07-21

**Configured for AI datacenter economics.** Does **not** raise
`nMatMulRCHeight` / `nMatMulRCCoupledHeight` (public nets stay `INT32_MAX`).
Does **not** enable the GKR arbiter.

Source of truth: `src/matmul/matmul_v4_rc_datacenter.h` (`matmul::v4::rc::dc`)
and Stage F dials in `matmul_v4_rc_scale_axes.h`.

## Analysis lock (why these defaults)

Lever-B MX Extract @ MatExpand `w=1024` (perf model, single 5090 vs B200):

| Metric | Value |
|---|---|
| B200:5090 throughput | ≈ **2.3×** (was ≈1.2× under ChaCha-cell Extract) |
| B200:5090 rent | ≈ **15×** |
| Blocks/$ if tensor-only | **consumer-favorable** (~2.3/15) |
| Claim from params alone | **Do not claim ≥4×** |

So epoch-0 levers must add **HBM + full-bank traffic + fabric**, not more GEMM
width. Cheap cards stay consensus-valid via Streamed; Resident LLM-class nodes
win on attempts per dollar.

## Defaults table

| Knob | Default | Class | Notes |
|---|---|---|---|
| `kRCCoupFullBankScheduleEnabled` | **true** | Consensus-gated | 12 pages / barrier×lobe; ~12× bank traffic |
| `kRCCoupPagesPerBarrierLobe` | 12 | Consensus-gated | Production 8×8×12 covers 768 pages once |
| `kRCCoupMaterialExchangeEnabled` | **true** | Consensus-gated | Mix domain absorbs `exchange_rows` |
| `kRCCoupExchangeRowsDefault` | 128 | Consensus-gated | Sweep 64 / 128 / 256 |
| `kRCThreeAxisScheduleWireEnabled` | **true** | Consensus-gated | Matches `kRCThreeAxisScheduleEnabled` |
| `kRCAxisW0State` | **48 GiB** | Stage F | = MakeProduction resident bank |
| `kRCAxisC0Local` | **12 Ti MAC** | Stage F | Scales with full-bank page count |
| `kRCAxisX0Exchange` | **4 GiB** | Stage F | Fabric / NVLink-class exchange |
| `kRCAxisHardCapState` | 96 GiB | Stage F | B200-class ladder |
| `kRCMinerBatchQDefault` | 32 | Miner-local | Digests unchanged |
| `kRCMinerBatchQMax` | 256 | Miner-local | Hard cap |
| `kRCPackedBankTargetGiB` | {48,64,80,96} | Miner-local | Floor 48 clears 32 GiB consumer Resident |
| `kRCMxPackedBytesPerElem` | 0.53125 | Miner-local | E2M1 + UE8M0/32 |
| GKR arbiter | **OFF** | Consensus | ExactReplay sole oracle |

Env must **never** flip consensus levers (digest purity). Harness may set
`RCCoupOptions::full_bank_schedule=false` / `material_exchange=false` only for
legacy golden differentials.

## Stage F note

`W_state` is the **HBM bank target**. Episode `n_ctx` uses
`kRCAxisEpisodeCtxBytesCap` (192 MiB) so ExactReplay episode dims stay viable
until Stage C wires coupled bank sizing from `W_state` directly.

## Tests

```
src/test/matmul_v4_rc_datacenter_tests.cpp
src/test/matmul_v4_rc_accel_policy_tests.cpp
```
