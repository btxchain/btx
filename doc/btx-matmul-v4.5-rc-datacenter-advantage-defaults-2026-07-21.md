# ENC_RC / ENC_RC_COUPLED datacenter-advantage defaults — 2026-07-21

**Scaffolding only.** Does **not** raise `nMatMulRCHeight` / `nMatMulRCCoupledHeight`
(public nets stay `INT32_MAX`). Does **not** enable the GKR arbiter.

Source of truth: `src/matmul/matmul_v4_rc_datacenter.h` (`matmul::v4::rc::dc`).

## Defaults table

| Knob | Default | Class | Notes |
|---|---|---|---|
| `kRCCoupFullBankScheduleEnabled` | **false** | Consensus-gated | 8×8×12=768 pages at production dims; digest-breaking |
| `kRCCoupPagesPerBarrierLobe` | 12 | Consensus-gated | Pages accumulated per (barrier, lobe) when full schedule ON |
| `kRCCoupMaterialExchangeEnabled` | **false** | Consensus-gated | NVLink-shaped multi-row exchange; not wired |
| `kRCCoupExchangeRowsDefault` | 128 | Consensus-gated | Sweep 64 / 128 / 256 |
| `kRCThreeAxisScheduleWireEnabled` | **false** | Consensus-gated | Still deferred (see `kRCThreeAxisScheduleEnabled`) |
| `kRCMinerBatchQDefault` | 32 | Miner-local | Stack nonce rows into Q×W·W×W; digests unchanged |
| `kRCMinerBatchQMax` | 256 | Miner-local | Hard cap for `TryMineRCCoupledBatch` |
| `kRCPackedBankTargetGiB` | {40,56,72,96} | Miner-local | Packed-MX resident sizing sweep |
| `kRCMxPackedBytesPerElem` | 0.53125 | Miner-local | E2M1 + UE8M0/32 |
| GKR arbiter (`BTX_RC_GKR_ARBITER`) | **OFF** | Consensus | Must stay unset / not enabled from this surface |

Env research toggles (still digest-breaking; default unset):

- ~~`BTX_RC_COUP_FULL_BANK_SCHEDULE=1`~~ **REMOVED** — env must not touch consensus.
  Use `RCCoupOptions::full_bank_schedule` in harness/tests only.
- ~~`BTX_RC_COUP_MATERIAL_EXCHANGE=1`~~ **REMOVED** — same rule.

## Miner-local vs consensus-gated

**Consensus-gated** (must stay OFF on live params):

- Full bank schedule (`SelectCoupledBankPageIds(..., full_bank_schedule=true)`)
- Material exchange
- Three-axis schedule wire

When full schedule is OFF, the barrier loop is byte-identical to the legacy
single-page rule `(barrier+lobe)%bank_pages`.

**Miner-local** (safe; digests unchanged):

- Q-batch CPU reference: `TryMineRCCoupledBatch` / `MineRCCoupledEpisode`
- Packed-GiB → `bank_pages` via `BankPagesForPackedGiB`
- `RCCudaEpisodeContext` persistent arena + CUDA Graphs scaffold (`RunBarrierGraph`
  returns false until device GEMM+Extract is wired)

## Helpers

- `ProbeRCDcStatus()` — what is enabled, arch key, deficit string
- `BankPagesForPackedGiB(gib, lobe_width)` —
  `ceil(gib·2³⁰ / (W·W·0.53125))`
- Production covering: `MakeProductionRCCoupParams()` with full schedule yields
  each of 768 pages exactly once across the episode (helper-tested; height inert)

## Ship-first CUTLASS / capacity defaults (research)

| Knob | Default |
|---|---|
| SM100 peak | `KernelTmaWarpSpecialized2SmMxf4Sm100`, cluster `<_4,_4,_1>`, tile `256×256×256`, SFVecSize=32 |
| SM120 (5060/5090) | `KernelTmaWarpSpecializedMxf4Sm120`, cluster **`<_1,_1,_1>`**, tile `<_128,_128,_128>` |
| Packed bank | **48 GiB** frozen prod; ladder 40→48→64→96 (≤120 on B200 with Q-stack) |
| Q enable order | **1 → 8 → 32** (park 128/256 until Stage-G mem-cap) |
| NVLink state tile | **128** rows (sweep 64/128/256) |

SM100 and SM120 qualify on **separate** `arch_key` latches. Do not copy LT `native_mxfp4_qualified` into RC.

## Tests

```
src/test/matmul_v4_rc_datacenter_tests.cpp
```
