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

- `BTX_RC_COUP_FULL_BANK_SCHEDULE=1`
- `BTX_RC_COUP_MATERIAL_EXCHANGE=1`

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

## Tests

```
src/test/matmul_v4_rc_datacenter_tests.cpp
```
