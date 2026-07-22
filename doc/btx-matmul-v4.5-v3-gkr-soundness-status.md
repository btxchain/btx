# V3 GKR / succinct verification soundness status

## Status: NO-GO for arbiter — constructions integrated & validated in-tree; external cryptographic audit pending

- `nMatMulRCHeight` / `nMatMulRCCoupledHeight` = `INT32_MAX` (do not raise)
- `kRCGkrFormalSoundnessReady=false`: `EnvRCGkrArbiterEnabled` always false
  (ignores `BTX_RC_GKR_ARBITER`); toggling the env must not change ExactReplay
  consensus digest/acceptance while heights remain inert
- v7 defeats independent malicious constructors by **grounding** against the
  int64 reference — the G1–G5 succinct constructions (I–IV) are additionally
  **integrated and validated in-tree** (wired into `VerifyWinnerProofV7`); the
  residual gate is the **external cryptographic audit** (never claim CLOSED or
  audit-passed)
- Composed bound (v7 batched + dual-OOD + dual-α): ≈ **71.9 bits** post-grind at
  Q=128 over Fp2, FS-dominated (margin ≈ 7.9 bits over the 2^-64 target) —
  see `doc/btx-matmul-v4.5-v7-composed-soundness-bound-2026-07-22.md`
- External cryptographic review remains mandatory before any activation discussion

## GO / NO-GO table (honest)

| Gate | Verdict | Notes |
|---|---|---|
| Arbiter cutover (`BTX_RC_GKR_ARBITER`) | **NO-GO** | Hard-disabled; ExactReplay is sole consensus accept |
| Raise RC / coupled heights | **NO-GO** | Stay `INT32_MAX` |
| V3 config in FS transcript | **GO (hooks)** | `AbsorbCoup` tag `coup_v3` binds `rows_per_lobe`, `pages_per_barrier_lobe`, and canonical dc full-bank / material-exchange / `exchange_rows` constants; wire format carries the two V3 shape fields |
| Coupled prove ↔ verify schedule | **GO (fix)** | Verify uses `dc::kRCCoupFullBankScheduleEnabled` (matches `RecomputeCoupledPuzzleReference` defaults). Unit tests use `pages_per_barrier_lobe=1` for CI tractability while still exercising full-bank `SelectCoupledBankPageIds`. |
| Layer `m` vs V3 `rows_per_lobe` | **GO (layout)** | `coupled:wrong_m` rejects `layer.m ≠ coup.rows_per_lobe` |
| Fabricated-witness closure (G1–G5 / bank PCS) | **NO-GO (audit)** | Constructions integrated & validated in-tree; external cryptographic audit pending — attack table below records the scaffold-path (`VerifyWinnerProof`) gap evidence |
| Production V3 binding complete | **NO-GO** | Header/template/nonce, packed-bank PCS openings, every page under `bank_root`, exchange re-derive, Extract AIR still incomplete |

## Fabricated-witness policy

Reject at substantive relation IDs (`coupled:*`, `v7:*`, …). Final-digest-only rejects
do not count as sound closure. Mutation-of-honest forges prove transcript integrity only.

## Attack results (scaffold `VerifyWinnerProof`)

| Attack | Result | Relation / OPEN id |
|---|---|---|
| Omitted pages | **PASS (reject)** | `coupled:omitted_page` (or `coupled:layer_order` / `coupled:omitted_barrier`) |
| Duplicated pages | **PASS (reject)** | `coupled:duplicated_layer` (or order / `coupled:page_id`) |
| Wrong M (`rows_per_lobe`) | **PASS (reject)** | `coupled:wrong_m` |
| Cross-version replay | **PASS (reject)** | `v7:version` |
| UnrelatedBankPages | **OPEN** | `OPEN-GKR-BANK` — B unbound to `bank_root` page openings; internally consistent forge still verifies |
| Wrong exchange transcript | **OPEN** | `OPEN-GKR-XCHG` — dc exchange constants are FS-bound, but mix/exchange columns are not re-derived; fabricated Extract I/O still verifies |
| G1 ArbitraryAbFactorization | **OPEN** | `OPEN-GKR-G1` |
| G1/G2 UnrelatedLayerRoots | **OPEN** | `OPEN-GKR-G1G2` |
| G2 FabricatedTraceWires | **OPEN** | `OPEN-GKR-G2` |
| G3 IdenticalFabricatedLookup | **OPEN** | `OPEN-GKR-G3` |
| G3/G4 FabricatedExtractIO | **OPEN** | `OPEN-GKR-G3G4` |

## Required binding (remaining for any future GO)

1. Header/template/nonce  
2. Canonical packed-bank commitment + PCS page openings under `bank_root`  
3. Every selected page + full 1536 coverage (production V3)  
4. Every M=`rows_per_lobe` GEMM claim grounded to bank pages  
5. Accumulation / permutation / exchange / Extract AIR (verifier-defined)  
6. Barrier roots + final digest / target with in-circuit grounding (`v7:ground:*` / `coupled:column_not_grounded`)
