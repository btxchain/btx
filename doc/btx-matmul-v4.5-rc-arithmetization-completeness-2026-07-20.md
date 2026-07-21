# ENC_RC — Arithmetization completeness audit (M7+) — 2026-07-21 (REVISED)

*Updated after proof v7: G1–G5 CLOSED with adversarial forge evidence + real
coupled ProveWinnerCoupled. Companion: emulated audit
`doc/btx-matmul-v4.5-rc-crypto-audit-emulated-2026-07-21.md`.
**Does not** flip arbiter / raise height.*

**REVISION 2026-07-21 (WS2):** a prior "CLOSED (scaffold)" claim for G1–G5 was
overstated for proof v6 (Forgery F0 / unbound openings). Companion construction
`doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md` and soundness table
remain the formal target for any future arbiter cutover. **Proof v7** closes the
engineering relations under the forge suite below (commit-then-challenge A/B/Y
roots + openings, Haböck multiplicity, extract chain, residual link, real coupled
transcripts). ExactReplay remains the sole consensus authority.

## Gap status (honest)

| ID | Status | Reality |
|---|---|---|
| **G1** | **CLOSED** | `a_fri`/`b_fri` + layer `a_root`/`b_root`; `a_at_r * b_at_r = final_eval` enforced; forge: `gkr_forge_a_root_rejects`, `gkr_forge_b_root_rejects`, `gkr_forge_ab_opening_rejects` |
| **G2** | **CLOSED** | `trace_fri`+DEEP before `(ri,rj)`; per-layer `y_root` absorbed; forge: `gkr_forge_trace_opening_rejects` |
| **G3** | **CLOSED** | Haböck LogUp + multiplicity=1 (unique table keys); forge: `gkr_forge_extract_witness_rejects`, `gkr_forge_table_multiplicity_rejects` |
| **G4** | **CLOSED** | `extract_out_commit` chain across layers (FS-bound); covered by transcript / layer-order forges |
| **G5** | **CLOSED** | `acc_claim = claim + residual_mle`; non-Fwd residual=0; forge: `gkr_m7_g5_residual_tamper_rejects` |
| **Coupled** | **CLOSED** | Real lobe-GEMM + barrier-Extract from `RecomputeCoupledPuzzleReference` transcripts; forge: omitted barrier / page ID |
| **DEEP/OOD** | **CLOSED (FRI)** | Quotient openings + identity at query sites |

## Forge suite (DONE evidence)

Each forgery independently REJECTED (`matmul_v4_rc_gkr_tests`):

| Forge | Test |
|---|---|
| A root | `gkr_forge_a_root_rejects` |
| B root | `gkr_forge_b_root_rejects` |
| A/B opening | `gkr_forge_ab_opening_rejects` |
| final_eval | `gkr_forge_final_eval_rejects` |
| trace opening | `gkr_forge_trace_opening_rejects` |
| Extract witness | `gkr_forge_extract_witness_rejects` |
| table multiplicity | `gkr_forge_table_multiplicity_rejects` |
| layer order | `gkr_forge_layer_order_rejects` |
| repeated layer | `gkr_forge_repeated_layer_rejects` |
| omitted barrier | `gkr_forge_omitted_barrier_rejects` |
| page ID | `gkr_forge_page_id_rejects` |
| sigma | `gkr_forge_sigma_rejects` |
| dims | `gkr_forge_dims_rejects` |
| target | `gkr_forge_target_rejects_under_arbiter` |
| claimed digest | `gkr_forge_claimed_digest_rejects` |

Ship parameters g=40 / Fp2 / blowup=16 / Q=116 remain the Stage-I FRI budget.
Further formal upgrades in the WS2 construction (batched FRI, dual-OOD, dual-α
LogUp) are **not** required to keep ExactReplay as consensus, and do **not**
raise height or enable the arbiter.

## Verdict

Under-constraint gaps **G1–G5 are CLOSED** under the forge suite above (proof v7).
**Independent human crypto audit** remains before any arbiter cutover.
ExactReplay stays consensus. Do **not** raise `nMatMulRCHeight`. Do **not** enable `BTX_RC_GKR_ARBITER`.
