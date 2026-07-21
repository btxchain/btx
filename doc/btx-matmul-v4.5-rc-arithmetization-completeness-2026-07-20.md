# ENC_RC — Arithmetization completeness audit (M7+) — 2026-07-21 (WS-D REVISED)

*Workstream D (GKR/FRI/LOOKUP soundness bindings). Does **not** flip arbiter /
raise height. External crypto audit remains **mandatory** before any arbiter
cutover.*

**REVISION 2026-07-21 (WS-D):** prior "G1–G5 CLOSED (proof v7 + forge suite)"
claims are **reverted**. The `gkr_forge_*` suite only mutates honest proofs
(transcript integrity). Independent malicious constructors
(`ProveIndepMalicious*ForTest`) currently **ACCEPT**, demonstrating the gaps
below. Formal target remains
`doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md`. ExactReplay is
the sole consensus authority. `BTX_RC_GKR_ARBITER` stays OFF.

## Gap status (honest)

| ID | Status | Missing relation (exact) |
|---|---|---|
| **G1** | **OPEN/PARKED** | `a_at_r`/`b_at_r` checked only via `a*b=final_eval`; **no** verifier PCS opening of `a_fri`/`b_fri` at the sumcheck point. Layer `a_root`/`b_root` absorbed into FS but **unbound** to global FRI. Indep: `ArbitraryAbFactorization`, `UnrelatedLayerRoots` ACCEPT. |
| **G2** | **OPEN/PARKED** | Layer `claim`/`y_root` not opened against `trace_fri` segment at `(ri,rj)`. Fabricated A/B/Y consistent with sumcheck+FRI self-verify. Indep: `FabricatedTraceWires` ACCEPT. |
| **G3** | **OPEN/PARKED** | Haböck check is `lookup_fri.root == table_fri.root` — prover manufactures both (Theorem 5.1 vacuity). Need verifier-defined Extract AIR + fixed preprocessed tables (construction §5). Indep: `IdenticalFabricatedLookup`, `FabricatedExtractIO` ACCEPT. |
| **G4** | **OPEN/PARKED** | `extract_out_commit` is FS-chained only; no column wiring / tile-tree AIR to committed extract_out. |
| **G5** | **OPEN/PARKED** | `acc_claim = claim + residual_mle` is algebraic only; residual column not wired to committed X. |
| **Coupled** | **OPEN/PARKED** | Format uses real lobe-GEMM + barrier-Extract transcripts, but page matrices unbound to `bank_root` openings. Indep: `UnrelatedBankPages` ACCEPT. |
| **DEEP/OOD** | **CLOSED (FRI)** | Quotient openings + identity at query sites (FRI v4). Does **not** close G1–G5. |
| **DoS limits** | **DONE** | Hard caps: proof bytes (32 MiB), layer count, sumcheck rounds, FRI depth/queries/coeffs/nested DEEP — reject before expensive work. Soft budget remains 3 MiB (over_budget → ExactReplay). |

## Mutation forge suite (transcript integrity ONLY — not G1–G5 closure)

| Forge | Test | Meaning |
|---|---|---|
| Bit-flip fields on honest proof | `gkr_forge_*` / `gkr_m7_*` | FS/transcript rejects tampering of an otherwise-honest proof |

## Independent malicious constructors (gap evidence)

| Kind | API | Expected until bindings land |
|---|---|---|
| Arbitrary A/B factorization | `ArbitraryAbFactorization` | **ACCEPT** |
| Unrelated layer roots | `UnrelatedLayerRoots` | **ACCEPT** |
| Fabricated trace wires | `FabricatedTraceWires` | **ACCEPT** |
| Identical fabricated lookup | `IdenticalFabricatedLookup` | **ACCEPT** |
| Fabricated Extract I/O | `FabricatedExtractIO` | **ACCEPT** |
| Unrelated bank pages | `UnrelatedBankPages` | **ACCEPT** |

Mark CLOSED only when each corresponding independent constructor is **REJECTED**
under PCS openings + verifier-defined Extract (construction doc §2–§5).

Ship parameters g=40 / Fp2 / blowup=16 / Q=116 remain the Stage-I FRI budget.

## Verdict

Under-constraint gaps **G1–G5 are OPEN/PARKED**. Verifier remains a succinct
scaffold; **do not** claim production soundness. **Independent human crypto
audit** remains before any arbiter cutover. ExactReplay stays consensus. Do
**not** raise `nMatMulRCHeight`. Do **not** enable `BTX_RC_GKR_ARBITER`.
