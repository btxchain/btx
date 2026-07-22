# ENC_RC — Arithmetization completeness audit (M7+) — 2026-07-22 (WP-C REVISED)

*Workstream D / WP-C (GKR/FRI/LOOKUP soundness bindings). Does **not** flip arbiter /
raise height. External crypto audit remains **mandatory** before any arbiter
cutover.*

**REVISION 2026-07-22 (WP-C):** arbiter is compile-time hard-disabled
(`kRCGkrFormalSoundnessReady=false` ⇒ `EnvRCGkrArbiterEnabled` ignores
`BTX_RC_GKR_ARBITER`). Composed bound writeup:
`doc/btx-matmul-v4.5-v7-composed-soundness-bound-2026-07-22.md` (v7 batched ≈ **65.7
bits** post-grind — clears 64 with <1 bit margin under batched FRI + dual-OOD +
dual-α). Prior "G1–G5 CLOSED" claims remain **reverted**.

**REVISION 2026-07-21 (WS-D):** prior "G1–G5 CLOSED (proof v7 + forge suite)"
claims are **reverted**. The `gkr_forge_*` suite only mutates honest proofs
(transcript integrity). Formal target remains
`doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md`. ExactReplay is
the sole consensus authority.

## Gap status (honest)

| ID | Status | Missing relation (exact) |
|---|---|---|
| **G1** | **OPEN/PARKED** | Succinct PCS opening of `a_fri`/`b_fri` at the sumcheck point unbound. Layer `a_root`/`b_root` FS-absorbed but not tied to global FRI segments. |
| **G2** | **OPEN/PARKED** | Layer `claim`/`y_root` not opened against `trace_fri` segment at `(ri,rj)` under PCS. |
| **G3** | **OPEN/PARKED** | Haböck vacuity without verifier-defined Extract AIR + fixed preprocessed tables (construction §5). |
| **G4** | **OPEN/PARKED** | `extract_out_commit` is FS-chained only; no column wiring / tile-tree AIR. |
| **G5** | **OPEN/PARKED** | `acc_claim = claim + residual_mle` algebraic only; residual column not wired to committed X. |
| **Coupled** | **OPEN/PARKED** | Page matrices unbound to `bank_root` openings under succinct PCS. |
| **DEEP/OOD** | **CLOSED (FRI)** | Quotient openings + identity at query sites (FRI v4). Does **not** close G1–G5. |
| **DoS limits** | **DONE** | Hard caps: proof bytes (32 MiB), layer count, sumcheck rounds, FRI depth/queries/coeffs/nested DEEP — reject before expensive work. Soft budget remains 3 MiB (over_budget → ExactReplay). |

## v7 grounding vs succinct CLOSED

| Path | Independent malicious constructors | Meaning |
|---|---|---|
| `VerifyWinnerProof` (scaffold / non-grounded) | May **ACCEPT** fabricated-witness forges | Gap evidence for G1–G5 succinct bindings |
| `VerifyWinnerProofV7` / Coupled V7 | **REJECT** via native re-derivation against the int64 reference | Sound by **grounding**, not by a compact in-circuit AIR |
| Consensus | ExactReplay only | Arbiter hard-disabled; heights `INT32_MAX` |

Mark G1–G5 **CLOSED** only when each corresponding independent constructor is
**REJECTED under PCS openings + verifier-defined Extract** (construction doc
§2–§5) — grounding rejects do **not** count as succinct CLOSED.

Ship parameters g=40 / Fp2 / blowup=16 / Q=116 remain the Stage-I FRI budget.
v7 composed: ≈ 65.7 bits post-grind under batched + dual-OOD + dual-α
(legacy 7-instance ≈ 63; single-OOD ≈ 59.6; single-α as low as ≈ 45).

## Verdict

Under-constraint gaps **G1–G5 are OPEN/PARKED**. v7 defeats independent
malicious constructors by **grounding**, not by a succinct SNARK. **Do not**
claim production succinct soundness. **Independent human crypto audit** remains
before any arbiter cutover. ExactReplay stays consensus. Do **not** raise
`nMatMulRCHeight`. Do **not** enable arbiter (`kRCGkrFormalSoundnessReady`
stays `false`).
