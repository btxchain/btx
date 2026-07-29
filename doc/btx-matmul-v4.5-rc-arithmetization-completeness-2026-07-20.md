> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# ENC_RC — Arithmetization completeness audit (M7+) — 2026-07-22 (WP-C REVISED)

> **Corrected 2026-07-22 (v4.6):** superseded figures updated to the shipped Q=128/Fp2 ≈71.9-bit bound and V3-production default; see doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md.

*Workstream D / WP-C (GKR/FRI/LOOKUP soundness bindings). Does **not** flip arbiter /
raise height. External crypto audit remains **mandatory** before any arbiter
cutover.*

**REVISION 2026-07-22 (WP-C):** arbiter is compile-time hard-disabled
(`kRCGkrFormalSoundnessReady=false` ⇒ `EnvRCGkrArbiterEnabled` ignores
`BTX_RC_GKR_ARBITER`). Composed bound writeup:
`doc/btx-matmul-v4.5-v7-composed-soundness-bound-2026-07-22.md` (v7 batched ≈ **71.9
bits** post-grind at Q=128, FS-dominated — clears 64 with ≈ 7.9-bit margin under
batched FRI + dual-OOD + dual-α; the earlier Q=116 / ≈65.7-bit configuration was
rejected as inadequate). The G1–G5 constructions (I–IV) are now **integrated and
validated in-tree**; the open gate is the **external cryptographic audit** — never
claim CLOSED or audit-passed (validated-in-tree ≠ externally-audited).

**REVISION 2026-07-21 (WS-D):** prior "G1–G5 CLOSED (proof v7 + forge suite)"
claims are **reverted**. The `gkr_forge_*` suite only mutates honest proofs
(transcript integrity). Formal target remains
`doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md`. ExactReplay is
the sole consensus authority.

## Gap status (honest)

| ID | Status | Formerly missing relation (exact; now implemented in-tree) |
|---|---|---|
| **G1** | **INTEGRATED (external audit pending)** | Succinct PCS opening of `a_fri`/`b_fri` at the sumcheck point was unbound. Layer `a_root`/`b_root` FS-absorbed but not tied to global FRI segments. |
| **G2** | **INTEGRATED (external audit pending)** | Layer `claim`/`y_root` was not opened against `trace_fri` segment at `(ri,rj)` under PCS. |
| **G3** | **INTEGRATED (external audit pending)** | Haböck vacuity without verifier-defined Extract AIR + fixed preprocessed tables (construction §5). |
| **G4** | **INTEGRATED (external audit pending)** | `extract_out_commit` was FS-chained only; no column wiring / tile-tree AIR. |
| **G5** | **INTEGRATED (external audit pending)** | `acc_claim = claim + residual_mle` was algebraic only; residual column not wired to committed X. |
| **Coupled** | **INTEGRATED (external audit pending)** | Page matrices were unbound to `bank_root` openings under succinct PCS. |
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

Ship parameters g=40 / Fp2 / blowup=16 / Q=128 are the Stage-I FRI budget
(the earlier Q=116 budget was rejected as inadequate). v7 composed: ≈ 71.9 bits
post-grind, FS-dominated, under batched + dual-OOD + dual-α (rejected Q=116
config ≈ 65.7; legacy 7-instance ≈ 63; single-OOD ≈ 59.6; single-α as low as ≈ 45).

## Verdict

The **G1–G5 constructions are integrated and validated in-tree** (rack/unit
tests pass); the remaining gate is the **external cryptographic audit** — never
claim CLOSED or audit-passed. v7 additionally defeats independent malicious
constructors by **grounding**. **Do not**
claim production succinct soundness ahead of the external audit. **Independent human crypto audit** remains
before any arbiter cutover. ExactReplay stays consensus. Do **not** raise
`nMatMulRCHeight`. Do **not** enable arbiter (`kRCGkrFormalSoundnessReady`
stays `false`).
