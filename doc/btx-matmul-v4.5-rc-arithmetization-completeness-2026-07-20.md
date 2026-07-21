# ENC_RC — Arithmetization completeness audit (M7+) — 2026-07-21

*Updated after DEEP/OOD + Haböck LogUp scaffold work (proof v6 / FRI v3).
Companion: emulated audit `doc/btx-matmul-v4.5-rc-crypto-audit-emulated-2026-07-21.md`.
**Does not** flip arbiter / raise height.*

## Gap status

| ID | Status | Notes |
|---|---|---|
| **G1** | **OPEN** (scaffold only) | `a_fri`/`b_fri` + layer `a_root`/`b_root`; commit-then-challenge — A/B PCS completeness still open |
| **G2** | **OPEN** (scaffold only) | `trace_fri`+DEEP before `(ri,rj)`; claims FS-bound to roots — claim↔trace MLE PCS still open |
| **G3** | **OPEN** (scaffold only) | Haböck LogUp scaffold (virtual Extract-table keys); Extract-table PCS binding still open |
| **G4** | **OPEN** (scaffold only) | `extract_out_commit` chain across layers — algebraic equality inside PCS still open |
| **G5** | **OPEN** (scaffold only) | `acc_claim = claim + residual_mle` enforced in verifier; composition audit still open |
| **DEEP/OOD** | **scaffold (FRI)** | Quotient openings + identity at query sites — not a substitute for closed PCS |

Code pointer (`VerifyWinnerProof`): **OPEN gaps (A/B PCS, claim↔trace MLE, Extract table)** remain; see `matmul_v4_rc_gkr.h`.

## Decision (Fable)

Ship **g=40 / Fp2 / blowup=16 / Q=116**. Fp3 unbuilt (g≥64 lever only).

## Verdict

Under-constraint gaps **G1–G5 remain OPEN** and **block the GKR arbiter**.
Scaffold / Haböck work does not close PCS completeness.
**Independent human crypto audit** remains before any arbiter cutover.
ExactReplay stays consensus. Do **not** raise `nMatMulRCHeight`. Do **not** enable `BTX_RC_GKR_ARBITER`.
