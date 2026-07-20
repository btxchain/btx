# ENC_RC — Arithmetization completeness audit (M7+) — 2026-07-21

*Updated after DEEP/OOD + G1–G5 + Haböck G3 (proof v6 / FRI v3).
Companion: emulated audit `doc/btx-matmul-v4.5-rc-crypto-audit-emulated-2026-07-21.md`.
**Does not** flip arbiter / raise height.*

## Gap status

| ID | Status | Close |
|---|---|---|
| **G1** | **CLOSED (scaffold)** | `a_fri`/`b_fri` + layer `a_root`/`b_root`; commit-then-challenge |
| **G2** | **CLOSED (scaffold)** | `trace_fri`+DEEP before `(ri,rj)`; claims FS-bound to roots |
| **G3** | **CLOSED (scaffold)** | Haböck LogUp (ePrint 2022/1530): witness keys ≡ virtual Extract-table keys (FRI root/DEEP); α←FS; `inv_i=1/(α−t_i)`; `I(1)=Σ inv` via forced DEEP at z=1; `R_i=inv_i·(α−t_i)−1` ≡0 |
| **G4** | **CLOSED (scaffold)** | `extract_out_commit` chain across layers |
| **G5** | **CLOSED** | `acc_claim = claim + residual_mle` enforced; non-Fwd residual=0 |
| **DEEP/OOD** | **CLOSED (FRI)** | Quotient openings + identity at query sites |

## Decision (Fable)

Ship **g=40 / Fp2 / blowup=16 / Q=116**. Fp3 unbuilt (g≥64 lever only).

## Verdict

Under-constraint gaps G1–G5 are closed at scaffold strength (proof v6).
**Independent human crypto audit** remains before any arbiter cutover.
ExactReplay stays consensus.
