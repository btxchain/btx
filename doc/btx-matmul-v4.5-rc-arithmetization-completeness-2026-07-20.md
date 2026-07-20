# ENC_RC — Arithmetization completeness audit (M7+) — 2026-07-21

*Updated after DEEP/OOD + G1–G5 code closes (proof v5 / FRI v3).
Companion: emulated audit `doc/btx-matmul-v4.5-rc-crypto-audit-emulated-2026-07-21.md`.
**Does not** flip arbiter / raise height.*

## Gap status

| ID | Status | Close |
|---|---|---|
| **G1** | **CLOSED (scaffold)** | `a_fri`/`b_fri` + layer `a_root`/`b_root`; commit-then-challenge |
| **G2** | **CLOSED (scaffold)** | `trace_fri`+DEEP before `(ri,rj)`; claims FS-bound to roots |
| **G3** | **PARTIAL** | LogUp keys FRI+DEEP + `(in,out)` hash; full Haböck table IOP still open |
| **G4** | **CLOSED (scaffold)** | `extract_out_commit` chain across layers |
| **G5** | **CLOSED** | `acc_claim = claim + residual_mle` enforced; non-Fwd residual=0 |
| **DEEP/OOD** | **CLOSED (FRI)** | Quotient openings + identity at query sites |

## Decision (Fable)

Ship **g=40 / Fp2 / blowup=16 / Q=116**. Fp3 unbuilt (g≥64 lever only).

## Verdict

Under-constraint gaps that blocked a responsible shadow harden are closed or
partially closed as above. **G3 Haböck completeness** and external audit remain
before any arbiter cutover. ExactReplay stays consensus.
