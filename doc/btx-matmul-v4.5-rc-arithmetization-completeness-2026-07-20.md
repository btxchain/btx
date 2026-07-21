# ENC_RC — Arithmetization completeness audit (M7+) — 2026-07-21 (REVISED)

*Updated after DEEP/OOD + Haböck LogUp scaffold work (proof v6 / FRI v3).
Companion: emulated audit `doc/btx-matmul-v4.5-rc-crypto-audit-emulated-2026-07-21.md`.
**Does not** flip arbiter / raise height.*

**REVISION 2026-07-21 (WS2):** the previous revision of this file marked G1–G5
"CLOSED (scaffold)". A rigorous re-derivation
(`doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md`, with companion
`doc/btx-matmul-v4.5-rc-gkr-soundness-table-2026-07-21.md`) shows those claims were
**overstated**: the v6 checks are format-complete but carry **zero soundness** against a
Byzantine prover (Forgery F0: grind arbitrary `round_roots` to target, fabricate
self-consistent wires, accepted with probability 1 and no episode work). The table below
is the honest status. ExactReplay remains the sole consensus authority.

## Gap status (honest)

| ID | Status | Reality |
|---|---|---|
| **G1** | **OPEN (construction specified)** | `a_fri`/`b_fri` are committed but **never opened**; `a_root`/`b_root` absorbed, never opened; `final_eval` unbound to any commitment (Forgeries F1–F4). Sound fix: batched-FRI + dual-OOD evaluation argument binding `final_eval = Ã(r_i,r_k)·B̃(r_k,r_j)` — construction §2–3, Theorem 3.1. |
| **G2** | **OPEN (construction specified)** | `trace_fri` DEEP at one unrelated point does not bind per-layer `claim` (prover-supplied, Forgery F5); round_roots not bound to committed columns (Forgery F0). Fix: layout-driven wiring + tile-tree SHA AIR — construction §4, §6.3, Theorem 4.1. |
| **G3** | **OPEN (construction specified)** | Witness ≡ table root equality is vacuous: both prover-computed (Theorem 5.1 — rejection probability of a forged Extract witness is 0). Extract is a keyed PRF map, not a fixed table. Sound fix: in-circuit ChaCha20+SHA-256 AIR + preprocessed-table LogUp with **dual-α over Fp2** (single α provably insufficient: 45 bits post-grinding) — construction §5, Theorem 5.2. |
| **G4** | **PARTIAL** | `extract_out_commit` chain orders prover data in FS but binds it to nothing committed; superseded by §4/§6.3 wiring. |
| **G5** | **CLOSED (given G1–G3)** | `acc_claim = claim + residual_mle` is a sound algebraic link **only once** claim/residual are themselves bound (construction §4.2); standalone it constrains prover-supplied values only. |
| **DEEP/OOD** | **PARTIAL** | Quotient openings are real, but a **single** OOD point over Fp2 caps column degree at 2^24 (post-grinding 64-bit target); consensus columns reach 2^28 → dual-OOD required (soundness table). |
| **FRI layout** | **NEW FINDING** | 7 separate FRI instances union-bound to 2^-63.05 < 2^-64 target → single batched instance (or Q ≥ 128) required. Also: Goldilocks 2-adicity caps columns at 2^28 coeffs; the current single concatenated trace vector cannot run at consensus dims. |
>>>>>>> 5859d72 (doc(ENC_RC): WS2 rigorous GKR arithmetization construction + honest G1-G5 revert)

## Decision (Fable) — updated

Ship parameters g=40 / Fp2 / blowup=16 / Q=116 remain adequate **for the specified
construction** (composed bound ≈ 2^-65.7, Theorem 8.1) under three mandatory changes:
single batched FRI, dual-OOD, dual-α LogUp. Fp3 (x³−7, well-defined; unbuilt) is forced
only if single-challenge LogUp/OOD is insisted upon. Q=128 recommended for margin.

## Verdict

Under-constraint gaps G1–G3 are **not closed** in proof v6 and **block the GKR arbiter**;
complete sound constructions with soundness theorems now exist on paper (WS2 document) and
await implementation (blueprint §10 there) plus **independent human crypto audit** before
any arbiter cutover. Scaffold / Haböck work does not close PCS completeness.
ExactReplay stays consensus. Do **not** raise `nMatMulRCHeight` (stays INT32_MAX).
Do **not** enable `BTX_RC_GKR_ARBITER`.
