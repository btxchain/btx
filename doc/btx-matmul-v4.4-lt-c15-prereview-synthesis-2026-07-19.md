# C-15 dual-panel pre-review synthesis (2026-07-19)

*Folded from `/tmp/c15_audit_synthesis_grok.md` (Grok panel synthesis).*  
*Sources: `/tmp/c15_audit_{algebraic,prf_statistical,shortcut_tmto,lattice_spectral,protocol_specgap,prior_art}.md`.*  
*Do not claim C-15 cryptographically closed. Public activation remains inert (`INT32_MAX`).*

Companion packet (hardened after this synthesis):
`doc/btx-matmul-v4.4-lt-external-c15-packet.md`.

## Cross-panel consensus

| Question | Consensus |
|---|---|
| Raise `nMatMulDRLTHeight`? | **NO-GO** — all panels |
| Affine / low-degree Extract surrogates (C15-A)? | **PASS on dense samples** (algebraic + PRF empirics); not a proof |
| Linear Freivalds rewrite through `GWH` (C15-B)? | **PASS for linear class**; **INCONCLUSIVE** for unrestricted adversaries |
| Leftover Extract structure (C15-C)? | **Residue documented**; no PoW shortcut shown |
| ChaCha-as-PRF ⇒ MatExpand work-binding? | **Does not reduce** — novel no-shortcut conjecture (prior-art) |
| Packet firm-ready (pre-harden)? | **No** (~58/100) — needed security game, oracles, FAIL criteria |
| Rank-128 pre-Extract core? | Real and **load-bearing**: without Extract, L1 thin-panel collapse returns (~30–32×) |

## Panel one-liners

1. **Algebraic** — Extract not affine/low-degree on dense samples; linear `Ĉ→G,W,H` rewrite blocked; unrestricted class open.
2. **PRF/statistical** — Ideal Extract has 23-value alphabet (TV≈0.76 vs uniform by design); `P(0)=1/11≈9.1%` under IdealExtract; cross-lane `Mant(raw)=Scale(raw⊕Δ)` related-nonce; μ′↔e lock when first nibble accepts; no Freivalds/GEMM skip.
3. **Shortcut/TMTO** — Extract **necessary** vs affine fold; **sufficiency unproven**; Q* Phase A does not bind fat windows; Phase B inert. MatExpand is `O(n²·w)`; deep-m sketch/combine is the cubic floor.
4. **Lattice/spectral** — `rank(B32)≤128` unconditional; position-salted ChaCha plausibly kills shared-φ spectral residue; `U`/`V` rank-transparent; W-space `128n` is honest work, not an attack win.
5. **Protocol/spec-gap** — Assumption under-formalized (addressed in packet §0.1 harden); tests are witnesses not proofs; goldens thin; leap-checklist HeaderPoW row was stale (bit-26 withdrawn); activation-tangled with HeaderPoW NO-GO.
6. **Prior-art** — Closest class: Pearl/cuPOW transcript unpredictability; MatExpand+Extract+Freivalds is **novel encoding risk**.

## Highest-priority firm deliverables

1. Formal C-15 game (adversary class, cost, ε, FAIL/PASS) — **drafted in packet §0.1**.
2. Oracle pack + expand goldens (keystream/remix/`n=4096`).
3. Human review of cross-lane related-nonce for any amortization beyond per-cell ChaCha.
4. Degree / approximate-`B̂` Freivalds forgery analysis (algebraic next steps).
5. Keep activation inert until firm C15 PASS **and** silicon/tip-soak/HeaderPoW gates separately.

## Dual-track note

Six Opus agents on another machine were intended to run the same six disciplines.
When Opus reports arrive, diff: agreements strengthen confidence; contradictions
become the next experiment list. This fold is the **Grok-panel** synthesis only.

## Explicit non-claims

- C-15 closed
- Finite public `nMatMulDRLTHeight`
- ChaCha-PRF alone as a MatExpand MAC lower bound
