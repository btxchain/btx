> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# C-15 dual-panel pre-review synthesis (2026-07-19)

> **Lever-B supersession note (2026-07-20).** The panel reviewed the historical
> `w=128`, per-cell `MANT`/`SCLE` extractor. Current consensus code uses
> `w=1024`, so `rank(B32)≤min(n,1024)` and the production raw panel ratio is
> `n/w=4`, not 30–32×. It also uses real 32-value MX tiles salted by `(i,bj)`,
> not independent per-cell streams. Results below are historical evidence, not
> review of the current extractor. C-15 remains OPEN.

*Grok panel:* `/tmp/c15_audit_synthesis_grok.md` + six lens notes
`/tmp/c15_audit_{algebraic,prf_statistical,shortcut_tmto,lattice_spectral,protocol_specgap,prior_art}.md`.  
*Opus panel (separate machine):* six independent cryptanalytic lenses; convergent
payload folded below. **Both panels: no concrete break; C-15 OPEN; activation NO-GO.**  
*Do not claim C-15 cryptographically closed. Public activation remains inert (`INT32_MAX`).*

Companion packet (hardened after this synthesis):
`doc/btx-matmul-v4.4-lt-external-c15-packet.md`.  
Reviewer kit: `contrib/matmul-c15-reviewer-kit/`.

## Cross-panel consensus

| Question | Consensus |
|---|---|
| Raise `nMatMulDRLTHeight`? | **NO-GO** — all panels (Grok + Opus) |
| Affine / low-degree Extract surrogates (C15-A)? | **PASS on dense samples** (algebraic + PRF empirics); not a proof |
| Linear Freivalds rewrite through `GWH` (C15-B)? | **PASS for linear class**; **INCONCLUSIVE** for unrestricted adversaries |
| Leftover Extract structure (C15-C)? | **Residue documented**; no PoW shortcut shown |
| ChaCha-as-PRF ⇒ MatExpand work-binding? | **Does not reduce** — novel no-shortcut conjecture (prior-art) |
| Packet firm-ready (pre-harden)? | Pre-harden **No**; post-harden packet has §0.1 game + kit — still needs a human firm |
| Current rank-≤1024 pre-Extract core? | Real and **load-bearing**: without Extract, L1 panel collapse returns (~4× at production); historical panel measured rank-128 / ~30–32× |

### Three pillars (both panels)

1. Position-salted per-cell PRF (`(i,j)` in ChaCha nonce) — load-bearing rank-lift.
2. Exact `𝔽_q` binding — approximation / surrogates worthless under Freivalds.
3. Nonce-fresh `W_B` entering twice nonlinearly — blocks TMTO / cross-nonce amortization.

## Panel one-liners

1. **Algebraic** — Extract not affine/low-degree on dense samples; linear `Ĉ→G,W,H` rewrite blocked; unrestricted class open.
2. **PRF/statistical** — Ideal Extract has 23-value alphabet (TV≈0.76 vs uniform by design); `P(0)=1/11≈9.1%` under IdealExtract; cross-lane `Mant(raw)=Scale(raw⊕Δ)` related-nonce; μ′↔e lock when first nibble accepts; no Freivalds/GEMM skip.
3. **Shortcut/TMTO** — Extract **necessary** vs affine fold; **sufficiency unproven**; Q* Phase A does not bind fat windows; Phase B inert. MatExpand is `O(n²·w)`; deep-m sketch/combine is the cubic floor.
4. **Lattice/spectral** — current `rank(B32)≤min(n,1024)` unconditional; MX tile-salted ChaCha plausibly kills shared-φ spectral residue; `U`/`V` rank-transparent; W-space `1024n` is honest work, not an attack win. The panel's rank-128 result is historical.
5. **Protocol/spec-gap** — Assumption under-formalized (addressed in packet §0.1 harden); tests are witnesses not proofs; goldens thin; leap-checklist HeaderPoW row was stale (bit-26 withdrawn); activation-tangled with HeaderPoW NO-GO.
6. **Prior-art** — Closest class: Pearl/cuPOW transcript unpredictability; MatExpand+Extract+Freivalds is **novel encoding risk**.

## Highest-priority firm deliverables

1. Formal C-15 game (adversary class, cost, ε, FAIL/PASS) — **drafted in packet §0.1**.
2. Oracle pack + expand goldens (keystream/remix/`n=4096`).
3. Human review of cross-lane related-nonce for any amortization beyond per-cell ChaCha.
4. Degree / approximate-`B̂` Freivalds forgery analysis (algebraic next steps).
5. Keep activation inert until firm C15 PASS **and** silicon/tip-soak/HeaderPoW gates separately.

## Dual-track note

Opus six-lens pre-review (separate machine) **arrived and agreed** with the Grok
panel on verdict, pillars, and the actionable harden list (falsifiable claim,
C15-B LS collapse + deg-2/3 R², rank-128 docs, reviewer kit, encoding pin,
full-width position salt, scoping / LT-Q1–Q2 labels). Residual disagreements to
watch in a firm review: cross-lane related-nonce amortization depth; Strassen /
FMM calibration of ASERT vs naive GEMM
(`doc/btx-matmul-v4.4-lt-c15-asert-fmm-calibration-2026-07-19.md`).

## Shipped hardenings (post-synthesis)

| Gap | Status |
|---|---|
| Falsifiable §0.1 cost-model game | Packet |
| C15-B LS surrogate + deg≤3 R²<0.05 | `matexpand_c15b_*` / `matexpand_extract_r2_*` |
| Rank-128 / encoding / pillars | Packet §1.1–§1.4 |
| Reviewer kit | `contrib/matmul-c15-reviewer-kit/` |
| Full-width `(i,j)` salt | CPU/CUDA/HIP + AccelReplica + high-half test |
| LT-Q1/Q2 “review pending”; P(0)≈9.1%; MatExpand `O(n²·w)` | Docs + lt-gate G5 wording |

## Reduction research status (2026-07-19)

Wave-1 reduction mapping is **folded** — see the index:

→ **`doc/btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md`**

That fold indexes fine-grained + crypto/PoW surveys, obstruction notes,
reduction sketches (explicit GAP lists), ASERT/FMM calibration split, and
related-nonce ExtractStruct residue. **No reduction** of LT-C15 / MatExpand
non-collapse to a standard named problem (SETH, OV, APSP, 3SUM, KW secret
low-rank, ChaCha20-PRF alone, Freivalds soundness, …) is claimed or completed.
C-15 remains **OPEN**.

What *is* formalized: novel unreduced assumption **`BTX-C15-NonCollapse-v1`**
in packet §0.2 (game = §0.1; witness ≠ proof), aliased as
`BTX-MatExpand-NonCollapse-v1` / MENC family in Wave-1 drafts. Reviewer
pointer: `contrib/matmul-c15-reviewer-kit/named-assumption.md`.

Wave 3 Gap #2 fragment (DRAFT, not a theorem): **`Extract-Nonlinearity-v1`**
+ MatExpand nonce-packing PRF hybrid outline, related-nonce → ExtractStruct —
`doc/btx-matmul-v4.4-lt-c15-extract-nonlinearity-v1-2026-07-19.md`. Does **not**
close C-15.

## Explicit non-claims

- C-15 closed
- Finite public `nMatMulDRLTHeight`
- ChaCha-PRF alone as a MatExpand MAC lower bound
- Reduction of `BTX-C15-NonCollapse-v1` to any classical / fine-grained named conjecture
