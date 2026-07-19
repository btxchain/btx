# Spectral / approx-`B̂` probe note (C-15 Gap #6)

**Status: C-15 OPEN** — empirical kit aid, not a security proof and **not** a
packet §0.1 verdict.

## What this is

`spectral_approx_probe.py` is a **stdlib-only** SVD / CCA-style residual
campaign against normative Lever-B MX-block Extract on toy MatExpand
accumulators for `n ∈ {32, 64}` (override with `--n`). Every input dimension
must be a multiple of 32; each probe passes the real adjacent 32-value `B32`
tile to Extract, matching consensus rejection-sampling alignment.

For each `n` it reports:

| Metric | Meaning |
|---|---|
| `rank(B32)` | Modular rank of synthetic `(G·W)·H` (expect `≤ w`) |
| top-`w` energy | Fraction of `‖B̂‖_F²` in the largest `w` singular values |
| `CCA_max` | cos(θ_min) between col(`B32`) and top-`w` left singular subspace of `B̂` |
| rel. Frobenius | `‖B̂ − P_col(B32) B̂ P_row(B32)‖_F / ‖B̂‖_F` |
| Freivalds zeros | How often `rᵀ(B̂−B̂')s = 0` for the structured approx `B̂'` |

Honest MX-block Extract is expected to **reject** near-perfect B32-space
collapse (energy not locked in top-`w`, CCA well below 1, nonzero Freivalds
residuals on the structured approx). That matches checklist **A5** /
drafts **GAP-B3** (high-rank yet still forgery-friendly approx-`B̂`).

## Hard rule — empirics ≠ FAIL ≠ closed

> **A concrete win against packet §0.1 cost thresholds is required to claim
> FAIL.** Toy SVD/CCA residuals, smoke `PASS`/`FAIL`, or “looks collapsed on
> `n=32`” alone do **not** close C-15 and must not be filed as a reduction
> or as Rank-1 GO.

Map any interesting residue through
[`reduction-attack-checklist.md`](reduction-attack-checklist.md) **A5** and
cost it against `HonestMAC(n)` in
[`doc/btx-matmul-v4.4-lt-external-c15-packet.md`](../../doc/btx-matmul-v4.4-lt-external-c15-packet.md)
**§0.1**. Alphabet concentration or distinguisher-only structure without a
MAC shortcut → **INCONCLUSIVE** / non-finding.

## Smoke

```bash
cd contrib/matmul-c15-reviewer-kit
python3 spectral_approx_probe.py
python3 spectral_approx_probe.py --n 32 64 --w 4 --seed 1
```

Companion: [`rank_spectral_regression.md`](rank_spectral_regression.md)
(`rank(B32) ≤ w` only). Poly R² / Freivalds on entrywise surrogates remain in
`toy_attack_harness.py`.

## Explicit non-claims

- C-15 cryptographically closed — **NO**
- §0.1 PASS/FAIL from this probe alone — **NO**
- Production `n=4096` spectral bound — **NO**
- Height raise / Rank-1 GO — **NO**
