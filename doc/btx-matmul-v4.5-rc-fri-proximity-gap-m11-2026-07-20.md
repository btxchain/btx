# ENC_RC FRI — list-decoding / proximity-gap option (M11) — 2026-07-20

> **Corrected 2026-07-22 (v4.6):** superseded figures updated to the shipped Q=128/Fp2 ≈71.9-bit bound and V3-production default; see doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md.

*Optional efficiency. Unique decoding **Q=128** (k=40/Fp2/blowup-16) is
the **shipped default** (M6; the earlier Q=116 configuration was rejected as
inadequate). `nMatMulRCHeight = INT32_MAX`.*

*v7 composed budget (batched FRI + dual-OOD + dual-α): see
`doc/btx-matmul-v4.5-v7-composed-soundness-bound-2026-07-22.md` — ≈ **71.9 bits**
post-grind at Q=128, FS-dominated (clears 64 with ≈ 7.9-bit margin). Arbiter
hard-disabled (`kRCGkrFormalSoundnessReady=false`); the G1–G5 constructions are
integrated and validated in-tree, with the external cryptographic audit as the
residual gate.*

## Motivation

Shipped unique-decoding uses **Q=128** at ρ=1/16, g=40 (76.80 bits net; Q=116's
65.85 left the composed bound at ≈65.7 with <2 bits of margin and was rejected).
BCIKS20 proximity gaps can reduce QUERY iterations when field/domain hypotheses hold.

## Proven theorem (not conjecture)

**BCIKS20**, ePrint [2020/654](https://eprint.iacr.org/2020/654): for \(q\gg n^2\),

\[
t \;\approx\; \frac{2\lambda}{\log(1/\rho)}.
\]

With \(\lambda_{\mathrm{pre}}=65+g=105\), \(\rho=1/16\):

\[
t \approx 2\cdot 105 / 4 = 52.5 \;\Rightarrow\; \texttt{kRCFriNumQueriesBciKs20Optional}=53.
\]

**Not shipped** — `FriCommitAndFold` uses the unique-decoding default Q=128.

## Adopt only if

1. Auditor confirms BCIKS20 hypotheses for Goldilocks² LDE.
2. Composed bound + `FriSoundnessBoundBits()` updated to match.
3. Unique-decoding profile remains available.

## Verdict

**Keep Q=128 unique-decoding default.** M11 is how we might beat 128 later —
the conservative proven bound was deliberately used for the number to ship *now*.
