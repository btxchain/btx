# ENC_RC FRI — list-decoding / proximity-gap option (M11) — 2026-07-20

*Optional efficiency. Unique decoding **Q=116** (Fable k=40/Fp2/blowup-16) remains
the **shipped default** (M6). `nMatMulRCHeight = INT32_MAX`.*

*v7 composed budget (batched FRI + dual-OOD + dual-α): see
`doc/btx-matmul-v4.5-v7-composed-soundness-bound-2026-07-22.md` — ≈ **65.7 bits**
post-grind (clears 64 with <1 bit margin). Arbiter hard-disabled
(`kRCGkrFormalSoundnessReady=false`); G1–G5 remain OPEN/PARKED.*

## Motivation

Shipped unique-decoding needs **Q=116** at ρ=1/16, g=40 for ≥64 bits net.
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

**Not shipped** — `FriCommitAndFold` still uses Q=116.

## Adopt only if

1. Auditor confirms BCIKS20 hypotheses for Goldilocks² LDE.
2. Composed bound + `FriSoundnessBoundBits()` updated to match.
3. Unique-decoding profile remains available.

## Verdict

**Keep Q=116 unique-decoding default.** M11 is how we might beat 116 later —
Fable deliberately used the conservative proven bound for the number to ship *now*.
