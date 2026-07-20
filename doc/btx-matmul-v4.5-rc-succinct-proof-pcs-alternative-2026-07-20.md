# ENC_RC succinct proof — PCS alternative note (2026-07-20)

*Flag for the owner — not a decision. `nMatMulRCHeight = INT32_MAX`.*

## Question

Rather than hand-rolling production FRI (M1 on tip `7489f8e`+), should ENC_RC
integrate a vetted transparent STARK / Goldilocks-FRI stack as the polynomial
commitment scheme?

## Candidates (illustrative)

- **Plonky3-style** Goldilocks FRI / STARK toolkit
- **Winterfell-style** STARK prover/verifier core

## Trade

| Hand-rolled FRI (in-tree) | Vetted STARK PCS |
|---|---|
| No new consensus dependency | External dependency / subtree |
| Full control of FS bind to `pow_bind` | Must re-bind transcripts carefully |
| Soundness claim needs owner audit (§3 of soundness note) | Inherit upstream proximity work; still audit binding + circuit |
| Higher ongoing eng cost | Lower eng cost after integration spike |

## Recommendation posture

Keep the in-tree REAL FRI path (M1) as the default shippable scaffold.
If an external audit prefers a named STARK core, swap the PCS behind the same
GKR/LogUp arithmetization and the same shadow/ExactReplay consensus wiring.

Do **not** treat either path as production-complete until Gate M3 audit + M4
silicon cost close.
