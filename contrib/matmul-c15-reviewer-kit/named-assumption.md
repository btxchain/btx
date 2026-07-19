# Named assumption pointer — `BTX-C15-NonCollapse-v1`

**C-15 remains OPEN.** Do not treat this kit, green goldens, or low toy R² as
cryptographic closure or permission to raise `nMatMulDRLTHeight`.

## Where to read

Full formalization (game, parameter pin, non-PRF paragraph, attack-surface
checklist, witness ≠ proof):

→ **[`doc/btx-matmul-v4.4-lt-external-c15-packet.md` §0.2](../../doc/btx-matmul-v4.4-lt-external-c15-packet.md)**  
→ Falsifiable cost-model game (identical base): **§0.1** of the same packet

## One-line statement

No classical PPT adversary wins the §0.1 half-cost / `ε=2⁻⁴⁰` game against
normative ChaCha20-PRF MatExpand Extract + deep-`m` sketch/combine.

## What this is / is not

| Is | Is not |
|---|---|
| A **named, unreduced** work-binding assumption for firm SOW | A theorem |
| Aligned with packet FAIL/PASS/INCONCLUSIVE | A reduction to ChaCha20-PRF alone |
| The target behind C15-A/B/C + I1′ / batch surfaces | Permission to activate Rank-1 |

## Kit vs assumption

- `reference_extract.py` / `test-vectors.json` — reproduce normative Extract
- `toy_attack_harness.py --degree 3` — smoke affine / deg-1..3 collapse at toy `n`
- `reduction-attack-checklist.md` — firm attacks mapped to §0.1 FAIL
- In-tree `matmul_v4_lt_tests` — denser **witnesses** (optional node build)

All of the above are **witnesses**. Breaking (or carefully ruling out) the
§0.2 checklist is the firm’s job.
