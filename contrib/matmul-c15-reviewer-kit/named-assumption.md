# Named assumption pointer — `BTX-C15-NonCollapse-v1`

**C-15 remains OPEN.** Do not treat this kit, green goldens, or low toy R² as
cryptographic closure or permission to raise `nMatMulDRLTHeight`.

> **Aliases (one assumption; class labels)**  
> **Canonical:** `BTX-C15-NonCollapse-v1` (packet §0.2)  
> **Also used in Wave-1 drafts:** `BTX-MatExpand-NonCollapse-v1`, **MENC** (*MatExpand–Extract Non-Collapse*), *LT-C15 Work-Binding*  
> **Class labels (packet §0.1):** **MENC-Lin** (deg≤2 primary FAIL), **MENC-Unres** (unrestricted; Lin PASS ≠ Unres PASS), **MENC-Cubic** (sketch-floor `B̂·V`+combine — **not** MatExpand)  
> Same §0.1 game; labels differ by adversary restriction. Prefer the packet id in firm SOWs.

## Where to read

Full formalization (game, parameter pin, non-PRF paragraph, attack-surface
checklist, witness ≠ proof):

→ **[`doc/btx-matmul-v4.4-lt-external-c15-packet.md` §0.2](../../doc/btx-matmul-v4.4-lt-external-c15-packet.md)**  
→ Falsifiable cost-model game (identical base): **§0.1** of the same packet  
→ Wave-1 reduction fold / naming aliases (MENC ≡ this id):  
  [`doc/btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md`](../../doc/btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md)

## One-line statement

No classical PPT adversary wins the §0.1 half-cost / `ε=2⁻⁴⁰` game against
normative ChaCha20-PRF MatExpand Extract + deep-`m` sketch/combine.

## Break modes (both count)

Per packet §0.2 (GAP-D1 pin), either §0.1 **FAIL** form breaks
`BTX-C15-NonCollapse-v1`:

| Mode | Meaning |
|---|---|
| **Full-digest FAIL** | Accepting digest/seal at `Adv ≥ ε` and MAC `≤ (1−δ)·HonestMAC` |
| **Structured-surrogate FAIL** | Affine / deg-≤2 Extract surrogate + Freivalds-usable rewrite (no full digest required) |

Same assumption; two break modes. **C-15 remains OPEN.**

## What this is / is not

| Is | Is not |
|---|---|
| A **named, unreduced** work-binding assumption for firm SOW | A theorem |
| Aligned with packet FAIL/PASS/INCONCLUSIVE (both FAIL modes = break) | A reduction to ChaCha20-PRF alone |
| The target behind C15-A/B/C + I1′ / batch surfaces | Permission to activate Rank-1 |

## Kit vs assumption

- `reference_extract.py` / `test-vectors.json` — reproduce normative Extract
- `toy_attack_harness.py --degree 3` — smoke affine / deg-1..3 collapse at toy `n`
- `reduction-attack-checklist.md` — firm attacks mapped to §0.1 FAIL (**§LFR** linear Freivalds rewrite taxonomy)
- In-tree `matmul_v4_lt_tests` — denser **witnesses** (optional node build)

All of the above are **witnesses**. Breaking (or carefully ruling out) the
§0.2 checklist is the firm’s job.
