# C15-C related-nonce note — Mant/Scale lane-XOR as reduction / attack surface

*Date: 2026-07-19. Branch: `feat/bmx4c-exact-accel-lanes`.*  
*Sources: `/tmp/c15_audit_prf_statistical.md` (F2), `src/matmul/matmul_v4_lt.cpp`
(`MatExpandPrfKeystream`, `ExtractDequantMatExpand`), prior-art reduction sketch
(`/tmp/c15_audit_prior_art.md` §4).*  
*Witness test: `matexpand_related_nonce_lane_xor_identity` in
`src/test/matmul_v4_lt_tests.cpp`.*  
***Do not claim C-15 cryptographically closed.***

---

## 1. Formal identity

Normative nonce packing (fixed `prf_key`, `(i,j)`, remix counter):

```
MANT  = 0x4D414E54          // 'MANT'
SCLE  = 0x53434C45          // 'SCLE'
Δ     = MANT ⊕ SCLE         // = 0x1e020211

Nonce96(raw, lane) = ( raw ⊕ lane ,  pack(i,j)=(i<<32)|j )
ctr                = remix

MantPRF(raw)  ≜  ChaCha20_block(key, Nonce96(raw, MANT), remix)[0:8] as LE64
ScalePRF(raw) ≜  ChaCha20_block(key, Nonce96(raw, SCLE), remix)[0:8] as LE64
```

**Proposition (lane-XOR related-nonce identity).** For every
`(key, raw, i, j, remix)`:

```
MantPRF(raw)  =  ScalePRF(raw ⊕ Δ)
ScalePRF(raw) =  MantPRF(raw ⊕ Δ)
```

**Proof (algebra of the first nonce word only).**

```
ScalePRF(raw ⊕ Δ)
  = ChaCha(..., (raw⊕Δ) ⊕ SCLE, pack(i,j), remix)
  = ChaCha(..., raw ⊕ (MANT⊕SCLE) ⊕ SCLE, ...)
  = ChaCha(..., raw ⊕ MANT, ...)
  = MantPRF(raw).
```

The second identity is symmetric. Position salt and counter are identical on both
sides; only the XOR-linear lane tag moves.

**Extract consequence.** Normative `Extract(raw)` takes mantissa bits from
`MantPRF(raw)` and scale `e = ScalePRF(raw) & 3`. By the identity,
`e(Extract(raw))` is the low 2 bits of `MantPRF(raw⊕Δ)`. When the **first
nibble** of that word is M11-accepted (~11/16), the related call
`Extract(raw⊕Δ)` locks `(μ′, e)` to a deterministic pair (each accepted μ forces
a unique `e = nibble & 3`):

| μ′ | forced e |
|----|----------|
| 0  | 0 |
| ±1 | 2 |
| ±2 | 0 |
| ±3 | 1 |
| ±4 | 2 |
| ±6 | 3 |

Empirical mild correlation at distance Δ: `P(Extract(raw)=Extract(raw⊕Δ))≈0.067`
vs independent collision baseline `∑ p_v² ≈ 0.052` (PRF audit F2).

---

## 2. PRF break? No. Leftover structure? Yes.

| Claim | Verdict |
|---|---|
| “Related nonces break ChaCha-as-PRF” | **No.** A secure PRF remains secure under *chosen* related inputs. Distinct `(nonce_first, nonce_second, ctr)` queries still look independent uniform. The identity above is exactly what an ideal PRF predicts when the adversary queries both `raw` and `raw⊕Δ`. |
| “Leftover structure in the Extract *composition*” | **Yes.** Lane tags are XOR-linear in `raw`, so Mant/Scale for one raw reuse the mantissa/scale streams of the Δ-shifted raw. That induces a **deterministic cross-raw link** inside Extract — not a distinguisher against ChaCha, but a **compositional residue** relative to “independent Extract cells.” |

So: **not a cryptanalytic break of the mixer**; **yes, leftover C15-C structure** that any reduction or firm brief must name (absorb into `Adv_ExtractStruct`, not into `Adv_PRF`).

**Hybrid absorption (Wave 3 Gap #2):** the PRF hybrid under MatExpand nonce
packing keeps related-nonce in game **C** — see
[`doc/btx-matmul-v4.4-lt-c15-extract-nonlinearity-v1-2026-07-19.md`](btx-matmul-v4.4-lt-c15-extract-nonlinearity-v1-2026-07-19.md)
§2–§4. That formalization does **not** close C-15.

---

## 3. Impact on reduction sketches A / D

From the prior-art sketch (`/tmp/c15_audit_prior_art.md` §4):

```
Adv_LT-C15(A)
  ≤ Adv_PRF^ChaCha(B) + Adv_ExtractStruct(C) + Adv_Shortcut_MBv(D) + negl(Freivalds)
```

with subgoals **R-A** (Extract∘MatExpand not Freivalds-linear in panels) and
**R-D** (I1′: fixed `Â,U,V,P` does not yield sub-GEMM solve for fresh `B̂`).

### Sketch A / R-A (linearity / PRF fragment) — mild **hurt**, not fatal

- A **naive** write-up that assumes “Mant and Scale are independent PRF draws for
  each raw, and Extract outputs at distinct raws are independent” is
  **over-strong**: independence fails at distance Δ.
- A **correct** PRF reduction still goes through: map Extract’s two lane queries
  to two (related) PRF queries; standard PRF security already covers related
  nonces. The residue belongs in **game C** (`Adv_ExtractStruct`), not as an
  inflation of `Adv_PRF`.
- The related-nonce link **does not restore affinity** in `raw`, does **not**
  give a Freivalds-linear surrogate through `G·W·H`, and does **not** reopen
  the C15-A/B algebraic collapses already witnessed against Fold / SplitMix /
  low-degree LS. Net: sketch A stays viable if C is explicit; it is **hurt only
  if the sketch silently claims full Extract-cell independence**.

### Sketch D / R-D (amortization / I1′ floor) — **does not help the attacker**

- Honest MatExpand evaluates **one** `raw = B32[i,j]` per cell. The mate
  `raw⊕Δ` is not co-resident at the same `(i,j)` under the GWH core.
- Sharing one ChaCha block across `(raw, raw⊕Δ)` is at best a **2→1
  related-input micro-opt** for an oracle that deliberately queries both —
  irrelevant to paying for `G·W` + `Y·H`, and not a sub-GEMM solve for fresh
  `B̂` under fixed projectors.
- Therefore the lane-XOR identity **does not yield amortization** against the
  I1′ / MatExpand work floor that sketch D must protect. It also does **not**
  strengthen D’s hardness claim (structure is real; shortcut is not).

**One-line reduction posture:** related-nonce **hurts sloppy independence
claims in A**, **belongs in C**, **does not amortize D**.

---

## 4. Firm experiment (Wave 3 Gap #5 — shipped)

**Firm (primary):** machine-checkable vector pack + independence game.

1. **Published ≥32 identity tuples** in
   `contrib/matmul-c15-reviewer-kit/test-vectors.json::related_nonce_lane_xor`
   as
   `(seed_w, raw, i, j, remix, Δ, mant_le64, scale_le64, mant_at_raw⊕Δ, scale_at_raw⊕Δ)`
   with `mant_le64 == scale_at_raw⊕Δ` and `scale_le64 == mant_at_raw⊕Δ`
   (oracles: `MatExpandPrfLaneLE64` / `reference_extract.py`).
2. Conditionally, when first nibble of `mant_at_raw⊕Δ` accepts, the C++ witness
   checks the `(μ′, e)` lock table in §1 on a dense sample.
3. **Amortization negative control (shipped):**
   - Reviewer-kit synthetic `(G·W)·H` grid (`n=16`, `w=4`, seed `20260719`):
     `Δ`-collision count `0` on `C(256,2)` pairs (≈ uniform / `2³²`).
   - In-tree honest MatExpand `B32` at `n=8` via `ExpandOperandBB32ForTest`:
     `Δ`-collision count `≤ 1` (expect `0`; `C(64,2)/2³² ≈ 4.7×10⁻⁷`).
   Even a perfect 2→1 ChaCha share on those rare pairs cannot drop below the
   GEMM term of sketch D.
4. Optional defense-in-depth (consensus-breaking if adopted): put scale on
   `ctr = remix + 2³¹` or a nonce half nonlinear in `raw`, killing the XOR
   identity — only if activation wants a cleaner C15-C story.

**In-tree witness (shipped):** `matexpand_related_nonce_lane_xor_identity`
pins ≥32 frozen LE64 identity tuples (mirroring `test-vectors.json`), a dense
sample + μ′↔e lock, and the honest-`B32` Δ-collision negative control.
`python3 contrib/matmul-c15-reviewer-kit/reference_extract.py` re-checks the
JSON pack. Empirical only — **not** a PRF proof and **not** a C-15 closure.
**C-15 remains OPEN.**

---

## 5. Verdict (Wave 1 — RELATED-NONCE)

| Question | Answer |
|---|---|
| Help a reduction to PRF? | **Neither break nor free lunch.** Identity is PRF-*consistent*; leftover belongs in ExtractStruct (C). |
| Hurt a reduction to PRF? | **Mildly**, if sketches claim independent Extracts across all raws. |
| Yield amortization? | **No** — not Freivalds-linear; not GEMM-skipping; Δ-mates not free in honest `B32`. |
| C15-C / C-15 | Residue **documented**; **C-15 remains OPEN**. |

---

*End of related-nonce reduction note. No closed claim.*
