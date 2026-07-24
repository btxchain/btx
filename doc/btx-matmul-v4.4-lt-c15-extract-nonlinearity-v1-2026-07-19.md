> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# Extract-Nonlinearity-v1 + PRF hybrid (Wave 3 Gap #2) — 2026-07-19

> **Lever-B supersession note (2026-07-20).** This Wave-3 draft models the
> historical per-cell `MANT`/`SCLE` ChaChaCell extractor. It is not the current
> normative construction. Consensus now uses `w=1024` and MX-block extraction:
> one `MXBL` ChaCha stream and one hash-derived scale per real 32-value `B32`
> tile, salted by full-width `(i,bj)` where `bj=j/32`. The draft remains useful
> only as historical/differential analysis; every lemma must be restated for MX
> tiles before use. C-15 remains OPEN.

*Branch: `feat/bmx4c-exact-accel-lanes`.*  
*Status: **DRAFT formalization + hybrid outline.** Every incomplete step is
tagged **GAP**. This file does **not** prove the lemma, does **not** reduce
LT-C15 to ChaCha20-PRF, and does **not** close C-15.*  
***C-15 remains OPEN.** Public activation remains inert (`nMatMulDRLTHeight =
INT32_MAX`).*

**Parents:** packet
[`doc/btx-matmul-v4.4-lt-external-c15-packet.md`](btx-matmul-v4.4-lt-external-c15-packet.md)
§0.1–§0.2; Sketch A in
[`doc/btx-matmul-v4.4-lt-c15-reduction-drafts-2026-07-19.md`](btx-matmul-v4.4-lt-c15-reduction-drafts-2026-07-19.md);
related-nonce note
[`doc/btx-matmul-v4.4-lt-c15-related-nonce-reduction-note-2026-07-19.md`](btx-matmul-v4.4-lt-c15-related-nonce-reduction-note-2026-07-19.md);
Wave-1 fold
[`doc/btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md`](btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md)
§4 rank **2**.

**Deliverable for Gap #2:** stated lemma + PRF hybrid outline under MatExpand
nonce packing, with related-nonce absorbed into `Adv_ExtractStruct`, plus a
quantitative agreement ⇒ advantage map. **Not a theorem.**

---

## 0. Role in the aspirational inequality

Aspirational (packet / drafts / related-nonce; **not proved**):

```
Adv_LT-C15(A)
  ≤ Adv_PRF^ChaCha(B) + Adv_ExtractStruct(C) + Adv_NonCollapse(D) + negl(Freivalds)
```

| Term | What this file addresses |
|---|---|
| **B** `Adv_PRF^ChaCha` | Hybrid outline (§3–§4): real ChaCha under MatExpand packing ↔ ideal RF |
| **C** `Adv_ExtractStruct` | Related-nonce Mant/Scale XOR + remix / M11 composition residue (§2) — **absorbed here, not into B** |
| **Lemma** `Extract-Nonlinearity-v1` | Ideal / RF world: affine / deg≤2 entrywise surrogates cannot match IdealExtract (§1) |
| **D** `Adv_NonCollapse` | Remains packet §0.2 `BTX-C15-NonCollapse-v1` — **out of scope** for this fragment |

Sketch A arrow (conditional): structured-surrogate §0.1 FAIL ⇒ break of
`Extract-Nonlinearity-v1` and/or ChaCha20-PRF under packing. That arrow is
still incomplete (**GAP** list §6). Closing this file’s outline does **not**
close C-15.

---

## 1. Lemma `Extract-Nonlinearity-v1` (DRAFT, unproven)

### 1.1 Normative Extract (pin)

Packet §1 / §1.4:

```
prf_key = SHA256("BTX_MATEXPAND_PRF_V44LT" ‖ seed_W)
Nonce96(raw, lane) = ( uint32(raw) ⊕ lane ,  pack(i,j)=(uint64(i)<<32)|uint64(j) )
ctr                = remix  (starts 0; Seek then ReadLE64)

MANT = 0x4D414E54,  SCLE = 0x53434C45
MantPRF(raw; i,j,remix)  ≜  ChaCha20_block(key, Nonce96(raw, MANT), remix)[0:8] LE64
ScalePRF(raw; i,j,remix) ≜  ChaCha20_block(key, Nonce96(raw, SCLE), remix)[0:8] LE64

Extract(raw, i, j, key):
  walk remix = 0,1,… until first M11-accepted nibble of MantPRF;
  e = ScalePRF(...) & 3 at the same remix;
  return μ · 2^e  ∈ [-48,48]   // exact mul, not signed <<
```

**IdealExtract:** replace MantPRF/ScalePRF with independent uniform draws in
`{0,1}⁶⁴` (subject to the remix walk), then the same M11 + scale table.
Alphabet has 23 values; `P(0)=1/11≈9.1%` by design (packet §1.2).

### 1.2 Statement

> **`Extract-Nonlinearity-v1` (DRAFT).** Fix packet public params
> (current `n∈{64,256,4096}`, `w=1024`, …) and thresholds `δ=1/2`, `ε` as in §0.1,
> sample size `N=10⁶`. Let `IdealExtract` be as above. For a uniformly random
> `prf_key` **or** in the IdealExtract / RF world, and for every classical
> circuit / map `f` of size `≤ (1−δ)·HonestMAC(n)` that is **entrywise** of the
> form
>
> ```
> f(B32)[i,j] = φ(B32[i,j]; i, j)
> ```
>
> with `φ` affine or total degree `≤ 2` in the raw accumulator (coefficients
> may depend on `(i,j)` and on poly-many public oracle transcripts, but must
> not embed a full ChaCha evaluation budget that restores honest cost),
>
> ```
> Pr[ f agrees with IdealExtract on ≥ N cells of a realistic GWH / B32 sample ]
>   ≤ ε_surr
> ```
>
> with `ε_surr ≪ ε` (target: negligible vs Freivalds false-accept advantage;
> empirics use R² ≪ 0.05 / dense-match ≪ Freivalds-usable).

**Scope:** primary FAIL class only (affine / deg≤2 entrywise). Deg≥3,
spectral/TMTO, unrestricted PPT → **GAP-EN4**.

**Status:** **unproven conjecture / lemma candidate.** In-tree witnesses
(`matexpand_not_affine_in_raw`, `matexpand_extract_r2_nonapproximability`,
C15-B LS reject) are **empirics**, not a proof.
**GAP-EN1.**

### 1.3 What the lemma is *not*

| Non-claim | Why |
|---|---|
| Not a ChaCha PRF theorem | Speaks about IdealExtract / composition; PRF is separate game B |
| Not `BTX-C15-NonCollapse-v1` | NonCollapse is work-binding (MAC floor); this is surrogate non-approximability |
| Not a height-raise gate | Even a proved lemma would leave NonCollapse / silicon / HeaderPoW open |
| Not independence of Extract cells | Related-nonce links cells at distance `Δ` — see §2 |

---

## 2. Related-nonce → `Adv_ExtractStruct` (absorption)

Normative identity (related-nonce note §1; witness
`matexpand_related_nonce_lane_xor_identity`):

```
Δ = MANT ⊕ SCLE = 0x1e020211
MantPRF(raw)  = ScalePRF(raw ⊕ Δ)
ScalePRF(raw) = MantPRF(raw ⊕ Δ)
```

**Absorption rule (load-bearing for hybrids):**

| Phenomenon | Bucket |
|---|---|
| ChaCha looks random on distinct `(key, Nonce96, ctr)` queries, including *chosen related* nonces | **B** `Adv_PRF` |
| Deterministic Mant↔Scale cross-raw link; μ′↔e lock when first nibble accepts; mild `P(Extract(raw)=Extract(raw⊕Δ))≈0.067` vs `∑p_v²≈0.052` | **C** `Adv_ExtractStruct` |
| Sub-HonestMAC Freivalds-usable shortcut / GEMM skip | **D** `Adv_NonCollapse` (not implied by the identity) |

**Consequences for formal write-ups:**

1. Do **not** inflate `Adv_PRF` with the lane-XOR identity — a secure PRF
   already predicts it under related queries.
2. Do **not** claim full Extract-cell independence across all raws in Sketch A
   hybrids; independence fails at distance `Δ`.
3. Do **not** treat the identity as MatExpand amortization: honest cells do not
   co-reside as `(raw, raw⊕Δ)` pairs at the same `(i,j)` under GWH
   (related-nonce note §3 Sketch D).

**GAP-EN2:** Formal game for `Adv_ExtractStruct` (distinguisher interface,
bound vs IdealExtract-with-lane-XOR vs IdealExtract-independent) is only
outlined here — not reduced to a named crypto assumption.

### 2.1 ExtractStruct game (outline)

```
Game_ExtractStruct:
  Challenger samples key / Ideal streams with normative packing
    (including Mant/Scale related-nonce identity).
  Adversary may query Extract / MantPRF / ScalePRF on chosen (raw,i,j,remix)
    and receive outputs consistent with packing.
  Win: exhibit leftover structure usable as a Freivalds-linear / amortized
    PoW shortcut beyond what IdealExtract-with-lane-XOR already implies
    — OR distinguish normative composition from IdealExtract-with-lane-XOR
    at advantage ≥ ε_struct.
```

Related-nonce alone is **PRF-consistent** and **not** a win of
`Game_ExtractStruct` under the “beyond IdealExtract-with-lane-XOR” clause.
**GAP-EN2** remains until ε_struct and the win predicate are pinned in a firm
SOW.

---

## 3. MatExpand nonce-packing PRF game (pin)

Standard PRF advantage, **restricted to the MatExpand query interface**:

```
Nonce96(raw, lane) = (uint32(raw) ⊕ lane, pack(i,j))   // full-width i,j
ctr                = remix ∈ ℕ

Oracle O_b:
  b=0: ChaCha20_block(K, Nonce96, remix)[0:8] LE64   // real
  b=1: independent uniform U({0,1}⁶⁴) on each distinct
       (Nonce96, remix)   // ideal RF  (**GAP-EN3:** RF must respect that
       related Nonce96 queries are still distinct points — do not force
       Mant/Scale independence by construction unless Game C is separate)
```

`Adv_PRF^ChaCha(B) = |Pr[B^{O_0}=1] − Pr[B^{O_1}=1]|`.

**Packing facts the hybrid must name:**

| Fact | Handling |
|---|---|
| Two lanes per Extract cell (MANT + SCLE) | Two PRF queries per accepted remix |
| Remix walk | Variable number of queries; almost-sure termination under IdealExtract |
| Related-nonce `raw` vs `raw⊕Δ` | Distinct Nonce96 points; identity is algebraic on the *first nonce word* — belongs in **C**, not as a PRF failure |
| Position salt `(i,j)` | Part of Nonce96; truncation is a consensus bug / separate FAIL surface (packet checklist #6), not this lemma |

---

## 4. PRF hybrid outline (Sketch A fill-in for GAP-A2)

Conditional on a **structured-surrogate** §0.1 FAIL (or an explicit published
`φ` matching Extract on ≥`N` cells with Freivalds-usable rewrite).

### Hybrid chain

```
H0  Real world: normative Extract via ChaCha under MatExpand packing
      + related-nonce identity (composition as deployed).

H1  Replace ChaCha blocks by RF on (Nonce96, remix), but keep the
      *composition* Mant/Scale lane tags and remix/M11 walk identical
      (IdealExtract-with-lane-XOR).
      Gap closed by: standard PRF multi-query reduction.
      Advantage hop ≤ q_H · Adv_PRF   (**GAP-EN5:** pin query bound q_H
      vs HonestMAC budget — distinguishing game must not burn more MACs
      than the reduction allows; was GAP-A6).

H2  Move from IdealExtract-with-lane-XOR to IdealExtract-independent
      (break the forced Mant(raw)=Scale(raw⊕Δ) link — e.g. independent
      streams, or ctr offset defense).
      Advantage hop ≤ Adv_ExtractStruct   (**absorption:** this is game C,
      not PRF). Under normative consensus we do **not** take this hop for
      reduction *to PRF*; we keep H1 as the Ideal world for lemma EN-v1.
      **GAP-EN6:** quantitative bound on H1↔H2 (empiric Δ-correlation only).

H3  IdealExtract-independent (or H1, preferred) + surrogate test:
      measure agreement of recovered φ vs IdealExtract on N cells.
```

### Branching conclusion (GAP-A3 map)

Let `Agree_real = Pr[φ matches normative Extract on ≥ N cells]`  
and `Agree_ideal = Pr[φ matches IdealExtract(-with-lane-XOR) on ≥ N cells]`.

| Observation | Conclude |
|---|---|
| `Agree_real` high **and** `Agree_ideal` high | Break / falsify **`Extract-Nonlinearity-v1`** (lemma, not necessarily ChaCha) |
| `Agree_real` high **and** `Agree_ideal` low | **PRF distinguisher** under MatExpand packing: output “real” iff agreement high (**GAP-EN7:** make the threshold / Chernoff explicit) |
| `Agree_real` already low (empirics) | No §0.1 FAIL in this class ⇒ reduction is vacuously conditional; witnesses ≠ PASS on NonCollapse |

**Preferred firm posture:** treat EN-v1 as the Ideal-world statement (H1), and
route leftover lane-XOR structure exclusively through `Adv_ExtractStruct`, so
a high-`Agree_real` adversary that also wins under H1 falsifies the lemma
without claiming a ChaCha break.

### Surrogate extraction (GAP-A1 carry-forward)

**GAP-EN8** (= GAP-A1): extracting an explicit entrywise `φ` from an arbitrary
black-box PPT that only emits accepting digests (without publishing a
surrogate) is not formalized. Structured-surrogate break mode (packet §0.2
GAP-D1 pin) is the class this hybrid targets.

---

## 5. Quantitative agreement ⇒ advantage map (outline)

Targets (defaults; firm may retune in SOW — do not silently change):

| Symbol | Default / meaning |
|---|---|
| `N` | `10⁶` cells (packet structured-surrogate FAIL) |
| `ε` | `2⁻⁴⁰` above Freivalds false-accept (§0.1) |
| `ε_surr` | Target upper bound in EN-v1; require `ε_surr ≪ ε` |
| `δ` | `1/2` cost gap |
| `θ` | Decision threshold for distinguisher: e.g. declare “real” if empirical match rate `≥ θ` |

**Sketch inequality (aspirational, not proved):**

```
Adv_PRF(B_φ)
  ≥  |Agree_real − Agree_ideal| − negl(N)
  ≥  Agree_real − ε_surr − negl(N)     // if EN-v1 holds in H1
```

If `Agree_real ≥ η` with `η ≫ ε_surr` (e.g. Freivalds-usable match), then
either EN-v1 fails or `Adv_PRF ≳ η − ε_surr`. Cost: constructing `B_φ` may
evaluate `φ` and oracle Extract on `N` cells — **GAP-EN5** requires
`N · Cost(Extract oracle)` to fit inside the reduction’s accounting relative
to `(1−δ)·HonestMAC` (typically oracle queries are free in the PRF game, but
the PoW cost model is MAC-count — keep the two meters separate in the write-up).

**GAP-EN7:** Replace the sketch inequality with a Chernoff / Hoeffding bound
and an explicit `θ(N, ε_surr)`.

**Link to Freivalds rewrite (GAP-A5):** high entrywise agreement alone does not
finish Sketch A; a Freivalds-usable rewrite through `G,W,H` is required for
structured-surrogate FAIL (packet §0.2). That hop lives in Sketch B /
`PositionSalted-FullRank-Heuristic-v1` — **GAP-EN9**.

---

## 6. Master GAP LIST

| ID | Gap | Maps from |
|---|---|---|
| **GAP-EN1** | EN-v1 unproven; witnesses ≠ proof | Lemma §1 |
| **GAP-EN2** | `Adv_ExtractStruct` game not fully pinned (ε_struct, win vs Ideal+lane-XOR) | §2 |
| **GAP-EN3** | Ideal RF interface vs forced related-nonce consistency in code | §3 |
| **GAP-EN4** | Deg≥3 / spectral / TMTO / unrestricted out of lemma scope | §1.2 |
| **GAP-EN5** | Query / MAC budget for hybrid distinguisher (was GAP-A6) | §4 H1 |
| **GAP-EN6** | Quantitative H1↔H2 (lane-XOR correlation bound) | §4 H2 |
| **GAP-EN7** | Chernoff threshold `θ` for agreement ⇒ Adv map (was GAP-A3) | §5 |
| **GAP-EN8** | Surrogate extraction from general PPT (was GAP-A1) | §4 |
| **GAP-EN9** | Freivalds-usable rewrite after match (was GAP-A5; needs Sketch B) | §5 |
| **GAP-EN10** | Does **not** reduce `BTX-C15-NonCollapse-v1` / close C-15 (was GAP-A4 scope + GAP-D2) | file-level |

Sketch A GAP-A2 is **addressed as an outline** by §3–§4, not discharged.
C-15 remains **OPEN**.

---

## 7. Cross-links (maintainers)

| Doc | Update expectation |
|---|---|
| Packet §0.2 | Point here as Wave 3 Gap #2 formalization of EN-v1 + hybrid |
| Reduction drafts Sketch A | Prefer this file over the inline draft lemma; keep GAP-A\* ids |
| Related-nonce note | Absorption into ExtractStruct unchanged; cite this hybrid |
| Research synthesis §4 rank 2 | Mark deliverable landed; status still OPEN |
| Reviewer kit | Optional pointer from `named-assumption.md` / checklist A7 |

---

## 8. Explicit non-claims

- C-15 cryptographically closed — **NO**
- Finite public `nMatMulDRLTHeight` — **NO**
- ChaCha20-PRF alone ⇒ MatExpand MAC lower bound — **NO**
- `Extract-Nonlinearity-v1` proved — **NO**
- PRF hybrid complete / GAP-A2 discharged — **NO** (outline only)
- Related-nonce is a ChaCha break or GEMM amortization — **NO**
- Reduction of `BTX-C15-NonCollapse-v1` to EN-v1 or PRF — **NO**

*End of Extract-Nonlinearity-v1 formalization. C-15 OPEN. No closed claim.*
