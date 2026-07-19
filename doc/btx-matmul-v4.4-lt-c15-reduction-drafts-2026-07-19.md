# C-15 reduction sketches (Wave 1 — DRAFT) — 2026-07-19

*Status: **DRAFT candidate sketches only.** Every sketch ends with an explicit
GAP LIST. **No sketch is complete. C-15 remains OPEN.** Do not raise
`nMatMulDRLTHeight`. Do not treat any sketch as a PASS.*

**Source game:** packet `doc/btx-matmul-v4.4-lt-external-c15-packet.md` §0.1
(efficient classical adversary: accepting Phase-A digest with `Adv ≥ ε` at
exact-int MAC cost `≤ (1−δ)·HonestMAC(n)`).

**Notation (packet §1):**

```
Y = G·W,  B32 = Y·H = (G·W)·H,  rank(B32) ≤ w = 128
B̂[i,j] = ExtractDequantMatExpand(B32[i,j], i, j, prf_key)
Ĉ = (U·Â)(B̂·V) over q = 2⁶¹−1
```

**How to read this file:** arrows `⇒` are *candidate* implications under
stated lemmas/heuristics. Every incomplete, unformalized, or unproven step is
tagged **GAP**.

---

## Sketch ranking (least-gappy first)

| Rank | Sketch | Why |
|---|---|---|
| 1 (least-gappy) | **D** — `BTX-C15-NonCollapse-v1` | First hop is nearly definitional (§0.1 FAIL ⇔ assumption break). Further hops to SETH/OV/KW/PRF remain open. |
| 2 | **A** — surrogate ⇒ PRF / Extract-nonlinearity | Concrete oracle construction; still needs a formal Extract-nonlinearity lemma and PRF hybrid. |
| 3 | **B** — Freivalds rewrite ⇒ full-rank heuristic | Relies on an unstated spectral/full-rank heuristic after position salt. |
| 4 | **C** — KW secret-low-rank | Intentionally a **failure** sketch (shows where KW does not apply). |
| — | **E** — dead end | Fallacious (named fallacy); not a reduction path. |

---

## Sketch A — Affine / entrywise surrogate ⇒ ChaCha20-PRF break
### (or break of a stated Extract-nonlinearity lemma)

### Target assumptions

1. **ChaCha20-as-PRF** under MatExpand nonce packing
   (`Nonce96 = (uint32(raw)⊕lane, pack(i,j))`, counter = `remix`), or
2. Novel lemma **`Extract-Nonlinearity-v1`** (stated below) — preferred if the
   firm does not want to claim a full ChaCha PRF break from a PoW surrogate.

### Candidate lemma `Extract-Nonlinearity-v1` (DRAFT, unproven)

> For random `prf_key` and for any classical circuit `f` of size
> `≤ (1−δ)·HonestMAC` that is **entrywise** of the form
> `f(B32)[i,j] = φ(B32[i,j]; i, j)` with `φ` affine or total degree `≤ 2`
> in the raw accumulator (coefficients may depend on `(i,j)` but not on
> `prf_key` beyond poly-many oracle queries),  
> `Pr[ f(B32) agrees with Extract on ≥ N = 10⁶ cells of a realistic GWH
> sample ] ≤ ε_surr`  
> with `ε_surr ≪ ε` (packet Freivalds advantage threshold).

### Sketch steps

1. Let `A` be a §0.1 FAIL adversary in the **primary FAIL class** (affine /
   deg≤2 entrywise surrogate of Extract with Freivalds-usable rewrite through
   `G,W,H`), producing accepting digests at cost `≤ (1−δ)·HonestMAC`.
2. From `A`’s accepting transcripts / surrogate circuit, extract an explicit
   entrywise map `φ` (or a deg≤2 polynomial family) that matches Extract on a
   dense sample of size `≥ N` with advantage ≫ Freivalds ε.
   - **GAP-A1:** Formal extraction of `φ` from an arbitrary PPT adversary (not
     just from adversaries that *publish* a surrogate). Black-box PPT may
     hide structure.
3. Build PRF distinguisher `D` that, given oracle access to either ChaCha20
   keystream under a random key or a random function into `{0,1}⁶⁴` (then
   IdealExtract table), samples realistic `B32` cells, evaluates normative
   Extract via the oracle, and compares agreement rate vs the recovered `φ`.
   - **GAP-A2:** Hybrid from “real Extract” to “IdealExtract / random
     function” under the *exact* MatExpand nonce packing (related-`raw`,
     Mant/Scale related-nonce XOR, remix) is **not** written.
4. If agreement remains high under a true random function, contradict
   `Extract-Nonlinearity-v1` (lemma break, not necessarily ChaCha break).
5. If agreement collapses under IdealExtract but stays high under ChaCha,
   output “ChaCha distinguishable from RF” — a **PRF break** under this
   packing.
   - **GAP-A3:** Step 5 needs a quantitative hybrid: high surrogate agreement
     under ChaCha *and* low under RF. Empirics (C15-A witnesses) suggest
     surrogates already fail under real ChaCha — so a §0.1 FAIL may never
     exist in this class; the reduction is conditional on FAIL.
6. Conclude: §0.1 FAIL in the affine/deg≤2 class ⇒ break of
   `Extract-Nonlinearity-v1` and/or ChaCha20-PRF (under packing).

### Explicit non-claim

This does **not** show that ChaCha20-PRF alone implies §0.1 PASS. Packet §0.1
already states the converse is false. Sketch A only maps a *surrogate-class*
FAIL into a primitive/lemma break.

### GAP LIST (Sketch A)

| ID | Gap |
|---|---|
| **GAP-A1** | Surrogate extraction from general PPT (not oracle-published `φ`). |
| **GAP-A2** | PRF hybrid under MatExpand nonce packing / related-nonce / remix. |
| **GAP-A3** | Quantitative: when does high `φ`-agreement imply PRF advantage vs lemma break? |
| **GAP-A4** | Deg≤2 only; deg≥3 / spectral / TMTO adversaries out of scope for this arrow. |
| **GAP-A5** | Freivalds-usable rewrite through `G,W,H` after surrogate match not reduced to a named lemma (needs Sketch B link). |
| **GAP-A6** | Cost accounting: distinguishing game must not burn more MACs than the reduction budget allows. |

**Status:** incomplete draft. **C-15 not closed.**

---

## Sketch B — Linear Freivalds reassociation through GWH
### ⇒ contradiction with position-salted full-rank heuristic

### Target heuristic

**`PositionSalted-FullRank-Heuristic-v1` (DRAFT, not a theorem):**

> After normative Extract with full-width `(i,j)` salts and `seed_W`-derived
> `prf_key`, the matrix `B̂ ∈ 𝔽_q^{n×n}` has no *usable* factorization
> `B̂ ≈ L R` (or shared entrywise `φ∘(GWH)`) of rank `r ≤ w` that is
> predictable from public panels alone and that lets Freivalds matvecs
> reassociate past Extract at cost `≪ HonestMAC`.

(Contrast: pre-Extract `rank(B32) ≤ w` is unconditional — packet §1.1.)

### Sketch steps

1. Assume a linear Freivalds rewrite adversary (packet C15-B): probes linear in
   `B̂` rewrite as probes on `G,W,H` alone (or on a cheap fold), yielding
   accepting sketches at `≤ (1−δ)·HonestMAC`.
2. Linear rewrite implies existence of coefficients such that, for Freivalds
   challenges `x,y` (or for the sketch projectors `U,V`),
   ```
   xᵀ Ĉ y  ≈  algebraic form in (G, W, H) only
   ```
   with error below Freivalds soundness — typically via an affine entrywise
   model `B̂[i,j] ≈ α·B32[i,j] + β_{i,j}` (Sketch A class) or a shared-φ
   spectral residue of rank `≤ w`.
   - **GAP-B1:** Classify *all* linear rewrites beyond affine / shared-φ.
     **Wave-3 partial close:** firm taxonomy + per-subclass oracles (heuristic
     vs theorem) live in
     `contrib/matmul-c15-reviewer-kit/reduction-attack-checklist.md` §LFR
     (LFR-0..LFR-11). Taxonomy ≠ proof that the list is exhaustive or that
     Sketch B holds.
3. Affine / shared-φ models imply `B̂` retains effective rank `≲ w` correlated
   with `GWH` (Simon-style φ∘(low-rank); lattice/spectral pre-review).
4. Full-width position salt + per-cell PRF is argued to destroy shared-φ /
   translation collapses (packet pillars; `matexpand_position_salt_differential`).
   - **GAP-B2:** Empirical witnesses ≠ proof of full-rank / no usable residue.
5. Therefore a successful linear rewrite contradicts
   `PositionSalted-FullRank-Heuristic-v1`.
6. Conclude: C15-B linear FAIL ⇒ heuristic false (or GAP-B1 class incomplete).

### Explicit non-claim

Heuristic contradiction is **not** a reduction to ChaCha-PRF, SETH, OV, or KW.
Unrestricted (nonlinear) adversaries remain INCONCLUSIVE (synthesis).

### GAP LIST (Sketch B)

| ID | Gap |
|---|---|
| **GAP-B1** | Taxonomy of “linear Freivalds rewrite” beyond affine/shared-φ — **checklist §LFR landed** (heuristic vs theorem per subclass); exhaustiveness / Sketch B proof still open. |
| **GAP-B2** | Full-rank / no-usable-residue after Extract is a **heuristic**, not proven. |
| **GAP-B3** | Spectral residue could be high-rank yet still Freivalds-forgery-friendly (approx-`B̂`). |
| **GAP-B4** | `U`/`V` rank-transparency noted; no formal lemma that projectors cannot *create* usable structure. |
| **GAP-B5** | Truncated `(i,j)` salt reopens ~32× low-rank shortcut — normative full-width assumed; device twin bugs are consensus-splits, not a hardness proof. |
| **GAP-B6** | Link from heuristic falsehood to a standard assumption (PRF / random matrix) missing. |

**Status:** incomplete draft. **C-15 not closed.**

---

## Sketch C — Attempted KW secret-low-rank reduction
### (shows where it FAILS for public B32)

### Target (literature)

**Komargodski–Weinstein (KW) / cuPOW-style secret low-rank hardness**
(ePrint 2025/685): hardness arguments that rely on a *secret* low-rank
correction / noise structure (or secret factors) so that miners cannot peel
cheap algebraic shortcuts; Pearl/cuPOW further binds work via **transcript**
hashing. Closest named object: batch low-rank random linear equations
(conjecture) — **not** identical to BTX MatExpand.

### Attempted reduction (intended arrow)

```
§0.1 FAIL  ⇒?  break KW secret-low-rank / cuPOW transcript conjecture
```

### Where the attempt FAILS

1. **Public deterministic panels.** In BTX, `G`, `W`, `H` (hence `B32 = GWH`)
   are **deterministic from public seeds** (`seed_W`, template/header binding).
   There is **no secret low-rank factor** for the reduction to hide behind.
   - **Missing secret:** KW needs a secret (noise / factors / transcript tiles)
     unknown to the adversary. BTX publishes the thin factorization *by design*
     (`rank(B32)≤128` is priced structure — packet §1.1).
2. **Different firewall.** BTX’s candidate firewall is **nonlinear position-salted
   Extract** into a small alphabet under sketch Freivalds — not KW’s secret
   noise + transcript RO.
3. **Wrong conclusion direction.** Even if KW’s conjecture is true, it does
   **not** imply §0.1 PASS for public `B32`. Even if §0.1 FAIL, it does **not**
   imply a KW break — the FAIL may exploit *public* low-rank + bad Extract
   surrogate without touching KW’s secret instance.
4. **Freivalds vs transcript.** KW/Pearl treat Freivalds as insufficient for
   work-binding (correct); BTX still uses Freivalds for *verify* and tries to
   push work-binding into Extract+MAC accounting — a different conjecture
   surface (prior-art audit).

### Explicit verdict on this sketch

**Reduction FAILS.** Do not cite KW as a hardness substrate for LT-C15 under
the current public-panel design.

### What would be required to even *attempt* KW-style (out of scope; not proposed)

- Introduce a **secret** low-rank object (or secret transcript) into consensus
  MatExpand such that public verifiers check without learning the secret; **or**
- Adopt Pearl-style transcript commitments for thin GEMMs.
- Either path is a **consensus redesign**, not a papering-over of C-15.

### GAP LIST (Sketch C)

| ID | Gap |
|---|---|
| **GAP-C1** | No secret low-rank instance in normative BTX MatExpand — reduction premise missing. |
| **GAP-C2** | No embedding of public `GWH` into a KW challenge distribution. |
| **GAP-C3** | No transcript-RO object corresponding to cuPOW’s work binder. |
| **GAP-C4** | Even a future redesign would need a fresh game; current §0.1 does not match KW. |

**Status:** negative / obstruction sketch (useful). **C-15 not closed.**

---

## Sketch D — Novel intermediate assumption
### `BTX-C15-NonCollapse-v1`

### Name (careful)

> **Aliases (one assumption)**  
> **Canonical:** `BTX-C15-NonCollapse-v1` (packet §0.2)  
> **Also used in Wave-1 drafts:** `BTX-MatExpand-NonCollapse-v1`, **MENC** (*MatExpand–Extract Non-Collapse*), *LT-C15 Work-Binding*  
> Same §0.1 game; names differ only in emphasis. Prefer the packet id in firm SOWs.

**`BTX-C15-NonCollapse-v1`**

*Not* “ChaCha-NonCollapse” (overclaims primitive). *Not* “C15-Closed”
(overclaims status). Named for the **C-15 / MatExpand+Extract+sketch MAC floor**.
The MatExpand-emphasizing alias (`BTX-MatExpand-NonCollapse-v1`) stresses that
hardness is *not* “ChaCha alone”; it is **not** a second assumption.

### Game (precise; aligns with packet §0.1)

| Item | Definition |
|---|---|
| **Params** | `n ∈ {64,256,4096}` (prod. `4096`), `w=128`, `b=2`, `m=n/2`, `q=2⁶¹−1`, Extract = `ENC_BMX4C_LT` ChaCha20-PRF+M11 |
| **HonestMAC(n)** | Exact-int MAC of one marginal nonce: MatExpand-B (`G·W`+`Y·H`) + `B̂·V` + combine `P·Q` (I1′ template A / `U`/`V`/`P` excluded) |
| **Adversary** | Classical PPT relative to `HonestMAC`; poly adaptive MatExpand/digest/Freivalds queries |
| **Win** | Accepting Phase-A digest with `Adv ≥ ε` over Freivalds false-accept **and** exact-int MatExpand+BV+combine MAC `≤ (1−δ)·HonestMAC(n)` |
| **Defaults** | `δ = 1/2`, `ε = 2⁻⁴⁰` (packet; firm may retune in SOW) |
| **Assumption** | No such adversary exists (for the stated primary class: linear / deg≤2 entrywise surrogates; unrestricted class may be labeled separately as `…-unrestricted-v1`) |

### Hop 1 — almost definitional

```
§0.1 FAIL  ⇒  break of BTX-C15-NonCollapse-v1
```

**Argument:** The §0.1 FAIL criterion *is* the winning condition of the
assumption game (same cost model, same ε/δ, same public params). A concrete
FAIL vector/surrogate **is** a break of `BTX-C15-NonCollapse-v1`.

- **GAP-D1 (minor):** Packet FAIL also allows “affine/low-degree surrogate
  matching Extract on ≥ N samples with Freivalds-usable rewrite” without a
  full digest — pin whether that alone counts as an assumption break
  (recommended: **yes**, as a *structured* break mode of the same assumption).

### Hop 2 — what would be needed to reduce the assumption further

To reduce `BTX-C15-NonCollapse-v1` to a *named* classical assumption,
a firm write-up would need **all** of the following (none currently exist):

| Target | Needed bridge | Status |
|---|---|---|
| **ChaCha20-PRF** | Sketch A hybrids + proof that any ≤(1−δ) shortcut implies a PRF distinguisher or Extract-nonlinearity lemma break | **GAP-D2** |
| **SETH / OV** | Fine-grained embedding: OV/SETH instance → MatExpand panels/seeds such that a sub-HonestMAC accepting miner solves OV — Ball–Rosen–Segev–style non-amortization adapted to Extract+sketch (BRSV is for different polynomials) | **GAP-D3** |
| **KW secret-low-rank** | Requires secret instance — blocked by Sketch C unless consensus redesign | **GAP-D4** (obstruction) |
| **cuPOW transcript unpredictability** | Map Extract+Freivalds transcripts to Pearl transcript RO game; distributions differ (noise tiles vs PRF Extract alphabet) | **GAP-D5** |
| **SIS/LWE / spectral LRA** | Show usable low-rank residue after Extract yields a lattice/spectral oracle break; Kikuchi-style sparse-LWE does not directly apply (lattice pre-review) | **GAP-D6** |

Suggested *aspirational* inequality (prior-art audit; **not proven**):

```
Adv_§0.1(A)  ≤  Adv_PRF^ChaCha(B) + Adv_ExtractStruct(C) + Adv_NonCollapse_residual(D) + negl(Freivalds)
```

with `Adv_NonCollapse_residual` currently as conjectural as cuPOW’s algebraic
assumption.

### Explicit non-claims

- Naming the assumption does **not** close C-15.
- Does **not** follow from ChaCha20-PRF alone (packet §0.1 load-bearing sentence).
- Does **not** authorize height raise.

### GAP LIST (Sketch D)

| ID | Gap |
|---|---|
| **GAP-D1** | Pin structured-surrogate FAIL vs full digest FAIL as assumption break modes. |
| **GAP-D2** | No reduction of NonCollapse to ChaCha20-PRF. |
| **GAP-D3** | No SETH/OV embedding / BRSV-style non-amortization for MatExpand. |
| **GAP-D4** | KW path blocked for public B32 (see Sketch C). |
| **GAP-D5** | No distributional reduction to cuPOW transcript unpredictability. |
| **GAP-D6** | No SIS/LWE/spectral reduction for post-Extract residue. |
| **GAP-D7** | Unrestricted adversary class not folded into v1 (may need `…-unrestricted-v1`). |
| **GAP-D8** | I1′ / batch algebra / Phase-B seal are separate surfaces (packet §§3–5). Multi-instance *shape* stated as heuristic game (Wave 3 Gap #9: `…-qstar-i1-amortization-game-…`); not a BRSV reduction. |

**Status:** best intermediate naming for firms; still **unreduced**. **C-15 not closed.**

---

## Sketch E — DEAD END (tempting but fallacious)

### Tempting claim

> “Freivalds soundness over `q=2⁶¹−1` with `R=3` rounds already implies that
> any accepting miner must have computed the full dense product / MatExpand
> honestly; therefore §0.1 PASS follows from Freivalds alone.”

### Named fallacy

**Work–soundness conflation** (a.k.a. *verification-soundness ≠ work lower
bound*; Pearl/cuPOW “Freivalds pitfall”).

### Why it is fallacious

1. Freivalds soundness bounds the probability that a **false** sketch
   `Ĉ ≠ (UÂ)(B̂V)` accepts. It says nothing about *how cheaply* a miner can
   produce a **true** `Ĉ` (or a true-looking surrogate that equals the sketch
   algebraically via a shortcut).
2. Linear / affine Extract folds make **true** sketches available via
   reassociation through public `GWH` at `≪` dense cost — accepting with
   probability ~1, not ~`q^{-R}`. Soundness is irrelevant to that class.
3. Packet §0.1 correctly prices **MAC work**, not Freivalds ε alone.

### GAP LIST (Sketch E)

| ID | Gap |
|---|---|
| **GAP-E1** | Not a gap in a reduction — the arrow is **invalid**. Listed for quarantine. |

**Status:** dead end. Do not ship as a reduction path.

---

## Cross-sketch dependency map (draft)

```
§0.1 FAIL
   │
   ├─(almost def.)──► break BTX-C15-NonCollapse-v1     [Sketch D]
   │                      │
   │                      ├─?─► ChaCha20-PRF / Extract-Nonlinearity-v1  [A, GAP-D2]
   │                      ├─?─► SETH/OV (BRSV-style embed)               [GAP-D3]
   │                      ├─✗─► KW secret-low-rank                      [C blocked]
   │                      └─?─► cuPOW transcript / SIS-LWE              [GAP-D5/D6]
   │
   ├─(surrogate class)──► Sketch A
   │
   ├─(linear rewrite)───► Sketch B ──?──► PositionSalted-FullRank-Heuristic-v1
   │
   └─(fallacious)───────► Sketch E  [REJECT: work–soundness conflation]
```

---

## Harden requests emitted by this draft

See append-only log `/tmp/c15_wave1_harden_requests.md` (Wave 1 drafts agent).

## Explicit non-claims (file-level)

- C-15 cryptographically closed — **NO**
- Finite public `nMatMulDRLTHeight` — **NO**
- ChaCha-PRF alone ⇒ MatExpand MAC lower bound — **NO**
- Any sketch above is complete — **NO**

*Companions:* `doc/btx-matmul-v4.4-lt-external-c15-packet.md` §0.1,
`doc/btx-matmul-v4.4-lt-c15-prereview-synthesis-2026-07-19.md`,
`contrib/matmul-c15-reviewer-kit/`.
