# BTX MatMul v4.4-LT — External C-15 adversarial review packet

*Status: **DRAFT for independent cryptanalyst** — not closed. Lever-B MX/E2M1
block-scale MatExpand Extract is implemented with frozen goldens; this packet is
the external review brief. C-15 remains **OPEN**.*
*Companions: `doc/btx-matmul-v4.4-lt-normative-spec.md`,
`doc/btx-matmul-v4.4-lt-adversarial-analysis.md`,
`doc/btx-matmul-v4.4-lt-c15-prereview-synthesis-2026-07-19.md`.*
*Do not treat completion of this packet as automatic GO for Rank-1 activation.*
*Do not claim C-15 cryptographically closed.*
*Public activation remains inert (`nMatMulDRLTHeight = INT32_MAX`).*

## 0. Scope and non-goals

**In scope (ask the reviewer to break):**

1. **MatExpand non-collapse** — can an adversary replace the dense `G·W·H`
   MatExpand GEMMs with a cheaper Freivalds-linear / affine shortcut that still
   produces accepting digests with non-negligible probability?
2. **Invariant I1′ amortization** — does template-scoped MatExpand-A / `U` /
   `V` / `P=U·Â` create a reusable algebraic identity that collapses per-nonce
   MatExpand-B work?
3. **Batch algebra** — does optimal factoring `Ĉ=(U·Â)(B̂·V)` interact with
   MatExpand Extract to re-open a linear association attack?
4. **Seal-binding (Phase B)** — if Rank-1 launches with `fMatMulLTSealAsPoW`,
   does `SealWindowCommit(σ, Merkle(slot digests), Q*)` bind the window tightly
   enough that skinny single-nonce or cross-anchor amortization fails?
   *(Optional annex — not core C-15 algebra.)*

**Out of scope for this packet:** silicon nonce/s campaigns, ASERT calibration,
Header-PoW / chainwork (separate gates; bit-26 wire **withdrawn**), tip-verify
soak budgets. C-15 PASS does not unblock HeaderPoW; HeaderPoW NO-GO does not
vacate C-15 findings. Exact FMM / Strassen–Winograd efficiency vs ASERT is a
**separate** calibration track — see
`doc/btx-matmul-v4.4-lt-c15-asert-fmm-calibration-2026-07-19.md` (does not close
C-15; invents no silicon).

**Hard rule for reviewers and operators:** invent no silicon numbers; do not
raise `nMatMulDRLTHeight`; do not claim GO/NO-GO closed from this draft alone.

**Scoping correction (load-bearing):** MatExpand ExactGemm work is
`O(n²·w)` (panels, `w=1024`), **not** `O(n³)`. The cubic MAC floor on the
honest marginal unit is the deep-`m` sketch/combine path (`B̂·V` + `P·Q`), not
MatExpand itself. See §1.1–§1.2.

---

## 0.1 Falsifiable C-15 security claim (FIXED cost model)

> **A PRF (or MX-block ChaCha tile stream) does not imply a MatExpand work lower
> bound.** Primitive security and PoW non-collapse are separate. A PASS on
> “ChaCha looks like a PRF” is **not** a PASS on LT-C15. Lever-B ~32× PRF
> dilution vs per-cell ChaCha **does not** close C-15.

### Game (review target)

| Item | Fixed definition |
|---|---|
| **Public params** | `n ∈ {64,256,4096}` (production `n=4096`), `w=1024`, `b=2`, `m=n/2`, `q=2⁶¹−1`, Extract = normative **MX-block E8M0 + tile ChaCha M11** (`ENC_BMX4C_LT`, Lever B) |
| **Honest cost** `HonestMAC(n)` | Exact-int MAC count of one marginal nonce unit: **MatExpand-B** (`G·W` + `Y·H`) + **`B̂·V`** + **combine `P·Q`** (I1′: template A / `U`/`V`/`P` excluded from marginal). At `n=4096`: MatExpand-B `4n²w ≈ 6.87×10¹⁰`; `B̂·V` `2n²m ≈ 6.87×10¹⁰`; combine on `m×m` sketch (see shortcut/TMTO pre-review). |
| **Adversary class** | Classical PPT relative to `HonestMAC`; may use poly-many adaptive honest MatExpand/digest queries and Freivalds verify transcripts at production EncDr rounds. Label the class explicitly (**MENC-Lin** / **MENC-Unres** / optional **MENC-Cubic** — table below). Primary FAIL class = **MENC-Lin** (linear / degree-≤2 entrywise or MX-tile-local surrogates). **MENC-Unres** may return INCONCLUSIVE. |
| **Win** | Output an accepting Phase-A digest (or seal if SB annex in scope) with **advantage** `Adv ≥ ε` over Freivalds false-accept, while using exact-int MatExpand+BV+combine MAC count `≤ (1−δ)·HonestMAC(n)`. |
| **Metric** | Exact-int MAC (multiply-accumulate) count vs `HonestMAC`; optional same-machine wall-time of CPU ExactGemm reference as secondary (must not invent silicon). Wall-time / Strassen wins update **ASERT** baselines only — see FMM calibration note; they do not substitute for a C-15 MAC-count FAIL/PASS. |
| **Thresholds (review defaults)** | `δ = 1/2` (half-cost); `ε = 2⁻⁴⁰` above Freivalds false-accept for the stated round count. Firm may retune in SOW — **do not silently change**. |

### Adversary-class labels (MENC aliases under `BTX-C15-NonCollapse-v1`)

One named assumption (`BTX-C15-NonCollapse-v1`); three **class labels** so firm notes do not conflate verdicts. Prefer the packet id in SOWs; MENC-* are aliases only (FG survey §3).

| Label | Restriction | Typical firm return | Must not confuse with |
|---|---|---|---|
| **MENC-Lin** | Linear / degree-≤2 entrywise **or 32-cell tile-local** Extract surrogates + Freivalds-linear rewrites through `G,W,H` | Primary FAIL/PASS target | — |
| **MENC-Unres** | No degree restriction (classical PPT) | Often **INCONCLUSIVE** for years | **MENC-Lin PASS ≠ MENC-Unres PASS** |
| **MENC-Cubic** *(optional strengthening)* | Shortcut that cuts **`B̂·V` + combine** below `(1−δ)` of honest deep-`m` MAC (Extract ideal) | Separate sketch-floor claim | **Not** a MatExpand Θ(n²·w) claim — cubic floor is sketch/combine, not Expand |

**Hard wording rules:** (1) A **PASS** written against **MENC-Lin** does **not** imply a PASS against **MENC-Unres**. (2) Sketch-floor / deep-`m` MAC claims belong under **MENC-Cubic** (or explicit “sketch floor” language) — **do not** attribute them to MatExpand alone. See scoping correction above and §1.1–§1.2.

### Return criteria

| Verdict | When |
|---|---|
| **FAIL** | Concrete vectors + measured cost showing `Adv ≥ ε` at `≤ (1−δ)·HonestMAC`, **or** an affine/low-degree (deg ≤ 2) entrywise or MX-tile-local surrogate matching Extract on ≥ `N=10⁶` realistic real-tile `B32` samples with Freivalds-usable rewrite through `G,W,H`. State which MENC label was broken. |
| **PASS** | No such adversary for the **stated** MENC class; write-up argues why that class fails under the sample regime; residual risks listed and bounded. **Lin PASS ≠ Unres PASS.** **Still does not authorize height raise.** |
| **INCONCLUSIVE** | Neither FAIL nor PASS (e.g. **MENC-Unres** open; bias documented without PoW shortcut; missing oracles). |

Internal non-affinity / golden tests are **witnesses**, not a PASS.

---

## 0.2 Named novel assumption (unreduced)

**Name:** `BTX-C15-NonCollapse-v1`

**Status:** **UNREDUCED** novel assumption. C-15 remains **OPEN**. This section
names what external review must stress-test; it does **not** close C-15, does
**not** authorize raising `nMatMulDRLTHeight`, and does **not** claim a
reduction to ChaCha20-PRF, SETH/OV/APSP/3SUM, KW secret low-rank, Freivalds
soundness, or any other standard named problem.

### Informal statement

Under the normative ENC_BMX4C_LT MatExpand Extract (Lever-B MX-block E8M0 +
tile ChaCha M11 + position salts) and deep-`m` sketch/combine path, no classical
PPT adversary in the §0.1 class wins the §0.1 game: accepting Phase-A digests
(or seals if SB in scope) at advantage `≥ ε` while paying `≤ (1−δ)·HonestMAC(n)`
exact-int MACs.

### Game (identical to §0.1; parameter pin)

| Pin | Value |
|---|---|
| **Assumption id** | `BTX-C15-NonCollapse-v1` |
| **Aliases (class labels)** | **MENC-Lin** / **MENC-Unres** / **MENC-Cubic** — adversary-class aliases under this id (§0.1 table). Also: `BTX-MatExpand-NonCollapse-v1`, umbrella **MENC**. Same assumption; labels differ by restriction. |
| **Public params** | `n ∈ {64,256,4096}` (production `n=4096`), `w=1024`, `b=2`, `m=n/2`, `q=2⁶¹−1`, Extract = normative MX-block E8M0 + tile ChaCha M11 (`ENC_BMX4C_LT`) |
| **Honest cost** | `HonestMAC(n)` as in §0.1 (MatExpand-B + `B̂·V` + combine `P·Q`; I1′ template work excluded from marginal). MatExpand = Θ(n²·w); **cubic MAC floor** = deep-`m` sketch (`B̂·V` + combine) — MENC-Cubic scope, not Expand. |
| **Adversary class** | Classical PPT vs `HonestMAC`; poly-many adaptive MatExpand/digest queries and Freivalds transcripts at production EncDr rounds. Primary FAIL class: **MENC-Lin** (linear / degree-≤2 entrywise or MX-tile-local Extract surrogates); deg-≤3 and spectral/TMTO surfaces are mandatory firm checklist items (below). **MENC-Unres** may return INCONCLUSIVE. |
| **δ, ε** | `δ = 1/2`, `ε = 2⁻⁴⁰` above Freivalds false-accept (firm may retune in SOW — do not silently change) |
| **Win** | Accepting digest/seal with `Adv ≥ ε` at MAC cost `≤ (1−δ)·HonestMAC(n)` |

PASS/FAIL/INCONCLUSIVE return criteria are exactly those of §0.1 (state the MENC
label). A firm **PASS** on **MENC-Lin** is **not** a PASS on **MENC-Unres**, and
is still **not** a height raise. **C-15 remains OPEN.**

### Break modes (GAP-D1 pin)

Either §0.1 **FAIL** form is a **break** of `BTX-C15-NonCollapse-v1`. They are
two modes of the **same** assumption — not separate conjectures:

| Mode | §0.1 FAIL clause | Counts as assumption break? |
|---|---|---|
| **Full-digest FAIL** | Concrete vectors + measured cost: accepting Phase-A digest/seal with `Adv ≥ ε` at exact-int MAC `≤ (1−δ)·HonestMAC(n)` | **Yes** |
| **Structured-surrogate FAIL** | Affine / low-degree (deg ≤ 2) entrywise or MX-tile-local Extract surrogate matching on ≥ `N=10⁶` realistic real-tile `B32` samples **with** Freivalds-usable rewrite through `G,W,H` — **even without** a full accepting digest artifact | **Yes** |

Rationale: a Freivalds-usable structured surrogate is already a work-binding
collapse (reopens thin-panel / linear rewrite); requiring a packaged digest on
top would under-count the assumption. Deg-≤3 / spectral / TMTO checklist wins
that meet §0.1 thresholds likewise break the assumption; checklist items that
do not meet thresholds remain witnesses / INCONCLUSIVE, not breaks.

**C-15 remains OPEN.** Pinning break modes does **not** close the assumption,
does **not** authorize raising `nMatMulDRLTHeight`, and does **not** invent a
reduction to a classical named problem.

### Fragment lemma + PRF hybrid (Wave 3 Gap #2 — not a reduction)

Structured-surrogate FAIL is the primary class Sketch A maps toward a
**fragment** lemma / PRF break — not toward closing NonCollapse. The linked
formalization is a **historical per-cell ChaChaCell draft** and is not a lemma
for the current MX tile extractor (DRAFT, every step **GAP**-tagged):

→ **`doc/btx-matmul-v4.4-lt-c15-extract-nonlinearity-v1-2026-07-19.md`**
(`Extract-Nonlinearity-v1` + MatExpand nonce-packing hybrid outline).

That note must be restated over real 32-value MX tiles before use. It does
**not** prove the lemma, does **not** discharge Sketch A GAP-A2/A3, and does
**not** imply “ChaCha is fine ⇒ C-15 closed.” **C-15 remains OPEN.**

### Does NOT follow from ChaCha20-PRF alone

ChaCha20 being a secure PRF (in the AEAD sense), or even granting an ideal
stream on every distinct tile input, is **necessary evidence for the candidate
mixer**, not **sufficient for MatExpand work-binding**. The consensus-derived
`prf_key` is public, so the ordinary secret-key PRF game is not itself the
mining game. Neither formulation implies that there is no algebraic /
amortized / spectral shortcut
that produces Freivalds-accepting sketches cheaper than `HonestMAC`. Counterexample
template: wrap a low-rank public core (`rank(B32)≤w`) in a thin PRF that an
adversary can bypass via an affine fold, MX tile structure, truncated
`(i,bj)` salt, or TMTO across nonces — the PRF game can still hold on honest
queries while the PoW non-collapse game fails. Therefore
`BTX-C15-NonCollapse-v1` is a **separate, unreduced** assumption. Do not write
“ChaCha is fine ⇒ C-15 closed.”

### 0.3 Non-reduction one-pager annex

> **LT-C15 does not follow from SETH / OV / APSP / 3SUM / combinatorial BMM /
> ω / KW / ChaCha20-PRF / Freivalds.**

This is a **banner for reviewers**, not a proof of hardness. Do not invent a
SETH→C-15 (or OV/APSP/3SUM/BMM/ω/KW/PRF/Freivalds→C-15) reduction and treat it
as closing work-binding. The packet game (§0.1) and named assumption (§0.2)
remain the review target; C-15 remains **OPEN**.

| Tempting citation | Why it does **not** pin LT-C15 |
|---|---|
| **SETH** | Exp SAT ≠ poly MAC shortcut; no embedding into Expand/Extract/Freivalds |
| **OV** | Set-disjointness ≠ thin arithmetic GEMM + PRF Extract |
| **APSP** | Digests ≠ distance matrices; cubic floor is sketch `B̂·V`, not Expand |
| **3SUM** | Position salts + nonlinear Extract destroy additive 3-linear structure |
| **Combinatorial BMM** | Wrong alphabet / axis vs Extract nonlinearity |
| **ω (MM exponent)** | Upper bounds *weaken* “must pay n³”; algebraic bilinear ≠ Extract∘GWH |
| **KW secret low-rank** | Premise missing — `G,W,H` / `rank(B32)≤w` are **public** |
| **ChaCha20-PRF alone** | Distinguisher game ≠ `HonestMAC` lower bound (§0.2) |
| **Freivalds soundness** | Correctness / integrity ≠ miner MAC lower bound (ε floor only) |

**Fold / index (full Wave-1 map, attempted-target table, ranked gaps):**
`doc/btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md`
(detail: fine-grained survey + crypto survey + obstruction notes + drafts).
**Does not close C-15. Does not authorize raising `nMatMulDRLTHeight`.**

Operator hygiene (orthogonal track): hardness metric = `HonestMAC` MAC count;
efficiency / ASERT baselines = **fastest known exact** tournament — see
`doc/btx-matmul-v4.4-lt-c15-asert-fmm-calibration-2026-07-19.md`. Invent no
silicon. lt-gate **G5** (this packet ack) is orthogonal to FMM calibration.

### Attack-surface checklist (human firm)

Firms should explicitly attempt (or rule out with vectors/metrics) each surface.
Any concrete win against §0.1 thresholds is a **FAIL** of
`BTX-C15-NonCollapse-v1`.

| # | Surface | What to try / measure |
|---|---|---|
| 1 | **Affine surrogate** | Entrywise `f(B32)=α·raw+β` baseline plus tile-local affine features over all 32 real raws (normative rejection alignment is joint); Freivalds rewrite through `G,W,H` |
| 2 | **Degree ≤ 3** | Polynomial / low-degree LS surrogates over raw and tile context; require R² ≪ 0.05 on dense real-tile samples **or** exhibit usable rewrite |
| 3 | **Spectral / low-rank residue** | Shared-φ / Fourier structure on `B̂` after Extract; usable rank ≪ `n` for reassociation (`U`/`V` are rank-transparent) |
| 4 | **TMTO / cross-nonce** | Tables or partial Expand reuse across nonces / templates under I1′; cheaper than marginal MatExpand-B |
| 5 | **Related-nonce Mant/Scale XOR (legacy)** | Demoted ChaChaCell lanes `MANT`/`SCLE` and `Mant(raw)↔Scale(raw⊕Δ)` — not normative under MX; still a differential witness |
| 6 | **Truncated position salt** | Collapse full-width MX `(i,bj)` (`bj=j/32`) to low bits; equivalence classes that reopen ~`n/w=4×` panel shortcut |

### Witnesses ≠ proof (in-tree + reviewer kit)

| Artifact | Role |
|---|---|
| In-tree Boost tests (`matexpand_not_affine_in_raw`, `matexpand_extract_r2_nonapproximability`, `matexpand_c15b_affine_surrogate_sketch_rejected`, `matexpand_position_salt_differential`, goldens, …) | **Witnesses** that disagree with specific surrogate classes on sampled regimes |
| `contrib/matmul-c15-reviewer-kit/` (`reference_extract.py`, `toy_attack_harness.py`, goldens) | Build-free **reproduction** of Extract + toy collapse attempts |
| This named assumption + §0.1 game | What a firm must break or argue against |

Green witnesses / kit runs are **not** a cryptographic proof, **not** a
reduction, and **not** a C-15 PASS. Only an independent firm note against
§0.1 / this section (plus separate silicon/tip-soak/HeaderPoW gates) can move
activation process — and even then height raise is a separate operator
decision.

**Analog (non-claim):** cuPOW/Pearl conjectures transcript unpredictability /
batch low-rank equations; BTX conjectures Extract–Freivalds non-collapse under
public deterministic panels. Same *posture* (named work-binding conjecture),
different *encoding* — not interchangeable.

---

## 1. Normative objects (short)

Domain tags (V44LT) and map (see normative spec for full text):

```
Y = G · W          # s8×s8→s32, n×w, w=1024
B32 = Y · H        # s32×s8→s32, n×n
prf_key = SHA256("BTX_MATEXPAND_MXPRF_V44LT" ‖ seed_W)
e[i,bj] = SHA256("BTX_MATEXPAND_MXSCALE_V44LT" ‖ prf_key ‖ LE32(i) ‖ LE32(bj))[0] & 3
μ_tile = MX tile ChaCha M11 over B32[i, 32·bj ..]  # nonce_first=bj⊕'MXBL'
B̂[i,j] = μ[i,j] · 2^{e[i,j/32]}   # exact mul; alphabet [-48,48]
```

- Operand A: MatExpand with template-scoped `W_A` (I1′ amortized).
- Operand B: MatExpand with nonce-fresh `W_B` (marginal work).
- Sketch: `Ĉ = (U·Â)(B̂·V)` over `q=2⁶¹−1`, tile `b=2`, digest `H(σ‖Ĉ)`.
- Phase B seal (optional mode): `matmul_digest := SealWindowCommit(σ_anchor,
  Merkle(slot digests), Q*)` with `Q*∈{128,256,512}` and parent-MTP-threaded slot seeds.

Legacy `FoldInt32ToEmax48`, SplitMix `ExtractDequantMatExpandSplitMix`, and
per-cell `ExtractDequantMatExpandChaChaCell` (`BTX_MATEXPAND_PRF_V44LT`) are
**non-normative** (differential / related-nonce tests only). Related-nonce
Mant/Scale XOR identity notes apply only to that demoted twin.

**Candidate status:** Lever-B MX-block Extract is selected for `ENC_BMX4C_LT`
(~32× fewer MatExpand PRF blocks vs per-cell); **external review still required
before activation.** C-15 **OPEN**. Not closed.

Here “MX-block” names the exact logical mantissa/scale layout. It is not a
claim that mining executed native MXFP4. Current LT CUDA/HIP paths dequantize
to dense INT8 and use qualified IMMA/MFMA; native MXFP4 remains fail-closed.

### 1.1 Rank-≤`w=1024` structure of `B32` (load-bearing)

At production `n=4096`, `w = kMatExpandPanelW = 1024`:

- `Y = G·W` ⇒ `rank(Y) ≤ w = 1024`.
- `B32 = Y·H = (G·W)·H` ⇒ **`rank(B32) ≤ 1024`** unconditionally (over ℝ/ℚ; high-probability exact for random M11 panels).
- Honest MatExpand MAC is `Θ(n²·w)` per panel product (`G·W` and `Y·H`), **not** `Θ(n³)`.

**If Extract were linearized / omitted** (affine fold class / legacy `Fold`): Freivalds probes linear in `B̂` reassociate through `G,W,H` and reopen design-spec **L1** thin-panel collapse. Relative to treating the operand as an unstructured dense `n×n` ExactGemm (`Θ(n³)`), the panel factorization saves a factor on the order of **`n/w = 4096/1024 = 4`** (~**4×** arithmetic shortcut). Extract is **necessary** to destroy that class; sufficiency is **unproven** (this packet).

**`U` / `V` are rank-transparent:** Freivalds / sketch projectors are linear maps. They do **not** hide `rank(B32)≤1024` or a residual low-rank structure in `B̂`. Nonlinear, position-salted Extract is what must destroy usable low-rank residue for reassociation — not the projectors.

### 1.2 Parameter pin / justification

| Param | Normative | Justification / status |
|---|---|---|
| `w=1024` | `kMatExpandPanelW` | ExactGemm floor replacing SHA XOF; `n/w=4` is intentional priced structure **after** Extract. Rationale: Rank-1 param lever A (fatter MatExpand vs Extract). |
| M11 | E2M1-compatible `{0,±1,±2,±3,±4,±6}` | Frontier FP4 alphabet; prior BMX4 shortcut study. |
| `e∈{0..3}` | E8M0 shared on 32-col blocks per row | Discrete scale; `|μ·2^e|≤48`. |
| `b=2`, `m=n/2` | Deep-`m` under ENC-DR | ~3.6× tensor MACs; **cubic floor** is here (`B̂·V` / combine), not MatExpand. |
| `Q*∈{128,256,512}` (def 256) | Consensus window | Phase A = miner schedule; Phase B = seal (**regtest live**; public inert). Aggregate commitment ≠ GEMM proof. |
| Freivalds rounds | Consensus `nMatMulV4FreivaldsRounds` (mainnet pin **3**; see chainparams) | Soundness `~q^{-r}`; **TBD for firm SOW** if EncDr path uses a different effective round count — cite `SketchFreivalds` / verify path. |

**IdealExtract zero mass:** under IdealExtract (uniform `(μ,e)∈M11×{0..3}`, `v=μ·2^e`), `P(v=0) = 1/11 ≈ 9.1%` (four scale codes × `μ=0`). Distinguisher vs `U[-48,48]` is **by design**, not a PoW shortcut by itself.

### 1.3 Three pillars (why implementers believe the candidate blocks the linear class)

1. **Position-salted MX-block Extract** — E8M0 scale per `(i,bj)` + one ChaCha20
   stream per 32-col tile with full-width `pack(i,bj)` and B32-bound nibble mix;
   kills shared-φ / translation collapses (~32× fewer PRF blocks vs per-cell).
2. **Exact `F_q` binding** — sketch/combine over `q=2⁶¹−1` is exact integer; approximate / floating `B̂` is worthless for accepting digests.
3. **Nonce-fresh `W_B` twice nonlinear** — operand B uses header-fresh `W_B` (distinct PRF key from `seed_W`) **and** nonlinear Extract; template A amortization (I1′) does not collapse marginal B work.

These are **candidate arguments**, not a closed proof.

### 1.4 Normative byte encoding (pinned)

| Object | Encoding |
|---|---|
| `prf_key` | `SHA256("BTX_MATEXPAND_MXPRF_V44LT" ‖ seed_W)` → 32 bytes; Bitcoin `uint256` **little-endian** as `uint256::data()` / ChaCha20 key load. |
| Scale `e(i,bj)` | `SHA256("BTX_MATEXPAND_MXSCALE_V44LT" ‖ prf_key ‖ LE32(i) ‖ LE32(bj))[0] & 3`. |
| MX tile ChaCha | `nonce_first = bj ⊕ 0x4D58424C` (`MXBL`); `nonce_second = (uint64(i)<<32)\|bj` (**full-width**); `counter=remix`. Consume keystream nibbles; each candidate nibble XOR-mixed with `((uint32(raw)*0x9E3779B9)>>28)` before M11 rejection until 32 accepted μ. |
| Legacy cell (non-normative) | `BTX_MATEXPAND_PRF_V44LT`; `nonce_first = uint32(raw) ⊕ lane`; lanes `MANT`/`SCLE` — related-nonce differentials only. |
| Scale apply | **Exact mul** `μ * (1 << e)` as `int32` then narrow to `int8` — **never** signed left-shift on negative `μ` (UB). |

Device CUDA/HIP twins and `ExtractDequantMatExpandAccelReplica` must match bit-exactly. Metal injects ExactGemm only; Extract stays on host. See **`doc/btx-matmul-v4.4-lt-matexpand-position-salt.md`**.

---

## 2. Attack class LT-C15 (Freivalds reassociation)

**Claim under review:** there is no efficient adversary (per §0.1) that, given template
panels and Freivalds probes linear in `B̂`, recovers accepting sketches without
paying for MatExpand+BV+combine at the honest MAC floor (up to Freivalds soundness).

**Why implementers believe MX-block Extract+M11 blocks the linear class:**

- Extract is not an affine function of the GEMM accumulator `B32[i,j]`.
- Position salts `(i,bj)` and full `seed_W`-derived PRF key kill translation /
  panel-reuse collapses; B32-bound nibble mix keeps Extract non-XOF.
- M11 rejection + discrete scale `e∈{0..3}` destroy homomorphism useful to
  Freivalds reassociation through `fold(GWH)`.
- Mixer is reviewed in-tree ChaCha20 (tile stream), not SplitMix64.
- ~32× PRF dilution is a **cost** change, not a C-15 closure.

**Reviewer deliverables:**

| ID | Question | Expected artifact |
|---|---|---|
| C15-A | Exhibit (or rule out) an affine / low-degree surrogate `f(B32)` that matches Extract on a dense sample with advantage ≫ Freivalds ε | Proof sketch or concrete counterexample vectors |
| C15-B | Show whether Freivalds probes on `Ĉ` can be rewritten as probes on `G,W,H` alone | Reduction or impossibility argument |
| C15-C | Quantify any leftover structure (e.g. scale-lane bias, nibble remix cycles, ChaCha nonce packing) usable as a distinguisher | Notes + optional machine-checkable vectors |

Internal witnesses (not a substitute for external review):
`matexpand_not_affine_in_raw`, `matexpand_position_salt_differential`,
`matexpand_additivity_noncollapse`, `matexpand_chacha_prf_golden_vectors`
in `src/test/matmul_v4_lt_tests.cpp`.

## 3. Invariant I1′ (template amortization)

**Claim under review:** amortizing MatExpand-A / `U` / `V` / `P` once per
template does not create a cheaper-than-MatExpand-B path for fresh nonces.

**Multi-instance / Q* Phase A shape (Wave 3 Gap #9):** see
`doc/btx-matmul-v4.4-lt-c15-qstar-i1-amortization-game-2026-07-19.md` for the
explicit direct-sum *amortization game* (`BTX-I1p-QStar-DirectSum-Heuristic-v1`)
covering skinny single-nonce grind vs `t`-instance batches. That game is
**heuristic / unproved** — not a BRSV citation and not a C-15 close.

**Reviewer deliverables:**

| ID | Question | Expected artifact |
|---|---|---|
| I1-A | Can an adversary reuse a single MatExpand-B across many templates that share `P`? | Attack or binding argument via `DeriveSigma` / header hash |
| I1-B | Does fixing `Â` allow solving for `B̂` from sketch equations cheaper than GEMM? | Algebraic degree / MAC lower-bound discussion |
| I1-C | Confirm marginal priced work remains `{MatExpand-B, B̂·V, combine, digest}` | Stage-boundary checklist vs `matmul-v4-report --profile bmx4c-lt` |
| I1-D | Multi-instance: does `t` accepting Phase-A digests cost `≈ C_tmpl + t·HonestMAC`? | DS-A..E in the Q*/I1′ amortization-game note (heuristic) |

## 4. Batch algebra

**Claim under review:** integer-matrix associativity
`U·(Â·B̂)·V = (U·Â)·(B̂·V)` remains exact after MatExpand, and does **not**
reintroduce a linear fold of `G,W,H` into Freivalds.

**Reviewer deliverables:**

| ID | Question | Expected artifact |
|---|---|---|
| BA-A | Verify optimal factoring equals full-product sketch on MatExpand operands | Cross-check against `ComputeSketch` / `ComputeCombineModQ` |
| BA-B | Argue that associativity of exact int GEMMs does not commute past Extract | Short write-up |
| BA-C | Any batching / windowing (`Q*`) that accidentally linearizes Extract? | Yes/no with construction |

Internal witness: `matexpand_batch_algebra_optimal_equals_full` in
`src/test/matmul_v4_lt_tests.cpp`.

## 5. Seal-binding (Phase B)

**Claim under review:** when seal-as-PoW is active, the lottery object binds a
full `Q*` window of MTP-threaded sibling digests; skinny launches and
cross-anchor amortization fail.

**Reviewer deliverables:**

| ID | Question | Expected artifact |
|---|---|---|
| SB-A | Can two anchors share useful slot digests? | Binding via full `DeriveWindowSlotId(σ_anchor, j)` into seeds + Merkle leaf (`CommitWindowSlotLeaf`); `nNonce64` is only `ReadLE64(slot_id)` |
| SB-B | Does mutating one leaf / payload break `SealWindowCommit` and seal-auth? | Reduction to Merkle + tagged commit |
| SB-C | Parent-MTP omission / swap attack surface | Fail-closed checklist vs EncDr recompute |
| SB-D | Interaction with Phase-A sketch-cache auth (`H(σ‖Ĉ)==digest`) | Confirm Phase-A auth is correctly skipped in seal mode |

Internal witnesses: `phase_b_seal_round_trip_and_auth`,
`phase_b_seal_parent_mtp_slot_seeds_and_encdr`,
`seal_binding_sigma_and_merkle_leaf` in `src/test/matmul_v4_lt_tests.cpp`.

## 6. Suggested review procedure

1. Read normative + adversarial docs + pre-review synthesis; skim `src/matmul/matmul_v4_lt.{h,cpp}`.
2. **Build-independent kit (preferred first pass):** `contrib/matmul-c15-reviewer-kit/` —
   `python3 reference_extract.py` then `python3 toy_attack_harness.py --n 32 --w 4 --degree 3`.
   No node build required. See kit `README.md`, `rank_spectral_regression.md`,
   `named-assumption.md`, and **`reduction-attack-checklist.md`** (firm attacks → §0.1 FAIL).
   Oracle hints: `test-vectors.json` → `reduction_relevant_finding_notes` (high R², zero
   Freivalds residual, truncated salt equivalence class).
3. Optional in-tree witnesses (require `test_btx`): `matmul_v4_lt_tests`, especially
   `matexpand_chacha_prf_golden_vectors`, `matexpand_position_salt_differential`
   (full-width MX `(i,bj)`), `matexpand_extract_r2_nonapproximability` (affine/deg≤3 R²<0.05),
   `matexpand_c15b_affine_surrogate_sketch_rejected` (LS surrogate → forged sketch rejected by
   `VerifySketchBMX4CLT`). These are **witnesses**, not a firm PASS.
4. Attempt C15-A/B with a small `n` (e.g. 64) and dense accumulator samples; cost against §0.1.
5. Attempt I1 / batch-algebra rewrite against the optimal sketch path.
6. If Phase B is in the launch package, work SB-A..D against seal helpers.
7. Return a short signed note: **PASS / FAIL / INCONCLUSIVE** per table ID and for the §0.1 game /
   named assumption `BTX-C15-NonCollapse-v1` (§0.2), with any concrete vectors attached. Do **not**
   fill silicon nonce/s.

### 6.1 Wave-1 survey / reduction companions (not proofs)

**Non-reduction one-pager (packet §0.3):** LT-C15 does **not** follow from
SETH/OV/APSP/3SUM/BMM/ω/KW/PRF/Freivalds — banner + citation table; points here.

**Fold / index (start here for reduction research):**
`doc/btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md`
— executive non-reduction verdict, naming alignment
(`BTX-C15-NonCollapse-v1` ≡ `BTX-MatExpand-NonCollapse-v1` ≡ MENC family),
attempted-target table, ranked Wave 2/3 gaps. **Does not close C-15.**

Read individual surveys for detail — **none closes C-15**; all record gaps /
non-reductions:

| Doc | Role |
|---|---|
| `doc/btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md` | **Wave-1 fold / index** (this §6.1 entry point) |
| `doc/btx-matmul-v4.4-lt-c15-prereview-synthesis-2026-07-19.md` | Dual-panel empirics + reduction-research status |
| `doc/btx-matmul-v4.4-lt-c15-reduction-survey-finegrained-2026-07-19.md` | Fine-grained (SETH/OV/…) survey; MENC draft |
| `doc/btx-matmul-v4.4-lt-c15-reduction-survey-crypto-2026-07-19.md` | Crypto/PoW named-assumption survey |
| `doc/btx-matmul-v4.4-lt-c15-reduction-drafts-2026-07-19.md` | Reduction sketches with explicit GAP lists |
| `doc/btx-matmul-v4.4-lt-c15-reduction-obstructions-2026-07-19.md` | Why standard reductions miss hypotheses |
| `doc/btx-matmul-v4.4-lt-c15-asert-fmm-calibration-2026-07-19.md` | ASERT/FMM efficiency vs HonestMAC hardness (orthogonal) |
| `doc/btx-matmul-v4.4-lt-c15-related-nonce-reduction-note-2026-07-19.md` | Mant/Scale related-nonce → ExtractStruct |
| `doc/btx-matmul-v4.4-lt-c15-extract-nonlinearity-v1-2026-07-19.md` | Wave 3 Gap #2: `Extract-Nonlinearity-v1` + PRF hybrid outline (DRAFT; C-15 OPEN) |
| `doc/btx-matmul-v4.4-lt-c15-qstar-i1-amortization-game-2026-07-19.md` | **Wave 3 Gap #9:** Q*/I1′ direct-sum amortization game (heuristic; not BRSV) |

Leap checklist remains **C-15 OPEN** / public heights **`INT32_MAX`**:
`doc/btx-matmul-v4.4-lt-leap-checklist.md`.

## 7. How this plugs into the silicon campaign

```
measure-hardware.sh <cuda|metal|hip> --profile bmx4c-lt
        │
        ▼
matmul-v4-report-*.json   (schema_version 3, profile bmx4c-lt)
        │
        ▼
lt-gate.py <dir> --manifest parts.tsv [--cost ...] [--ack-external-c15]
```

- Silicon gates G1–G4 consume **measured** JSON only; missing
  `device_nonce_per_s` / labels / costs ⇒ **NO-GO** (fail closed).
- G5 (`--ack-external-c15`) is the operator attestation that **this packet**
  was completed by an independent cryptanalyst. Ack without that work is a
  process failure, not a math proof. C-15 remains **OPEN** until that review.
- G6–G8 remain separate (tip soak, Header-PoW/chainwork, seal-mode review).
- Nothing in this packet raises `nMatMulDRLTHeight`.

## 8. Explicitly not claimed

- External C-15 **closed** (candidate selected; review still required)
- Rank-1 GO/NO-GO **closed**
- Finite public `nMatMulDRLTHeight`
- Any B200/5090 nonce/s or nonce/$ figure
- Cryptographic proof that ChaCha20-PRF Extract has no cheaper algebraic shortcut
- That ChaCha-as-PRF alone is a MatExpand work lower bound
- That `BTX-C15-NonCollapse-v1` (§0.2) reduces to any standard named problem
  (SETH/OV/APSP/3SUM/BMM/ω/KW/PRF/Freivalds, …) — it is **named and unreduced**
  (see §0.3 one-pager + Wave-1 fold)
