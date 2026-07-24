> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# LT-C15 reduction research — Wave-1 fold / index (2026-07-19)

*Wave 2 — FOLD. Branch: `feat/bmx4c-exact-accel-lanes`.*  
*Status: **index + executive only**. Does **not** close C-15. Does **not**
authorize raising `nMatMulDRLTHeight`. No invented theorems.*

This file folds **all Wave-1 reduction artifacts** into one reviewer index.
Read the linked sources for proofs / sketches; treat this document as the
map, not a substitute for the packet game.

---

## 1. One-page executive

| Verdict | Status |
|---|---|
| Reduction of LT-C15 to a **standard named problem** (SETH, OV, APSP, 3SUM, combinatorial BMM, ω, OMV, ChaCha20-PRF alone, Freivalds soundness, KW secret low-rank, cuPOW transcript, SIS/LWE, …) | **NONE completed; none plausible near-term as written** |
| LT-C15 / MatExpand work-binding | **OPEN** |
| Public activation (`nMatMulDRLTHeight`) | Remains **`INT32_MAX`** (inert) |
| Height raise / Rank-1 GO from this fold | **NO** |

**What Wave 1 established.** Tempting citations from fine-grained complexity and
PoW literature share *taxonomy* with MatExpand non-collapse but miss load-bearing
hypotheses (public thin rank, wrong win condition, Extract nonlinearity, cost
model Θ(n²·w) vs dense cubic, correctness ≠ work). Residual useful lemmas are
mostly **negative** (what not to claim) plus fragment lemmas (ideal-PRF kills
affine surrogates; Freivalds sets ε floor only).

**What firms should stress-test.** Packet §0.1 cost-model game under the named
unreduced assumption below — not “SETH-hard MatExpand” or “ChaCha is a PRF ⇒
PASS.”

### Naming alignment (one assumption; MENC class labels)

| Label | Where | Use |
|---|---|---|
| **`BTX-C15-NonCollapse-v1`** | Packet §0.2; `named-assumption.md`; firm SOWs | **Canonical** id |
| **`BTX-MatExpand-NonCollapse-v1`** | Reduction drafts Sketch D | Alias emphasizing MatExpand+Extract+sketch MAC floor (not “ChaCha-NonCollapse”) |
| **MENC** (umbrella) | FG survey §3; Wave-1 drafts | Short alias for the same unreduced assumption |
| **MENC-Lin** | Packet §0.1 table; FG survey §3 | Deg-≤2 / Freivalds-linear primary FAIL class |
| **MENC-Unres** | Packet §0.1 table; FG survey §3 | Unrestricted PPT — often INCONCLUSIVE |
| **MENC-Cubic** | Packet §0.1 table; FG survey §3 | Optional **sketch-floor** strengthening (`B̂·V`+combine) — **not** MatExpand |

All are **aliases under one unreduced work-binding assumption** whose game is
packet §0.1. Prefer **`BTX-C15-NonCollapse-v1`** in firm SOWs.

**Hard rules (Wave 3 Gap #4):** **MENC-Lin PASS ≠ MENC-Unres PASS.** Sketch-floor /
deep-`m` claims are **MENC-Cubic** (or explicit “sketch floor”) — **do not**
mis-attribute them to MatExpand Θ(n²·w). Naming ≠ proof ≠ height raise.
C-15 remains **OPEN**.

**Aspirational inequality (not proved):**

```
Adv_LT-C15(A) ≤ Adv_PRF^ChaCha(B) + Adv_ExtractStruct(C) + Adv_NonCollapse(D) + negl(Freivalds)
```

`Adv_NonCollapse` / MENC residual is currently as ad-hoc as cuPOW’s algebraic
conjecture. Related-nonce Mant/Scale XOR belongs in **C** (`Adv_ExtractStruct`),
not as a ChaCha-PRF break and not as MatExpand amortization.

---

## 2. Wave-1 artifact index

| Artifact | Role |
|---|---|
| [`doc/btx-matmul-v4.4-lt-external-c15-packet.md`](btx-matmul-v4.4-lt-external-c15-packet.md) **§0.1–§0.2** | Falsifiable game + canonical named assumption |
| [`contrib/matmul-c15-reviewer-kit/named-assumption.md`](../contrib/matmul-c15-reviewer-kit/named-assumption.md) | Firm pointer to §0.2 |
| [`contrib/matmul-c15-reviewer-kit/reduction-attack-checklist.md`](../contrib/matmul-c15-reviewer-kit/reduction-attack-checklist.md) | A1–A7 attack menu → §0.1 FAIL |
| [`doc/btx-matmul-v4.4-lt-c15-reduction-survey-finegrained-2026-07-19.md`](btx-matmul-v4.4-lt-c15-reduction-survey-finegrained-2026-07-19.md) | FG survey (SETH…ω); drafts MENC |
| [`doc/btx-matmul-v4.4-lt-c15-reduction-survey-crypto-2026-07-19.md`](btx-matmul-v4.4-lt-c15-reduction-survey-crypto-2026-07-19.md) | Crypto/PoW named-assumption survey |
| [`doc/btx-matmul-v4.4-lt-c15-reduction-obstructions-2026-07-19.md`](btx-matmul-v4.4-lt-c15-reduction-obstructions-2026-07-19.md) | Why standard reductions fail for public Expand |
| [`doc/btx-matmul-v4.4-lt-c15-reduction-drafts-2026-07-19.md`](btx-matmul-v4.4-lt-c15-reduction-drafts-2026-07-19.md) | Sketches A–E + explicit GAP lists |
| [`doc/btx-matmul-v4.4-lt-c15-asert-fmm-calibration-2026-07-19.md`](btx-matmul-v4.4-lt-c15-asert-fmm-calibration-2026-07-19.md) | C-15 hardness vs ASERT/FMM efficiency (orthogonal) |
| [`doc/btx-matmul-v4.4-lt-c15-related-nonce-reduction-note-2026-07-19.md`](btx-matmul-v4.4-lt-c15-related-nonce-reduction-note-2026-07-19.md) | Mant/Scale lane-XOR → ExtractStruct |
| [`doc/btx-matmul-v4.4-lt-c15-extract-nonlinearity-v1-2026-07-19.md`](btx-matmul-v4.4-lt-c15-extract-nonlinearity-v1-2026-07-19.md) | Wave 3 Gap #2: EN-v1 + PRF hybrid outline (DRAFT; C-15 OPEN) |
| [`doc/btx-matmul-v4.4-lt-c15-qstar-i1-amortization-game-2026-07-19.md`](btx-matmul-v4.4-lt-c15-qstar-i1-amortization-game-2026-07-19.md) | Wave 3 Gap #9: Q*/I1′ direct-sum amortization game (heuristic) |
| [`doc/btx-matmul-v4.4-lt-c15-prereview-synthesis-2026-07-19.md`](btx-matmul-v4.4-lt-c15-prereview-synthesis-2026-07-19.md) | Dual-panel pre-review (empirical pillars) |
| `/tmp/c15_wave1_harden_requests.md` | Accumulated packet harden requests (Wave 1) |

---

## 3. Attempted targets → obstruction → residual useful lemma

| Attempted target / citation | Obstruction (why it does not pin C-15) | Residual useful lemma |
|---|---|---|
| **SETH** | Exp SAT ≠ poly MAC shortcut; no embedding into Expand/Extract/Freivalds | Do not claim “SETH-hard MatExpand” |
| **OV Hypothesis** | Combinatorial set-disjointness ≠ arithmetic thin GEMM + PRF Extract | Vocabulary only; wrong instance family |
| **APSP conjecture** | Digests ≠ distance matrices; cubic floor is sketch `B̂·V`, not Expand | Weak analogy for deep-m only — not a reduction |
| **3SUM** | Position salts + nonlinear Extract destroy additive 3-linear structure | No natural encoding |
| **Combinatorial BMM** | BTX is `F_q`/int not Boolean; thin rank≤w already “cheap”; wrong axis vs Extract | Alphabet / Strassen hygiene ≠ non-collapse |
| **ω (MM exponent)** | Upper bounds *weaken* “must pay n³”; algebraic bilinear ≠ Extract∘GWH | Never argue n³ information-theoretically mandatory |
| **OMV** | Online adaptive Mv ≠ offline public Expand | Loose “cannot skip Mv” metaphor only |
| **BRSV fine-grained PoW** | Prices OV/3SUM/APSP polynomials, not MatExpand | Demand explicit multi-instance game for I1′/Q* (vocabulary) |
| **cuPOW / Pearl transcript unpredictability** | Different encoding (transcript RO + noise vs Extract+sketch); no transfer | Closest *published peer* for stating `Adv_Shortcut`; Freivalds≠work pitfall |
| **KW secret low-rank** | **Secret not present** — `G,W,H` / `rank(B32)≤w` public deterministic | **Negative lemma:** Pearl⇏BTX; do not cite KW as substrate |
| **ChaCha20-PRF alone** | Distinguisher game ≠ HonestMAC lower bound; public `prf_key` | Ideal-model kill of affine/deg≤2 surrogates (fragment F1); insufficient for work-binding |
| **Ideal RO mining bounds** | Query lower bounds for unstructured search ≠ tensor MAC floor | Keep outer digest lottery separate from C-15 algebra |
| **Freivalds soundness** | Correctness / integrity ≠ miner MAC lower bound | Sets ε floor; split `Adv_forge` vs `Adv_shortcut` (**work–soundness conflation** = Sketch E dead end) |
| **SIS / LWE / Module-*** | No lattice instance in `B̂`/`Ĉ` | Avoid citation drift from shielded stack |
| **Entrywise-transform LRA / spectral** | Wrong `f` class vs ChaCha+M11; salts change model | Heuristic support for salts; schedule empirical SVD/CCA |
| **Strassen / Winograd exact FMM** | Same `Ĉ` bytes ⇒ binding intact; fewer MACs is efficiency | **ASERT calibration** only — orthogonal to C-15 FAIL/PASS |
| **Related-nonce Mant/Scale XOR** | PRF-consistent; leftover composition structure | Absorb into `Adv_ExtractStruct`; does **not** amortize MatExpand GEMM |
| **Primecoin / Equihash / RandomX / memory-hard** | Domain / metric mismatch | Process analogue (external review + residual risk), not theorems |
| **Sketch A** (surrogate ⇒ PRF / Extract-Nonlinearity) | Incomplete: GAP-A1..A6 (extraction, hybrid, quant, deg≥3) | Least-gappy *fragment* path for primary FAIL class — still draft |
| **Sketch B** (linear rewrite ⇒ full-rank heuristic) | Heuristic not theorem; taxonomy incomplete | Empirics ≠ proof; unrestricted class INCONCLUSIVE |
| **Sketch C** (KW reduction attempt) | Public B32 — premise missing | Useful **failure** sketch for reviewers |
| **Sketch D** (NonCollapse naming) | Further classical reductions absent (GAP-D2..D8) | Best intermediate naming; almost-definitional hop to §0.1 |
| **Sketch E** (Freivalds ⇒ work) | Named fallacy | Quarantine; do not ship as path |

---

## 4. Ranked remaining research gaps (Wave 2/3)

*Only falsifiable empirics / literature-tightening / explicit game formalization.
No fake theorems. Closing a gap below does **not** by itself close C-15 or
raise height.*

| Rank | Gap | Falsifiable / tightening deliverable | Source GAP ids |
|---|---|---|---|
| **1** | Pin break modes of `BTX-C15-NonCollapse-v1` | Packet wording: structured-surrogate FAIL vs full-digest FAIL both count as assumption breaks | GAP-D1; harden log |
| **2** | Formalize `Extract-Nonlinearity-v1` + PRF hybrid under MatExpand nonce packing | **Landed (DRAFT):** [`btx-matmul-v4.4-lt-c15-extract-nonlinearity-v1-2026-07-19.md`](btx-matmul-v4.4-lt-c15-extract-nonlinearity-v1-2026-07-19.md) — lemma + H0–H3 hybrid + ExtractStruct absorption + Adv map; **GAP-EN1..EN10** remain; **C-15 OPEN** | GAP-A2/A3; related-nonce note |
| **3** | Taxonomy of “linear Freivalds rewrite” beyond affine/shared-φ | **Wave-3 DONE (doc):** `contrib/matmul-c15-reviewer-kit/reduction-attack-checklist.md` §LFR (LFR-0..11) + heuristic/theorem marks + oracles; does **not** close C-15 / Sketch B | GAP-B1; A3/A5 checklist |
| **4** | Separate MENC-Lin vs MENC-Unres vs MENC-Cubic in packet language | **Wave-3 DONE (doc):** packet §0.1/§0.2 class-label table + fold naming; **Lin PASS ≠ Unres PASS**; sketch-floor ≠ MatExpand; C-15 OPEN | FG survey §3; harden log |
| **5** | Related-nonce firm vector pack | **Shipped (Wave 3):** ≥32 identity tuples in `test-vectors.json` + C++/`reference_extract` witness; B32 Δ-collision NC (synthetic n=16 + honest n=8). Residue documented; **not** C-15 closure | Related-nonce §4; checklist A7 |
| **6** | Spectral / approx-`B̂` Freivalds forgery probes | Empirical SVD/CCA / multi-probe residual campaign at `n∈{64,256}`; report only if §0.1 win | GAP-B3; crypto survey §6.3 |
| **7** | Non-reduction annex polish | **Wave-3 DONE (doc):** packet §0.3 one-pager “LT-C15 does not follow from SETH/OV/APSP/3SUM/BMM/ω/KW/PRF/Freivalds” → this fold; does **not** close C-15 | FG survey §6; harden log |
| **8** | ASERT vs HonestMAC operator hygiene | **Wave-3 DONE (doc):** leap checklist calibration table + lt-gate G5 comments — tournament = fastest known exact; G5 ⊥ FMM; no silicon invention; C-15 OPEN | ASERT/FMM calibration |
| **9** | Multi-instance / I1′ direct-sum *shape* (not BRSV citation) | **DONE (Wave 3):** explicit game in `doc/btx-matmul-v4.4-lt-c15-qstar-i1-amortization-game-2026-07-19.md` — heuristic / unproved; packet §3 I1-D + §6.1 link | Crypto survey §3; GAP-D8 |
| **10** | Optional consensus redesign (KW/transcript) | **SKIPPED** (Wave 3) — out of scope unless product fork | Sketch C; obstructions §5 |

**Explicitly not scheduled as “prove C-15”:** reductions to SETH/OV/KW/cuPOW
without embeddings (GAP-D3–D6 remain open research, not deliverable theorems).

---

## 5. Cross-links for packet / synthesis maintainers

- Packet §6.1 should list **this fold** as the Wave-1 index.
- Pre-review synthesis “Reduction research status” should point here once Wave-1
  surveys land.
- Harden requests log: `/tmp/c15_wave1_harden_requests.md` (many items DONE in
  packet-harden wave; residual items = §4 ranks above).

---

## 6. Explicit non-claims (file-level)

- C-15 cryptographically closed — **NO**
- Finite public `nMatMulDRLTHeight` — **NO**
- Named-problem reduction completed — **NO**
- ChaCha-PRF alone ⇒ MatExpand MAC lower bound — **NO**
- KW / Pearl ⇒ MatExpand hard — **NO**
- Freivalds alone ⇒ work lower bound — **NO**
- This fold invents theorems — **NO**

*End of Wave-1 fold. C-15 remains OPEN.*
