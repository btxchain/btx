# LT-C15 ↔ fine-grained complexity: reduction survey

*Date: 2026-07-19. Wave 1 — SURVEY only.*  
*Branch context: `feat/bmx4c-exact-accel-lanes`.*  
*Sources: `doc/btx-matmul-v4.4-lt-external-c15-packet.md` §0.1 / §1.1–§1.3;
`/tmp/c15_audit_prior_art.md`; `/tmp/c15_audit_synthesis_grok.md`;
standard FG literature (cited by name/year below).*

---

## NO CLAIM OF C-15 CLOSED

| Explicit non-claim | Status |
|---|---|
| C-15 cryptographically closed | **NO** — this survey does not close it |
| Completed reduction from any named FG conjecture to LT-C15 | **NO** — none constructed here |
| ChaCha20-PRF ⇒ MatExpand work lower bound | **NO** — packet §0.1 already forbids this inference |
| Raise `nMatMulDRLTHeight` / Rank-1 activation | **NO** — out of scope; remains inert |
| Invented theorems / fake citations | **Forbidden** — statements below are standard named assumptions or clearly marked **draft novel** |

This document is a **mapping and obstruction analysis**, not a security proof.

---

## 0. What LT-C15 actually asks (cost-model pinned)

From packet §0.1 / §1.1 (load-bearing):

```
Y = G·W,   B32 = Y·H = (G·W)·H     # rank(B32) ≤ w = 128
B̂[i,j] = ExtractChaCha20PRF(B32[i,j], i, j, prf_key)  # position-salted
Ĉ = (U·Â)(B̂·V) over F_q, q = 2⁶¹−1                   # exact Freivalds binding
```

| Object | Honest cost class | Notes |
|---|---|---|
| MatExpand ExactGemm | **Θ(n²·w)** with `w=128` fixed | Thin panels; **not** Θ(n³) |
| Marginal cubic floor | **`B̂·V` + combine `P·Q`** (deep-`m`, `m=n/2`) | Sketch path after Extract |
| Public structure | Deterministic Expand from seeds; **no secret low-rank** | Rank ≤ `w` is public and intentional |
| Win condition | Accepting digest / Freivalds transcript at `≤ (1−δ)·HonestMAC` with `Adv ≥ ε` | Forgery/shortcut game, not “output B̂ correctly” |

**Scoping correction (reaffirmed):** a fine-grained statement of the form “no O(n^{3−ε}) algorithm for dense n×n GEMM” does **not** pin MatExpand alone. Any reduction attempt that ignores this is malformed.

---

## 1. Candidate named assumptions — formal statements

### 1.1 Summary table

| ID | Named assumption | Canonical refs (name/year) | Formal hardness shape | Reduction FROM → “no MatExpand shortcut” in principle? | BTX obstruction (concrete) |
|---|---|---|---|---|---|
| FG-1 | **SETH** | Impagliazzo–Paturi 2001; Calabro–Impagliazzo–Paturi 2009 | ∀ε>0 ∃k: k-SAT ↛ O(2^{(1−ε)n}) | **Very unlikely / path-only via long chain** | Exponential SAT hardness ≠ poly(n) MAC shortcut on public Expand+Extract; no known bridge to Freivalds forgery |
| FG-2 | **OV Hypothesis** | Williams 2005 lineage; Abboud–Williams–Yu 2015 (popular form) | OV on n vectors, d=ω(log n): ↛ O(n^{2−ε} poly(d)) | **Unlikely as written** | OV is combinatorial set-disjointness; MatExpand is arithmetic thin GEMM + PRF Extract; instance distributions differ |
| FG-3 | **APSP conjecture** | Vassilevska Williams–Williams 2010/2018 survey lineage | APSP (suitable weights) ↛ O(n^{3−ε}) | **No direct** | APSP targets all-pairs distances; BTX digest lottery needs sketch acceptance, not distance matrix |
| FG-4 | **3SUM conjecture** | Gajentaan–Overmars 1995 folklore; Patrascu 2010; modern FG form | 3SUM ↛ O(n^{2−ε}) (model-dependent) | **No direct** | Quadratic element problem; no natural encoding into position-salted Extract / Freivalds |
| FG-5 | **Combinatorial BMM** | Abboud–Williams 2014; folklore “no combinatorial O(n^{3−ε}) Boolean MM” | No *combinatorial* truly subcubic Boolean matrix mult | **Partial analogy only** | (a) BTX is integer/`F_q` arithmetic not Boolean; (b) MatExpand already thin Θ(n²w); (c) “combinatorial” excludes algebraic Strassen — wrong axis for Extract |
| FG-6 | **Algebraic MM exponent ω** | Strassen 1969; Coppersmith–Winograd 1990; Alman–Duan–Williams–Xu–Xu–Zhou 2025: **ω < 2.371339** | Exists O(n^{ω+o(1)}) field MM; ω ≥ 2 trivial | **Does not yield C-15** | ω is an *upper* bound (algorithms exist). Subcubic algebraic MM **weakens** “must pay n³”, never proves miner must pay HonestMAC after Extract |
| FG-7 | **Online Matrix-Vector (OMV)** | Henzinger–Krinninger–Nanongkai–Raghavendra 2015 | Online Mv products hard ≈ naive under polynomial preprocessing | **Loose analogy** | OMV is online adaptive queries; BTX Expand is offline public panels + one-shot sketch |
| FG-8 | **#NSETH / fine-grained PoW (BRSV)** | Ball–Rosen–Sabo–Vasu ePrint 2017/203 → 2018/559 | PoW from OV/3SUM/APSP evaluations | **Historical cousin, not a reduction target** | BRSV prices *evaluation of hard FG problems*; BTX prices deterministic Expand+Extract+sketch — different problem family |
| FG-9 | **cuPOW batch low-rank equations** (ad-hoc) | Komargodski–Weinstein ePrint 2025/685 | Conjectured hardness of batch low-rank random linear equations under transcript RO | **Same meta-class, different encoding** | Closest PoUW cousin; still **not** a standard FG conjecture; BTX uses Extract+sketch Freivalds not transcript hash |
| **NEW** | **MENC / LT-C15 Work-Binding** (draft) | *This survey — novel* | See §3 | **This is the needed intermediate** | Explicitly tailored to packet §0.1 game |

---

### 1.2 Formal statements (research-quality; no invented theorems)

#### FG-1 — Strong Exponential Time Hypothesis (SETH)

**Assumption (standard form).** For every real ε > 0 there exists an integer k ≥ 3 such that *k*-SAT on n variables cannot be solved by a deterministic (or randomized, depending on formulation) algorithm in time O(2^{(1−ε)n}).

**Could a reduction FROM SETH TO “no MatExpand shortcut” exist in principle?**  
Only via a long, currently nonexistent chain: SETH → some poly-time combinatorial problem → an encoding into Expand seeds / Extract / Freivalds transcripts whose shortcut would yield a SETH break. No such encoding is known; constructing one would itself be a research contribution comparable to BRSV-style FG-PoW, and would still need to match BTX’s **public thin-panel + Extract** cost model.

**BTX obstruction.** SETH hardness is exponential in formula size. LT-C15 is a polynomial MAC-count gap at fixed production `n∈{64,256,4096}`. Public deterministic panels + PRF Extract do not present SAT-search structure. A shortcut that skips MatExpand MACs need not decide hard SAT instances.

#### FG-2 — Orthogonal Vectors (OV) Hypothesis

**Assumption (common fine-grained form).** For every ε > 0 there is no algorithm that, given two sets A,B of n Boolean vectors in dimension d = ω(log n), decides whether some a∈A, b∈B are orthogonal (⟨a,b⟩=0) in time O(n^{2−ε} · poly(d)).

**Reduction in principle?**  
OV is the workhorse for many *quadratic* lower bounds. In principle one might hope to embed OV into “cheap accepting digests,” but the natural embeddings produce combinatorial detection problems, not Freivalds-linear forgeries through `Extract∘(GWH)`.

**BTX obstruction.**  
1. Honest MatExpand is Θ(n²w) with fixed w — already “quadratic×constant,” not the OV quadratic bottleneck.  
2. Extract is cryptographic / statistical (ChaCha20 keystream + M11 reject), not an OV gadget.  
3. Verifier checks sketch consistency over `F_q`, not orthogonality witnesses.

#### FG-3 — APSP conjecture

**Assumption (standard FG form).** There is no O(n^{3−ε})-time algorithm (for any ε>0) for All-Pairs Shortest Paths on n-node graphs with integer weights from a polynomial range (equivalently: no truly subcubic APSP in the stated model).

**Reduction in principle?**  
APSP is the canonical *cubic* barrier. A reduction would need “accepting BTX digest cheaper than HonestMAC ⇒ truly subcubic APSP.” That requires BTX instances to be APSP-hard in the worst case — false for PRF-derived public Expand instances at fixed n.

**BTX obstruction.** Digests bind `H(σ‖Ĉ)` under Freivalds; they do not encode distance matrices. Moreover the cubic honest work is **`B̂·V` + combine**, which is rectangular sketch MM *after* Extract — not APSP, and not MatExpand.

#### FG-4 — 3SUM conjecture

**Assumption (modern form, slightly model-dependent).** There is no O(n^{2−ε})-time algorithm for 3SUM: given n integers, decide whether three sum to 0 (or a target), in a standard word-RAM / real-RAM formulation used in FG literature.

**Reduction in principle?**  
Unlikely without a custom gadget that turns Extract/Freivalds acceptance into a 3SUM oracle. No natural 3-linear form in MatExpand after nonlinear Extract.

**BTX obstruction.** Position salts `(i,j)` and discrete `(μ,e)` destroy the additive combinatorial structure 3SUM reductions rely on. Exact `F_q` Freivalds is bilinear in sketch factors, not a 3SUM instance.

#### FG-5 — Combinatorial Boolean Matrix Multiplication (combinatorial BMM)

**Assumption (informal but widely used).** There is no *combinatorial* algorithm that multiplies n×n Boolean matrices in O(n^{3−ε}) time. (“Combinatorial” roughly means: no reliance on algebraic Strassen / Coppersmith–Winograd–style bilinear algorithms.)

**Reduction in principle?**  
Closest *shape* among classical FG statements (cubic barrier for matrix-shaped work). Still fails as a C-15 reduction target for multiple independent reasons (below).

**BTX obstruction.**  
1. **Alphabet / ring:** BTX uses s8/s32 ExactGemm and `F_q` sketches, not Boolean (∨,∧) products.  
2. **Thin panel:** `B32=(G·W)·H` has **rank ≤ w=128**; honest MatExpand is Θ(n²w), already “combinatorially cheap” relative to dense n³ — Extract exists precisely because that structure is public.  
3. **Wrong hardness axis:** combinatorial BMM separates combinatorial vs algebraic *bilinear* MM; LT-C15 hardness is about **nonlinear Extract** blocking Freivalds reassociation — orthogonal to Strassen vs schoolbook.  
4. **Win condition:** adversary may forge digests without outputting a correct Boolean product.

#### FG-6 — Matrix-multiplication exponent ω (Strassen–Winograd lineage)

**Definition.** ω is the infimum of real numbers such that n×n matrices over a field can be multiplied in O(n^{ω+o(1)}) arithmetic operations.

**Current best published upper bound (as of this survey’s sources):**  
ω < **2.371339** (Alman, Duan, Vassilevska Williams, Y. Xu, Z. Xu, Zhou — *More Asymmetry Yields Faster Matrix Multiplication*, 2025; improves Vassilevska Williams–Xu–Xu–Zhou SODA 2024 bound ω < 2.371552).

**Historical anchors:** Strassen (1969) ω < 2.81; Coppersmith–Winograd (1990) and subsequent laser-method improvements.

**Does ω help C-15?**  
**No — it cuts the wrong direction.** Existence of O(n^ω) algorithms means algebraic bilinear MM can be *faster* than n³. That cannot prove a miner must pay `HonestMAC`. Practical constants make CW-style algorithms irrelevant at n=4096, but that is an engineering fact, not a FG reduction.

**BTX obstruction.** Extract is **entrywise and nonlinear** (PRF + rejection + scale). Algebraic MM complexity applies to bilinear maps `(X,Y)↦XY`, not to `Extract∘(GWH)`. Even for the post-Extract sketch `B̂·V`, ω-style algorithms do not create a *cryptanalytic* Freivalds reassociation through panels; they are just faster honest evaluation (still within priced work if counted in MAC/op models carefully — packet uses exact-int MAC count, which already prices the honest path).

#### FG-7 — Online Matrix-Vector conjecture (OMV)

**Assumption (Henzinger et al. 2015 form, paraphrased).** There is no algorithm that preprocesses an n×n matrix in polynomial time and then supports n online matrix-vector multiplications in total time n^{2−ε} (for some ε>0) with error probability ≤1/3.

**Reduction in principle?**  
Suggestive for “you cannot skip Mv work online,” but BTX’s Expand is not an online Mv service — panels are public and Expand is a fixed offline ExactGemm.

**BTX obstruction.** No adaptive online Mv interface in consensus MatExpand; adversary sees public `G,W,H` seeds and tries shortcut digests. OMV’s hardness relies on adaptive query lower bounds that do not map to one-shot PoW nonces.

#### FG-8 — Fine-grained useful PoW (BRSV)

**Construction class.** Ball–Rosen–Sabo–Vasu (ePrint 2017/203, updated 2018/559) build PoW schemes whose security is argued from OV / 3SUM / APSP-style evaluations (polynomial evaluation / fine-grained problems), with non-amortization concerns.

**Relevance.** Shows that *some* PoW can be tied to named FG conjectures — but only by **pricing those problems directly**. BTX does not ask miners to solve OV/APSP; it asks them to run Expand+Extract+sketch.

**BTX obstruction.** Replacing MatExpand with an OV instance would be a different consensus design. No reduction from BRSV security to LT-C15 (or converse) is claimed in literature or here.

#### FG-9 — cuPOW “batch low-rank random linear equations” (ad-hoc, not classical FG)

**Assumption (Komargodski–Weinstein 2025, paraphrased).** Under a random-oracle transcript-binding of noisy/low-rank-corrected matmul, batch low-rank random linear equations remain hard — used to argue no cheap correction-identity shortcut.

**Relevance.** Highest **meta-class** overlap with LT-C15 (prevent algebraic bypass of priced matmul). Still **not** a standard SETH/OV/APSP conjecture.

**BTX obstruction.** Encoding differs: Pearl/cuPOW uses **transcript hashing**; BTX uses **position-salted Extract + sketch Freivalds**. Prior-art audit: shared taxonomy, **no transfer of proof**.

---

## 2. Cross-cutting obstructions (why standard FG does not pin C-15)

| Obstruction | Why it blocks “standard FG ⇒ LT-C15” |
|---|---|
| **O1 — Cost-model mismatch** | MatExpand is Θ(n²·w), w=128 fixed. “No O(n^{3−ε})” statements target dense cubic problems. |
| **O2 — Public thin rank** | `rank(B32)≤w` is unconditional and public. Classical hard MM instances are dense unstructured products. |
| **O3 — Wrong win condition** | C-15 adversary wins by **accepting digests / Freivalds transcripts**, not by outputting correct `B32`/`B̂` as a named FG output. |
| **O4 — Nonlinear Extract** | Hardness after Extract is about destroying homomorphism for reassociation; FG MM conjectures are about bilinear product complexity. |
| **O5 — Deterministic PRF instances** | FG hardness is worst-case (or carefully planted). BTX instances are seed-derived and public; average-case FG is a different (harder) theory. |
| **O6 — Cubic floor elsewhere** | Honest cubic MAC mass is deep-`m` `B̂·V`+combine, not MatExpand. Collapsing MatExpand without collapsing sketch work is a *different* shortcut than beating APSP. |
| **O7 — Exact Freivalds ≠ work** | Freivalds proves product consistency, not MAC lower bounds (Freivalds 1979; PoUW literature pitfall). |
| **O8 — No secret low-rank** | Crypto low-rank assumptions often hide structure; BTX intentionally exposes panels then kills fold via Extract. |

---

## 3. Explicit answer: can C-15 reduce to a *standard* fine-grained conjecture as written today?

### Verdict

**No.** As the named conjectures are stated today (SETH, OV, APSP, 3SUM, combinatorial BMM, OMV, and the ω *upper-bound* theory), there is **no known — and no plausible near-term — reduction** from any of them **to** the packet §0.1 LT-C15 game (“no `(1−δ)·HonestMAC` accepting shortcut”).

What *is* true:

1. **ChaCha-as-PRF** can support a *fragment* (Extract not efficiently affine in `B32` in the ideal model) — already separated in prior-art audit as **F1**, insufficient for work-binding.  
2. **cuPOW-style ad-hoc algebraic conjectures** share the meta-class but do not transfer.  
3. Closing C-15 in FG style requires a **new intermediate assumption** (draft below), optionally with a future reduction *from* a standard conjecture *into* that intermediate — that second step is **open research**, not available off the shelf.

### Draft intermediate assumption (novel — not a theorem)

**Name:** **MENC** — *MatExpand–Extract Non-Collapse*  
*(alias: LT-C15 Work-Binding Conjecture)*

**Parameters.** Production pin `(n,w,b,m,q,Extract)=` packet §0.1; thresholds `(δ,ε)` as in the packet game (defaults `δ=1/2`, `ε=2^{-40}` above Freivalds false-accept).

**Assumption (MENC).**  
No classical probabilistic polynomial-time adversary, given public template/nonce seeds and oracle access to honest MatExpand/digest/Freivalds transcripts (poly-many, adaptive), outputs an accepting Phase-A digest (or seal if SB annex in scope) with advantage `≥ ε` over Freivalds false-accept while using exact-int MAC count

```
MAC(Adv) ≤ (1 − δ) · HonestMAC(n)
```

on the priced marginal unit (MatExpand-B + `B̂·V` + combine), except with negligible probability in the security parameter / round count.

**Restricted variant (MENC-Lin) — primary FAIL class in packet.**  
Same, but adversary restricted to linear / degree-≤2 entrywise surrogates of Extract and Freivalds-linear rewrites through `G,W,H`.

**Unrestricted variant (MENC-Unres).**  
No degree restriction — expected **INCONCLUSIVE** for years; do not equate MENC-Lin PASS with MENC-Unres PASS.

**Optional sketch-only strengthening (MENC-Cubic).**  
No shortcut that reduces **`B̂·V`+combine** below `(1−δ)` of honest deep-`m` MAC while keeping Extract ideal — separates MatExpand collapse from sketch-floor collapse.

**Status.** **Draft novel assumption** for external reviewers. Analogous in spirit to cuPOW’s batch low-rank equations conjecture, **not** equivalent, **not** reduced to SETH/OV/APSP.

**Ideal closing inequality (aspirational — not proved here):**

```
Adv_LT-C15(A) ≤ Adv_PRF^ChaCha(B) + Adv_ExtractStruct(C) + Adv_MENC(D) + negl(Freivalds)
```

with explicit games for B/C/D. **This survey does not establish that inequality.**

---

## 4. Where FG *does* usefully inform packet wording (without false reductions)

| Lesson from FG / PoUW literature | Packet / review implication |
|---|---|
| Correctness checkers ≠ work lower bounds (Freivalds pitfall) | Keep §0.1 cost game separate from Freivalds soundness |
| Named FG PoW prices the hard problem directly (BRSV) | Do not claim “SETH-hard MatExpand”; price Expand+Extract+sketch honestly |
| Combinatorial vs algebraic MM is a real distinction | Alphabet/Strassen cryptanalysis ≠ Extract non-collapse |
| ω < 2.38 exists | Never argue “n³ is information-theoretically mandatory” for bilinear MM |
| Average-case FG is harder than worst-case | Public PRF instances need MENC average-case language |
| Thin / structured MM is often easy | Rank≤w without Extract is the known L1 collapse — Extract is load-bearing |

---

## 5. Reduction-feasibility matrix (reviewer quick ref)

| From \ To | MENC-Lin | MENC-Unres | “No MatExpand Θ(n²w) eval” | “No deep-m sketch shortcut” |
|---|---|---|---|---|
| SETH | no known path | no known path | no | no |
| OV | no known path | no known path | no | no |
| APSP | no | no | no (wrong cost) | weak analogy only |
| 3SUM | no | no | no | no |
| Comb. BMM | analogy only | no | conflicts (thin rank) | weak |
| ω theory | **contra-positive useless** | same | same | faster honest MM ≠ break |
| OMV | loose | no | no | loose |
| cuPOW ad-hoc | meta-class cousin | cousin | different encoding | different encoding |
| ChaCha-PRF alone | supports non-affinity fragment | insufficient | insufficient | insufficient |

---

## 6. Suggested packet hardenings (from this survey)

*(Also appended to `/tmp/c15_wave1_harden_requests.md`.)*

1. State explicitly in the external packet: **“LT-C15 is not claimed to follow from SETH/OV/APSP/3SUM/combinatorial BMM/ω.”**  
2. Name **MENC / MENC-Lin** (or equivalent) as the work-binding assumption; separate from ChaCha-PRF fragment.  
3. Keep cost tables distinguishing **MatExpand Θ(n²w)** vs **sketch cubic floor** in every reduction-shaped claim.  
4. Require FAIL criteria to exhibit MAC accounting against `HonestMAC`, not merely “subcubic algorithm exists.”  
5. Add a one-page “non-reduction” annex pointing here, so reviewers do not invent SETH reductions.

---

## 7. Citations (named; for reviewer follow-up)

| Topic | Citation |
|---|---|
| SETH | Impagliazzo & Paturi, *On the complexity of k-SAT*, JCSS 2001; Calabro, Impagliazzo, Paturi, *The complexity of satisfiability of small depth circuits*, 2009 |
| OV / FG framework | Williams; Abboud, Williams, Yu, *Speeding up the Orthogonal Vectors problem…*, ICALP 2015; Vassilevska Williams surveys on fine-grained complexity |
| APSP | Vassilevska Williams & Williams, *Subcubic equivalences between path, matrix, and triangle problems*, FOCS 2010 / JACM lineage |
| 3SUM | Gajentaan & Overmars 1995; Pătraşcu, *Towards polynomial lower bounds for dynamic problems*, STOC 2010 |
| Combinatorial BMM | Abboud & Williams, *Popular conjectures imply strong lower bounds for dynamic problems*, FOCS 2014 |
| ω upper bounds | Strassen 1969; Coppersmith–Winograd 1990; Vassilevska Williams–Xu–Xu–Zhou, SODA 2024 (ω<2.371552); Alman–Duan–Williams–Xu–Xu–Zhou 2025 (ω<2.371339) |
| OMV | Henzinger, Krinninger, Nanongkai, Raghavendra, *Unifying and strengthening hardness for dynamic problems…*, STOC 2015 |
| FG PoW | Ball, Rosen, Sabo, Vasu, ePrint 2017/203 → 2018/559 |
| Freivalds | Freivalds 1979 |
| cuPOW | Komargodski & Weinstein, ePrint 2025/685 |
| In-repo | `doc/btx-matmul-v4.4-lt-external-c15-packet.md`; `/tmp/c15_audit_prior_art.md` |

---

## 8. One-paragraph bottom line

**LT-C15 does not sit under a standard fine-grained conjecture as those conjectures are written today.** SETH/OV/APSP/3SUM/combinatorial BMM/OMV fail on cost model, public thin rank, win condition, and/or Extract nonlinearity; ω cuts the wrong way. The honest path is to treat work-binding as a **named novel assumption (MENC)**, prove or empirically support **MENC-Lin** for the packet’s primary FAIL class, keep ChaCha-PRF as a separate fragment, and leave MENC-Unres open — **without claiming C-15 closed** and without raising `nMatMulDRLTHeight`.
