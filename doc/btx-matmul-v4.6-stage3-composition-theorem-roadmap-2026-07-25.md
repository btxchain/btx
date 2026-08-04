# Stage-3 certified-soundness roadmap — proof-obligation ledger (P1–P6) — 2026-07-25

> **MatMul v4.7 transition status:** historical proof-obligation analysis for
> possible Epochs B–D. It cannot authorize Epoch A, which requires complete
> Profile-1 ExactReplay. Any mandatory proof must be durable consensus data;
> Profile 2 is reserved for the separate Epoch-D activation. See
> `doc/btx-matmul-v4.7-transition-roadmap.md`.
>
> **Scope note (local independent track).** The code-verified findings below (esp. "M-LINK
> absent", "92.6 not in code") are established against the **COMMITTED** tree at HEAD. the relay host's
> relayed Stage-3 output describes an *uncommitted* CTL/LogUp link layer and a 92.6 FRI screen
> that would live in `src/matmul/matmul_v4_rc_stage3_*` — files not in this checkout. So read
> "does not exist in the shipped recursion" as **"absent from the committed tree; must be
> confirmed present, committed, and auditable in the stage3 tree once `wip/stage3-relation-local`
> lands."** The obligation stands either way: the closure must be committed and externally
> auditable, and the 92.6 screen must be reproduced, before certified soundness can be claimed.
> Companion arithmetic: `doc/btx-matmul-v4.6-stage3-global-composition-reconciliation-2026-07-25.md`.
> This is the theorem + obligation structure produced by an adversarial draft→gap-hunt pass
> (5 skeletons, opus gap review, 1 skeleton rejected).

---

# PR-89 Global Composition Soundness — Consolidated Deliverable Toward *Certified* Soundness

> **Status banner (must survive into any downstream artifact): ANALYSIS ONLY. NOT CLOSED, NOT AUDITED, NOT ACTIVATED.** Consensus authority remains ExactReplay; `kRCGkrFormalSoundnessReady = false`; `nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`. External cryptographic audit is a hard precondition for any soundness claim. Nothing below is asserted as CLOSED.

## 0. Ground-truth corrections established against the shipped tree (read first)

Three facts, verified in code, override the optimistic framing shared by all five proof skeletons. Every number and every theorem precondition downstream depends on them.

| Claim in skeletons | Shipped reality (verified) | Anchor |
|---|---|---|
| Per-node floor **92.60** ("stage3 screen") | Shipped composed bound is **76.80**, FRI-query-dominated; `RCGkrComposedSeparationBits()` pins to `kRCGkrFriProximityBitsV5 = 76.80`; test `gkr_integration_composed_separation_bound` asserts `∈ (76.7, 76.81)`. **92.6 appears nowhere in code** — only in the reconciliation doc row labeled source **"the relay host"**, i.e. an unshipped, unaudited measurement. | `matmul_v4_rc_gkr.cpp:2673`, `matmul_v4_rc_gkr.h:899`, `matmul_v4_rc_fri.h:56` |
| Global **84.09 bits** ("machine-checked") | Under **shipped** params the union is **76.80 − log₂341 = 68.39 bits** (GO vs 64, **FAILS the 71-bit / 7-bit policy**). 84.09 is reachable **only if** the 92.6 screen is real *and* inherited by internal nodes. | reconciliation doc §1, row "committed episode 76.8 → 68.39" |
| FRI-union (~84) is the binding floor | **False. The binding floor is P5/transport (H2c): the Fp2 child-proof-cell 14-span equality at ~67.6 bits** (single-α Fp2, receipt-sized cell), *below* the 71 policy and only ~3.6 bits above the 64 NO-GO. FRI is not the tightest lane. | reconciliation doc §2–§3, lane table |
| P2 closes via an additive Fp3 link-accumulator `A_v` folded up the tree, root checks `A_r = 0` | **No such object exists in the shipped recursion.** `matmul_v4_rc_air_recurse.{h,cpp}` maintains only the Merkle-digest compression accumulator `mp_acc` (Fp⁴, `acc(next)=Out(cur)`) pinned at `kLastRow` to the public root (`BuildMerkleRootBoundaryConstraints`). No `logup`/`link`/`multiset`/`additive`/`terminal-sum` machinery; the only "terminal" is the Merkle-glue root pin. | `matmul_v4_rc_air_recurse.{h,cpp}` (grep) |

**Consequence for the deliverable.** The honest certified-soundness state today is **≤ 2⁻⁶⁷·⁶ (binding-floor lane) / ~2⁻⁶⁸·⁴ (FRI-union) — and, for cross-shard equality (P2), effectively 0 certified bits because the closure mechanism is not in the construction.** The 2⁻⁸⁴ target is a *conditional* statement whose preconditions are unmet by shipped code. We state it as such below and never as achieved.

---

## 1. The single best theorem statement (conditional, preconditions explicit)

The strongest *architecture* merges three angles: **reduction-to-monolith (#3)** for the deterministic statement layer (P1+P2 as an exact equivalence that spends zero soundness budget), a **straight-line ROM extractor (#2)** for the probabilistic layer and the extraction identity, and the **transcript-DAG doomed-state argument (#4)** for additive Fiat–Shamir accounting (P4). The depth-induction angle (#1) is **rejected as mapped** — its load-bearing accumulator does not exist (§0, row 4).

> **GLOBAL COMPOSITION SOUNDNESS THEOREM (PR-89, arity-4 relation-local sharding), conditional form.**
>
> Fix the shipped construction: AIR `S` over the 52-endpoint / 14-role support hypergraph with 124,802 columns and row domain `D`; shard cover `Σ={Σ₁…Σ₂₄₄}`, `|Σ_i|≤512`; an **ownership bijection** `β: C → ⊔_i C_i`; a link set `L` of `Λ` cross-shard duplicated-column pairs, each realized as row-tagged `(row_index, value)` LogUp CTL terminals over `Fp3`; the arity-4 receipt tree `T` (256 leaves = 244 live + 12 vacuous, 85 internal, 341 total, root `r`), sealed by fixed-length Merkle **T-BIND** (`siblings.size()==depth`) on **one transcript DAG**. Model SHA256d as a random oracle; adversary query budget `Q ≤ 2⁴⁰`.
>
> Let `β_node` be the **shipped** per-node composed separation floor (`RCGkrComposedSeparationBits() ≈ 76.80`, FRI-query-dominated, post-grind), and `ε_H = 2⁻⁸⁸` the flat SHA256d collision-binding term.
>
> **Suppose the six code-measurable GO-conditions C-H2c, C-H1, C-Q, C-H2a, C-H2b, C-H3 (§4) hold, the P2 closure mechanism M-LINK exists (§2, P2), and assumptions A1–A10 (§2, per obligation) hold.** Then for every adversary that outputs a root receipt `R_r` the normalized verifier ACCEPTS (T-BIND well-formed on every opening, single transcript DAG, and the link-closure check of M-LINK passes), **except with probability**
>
> `ε_total ≤ 341·2^{−β_node} + 2Λ·ε_link + ε_H`,
>
> **there exist leaf traces `{T_u}` uniquely determined by the leaf commitments (within the decoding radius) whose glue `T[c] := T_i[c]` is well-defined and satisfies the original statement `S`.**
>
> **Quantitatively:** with the *shipped* `β_node = 76.80`, `ε_total ≈ 2^{−68.4}` (clears 2⁻⁶⁴, **fails** the ≥71 policy). The **2⁻⁸⁴ bound holds iff** every node (leaves *and* internal aggregators) attains `β_node ≥ 92.26` **and** the transport lane H2c reaches `≥ 84` bits (dual-α or Fp3 at the cell). Under any shipped configuration examined, the tightest lane is H2c at **~67.6 bits**, so the *currently provable* bound is `ε_total ≈ 2^{−67.6}`, not `2^{−84}`.

This is the most defensible statement: it carries the 2⁻⁸⁴ figure as a *conditional target* with its exact preconditions, and it refuses to detach that figure from the lanes (H2c, H1) that presently violate it.

---

## 2. Proof-obligation ledger P1–P6

For each obligation: the lemma to prove, the strongest merged approach, and residual gaps/assumptions. **[CODE]** = only checkable in stage3 code; **[MATH]** = pencil-and-paper closable; **[CONSTRUCTION]** = requires a mechanism that must first exist in the build.

### P1 — Projection faithfulness
**Lemma.** `(⋀_i local-quotient(Σ_i)) ∧ (all Λ links hold pointwise) ⟺ S`: no constraint dropped, none weakened, none spurious.
**Best approach (merged #2 Lemma 6 + #3 Lemma M, deterministic, 0 soundness bits).** Reduce to a **static cover certificate** `κ: C → (shard, local-index)` machine-checked for (i) totality, (ii) exactly-once (bijection `β`), (iii) **faithfulness** — the pulled-back local quotient is the *identical* polynomial over the *same* zerofier/coset, not a factor/restriction, and (iv) exhaustive-converse (every local constraint is a `κ`-image, a link constraint, or a pinned bookkeeping/padding constraint). Gluing well-definedness is supplied by P2.
**Residual gaps / assumptions.**
- **[CODE, undischarged]** The certificate checker over the 244-shard manifest **has not been written or run**. Until it exists, P1 is an assumption, not a lemma.
- **[MATH/CODE] Row-domain totality for *transition* constraints:** column-support faithfulness does **not** guarantee enforcement on shard-boundary and padding rows; multi-row constraints straddling a shard row range can be silently weakened at edges. Must be an explicit certificate clause. *(new gap — not in the skeletons’ column-only framing.)*
- **[CODE] Unregistered-duplication hole:** a column that is logically shared but appears *natively* in two shards without a link entry passes every check vacuously; the prover then reads a free copy. The certificate must prove the registered-duplicate set is **complete**, not merely connected.
- **[CODE] Support-closure feasibility:** every original constraint's full support must fit inside one ≤512-column shard; with 124,802 columns this is asserted, never demonstrated.

### P2 — Link soundness *(load-bearing; classic leak — see §3)*
**Lemma.** For each link, the dual LogUp terminals cancel **iff** the duplicated columns are **pointwise** equal at matched `row_index` (not value-multiset equal, which permits row reordering).
**Best approach (merged #2 Lemma 5 + #3 Lemma M4).** Row-tag turns the CTL into equality of *graphs of functions*: multiset equality of `(row, value)` pairs whose first coordinates enumerate `D` exactly once per side forces `a_L(r) = a_R(r)` for all `r`. Cancellation ⇒ multiset equality holds up to a Schwartz–Zippel term (LogUp lane, `kRCGkrLookupSepBits = 256`).
**Residual gaps / assumptions — this obligation is *not* currently closable as skeletoned:**
- **[CONSTRUCTION, decisive] The closure mechanism M-LINK does not exist in the shipped recursion.** Cross-subtree links can only cancel at their **lowest common ancestor**; that requires a running LogUp accumulator faithfully transported up the tree with domain separation preserved, and a root check. The shipped node has only `mp_acc` (Merkle-digest compression, §0). **Cross-shard equality is therefore uncertified regardless of the 84.1 arithmetic.** Either M-LINK must be built (an accumulator transport + LCA cancellation, separate from the digest transport) or its existing home in the leaf/CTL layer must be located and proven. *Depth-induction angle #1 is invalid precisely here.*
- **[CODE] `A_v`-in-digest is arithmetically incoherent (angle #1):** a hashed digest cannot carry an additively-cancellable field sum. Any real closure needs an **exposed** Fp3 accumulator carried at every level, not a value "inside `d_v`".
- **[MATH] Per-side vs per-link domain separation — a genuine contradiction in the skeletons.** For cancellation to imply *value* equality the two sides must share the **same** compressed tag on matching `(row, value)`; domain separation must be **per-link** (to stop cross-link cancellation), **never per-side**. The `tag_e^L ≠ tag_e^R` notation in angles #1/#2 makes the pointwise-collapse step invalid. Fix the construction to per-link tags and prove single-Fp3-challenge cancellation cannot decompose across links without a random-linear-combination challenge (adds a `~Λ/|Fp3|` term omitted from every budget).
- **[CODE] `row_index` must be a verifier-fixed canonical column, identical and injective across both linked shards, denoting the *same global row*.** If prover-witnessed, or per-shard-local, a shared permutation satisfies both terminals while reordering rows — the exact attack P2 claims to kill. Not visibly pinned.
- **[CODE] Common post-commitment challenge (A6):** `(α, γ)` must be drawn **after** all 244 leaf trace commitments seal into the DAG and be **common** to both sides of every link. Independent leaf FS transcripts do not provide this for free; if any duplicated column can be committed after `(α,γ)` is derivable, P2 collapses to adaptive forgery.
- **[MATH] Tuple-compression injectivity / no field wraparound** over the actual `(index, value)` range.

### P3 — Per-node verification soundness (inductive step)
**Lemma.** An internal node accepting ≤4 child receipts ⇒ (except `ε_node`) each child's claimed statement holds.
**Best approach (merged #2 Lemma 2 + #4 doomed-state).** Per-node STARK+FRI soundness as the induction engine; the extractor pulls the decoded codeword and re-applies down the tree.
**Residual gaps / assumptions.**
- **[CODE] H1 (dominant policy lever):** the theorem's constant assumes internal aggregating nodes attain `β_node ≥ 92.26`. **Shipped code gives 76.80** → global 68.4. Worst-case internal-node lane is **70.4** unless they retain the additive **known-term** decomposition and ≤4 child proximity instances batch into one query term. *This is the difference between policy PASS and FAIL.*
- **[CODE] Emulated ≠ standalone verifier soundness.** The induction consumes "*in-AIR* emulated child-verifier accepts ⇒ child true." An emulated verifier running fewer FRI queries / truncated challenges to fit the AIR budget has a **strictly lower** floor than the standalone 76.8 — a class closed by **neither P3 nor P5**. Must prove the in-circuit re-verification uses parameters ≥ the standalone floor.
- **[CODE/MATH] Q-inclusivity (angle #4 G1).** The additive union is valid only if `β_node` is already the whole-budget (post-`2⁴⁰`) figure, not a per-query proximity floor; the code comment states post-grind, but the FS-transform per-query→whole-budget conversion must be pinned, not assumed. **Leaf grinding** is not blocked by T-BIND sealing (nothing is downstream of a leaf); its resistance rests entirely on the post-grind claim.
- **[MATH] Codeword vs raw committed leaves:** constraint satisfaction is a property of the **decoded** low-degree word; the extractor must argue agreement on constraint-touched positions, and DEEP must pin a **unique** codeword consistent across all constraints and all link terminals (list-decoding uniqueness / A1).

### P4 — Transcript / Fiat–Shamir binding (errors ADD, not multiply)
**Lemma.** Sealed T-BIND + one transcript DAG forecloses state-restoration regrinding, so per-node FS errors union.
**Best approach (angle #4 doomed-state).** Injective RO tagging + fixed-length openings make the accepting-receipt→query-DAG map injective (charge `ε_H` once); altering any descendant transcript changes every ancestor challenge (fresh sample), so retries are one global budget. Union bound then unconditional.
**Residual gaps / assumptions.**
- **[CODE] Node-position binding missing.** The shipped FS point chains `(prev_round_root, round_index)` with **no node-id / slot-index field** (`matmul_v4_rc.cpp` FS encoding). Without it: sibling **permutation** within a parent and cross-symmetric-node regrind (12 padding leaves, structurally identical subtrees) are not foreclosed — the 341-node union can under-count.
- **[MATH] Doomed-state base clause is missing:** `State(empty)=DOOMED iff S(tr) false` must be added or the induction cannot start.
- **[CODE] Absorb-before-squeeze order** (child terminal digests absorbed before any parent challenge) and single-DAG exclusivity (no auxiliary FS instance) must be verified against the shipped transcript schedule.

### P5 — Digest / cell transport soundness *(load-bearing; classic leak — see §3; this is the true binding floor)*
**Lemma.** The 14-span child-proof-cell mapping + terminal digest faithfully carry the child's *verified* claim upward: no substitution, no authority promotion, no slot replay, no pad-slot smuggling.
**Best approach (merged #3 Lemma T + #5 L4).** Parent AIR recomputes each child's T-BIND root over the transported cells and equality-binds it to the absorbed digest (substitution ⇒ SHA collision, flat 88); level/arity tag + canonical tree index in the digested statement block promotion/replay.
**Residual gaps / assumptions — this is the tightest lane in the whole system:**
- **[CODE, binding floor] H2c: the transport equality is a single-α Fp2 Schwartz–Zippel check at ~67.6 bits** for a receipt-sized cell (`128 − 48.41 − log₂N = 79.59 − log₂N`, `N≈2¹²`). **Below the 71 policy, ~3.6 bits above the 64 NO-GO.** The rescue is the standing **dual-α mandate** (`c=2`): `2·(128 − log₂N) − 48.41 ≥ 84` for `N ≤ 2⁶¹`, **or** field = Fp3 at the cell. Whether dual-α/Fp3 actually reaches *this specific cell* is unmeasured. **This, not FRI, is what makes certified soundness fall short of 84.**
- **[CODE] Lane-completeness (H2b) is a *negative* about the shipped circuit** — no unconstrained or sub-84-bit lane among {14-span transport, SHA FS-replay, parent-proof verification, terminal/proof digest}. No bit floor or audit artifact exists for this; a single truncated-digest or few-query-replay lane silently voids the constant while every other line still reads valid.
- **[MATH/CODE] Recursion tape-bridge (angle #2 most-serious gap):** a straight-line extractor reads the *external* oracle tape, but children are verified *in-circuit*; a child root can be an in-circuit-verified cell value never committed to the real oracle, so `Commit⁻¹` has no preimage tree for it and it is not chargeable as guessing. Recursive ROM extraction must **prove** in-circuit digests coincide with real-tape inputs (input-alignment), not assume it.
- **[CODE] Vacuous child-slots at arity<4 internal nodes** (unavoidable with 244 live + 12 vacuous over 4⁴): a slot marked "vacuous" must not skip a live child's in-circuit verification while still folding its digest.

### P6 — Union accounting
**Lemma.** `ε_total = (341-node statistical union) + (2Λ link terminals) + (flat SHA)` matches the machine-checked figure with the correct composition classes.
**Best approach.** Statistical terms union (`stat_union = β_node − log₂341 = β_node − 8.41`); SHA is **flat 88** (collision), *not* unioned — second-preimage is `≥216 − log₂t ≥ ~182`, so multi-target `t` never makes SHA the floor (H3 corrected). `global = −log₂(2^{−stat_union} + 2^{−88})`.
**Residual gaps / assumptions.**
- **[MATH] Numeric honesty:** with shipped `β_node = 76.80`, `stat_union = 68.39`, `global ≈ 68.4` — **report this, not 84.09.** 84.09 is contingent on the unshipped 92.6 screen.
- **[MATH] Missing terms:** the per-link RLC/separation Schwartz–Zippel term (from the P2 per-link fix) and the γ-batching injectivity term are omitted from every skeleton budget and must be instantiated from shipped `Λ`, `n_max`, `|D|`.
- **[CODE] Λ must be pinned** from the 244-shard duplication table (the 2¹² envelope holds at 80.6 only under the 92.6 screen; at 76.8 it is worse).

---

## 3. Discharge order and consensus-load-bearing obligations

**Order (dependency-driven, cheapest-decisive-first):**

1. **P5 / H2c first — it is the binding floor (~67.6), the only lane at real risk of a *policy* breach and closest to the 64 NO-GO.** Measure the 14-span transport equality: dual-α or Fp3 at the cell? If not, mandate it (cheapest fix in the set). Nothing else matters if transport caps at 67.6.
2. **P2 construction (M-LINK).** Confirm or *build* the cross-shard link accumulator + LCA cancellation. Until this exists, cross-shard equality is 0 certified bits and the theorem is unmappable — this is a **construction** blocker, not a proof detail.
3. **P3 / H1.** Confirm internal aggregating nodes retain the additive known-term decomposition (`≥92.26` to hold 84; `≥77.41` for the 71 policy) and that ≤4 child instances batch into one query term. Decides PASS/FAIL of the policy at the arithmetic level.
4. **P1 certificate.** Write and run the cover-certificate checker (totality, exactly-once, polynomial-identity faithfulness incl. transition-constraint row totality, exhaustive converse, registered-duplicate completeness).
5. **P4 binding.** Add node-id/slot-index to the FS encoding; verify absorb-before-squeeze and single-DAG exclusivity.
6. **P6.** Re-run the union with the *measured* `β_node`, the pinned `Λ`, and the added P2 RLC term.

**Load-bearing for consensus — the two classic leaks, with exact failure modes:**

- **P2 (cross-shard equality).** *Failure mode A (construction):* no accumulator transport exists → links never cancel anywhere → duplicated columns are independent free variables → the prover satisfies each shard-local quotient with inconsistent copies and `S` is *false* on any glue, yet the root accepts. *Failure mode B (row-reorder):* `row_index` not a shared canonical column, or per-side tags → value-multiset equality survives a permutation `u_j[i]=u_k[σ(i)]` → a reordered trace passes. Either failure is **invisible to every bit in the 84.1 accounting.**
- **P5 (transport).** *Failure mode A (arithmetic):* single-α Fp2 equality at a receipt-sized cell caps the whole system at ~67.6 bits — the true floor, *below* FRI, *below* policy. *Failure mode B (structural):* an unconstrained/under-screened lane (truncated digest, low-query replay) or a missing in-circuit `siblings.size()==depth` / span-boundary off-by-one aliases two children's cells → a foreign or unverified receipt is promoted → the tree certifies a statement no child proved, at **0 real bits**, while every per-node machine-checked bound still passes. No parameter change repairs it; only an equivalence audit of the arithmetized verifier against the native verifier does.

---

## 4. Genuinely OPEN — requires external cryptographic audit (never CLOSED)

These cannot be discharged locally and must be discharged before any
proof-bearing or proof-authoritative Epoch B, C, or D activation:

1. **[CODE] H2c transport-challenge amplification** — dual-α (c≥2) or Fp3 at the *actual* 14-span cell. **Currently the binding floor at ~67.6 bits. Top open item.**
2. **[CODE] H1 internal-node FRI screen** — additive known-term decomposition retained (not the 76.8 unique-decoding fallback) and ≤4-child batching. Governs whether the arithmetic clears 84 or sits at 68–70.
3. **[CODE] In-circuit verifier fidelity (A3)** — the arithmetized child-verifier is bit-identical to the native verifier, including in-circuit T-BIND geometry, and is **not** weakened by fewer queries/truncated challenges. No bit-accounting can certify this; it is a pure equivalence-audit fact and the single point where a missing check converts 84 bits to 0 silently.
4. **[CONSTRUCTION] P2 link-closure mechanism (M-LINK)** — locate or build the cross-shard accumulator transport + root cancellation; re-prove with per-link (not per-side) domain separation, common post-commitment `(α,γ)` ordering, and the added RLC error term.
5. **[CODE] ROM extractability of SHA256d / tape-bridge** — the composition is a ROM theorem; the concrete 88-bit collision budget does not by itself license straight-line recursive extraction of in-circuit-computed child digests. Either declare ROM explicitly or reprove using only verifier-opened positions (which weakens branch-(a) to constraint-touched positions).
6. **[CODE] Lane-completeness screen (H2b/H2a/H3)** — a systematic proof that no lane among {child-proof-cell transport, SHA FS-replay, parent-proof verification, digest lanes} drops below the floor (no sub-256-bit digest truncation; digest→field maps rejection-sampled/wide; every SHA site recompute-and-compare, no digest-set membership).
7. **[CODE] FRI/DEEP unique-decoding (A1/A2)** — a single committed codeword per column, consistent across parent and child views and across all constraints and link terminals; a divergent list-decode between views is an undetected substitution channel.
8. **[CODE] Transcript-DAG formalization** — node/slot-position injection into FS points, measurability of each node's bad event over its own oracle segment, and no second (debug/fallback/arbiter) accept path in the root verifier.
9. **[CODE] P1 certificate execution** — the checker over the 244-shard manifest (incl. transition-constraint row totality and registered-duplicate completeness) does not yet exist.

**Bottom line for the relay host.** The arithmetic side is *reconciled but not favorable*: shipped parameters give ~68 bits, and the tightest lane (P5/H2c) gives ~67.6 — **the composition theorem is not certified, and cross-shard equality (P2) has no closure mechanism in the current build.** The 2⁻⁸⁴ figure is a conditional target contingent on six code-measurable conditions (H2c and H1 at real risk) plus a P2 mechanism that must be built. Certified soundness must be reported as **OPEN pending completion of the remaining verification**, never as achieved.
