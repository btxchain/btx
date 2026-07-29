# PR-89 blocker #1 — the extractor→soundness bridge for the arity-4 recursion: a standard-assumption knowledge-soundness composition proof — 2026-07-25

> **Status banner (must survive into any downstream artifact): ANALYSIS / PROOF DRAFT. NOT AUDITED, NOT ACTIVATED.**
> Consensus authority remains ExactReplay; `kRCStage3SuccinctAuthorityReady = false`; all
> activation heights stay `INT32_MAX`. This document RESOLVES the proof-structure gap flagged by
> the adversarial panel (blocker #1: "extractor bounds Pr[extraction fails], not
> Pr[accept ∧ false]") under **standard assumptions** (ROM for Fiat–Shamir, collision-resistant
> hashing, knowledge-soundness of the base AIR/FRI argument) — the same assumption class under
> which Plonky2 / Boojum / RISC0 recursion is deployed. It is **conditional on the in-circuit
> statement-decomposition constraints D1–D7 (§4) landing in the parent AIR** (the aggregation
> worker's deliverable; `BuildFourSlotSelfSimilarCtlParentV1` now exists with 4-slot in-parent
> child verification, terminal-lane sourcing, and a statement-decomposition constraint, but its
> current aggregation is a LINEAR order-weighted sum — **insufficient**, see §6.4 — and is being
> upgraded to a **binding AlgHash/Poseidon2 sponge over the full child public-IO tuples**, which
> is exactly what D3 requires; D1's SHA-FS chip also remains open). Residual sub-claims that
> remain genuinely open are listed in §8 — none of them is the composition structure itself.

Companion documents:
`doc/btx-matmul-v4.6-stage3-composition-theorem-roadmap-2026-07-25.md` (P1–P6 ledger),
`doc/btx-matmul-v4.6-stage3-global-composition-reconciliation-2026-07-25.md` (arithmetic),
`doc/btx-matmul-v4.6-stage3-in-air-child-verifier-spec-2026-07-25.md` (chip inventory).

Code anchors (all paths under `src/matmul/`):
`matmul_v4_rc_stage3_recursive_parent_air.{h,cpp}` (`FourSlotSelfSimilarCtlParentV1`,
`BuildFourSlotSelfSimilarCtlParentV1`, terminal-lane sourcing constraint
`active_s · selector_row · (export − verifier_terminal_lane) = 0`, 8-lane
`computed_parent_statement`), `matmul_v4_rc_stage3_aggregation_schedule.h`
(`RoleAggregationPlan`, `ParentWorkItem`, arity 4, last-parent 1–3 children),
`matmul_v4_rc_stage3_global_soundness_ledger.h` (per-term screens),
`matmul_v4_rc_stage3_composition.h` (`ComputeRCStage3AggregationSeed`),
`matmul_v4_rc_gkr_field_ext3.h` (Fp3 = Goldilocks[x]/(x³−2)),
`matmul_v4_rc_alg_hash.h` (Poseidon2 AlgHash: rate 8, capacity 4, digest 4),
`matmul_v4_rc.h` (datacenter episode constants).

---

## 0. The gap being closed, stated exactly

The prior extraction analysis proved, per node, a bound of the form

&nbsp;&nbsp;&nbsp;&nbsp;Pr[ V accepts π **and** the extractor fails to output a valid witness ] ≤ κ,

and then *informally* concluded global soundness. The adversarial panel exhibited why that
conclusion does not follow from that quantity alone: **nothing in the shipped parent relation
forces the parent's claimed statement to be the aggregation of its children's statements.** The
shipped parent SHA-packs the four child receipt roots into its transcript; it never constrains
`x_parent = f(x_child1..x_child4)`. Standing counterexample:

> Four TRUE children, each with an honestly generated accepting proof, placed under a parent
> whose claimed statement `x_parent` is **not** `f(x_c1..x_c4)` (e.g. a different episode digest,
> a different link-accumulator value, or a foreign receipt root). Every child extraction
> *succeeds* — so the "extraction fails" event never fires and the old bound is vacuously
> satisfied — yet the parent proof ACCEPTS a FALSE statement. Soundness error 1, "extraction
> failure" probability 0.

The resolution has two parts, and both are necessary:

1. **A construction change** (aggregation worker, in flight): the parent AIR must verify the four
   child proofs in-circuit **and** enforce the statement decomposition
   `x_parent = f(x_c1..x_c4)` in-circuit (constraints D1–D7, §4). Then a mis-aggregated parent
   has **no satisfying witness at all**, and an accepting proof of it is by definition a break of
   the base argument's knowledge-soundness — a chargeable event.
2. **A proof-structure change** (this document): bound the joint event
   Pr[accept ∧ statement false] directly, by a top-down straight-line extraction walk in which
   *every* escape from the falsity-propagation induction is a named, charged bad event. §6 gives
   the proof; §7 shows the resulting bound is genuinely about accept∧false and exhibits, on the
   counterexample above, exactly which charged event absorbs it.

---

## 1. The object: tree, field, hashes (fixed by shipped code)

- Field: Fp3 = 𝔽_p[x]/(x³−2), p = 2⁶⁴−2³²+1 (Goldilocks). |Fp3| ≈ 2¹⁹¹·⁹; the ledger's
  conservative per-draw figure is `kConservativeFp3Bits = 189`.
- Algebraic hash: AlgHash = Poseidon2, t = 12, rate 8, capacity 4, digest 4 Fp limbs;
  collision floor `kHashCollisionFloorBits = 128` (capacity-bound).
- Byte hash: SHA256d; repo-conservative collision budget 2⁻⁸⁸ under adversary query budget
  Q ≤ 2⁴⁰ (`kConservativeGrindingBits = 40`); second-preimage ≥ ~2¹⁸², never the floor.
- Receipt tree T: full arity-4, depth 4. Levels ℓ = 0..4 with 4^ℓ nodes:
  1 + 4 + 16 + 64 + 256 = **341 nodes**; leaf level 4 has 256 slots = **244 live shard leaves +
  12 vacuous padding leaves**; 85 internal nodes. Node id ν = (ℓ, k), 0 ≤ k < 4^ℓ; children of
  (ℓ, k) are (ℓ+1, 4k+j), j ∈ {0,1,2,3}. (The `RoleAggregationPlan` realizes this as contiguous
  role/level/index ranges; a last parent with 1–3 live children is exactly a parent with vacuous
  slots — D7.)
- Per-node base argument: AIR + DEEP-FRI over Fp3, Fiat–Shamir by SHA256d, query count Q_FRI and
  grinding g per the shipped/selected profile. Its composed per-node separation is
  β_node = `RCGkrComposedSeparationBits()` = **76.80** shipped; **92.6** is the conditional
  stage-3 screen (unshipped; see reconciliation doc). This document is **parametric in
  β_node** — the composition structure is identical for either value.

## 2. The statement at each node, and the tensor-PoW semantics at the root and leaves

### 2.1 What the episode is (grounds `Sem` at the extremes)

The datacenter-profile episode (`matmul_v4_rc.h`) is a **deterministic function** of the block
header and nonce: seed chain → operand expansion (X0 row blocks, ChaCha/PRF-keyed MX extraction)
→ `rounds = 8` rounds of `L_lyr = 24` fused-FFN layers plus attention
(d_head 128, n_q 512, n_ctx 786 432, d_model 4096, d_ff 16 384, b_seq 87 552, T_leaf 4096),
each layer `X[l+1] = Extract(Extract(X[l]·W_up)·W_down + X[l])`, with every committed tile
entering the tile tree and the round roots chaining into the episode digest. Total structural
work: **MAC_dc = 2³⁷ · 16 422 = 2 257 022 493 917 184 ≈ 2.257·10¹⁵ MACs** (nonce-independent,
R.4.4). Because the map (header, nonce) → full trace is a *function*, truth of any sub-statement
below is decidable by ExactReplay, and a false sub-statement has **no** witness — this is the
unconditional anchor at the bottom of the induction (given P1 faithfulness, §3 A5).

The global arithmetization is one monolithic AIR **S** (124 802 columns, 52-endpoint / 14-role
support hypergraph) covered by the shard family Σ = {Σ₁…Σ₂₄₄}, |Σᵢ| ≤ 512 columns, with
ownership bijection β and cross-shard duplicated-column link set L (|L| = Λ), realized as
row-tagged LogUp CTL terminals (M-LINK / P2). **The arity-4 tree does not re-partition the GEMM
spatially; it aggregates the 244 relation-local shard proofs** in the canonical
role/level/index order of the `ProductionAggregationSchedule`. The "tile/shard/round
decomposition of the episode" lives inside S via the cover Σ (tiles and rounds are column/row
ranges of S assigned to shards by β); what the tree composes is *proof-level* validity plus the
*additive link accumulator* that makes the 244 shard-truths glue back into S.

### 2.2 The node statement (definition): full public-IO tuple vs. exposed digest

Every node ν has a **full public-IO tuple**

&nbsp;&nbsp;&nbsp;&nbsp;**io_ν = (pub, ν, ρ_ν, A_ν)**

and an **exposed statement digest**

&nbsp;&nbsp;&nbsp;&nbsp;**h_ν = AlgHash(tag_io(ν) ‖ enc(io_ν))**,

where enc is a fixed-length, domain-tagged, injective Fp3-lane encoding (no variable-length or
ambiguous packing) and tag_io(ν) is a per-node domain tag containing (ℓ, k). The proof π_ν is a
proof whose *public input, as absorbed by its Fiat–Shamir transcript and consumed by its
boundary/DEEP checks,* is h_ν; any circuit (parent or native consensus) that consumes the
*meaning* of the statement must **open** h_ν, i.e. materialize io_ν as in-circuit cells and
enforce h_ν = AlgHash(tag_io(ν) ‖ enc(io_ν)) as a constraint. At the root, consensus holds io_r
in plaintext (block header fields, unified root, A_r) and recomputes h_r natively.

This io/h split is deliberate and load-bearing (coordinator-confirmed against the in-flight
construction): the digest is what travels and what proofs bind to; the tuple is what carries
semantics; and the bridge between the two views is the CRHF binding of AlgHash. Hashing only
the child *terminal root digests* (row/trace Merkle limbs) instead of the full io tuple is NOT
sufficient — §6.4. The components of io_ν:

- **pub** — the global public context, *identical at every node by construction*:
  the block-header binding (header digest h_B, nonce, target), the claimed episode digest d_ep
  and round roots, the frozen episode-parameter digest (the datacenter constants above), the
  aggregation-schedule commitment `CommitProductionAggregationSchedule(…)`, and the statement
  seed σ = `ComputeRCStage3AggregationSeed(statement)`.
- **ν = (ℓ, k)** — the node's canonical position (level, index). Consensus-fixed, not
  prover-chosen.
- **ρ_ν ∈ Fp3⁸** — the node's receipt root: the eight terminal lanes
  (four row-root limbs + four trace-root limbs) of the node's own committed proof artifacts
  (`Arity4FamilyReceiptLayoutV1::kChildRootWords = 8`). For a vacuous leaf, ρ_ν = ρ_vac, a
  canonical constant.
- **A_ν ∈ Fp3** — the M-LINK additive link accumulator for the subtree rooted at ν
  (P2 interface; A_ν ≡ 0 for designs where link cancellation is confined to the leaf/CTL layer).

### 2.3 Semantic truth `Sem` (definition, by structural recursion on io tuples)

Sem is defined on **tuples** (where the meaning lives), and lifted to digests existentially:

- **Leaf, live slot** (ℓ = 4, slot k mapped by the schedule to shard i = s(k)):
  Sem(io) = 1 iff there exists a trace T_i satisfying the shard AIR C_i (the Σ_i-slice of S
  under β) whose boundary/public columns are pinned to pub and whose commitment opens ρ, and
  whose link-terminal contribution is A. Because the episode is deterministic, for fixed pub
  there is exactly one honest T_i; Sem(io) = 1 iff (ρ, A) match that honest computation's
  commitment and terminals — i.e. iff **ExactReplay of shard i confirms io**.
- **Leaf, vacuous slot**: Sem(io) = 1 iff io = io_vac(ν) (the canonical constant tuple); the
  honest io_vac is always true.
- **Internal node ν**:
  &nbsp;&nbsp;&nbsp;&nbsp;Sem(io_ν) = 1 iff ∃ (io_c0, io_c1, io_c2, io_c3) such that
  **Decomp_ν(io_ν; io_c0..io_c3) = 1** and Sem(io_cj) = 1 for all j ∈ {0..3}.
- **Digest lift**: Sem_h(h) = 1 iff ∃ io: h = AlgHash(tag_io(ν) ‖ enc(io)) ∧ Sem(io). (The
  existential over hash preimages is resolved computationally in the proof: the extractor
  always holds a *specific* opening, and two distinct openings of one digest are a charged
  AlgHash collision.)
- **Root** (ν = (0,0)): consensus natively holds io_r in plaintext and checks it against the
  block: pub binds the header actually being validated, ρ_r equals the unified root committed
  in `CBlock::matrix_c_data` (unified-root V3 packing), and **A_r = 0** (M-LINK root
  cancellation). Root falsity below always means ¬Sem(io_r) for this consensus-held io_r — no
  digest ambiguity exists at the root.

**Bridge to the consensus relation (P1/P2 interface).** By P1 (projection faithfulness: the
cover certificate) and P2 (link soundness: A_r = 0 forces pointwise equality of every duplicated
column, up to the P2 error budget), the conjunction "all 244 live-leaf statements true ∧ links
closed" is **equivalent** to "the monolithic AIR S is satisfied with public input pub", which by
the deterministic-builder relation is equivalent to "d_ep in the header is the digest of the
honestly computed 2.257·10¹⁵-MAC episode for (h_B, nonce)". This document consumes P1/P2 as
interfaces (they are separate obligations with their own budgets); everything tree-shaped is
proven here.

### 2.4 The aggregation function f — precise, for our use case

Decomp_ν(io_ν; io_c0..io_c3) is the conjunction of a **binding component** (fB) and four
**relational components** (f1)–(f2)–(f4)–(f5). These play different roles and BOTH kinds are
required: the hash **binds** (the parent's exposed claim computationally determines which child
claims were verified — anti-substitution), the relations **constrain** (the four bound claims
are mutually consistent and consistent with the parent's own claim — decomposition semantics).
A hash alone checks nothing about consistency; equalities alone bind nothing to the exposed
digest.

- **(fB) Binding aggregation over FULL child public-IO tuples (the required form of the
  in-circuit constraint).** The parent's exposed statement digest satisfies, in-circuit,
  &nbsp;&nbsp;&nbsp;&nbsp;h_ν = AlgHash( tag_io(ν) ‖ enc(io_ν) ), with
  &nbsp;&nbsp;&nbsp;&nbsp;io_ν = (pub_ν, ν, ρ_ν, A_ν) materialized as cells, and additionally
  the four **child** digests the in-parent verifier chips consume satisfy, in-circuit,
  &nbsp;&nbsp;&nbsp;&nbsp;h_cj = AlgHash( tag_io(ℓ+1, 4k+j) ‖ enc(io_cj) ), j = 0..3,
  with each io_cj = (pub_cj, ν_cj, ρ_cj, A_cj) materialized as cells (ρ_cj sourced from the
  in-parent verifier's own terminal lanes per D2). Equivalently stated as one map: the parent
  statement is `parent_statement = AlgHashSponge(child_public_IO_0 ‖ … ‖ child_public_IO_3)`
  composed with the parent's own io packing — a **collision-resistant compression of the
  ordered 4-tuple of full child public-IO tuples**, order-sensitivity supplied by the fixed
  lane positions in the sponge absorption (slot j occupies fixed lanes) plus the per-child tags.
  **Two non-negotiable properties:** (i) the hash is AlgHash/Poseidon2 (CRHF per A2) over the
  *entire* io tuples — not over the 8 terminal root limbs alone (§6.4, distinction (ii)); and
  (ii) a **linear** order-weighted sum is categorically insufficient — a linear map is not
  collision-resistant, and the proof's case (b)/(c) branch has nothing to contradict (§6.4,
  distinction (i)).
- **(f1) Public-context threading.** pub_cj = pub_ν for j = 0..3, componentwise Fp3/word
  equality on the materialized cells. This carries h_B, d_ep, the round roots, the parameter
  digest, σ and the schedule commitment unchanged from the root to every leaf.
- **(f2) Position threading.** ν_cj = (ℓ+1, 4k+j) — an affine function of ν and the slot
  ordinal j in the parent's receipt layout (order-sensitivity at the relational layer too:
  swapping two children violates (f2) and changes (fB)'s absorption lanes; sibling permutation
  is a Decomp violation, not a re-aggregation).
- **(f4) Link-accumulator folding.** A_ν = A_c0 + A_c1 + A_c2 + A_c3 + t_ν in Fp3, where t_ν is
  the node-local link-terminal contribution (0 at pure aggregation nodes). Root: A_r = 0
  (checked natively). This is M-LINK's transport; its *cancellation semantics* are P2's.
- **(f5) Vacuous slots.** For each slot j that the schedule marks vacuous under ν (schedule
  commitment is in pub, so this is verifier-computable): io_cj = io_vac(ν, j), a canonical
  constant, enforced against a **preprocessed** slot-activity mask (never witness-controlled),
  and the slot contributes A_cj = 0 and the canonical ρ_vac/h_vac to (fB)/(f4). A live child's
  slot may never satisfy (f5)'s branch: the mask is preprocessing, so "demoting" a live slot is
  a different (rejected) constraint system, not a witness choice.

f is the function (io_c0..io_c3) ↦ (io_ν, h_ν) induced by (fB)+(f1)+(f2)+(f4)+(f5): pub passes
through, ν is the parent position, A_ν = ΣA_cj + t_ν, ρ_ν is the parent's own commitment
material, and h_ν binds all of it. This is the exact statement-decomposition the parent AIR
must enforce (§4 renders it as circuit constraints D3).

## 3. Assumptions (all of them, explicitly)

- **A1 — Base-argument straight-line knowledge-soundness (ROM).** For each node's constraint
  system (the leaf shard AIRs C_i and the internal parent relation R^circ of §5), the
  Fiat–Shamir-compiled AIR/DEEP-FRI argument over Fp3 is knowledge-sound in the random-oracle
  model with a **straight-line** extractor E (BCS-style: E reads the adversary's oracle
  transcript, no rewinding): for every adversary 𝒜 making at most Q_RO oracle queries and
  outputting (x, π),
  &nbsp;&nbsp;&nbsp;&nbsp;Pr[ V^RO(x, π) = 1 ∧ (x, E(x, π, tape)) ∉ R ] ≤ κ(Q_RO),
  with κ(Q_RO) ≤ 2^{−β_node} for Q_RO ≤ 2⁴¹ (shipped β_node = 76.80 post-grind whole-budget;
  conditional 92.6). Note the event is the **joint** "accept ∧ extracted witness invalid" — this
  is the standard BCS knowledge-soundness form for FRI-based STARKs, the same property
  Plonky2/Boojum/RISC0 recursion relies on, and it is exactly the per-node property the old
  analysis mis-stated. The FS whole-budget conversion and the unique-decoding regime for the
  shipped parameters are recorded as closed cores in the step-5 ledger; the *numeric value* of
  β_node (H1 internal screen, grinding accounting = blocker #3) is out of scope and parametric
  here.
- **A2 — CRHF.** AlgHash/Poseidon2 (t = 12, rate 8, cap 4) is collision-resistant with advantage
  ≤ ε_alg = 2⁻¹²⁸ for our adversary class; SHA256d is collision-resistant with advantage
  ≤ ε_sha = 2⁻⁸⁸ under Q ≤ 2⁴⁰ (repo-conservative).
- **A3 — ROM instantiation / tape alignment ("A-ALIGN").** The concrete SHA256d instantiating
  Fiat–Shamir is modeled as the random oracle *both* when queried natively and when evaluated by
  the arithmetized SHA chip inside a parent; every in-circuit evaluation of the compression
  function on a fresh input is accounted as one oracle query by the adversary (so the effective
  budget is Q′ = Q + total in-circuit SHA evaluations). Consequence used in §6: "the in-circuit
  verifier V̂ accepts (h_c, π_c)" implies "the native verifier V accepts (h_c, π_c) with respect
  to the extended tape", so extracted sub-proofs are chargeable to A1. *This is the standard
  assumption under which all deployed recursive STARKs operate; its refinement into a clean
  CRHF-for-binding / ROM-for-challenges split with an input-alignment lemma is blocker #2 (a
  separate worker) and §8 item 1.*
- **A4 — In-circuit verifier fidelity.** V̂ ≡ V: the arithmetized child verifier enforces
  parameter-identical verification (same Q_FRI, same grinding g, full-width Fp3 challenges via
  the bounded **uniform** Fp3 sampler, identical T-BIND geometry with
  `siblings.size() == depth`, dual-OOD DEEP, and SHA-FS replay). This is an equivalence-audit
  fact, not a probabilistic assumption (roadmap §4 item 3); a V̂ weaker than V voids β_node
  silently.
- **A5 — Leaf faithfulness (P1 interface) and link closure (P2 interface).** The cover
  certificate (totality, exactly-once, polynomial-identity faithfulness incl. transition-row
  totality, registered-duplicate completeness) holds, so live-leaf AIR satisfiability with
  pinned pub ⇔ truth of the shard slice of S; and M-LINK cancellation at the root implies
  pointwise duplicated-column equality except with probability ε_P2(Λ) (P2's budget: LogUp lane
  + per-link RLC terms).
- **A6 — FS statement binding (P4 precondition).** The exposed digest h_ν is absorbed into node
  ν's FS transcript before any challenge is squeezed (absorb-before-squeeze), and the FS point
  contains the node id ν and slot index (the P4 node-position fix, currently unshipped — §8
  item 5). Together with D3b (h_ν opens in-circuit to the full tuple io_ν), this makes π_ν a
  proof *of io_ν* and not of an unbound floating statement.

## 4. The exact in-circuit constraints the aggregation worker must enforce (D1–D7)

These are the constraints under which the theorem of §6 holds. D2 is shipped; D1's SHA-FS chip
and D3–D6 are the worker's deliverable; D7 is schedule plumbing.

- **D1 (in-circuit child verification).** For each live slot j, the parent AIR contains the full
  child-verifier chip set accepting (h_cj, π_cj): Merkle/T-BIND path checks with
  **fixed-length openings** (`siblings.size() == depth`), every FRI fold equation, dual-OOD
  DEEP, the child quotient identity, **and the SHA256d Fiat–Shamir replay chip deriving every
  child challenge from the child transcript in-circuit** (with the bounded uniform Fp3
  sampler). No child challenge, query index, or root may enter as an unconstrained witness or
  host-supplied seed. *(Shipped status: Merkle/fold/DEEP/quotient are in
  `BuildFourSlotSelfSimilarCtlParentV1`; `child_fiat_shamir_replayed_in_parent` is still
  false — the child FS transcript is seed-supplied. D1 is NOT yet satisfied by HEAD.)*
- **D2 (statement sourcing — shipped).** Each of the 8 lanes of each io_cj's receipt root ρ_cj is
  read from the in-parent verifier's **own** terminal permutation cells:
  `active_s · selector_row · (export − verifier_terminal_lane) = 0` at the lane's row, with the
  selectors and activity mask preprocessed. No child root is host-pinned.
- **D3 (statement decomposition = the counterexample killer; BINDING form required).** Inside
  the same AIR (`parent_cs`), as constraints — **not** host-side recomputation
  (`statement_decomposition_enforced_in_air = true` must mean exactly this):
  - **(D3a) Materialize the openings.** The full child public-IO tuples io_c0..io_c3 and the
    parent's own io_ν are witness cells; each ρ_cj lane is sourced from the in-parent
    verifier's terminal cells per D2.
  - **(D3b) Bind digests to openings — the AlgHash sponge constraint.** For each live slot j,
    the in-AIR Poseidon2 permutation chip enforces
    h_cj = AlgHash(tag_io(ℓ+1, 4k+j) ‖ enc(io_cj)), where h_cj is **the exact public-input
    value the slot-j child-verifier chip and its FS-replay absorb** (no second, unconstrained
    copy); and h_ν = AlgHash(tag_io(ν) ‖ enc(io_ν)), where h_ν is the parent proof's own
    exposed public input. enc is fixed-length, domain-tagged, injective lane packing.
    **The aggregation map must be this CRHF sponge over the FULL io tuples. A linear
    order-weighted sum of statement lanes (the current
    `computed_parent_statement` in `BuildFourSlotSelfSimilarCtlParentV1`) does NOT satisfy D3b
    and voids the theorem's collision branch — it must be replaced, as is in flight.**
  - **(D3c) Relational decomposition on the openings.** (f1) pub_cj = pub_ν lanewise; (f2)
    ν_cj = (ℓ+1, 4k+j); (f4) A_ν − ΣA_cj − t_ν = 0; (f5) vacuous-slot constants against the
    preprocessed mask.
- **D4 (statement completeness — no free lane).** The public-input surface of the parent proof
  is exactly h_ν (plus preprocessing); every semantic lane reaches the transcript only through
  the D3b opening of h_ν. No witness column may alias a statement or opening cell except
  through the D2/D3 constraints. (Prevents a "shadow statement" the decomposition doesn't
  cover, and prevents a second opening path to the same digest inside one node.)
- **D5 (FS binding).** = A6, realized in-circuit for children (the D1 FS chip absorbs h_cj
  before squeezing child challenges) and natively for the node's own proof (the node's FS point
  includes ν and the slot index).
- **D6 (parameter rigidity).** The child-verifier chips run with consensus-pinned parameters
  (Q_FRI, g, LDE rate, challenge widths) taken from preprocessing, never from the witness; the
  program/registry key selecting the child constraint system is caller/consensus-pinned
  (`registry_root` / `program_key` in AIR), so a parent cannot "verify" a child against a weaker
  program. (This is what makes A4 auditable.)
- **D7 (vacuous slots).** The slot-activity mask is preprocessed from the schedule commitment in
  pub; a vacuous slot forces io_cj = io_vac(ν, j) by constant-equality constraints and skips D1
  for that slot only. A live slot can never take the vacuous branch (the mask is not a witness).
  This covers the schedule's 1–3-child last parents and the 12 padding leaves.

## 5. The per-node circuit relations

- **Internal node ν (levels 0–3):**
  R^circ_ν = { (h_ν; w) : w = (io_ν, io_c0..io_c3, h_c0..h_c3, π_c0..π_c3, aux) such that
  h_ν = AlgHash(tag_io(ν) ‖ enc(io_ν)) and h_cj = AlgHash(tag_io(ℓ+1,4k+j) ‖ enc(io_cj)) (D3b),
  Decomp_ν's relational part holds on the openings (D3c), for every live slot j:
  V̂(vk_{ℓ+1}, h_cj, π_cj) = 1 (D1), and for every vacuous slot j: io_cj = io_vac(ν, j) (D7) }.
  By D1–D7 this is precisely the relation attested by the parent's own AIR/FRI proof.
- **Live leaf u:** R^circ_u = { (h_u; (io_u, T)) : h_u = AlgHash(tag_io(u) ‖ enc(io_u)) and T
  satisfies the shard AIR C_{s(u)} with boundary/public pinning (pub, ρ_u, A_u) }.
- **Vacuous leaf:** R^circ = { (h; ⊥) : h = AlgHash(tag_io(ν) ‖ enc(io_vac(ν))) } (decided by
  the verifier alone).

## 6. THEOREM (arity-4 composition soundness, standard assumptions) and proof

> **Theorem.** Assume A1–A6 and that the parent AIR enforces D1–D7 — in particular D3b's
> **binding AlgHash sponge over the full child public-IO tuples** — at every internal node. Let
> 𝒜 be any adversary making at most Q = 2⁴⁰ oracle queries (in-circuit SHA evaluations included
> per A3) that outputs a block whose root tuple io_r is held natively by consensus (header
> binding, unified root, A_r = 0) with h_r recomputed natively, and whose root proof π_r the
> native verifier accepts (including T-BIND well-formedness). Then
>
> &nbsp;&nbsp;&nbsp;&nbsp;**Pr[ V accepts ∧ the monolithic statement S is false for pub ]
> ≤ 341·κ(Q′) + ε_alg + ε_sha + ε_P2(Λ)**
>
> where κ(Q′) ≤ 2^{−β_node} is the base knowledge error at the extended budget
> Q′ = Q + (total in-circuit hash evaluations) ≤ 2⁴⁰ + 341·2²⁰ < 2⁴⁰·⁰⁰⁷, ε_alg = 2⁻¹²⁸ is the
> **single flat AlgHash-collision charge covering every digest-opening alignment in the tree**
> (§6.2, §6.3 Step ℓ), ε_sha = 2⁻⁸⁸ the flat SHA256d collision charge, and ε_P2(Λ) is the P2
> link budget (2Λ·ε_link + RLC terms, consumed as an interface). The 341 splits per level as
> 1 + 4 + 16 + 64 + 256.

### 6.1 The global extractor E\* (straight-line, single probability space)

Run 𝒜 once; let τ be the complete oracle transcript and (io_r, π_r) its output (io_r plaintext
at the root; h_r recomputed natively). If the native verifier rejects, stop. Otherwise define,
top-down for every node of the 341-node tree, the triple (h_ν, io^↑_ν, π_ν) — where io^↑_ν is
the opening of h_ν held by ν's **parent** (at the root, by consensus) — and extracted witness
w_ν:

- Root: (h_r, io_r, π_r); w_r := E(h_r, π_r, τ) (A1's extractor for the root relation
  R^circ_root). Note w_r contains the root's **own** opening io_r′ of h_r; io_r′ = io_r unless
  an AlgHash collision is exhibited (event Coll below).
- If w_ν parses as (io_ν′, io_c0..io_c3, h_c0..h_c3, π_c0..π_c3, aux), assign io^↑_cj := io_cj
  and recurse: w_cj := E(h_cj, π_cj, τ′), where τ′ is τ extended per A3 with the in-circuit
  hash evaluations that the level-ℓ witness performed.
- At live leaves, w_u = (io_u′, T_u) with T_u the extracted shard trace; at vacuous leaves
  nothing is extracted.

The two openings per digest — io^↑_ν (parent's/consensus's view) and io_ν′ (the node's own
extracted view) — are the alignment pairs the collision charge covers.

Everything is a deterministic function of (𝒜's coins, oracle answers): **one probability
space, no rewinding, no forking.** This is what makes the loss additive (§7.2).

Two bookkeeping lemmas used below:

- **(L-acc) Extracted proofs are natively accepting.** For the root this is the acceptance
  hypothesis. Inductively, if w_ν ∈ R^circ_ν then V̂ accepted (h_cj, π_cj) in-circuit at every
  live slot; by A4 (V̂ ≡ V) and A3 (in-circuit hash evaluations are tape queries), the native
  verifier accepts (h_cj, π_cj) with respect to the extended tape. (This is the recursion
  tape-bridge; it is exactly the step A3 licenses, and only this step.)
- **(L-adv) Induced per-node adversaries.** For each node ν define 𝒜_ν: "run 𝒜, extract along
  the unique root→ν path, output (h_ν, π_ν)". By construction 𝒜_ν is a legitimate oracle
  adversary with budget Q′. A1 therefore applies at every node separately, against the same
  execution.

### 6.2 Bad events and their charges

On the single probability space, define for every node ν:

- **Bad_ν (knowledge break at ν):** π_ν natively accepts h_ν (w.r.t. the extended tape) and
  (h_ν, w_ν) ∉ R^circ_ν.
  By A1 applied to 𝒜_ν (L-adv): **Pr[Bad_ν] ≤ κ(Q′)**, each of the 341 nodes.
- **Coll (hash collision exhibited by E\*):** among the values E\* materializes, two distinct
  preimages of AlgHash or SHA256d with equal image. This includes, centrally, every
  **alignment pair**: io^↑_ν ≠ io_ν′ with
  AlgHash(tag_io(ν) ‖ enc(io^↑_ν)) = h_ν = AlgHash(tag_io(ν) ‖ enc(io_ν′)) — the parent's
  opening vs. the node's own extracted opening of the same digest (enc injective and the tag
  shared, so distinct tuples give distinct preimages) — plus all D3b sponge preimages, T-BIND
  openings, and transcript absorptions. A single reduction runs E\* and outputs the first such
  pair, so **Pr[Coll] ≤ ε_alg + ε_sha** — charged once, globally, NOT per node and NOT per
  level (collisions are constructively exhibited, so multi-target does not degrade the bound;
  this matches the roadmap's "SHA is flat, not unioned"). For a reviewer preferring per-site
  accounting anyway: there are at most 2 openings per node ⇒ ≤ 682 alignment sites ⇒
  ≤ 682·2⁻¹²⁸ < 2⁻¹¹⁸·⁵ — still invisible at the 68–84-bit floor (§7.1).
- **LinkFail:** A_r = 0 yet some duplicated column pair is pointwise unequal across the glued
  leaf traces. By A5/P2: **Pr[LinkFail] ≤ ε_P2(Λ)**.

### 6.3 Falsity propagation (the bridge)

Condition on the event
&nbsp;&nbsp;&nbsp;&nbsp;G := { V accepts } ∧ { S false for pub } ∧ ¬(∪_ν Bad_ν) ∧ ¬Coll ∧ ¬LinkFail
and derive a contradiction; the theorem then follows from
Pr[accept ∧ ¬S] ≤ Σ_ν Pr[Bad_ν] + Pr[Coll] + Pr[LinkFail].

**Descent invariant I(ν):** we hold a node ν together with (h_ν, io^↑_ν, π_ν) such that
π_ν natively accepts h_ν, h_ν = AlgHash(tag_io(ν) ‖ enc(io^↑_ν)), and **¬Sem(io^↑_ν)** — the
falsity is carried on a *concrete opening*, never on the bare digest.

**Step 0 (root falsity establishes I(root)).** On G, S is false for pub, where pub is read from
io_r — held **in plaintext by consensus** (header binding, unified root, A_r = 0; h_r
recomputed natively, so io^↑_root := io_r with no digest ambiguity). By A5's equivalence
(P1 + P2, and ¬LinkFail gives the link direction), "all 244 live leaf tuples true ∧ links
closed" ⇒ S. Hence on G, ¬Sem(io_r): if Sem(io_r) held, unrolling the ∃-definition four levels
would produce 256 true leaf tuples whose live members glue (via ¬LinkFail) into a satisfying
assignment of S — contradicting ¬S. So I(root) holds.

**Step ℓ → ℓ+1 (one descent under I(ν)).** Since ¬Bad_ν, extraction produced w_ν ∈ R^circ_ν,
i.e. the node's own opening io_ν′ with h_ν = AlgHash(tag_io(ν) ‖ enc(io_ν′)), child openings
io_c0..io_c3 with their digests h_cj = AlgHash(tag_io(ℓ+1,4k+j) ‖ enc(io_cj)) (D3b), the
relational decomposition Decomp on those openings (D3c), in-circuit acceptance of every live
(h_cj, π_cj) (D1) hence native acceptance (L-acc), and canonical constants at vacuous slots
(D7). Now the trichotomy — the task's (a)/(b)/(c), made exact:

- **(b) AlgHash collision on the parent commitment — impossible on G.** First, **alignment**:
  if io_ν′ ≠ io^↑_ν, then two distinct tagged preimages of h_ν are in hand (enc injective, tag
  shared) — a constructive AlgHash collision, i.e. **Coll**, excluded on G and contradicting
  CRHF at ε_alg = 2⁻¹²⁸ (A2). So on G, io_ν′ = io^↑_ν, and the falsity carried by io^↑_ν is the
  falsity of the very tuple the circuit decomposed. *This is the step that makes the binding
  full-IO sponge (fB/D3b) load-bearing: without it, the parent's exposed claim and the tuple
  the circuit verified against would be two unconnected objects — §6.4.*
- **(c) base-argument knowledge-soundness break — impossible on G.** A child opening or child
  proof "inconsistent with the in-circuit-forced decomposition" cannot be extracted, because
  D3b + D3c + D1 are *inside* R^circ_ν: an accepting π_ν whose witness violates the sponge
  constraint, the relational decomposition, or a child verification is precisely
  (h_ν, w_ν) ∉ R^circ_ν = **Bad_ν**, excluded on G (charged κ ≤ 2^{−β_node}). *This single line
  is what the old SHA-packing construction lacked and D3 supplies: it converts the
  mis-aggregation counterexample from "soundness error 1, extraction fine" into a per-node
  event of probability ≤ κ.*
- **(a) a false child public-IO therefore exists — descend.** On G, io_ν′ = io^↑_ν is false
  and Decomp_ν(io_ν′; io_c0..io_c3) holds. Were Sem(io_cj) = 1 for all four j, the extracted
  child tuple itself would witness the ∃ in Sem's definition, giving Sem(io_ν′) = 1 —
  contradicting I(ν). So there exists j\* with **¬Sem(io_cj\*)**, and π_cj\* natively accepting,
  and h_cj\* = AlgHash(tag ‖ enc(io_cj\*)) in hand (a vacuous slot cannot be j\*: its tuple is
  the canonical Sem-true constant). Set io^↑_cj\* := io_cj\* — **I(child) is restored one level
  down**, again on a concrete opening.

**Step 4 (leaf contradiction — the ExactReplay-refutable tensor tile).** After at most 4
descents we hold a leaf u with I(u): ¬Sem(io^↑_u), π_u natively accepting h_u. Since ¬Bad_u,
the extracted (io_u′, T_u) satisfies R^circ_u; by the alignment argument of case (b),
io_u′ = io^↑_u on G. So T_u satisfies the shard AIR C_{s(u)} with public pinning
(pub, ρ_u, A_u) taken from a **false** tuple. By A5 (P1 faithfulness),
C_{s(u)}-satisfiability with pinned pub is *equivalent* to truth of the shard slice of S at
those pinned values, i.e. to Sem(io_u) = 1 — **contradiction**. Concretely and
unconditionally: the episode is a deterministic function of (h_B, nonce) — 2³⁷·16 422 MACs of
fused-FFN GEMM/Extract whose every tile value is uniquely determined — so a leaf tuple
disagreeing with the unique honest shard computation admits no satisfying trace at all; this
is the same fact ExactReplay establishes by recomputing the tile. A vacuous leaf cannot carry
¬Sem at all.

G is therefore empty, and

&nbsp;&nbsp;&nbsp;&nbsp;Pr[accept ∧ ¬S] ≤ Σ_{ν∈T} Pr[Bad_ν] + Pr[Coll] + Pr[LinkFail]
≤ **341·κ(Q′) + ε_alg + ε_sha + ε_P2(Λ)**. ∎

### 6.4 Why the FULL public-IO tuple must be hashed — confirmation that the distinction from terminal-root digests is necessary

The coordinator's requirement (bind the **full** child public-IO tuples, not merely the 8
terminal root limbs) is confirmed necessary. Three separations, in increasing severity:

- **(i) A linear order-weighted sum is insufficient — no case-(b) branch exists.** The current
  `computed_parent_statement` (linear aggregation of sourced lanes) is not collision-resistant:
  preimage tuples form an affine subspace, so distinct child-claim tuples aggregating to the
  same parent value exist *freely and computably*. The descent's alignment step then has
  nothing to contradict: the parent's exposed claim does not computationally determine which
  child tuples were verified, so a FALSE parent claim can coexist with four TRUE verified
  children (claims chosen to sum to the false aggregate) and **no charged event fires** — the
  standing counterexample survives, merely pushed from "no constraint" to "non-binding
  constraint". Soundness requires the aggregation map to be a CRHF; in this system that is
  AlgHash/Poseidon2 at ε_alg = 2⁻¹²⁸ (A2).
- **(ii) Hashing ONLY the terminal-root digests (row/trace limbs) is insufficient — the
  child's semantic claim escapes the binding.** The terminal roots commit to the child's
  *trace*; they do not, at the parent's statement layer, bind the child's claimed pub
  (episode digest d_ep, header h_B, round roots), position ν, or link accumulator A. If the
  parent statement is H(ρ_c0..ρ_c3) while the in-circuit child verification consumes pub/A
  values from cells not covered by that hash, then the counterexample reappears one level
  down: a parent whose exposed digest is "correct" (right roots) can have verified its
  children against a *different* pub′ — a different episode — and nothing connects the
  consensus-held pub at the root to the pub the leaves were verified under. (One might hope
  the child's own boundary/DEEP checks bind io to the roots "through" verification; that
  binding is only *soundness-grade* — it costs a κ event per node to invoke, and worse, it is
  binding to *whatever io the verifier chip was run with*, which is exactly the quantity left
  unbound by a roots-only hash. The chain from block header to leaf tiles must pass through
  the statement layer, and it can only do so if the statement digest covers the full tuple.)
- **(iii) The hash alone is also not enough — binding without constraining.** Dually, D3b
  without D3c binds four child tuples into the parent's claim but never *checks* them against
  each other or against the parent's own tuple: pub threading (f1), position affineness (f2),
  and accumulator folding (f4) are relational facts the sponge does not enforce. Both layers
  are required, and the proof uses them at distinct steps: D3b at the alignment step
  (case (b)), D3c inside R^circ (case (c)), and their conjunction at the descent (case (a)).

One clarification for the audit record: an earlier draft of this document observed that under a
**wide-statement architecture** — where pub, ν, A are *themselves* plain public-input lanes of
every node's proof, equality-threaded between parent and child public-IO surfaces — the
soundness bound survives even a lossy receipt aggregation, because the semantic chain never
routes through the digest. That observation is architecture-conditional and does **not** apply
to the actual construction: the stage-3 recursion exposes a *narrow* statement (one digest;
the tuple lives behind it), precisely so the statement ABI stays constant-width across the
self-similar tree. In the narrow architecture the binding full-IO sponge is not an option but
the load-bearing mechanism, and it is additionally required — under *any* architecture — by
P4's transcript-DAG regrind accounting and T-BIND uniqueness (the 341-node union under-counts
regrinds against colliding aggregates otherwise). The construction decision (binding AlgHash
sponge over full child public-IO tuples) is therefore correct and necessary on both counts.

## 7. The exact bound, and why it does not collapse to the flagged quantity

### 7.1 Numbers

Per-level extraction loss (knowledge-error charges; level ℓ has 4^ℓ nodes):

| level ℓ | nodes | role | charge |
|---|---|---|---|
| 0 | 1 | root aggregator | 1·κ |
| 1 | 4 | internal aggregators | 4·κ |
| 2 | 16 | internal aggregators | 16·κ |
| 3 | 64 | internal aggregators | 64·κ |
| 4 | 256 | leaves (244 live shard proofs + 12 vacuous) | 256·κ |
| — | **341** | | **341·κ** |

plus the **flat** (not per-level) hash charges: ε_alg = 2⁻¹²⁸ covering every AlgHash
digest-opening alignment and D3b sponge in the whole tree at once (constructive exhibition —
one reduction outputs the first collision pair; worst-case per-site alternative
≤ 682·2⁻¹²⁸ < 2⁻¹¹⁸·⁵), and ε_sha = 2⁻⁸⁸ for SHA256d transcript/T-BIND collisions. All κ at the
same β_node if the H1 screen holds uniformly; if internal nodes only reach a lower β_int,
replace 341κ by 256·2^{−β_leaf} + 85·2^{−β_int} (the structure is unchanged; only the
arithmetic moves — that is H1/blocker #6, not this document).

- **Shipped parameters** (β_node = 76.80 everywhere):
  341·2^{−76.80} = 2^{8.4136−76.80} = **2^{−68.39}**; adding 2⁻⁸⁸ + 2⁻¹²⁸ moves this by
  < 10⁻⁵ bits. Global ≈ **68.39 bits** — clears the 64 NO-GO, fails the 71-bit policy, exactly
  the reconciliation doc's number, now attached to the *correct* event Pr[accept ∧ false].
- **Conditional screen** (β_node = 92.6 at all 341 nodes, unshipped):
  341·2^{−92.6} = 2^{−84.19}; −log₂(2^{−84.19} + 2^{−88} + 2^{−128}) = 84.19 − log₂(1+2^{−3.81})
  ≈ **84.09 bits** — this recomputes the ledger's 84.09 figure exactly, confirming that figure
  was implicitly "341-union + flat SHA", and is now a theorem-shaped quantity (still conditional
  on the 92.6 screen being real and inherited by internal nodes).
- Query-budget slack: Q′ ≤ 2⁴⁰ + 341·(SHA evals per node) ≈ 2⁴⁰ + 2²⁸·⁴ < 2⁴⁰·⁰⁰⁷ — absorbed
  into κ's stated budget with no visible bit cost.
- ε_P2(Λ) is additive and separate (P2's ledger: LogUp lane ~2⁻²⁵⁶-class terms, per-link RLC
  ~Λ/|Fp3| ≈ 2^{−192+log₂Λ}, γ-injectivity ~2⁻⁹⁴ per the M-LINK reference spec) — none of these
  approaches the 68–84 floor.

### 7.2 Why the loss is additive (and would not be, without straight-line extraction)

Because A1's extractor is straight-line (BCS/ROM), E\* runs on **one** execution transcript and
all 341 Bad events live on one probability space: the union bound is exact and the total loss is
341·κ. Had the base extractor required rewinding/forking (special-soundness style), composing
down a depth-4 arity-4 tree would multiply transcript trees: (forks per node)^{depth} — e.g.
even a modest 2-fork extractor costs 2⁴ = 16 full re-executions per root attempt and, in the
knowledge-error algebra, terms of the shape (Q·κ)^{1/2^depth}-style degradations that destroy
the 68/84-bit arithmetic entirely. The ROM/straight-line property of FRI-based STARK extraction
is therefore not a convenience but the enabling fact of the 341-additive ledger. (This is the
same reason Plonky2/RISC0-style recursion quotes additive recursion overhead.)

### 7.3 Non-collapse: the bounded quantity vs. the reviewer's flagged quantity

The reviewer's objection: the old analysis bounded
&nbsp;&nbsp;&nbsp;&nbsp;q_old = Pr[accept ∧ extraction fails] (per node),
and glued these into a claim about global soundness, which does not follow — q_old says nothing
when extraction *succeeds* on false statements.

The theorem of §6 bounds
&nbsp;&nbsp;&nbsp;&nbsp;q_new = Pr[accept ∧ S false],
and the proof never passes through "extraction fails" as a standalone quantity: every appeal to
A1 is to the **joint** event "accept ∧ extracted-witness-invalid" (Bad_ν), and every
extraction *success* is consumed by the propagation induction, which terminates in an
unconditional leaf contradiction. Concretely, on the standing counterexample (four TRUE
children, mis-aggregated FALSE parent):

- Old accounting: all four child extractions succeed; q_old-events never fire; the analysis is
  silent; the block is accepted with a false statement. Soundness error 1.
- New accounting: the parent's exposed digest h opens (uniquely, up to the charged ε_alg
  collision) to a FALSE tuple io^↑. Any witness the parent could hold must open the same h to
  its own tuple io′ — either io′ ≠ io^↑ (AlgHash collision, charged 2⁻¹²⁸) or io′ = io^↑ is
  false while D3 forces Decomp(io′; four sourced child tuples) with D1-verified child proofs.
  A false parent tuple decomposing onto four TRUE child tuples contradicts the ∃-definition of
  Sem — so no such witness exists, and an accepting π_parent is (h, w) ∉ R^circ — the event
  Bad_parent, of probability ≤ κ = 2^{−β_node}. The counterexample is not "handled"; it is
  **charged**: ≤ κ + ε_alg at exactly one node. (And §6.4(i) shows the charge evaporates if the
  binding sponge is replaced by the current linear aggregation — the constraint must be the
  CRHF form, not merely "some" decomposition constraint.)

Formally, q_new ≤ 341κ + ε is not derivable from any bound on q_old (the counterexample
separates them), and conversely our proof does not bound q_old (extraction may fail on *true*
statements without affecting q_new). The two quantities are incomparable; the composition
theorem needed — and now has — the second one.

## 8. Residual sub-claims that genuinely remain open (none is the bridge itself)

1. **A3 discharge (= blocker #2, separate worker).** The theorem stands on the ROM-instantiation
   /tape-alignment assumption for arithmetized SHA — the identical epistemic position of
   deployed Plonky2/Boojum/RISC0 recursion (which the task designates as the target standard).
   The planned refinement (CRHF for in-circuit binding + ROM for challenges + input-alignment
   lemma with domain separation) replaces A3 with weaker assumptions; it changes no constant in
   §7.
2. **A4 equivalence audit + the two unmet D-constraints at HEAD.** V̂ ≡ V is an audit fact.
   Additionally (i) D1's SHA-FS chip does not yet exist
   (`child_fiat_shamir_replayed_in_parent = false`,
   `kVerifierFiatShamirAirExecutable = false`), and (ii) D3b's binding sponge is not yet the
   shipped aggregation — `computed_parent_statement` is still the linear order-weighted lane
   sum, which §6.4(i) shows is categorically insufficient; the upgrade to the AlgHash sponge
   over full child public-IO tuples is the aggregation worker's in-flight deliverable. Until
   both land, this theorem's preconditions are not satisfied by the shipped tree — by design:
   this document specifies what must land, and the proof that then obtains.
3. **The numeric β_node.** 76.80 (shipped) vs 92.6 (conditional screen) vs the H1 internal-node
   question and the grinding-accounting question (blocker #3) — all orthogonal to the bridge;
   the theorem is parametric and §7.1 evaluates both endpoints.
4. **P1/P2 interfaces (A5).** The cover-certificate checker and M-LINK cancellation are separate
   obligations with their own budgets; this theorem consumes them and adds ε_P2(Λ) additively.
5. **A6/P4 node-id in the FS point** — required precondition, unshipped, cheap (in flight). Note
   D3's (f2) already forecloses sibling permutation at the *statement* layer; the FS node-id is
   still required for the *regrind* accounting (union validity across structurally identical
   subtrees).
6. **Base-argument regime.** κ ≤ 2^{−76.80} is quoted in the proven unique-decoding regime; any
   move to 92.6 that leans on correlated-agreement conjectures must be labeled as such in the
   ledger (it would make the theorem conditional on that conjecture as well).

**Bottom line.** With D1–D7 enforced in the parent AIR — in particular the **binding AlgHash
sponge over each child's FULL public-IO tuple** (not the terminal roots alone, and never a
linear sum) — the extractor→soundness bridge for the arity-4, depth-4, 341-node Fp3 recursion
is **proved** under (ROM + CRHF + base knowledge soundness + the P1/P2 interfaces): a
convincing accepting proof of a FALSE parent statement yields, via straight-line extraction,
either (a) a false child public-IO recursing to a false leaf that the deterministic
2³⁷·16 422-MAC episode relation (ExactReplay) refutes unconditionally, or (b) an AlgHash
collision on the parent commitment (contradicts CRHF at 2⁻¹²⁸), or (c) a base-argument
knowledge-soundness break (≤ 2^{−β_node} per node); hence
Pr[accept ∧ false] ≤ 341·2^{−β_node} + 2⁻¹²⁸ + 2⁻⁸⁸ + ε_P2 — 2^{−68.39} at shipped parameters,
2^{−84.09} under the conditional screen. Blocker #1 is closed as a proof obligation; what
remains on this lane is construction (D1's SHA-FS chip and D3b's sponge landing),
verification-fidelity audit (A4), and the independently tracked blockers #2/#3/#5/#6.
