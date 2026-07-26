# SHA256d hash-model reconciliation — CRHF/ROM split, domain separation, and the input-alignment lemma (PR-89 blocker #2) — 2026-07-25

> **Status banner (must survive into any downstream artifact): CONSTRUCTION + PROOF SPEC. NOT CLOSED, NOT AUDITED, NOT ACTIVATED.** Consensus authority remains ExactReplay; `kRCGkrFormalSoundnessReady = false`; heights INT32_MAX. This document RESOLVES the hash-model incoherence of roadmap §4 item 5 / P5 "tape-bridge" (the case-(iii) escape at the 85 internal receipt-tree nodes) under **standard assumptions**, in the same split used by every deployed recursive STARK. It converts the blocker from "model incoherence — bound does not cover the event" into (a) a coherent two-assumption model, (b) one small hard-fork domain-separation change set, (c) a proved input-alignment lemma with a straight-line two-preimage extractor, and (d) an explicit, *named* residual (A-FS-INST) that is shared by Plonky2/Boojum/RISC0 and is not the case-(iii) gap. Companion: `doc/btx-matmul-v4.6-stage3-composition-theorem-roadmap-2026-07-25.md`.

---

## 0. The gap being resolved (restated exactly)

SHA256d appears in the composition in two roles:

1. **Fiat–Shamir challenge derivation** — `RCGkrFsSeedV7` (`matmul_v4_rc_gkr.cpp:1278`, tag-first `"BTX_RC_GKR_WINNER_V7"`), the query draw `SHA256d("BTX_RC_FS_V1"‖σ‖digest‖le32(q))` (`matmul_v4_rc.h:316`), the FRI transcript tags (`BTX_RC_FRI_V5`, `BTX_RC_FRIB3ALG_*`), and the stage-3 position-bound role/child FS points (`matmul_v4_rc_stage3_recursive.h:112–160`). The composition theorem models these as a **random oracle** with query budget `Q ≤ 2⁴⁰`.
2. **Arithmetized in-circuit binding** — the fixed-program SHA-256 compression AIR (952 rows/compression, `matmul_v4_rc_stage3_hash_air.h`), used at the **85 internal nodes** of the arity-4 receipt tree (and at every in-circuit child-digest / T-BIND recomputation) to equality-bind an absorbed digest to a preimage carried in witness columns.

The adversarial review's escape (case iii): a forger who **authors** a preimage satisfying the in-circuit SHA constraint on a **false child view** makes **no RO query**. Nothing is on the tape, so nothing is chargeable to the flat `ε_H = 2⁻⁸⁸` term *as that term was justified* ("SHA256d Merkle/transcript bindings, 2⁴⁰-query adversary", `matmul_v4_rc_gkr_eval.h:301`). The bound, as written, did not cover the event — because it charged binding to *oracle queries*, which is the wrong accounting for an arithmetized hash.

**The resolution in one sentence:** binding events are never charged to RO queries; they are charged to a **straight-line collision-resistance reduction over *exhibited evaluation pairs***, of which an in-circuit constraint satisfaction is one — so "the forger made no RO query" stops being an escape, and the ROM survives, domain-separated, for challenge derivation only.

---

## 1. The model split (two distinct standard assumptions)

Partition every consensus use of SHA256d into three call classes with disjoint input domains (§2 makes the disjointness syntactic):

| Class | Uses | Model / assumption |
|---|---|---|
| **H_BIND** (`D_BIND`) | Tile-tree leaf/node/pad hashes (`kRCLeafTag 0x00` / `kRCNodeTag 0x01` / `kRCPadLeafTag 0x02`, `matmul_v4_rc.cpp:561–586, 1061`); all manifest commitments (`CommitShaManifest`, `CommitDirectSha256dManifest`, `CommitTileTreeManifest`, …); receipt-tree T-BIND digests, aggregation-seed statement digests; **every in-circuit SHA site**, incl. all 85 internal nodes | **Concrete collision-resistant hash (CRHF).** Standard assumption **A-CR**: SHA-256 is collision-resistant, hence SHA256d is (a SHA256d collision yields a SHA-256 collision in the inner or the outer call). No oracle, no query counting. |
| **H_FS** (`D_FS`) | All FS seeds and challenge draws listed in §0.1 | **Random oracle** (programmable, on `D_FS` only), plus the indifferentiability term for double-MD on a prefix-free tagged domain (§4). |
| **H_HDR** | The legacy 182-byte block-header double-SHA (`primitives/block.h:35`, no tag byte) | Folded into the **binding** role: header hashing is pure identity binding; its collisions are chargeable to A-CR like any other binding event. The FS oracle never absorbs raw header bytes — `RCGkrFsSeedV7` absorbs header *fields plus the header hash value* under its own tag. |

This is exactly the split deployed recursive STARKs make (see §5): **CRHF for everything the circuit checks; ROM only for what the (outermost) verifier derives.** The two models never compete for the same input because the domains are disjoint (§2), and — crucially — they never compete for the same *event class* because of the accounting rule fixed next.

**Accounting rule (the actual fix).** Define, for an accepted root receipt, the multiset

```
E := { (x, d) : d = SHA256d(x) exhibited by the accepted proof }
```

where "exhibited" means either (a) a concrete evaluation the verifier performs natively (Merkle path checks, manifest recomputation, header hash), or (b) an in-circuit constraint-satisfying assignment whose witness columns carry `x` and whose pinned boundary carries `d`. Under **A-EXACT** (§3, assumption: the SHA AIR is functionally exact), every element of E is a genuine input–output pair of the *concrete* function — an in-circuit satisfaction **is** an evaluation, whether or not any oracle was queried. All binding soundness is charged to collisions **within E** via the straight-line extractor of §3. RO queries are charged only to the FS terms. Case (iii) is by construction an element of class (b), hence inside E, hence covered.

---

## 2. Domain-separation construction (hard-fork transcript changes; normative)

### 2.1 What the shipped tree already has (verified)

- Tile-tree binding preimages begin with a single binary byte `0x00/0x01/0x02` (`matmul_v4_rc.h:197–199`); internal nodes are the fixed 65-byte `0x01‖left‖right` (`matmul_v4_rc.cpp:561`).
- FS preimages begin with ASCII `"BTX_…"` (first byte `0x42`), tag-first (`RCGkrFsSeedV7`, `kRCFsTag`, all FRI tags).
- **But** the separation is *not currently role-clean*: binding-side manifest commitments also use ASCII `"BTX_…"` tags (`CommitShaManifest` → `Sha256dTagged("BTX_RC_STAGE3_SHA_MANIFEST_V1", …)`, `matmul_v4_rc_stage3_hash_air.cpp:5271`; likewise `BTX_RC_STAGE3_DIRECT_SHA256D_V1`, the `BTX_RC_COUP_*` tags, `AGGREGATION_DOMAIN`). So today `D_BIND` and `D_FS` overlap in the ASCII class. The role split must be made **syntactic**, by role byte, not by tag registry convention.

### 2.2 Normative wrapper construction (V8, hard fork)

All consensus SHA256d calls MUST go through exactly one of two wrappers; the set of call sites is a compile-time registry (audit artifact, one enum per site):

```
Sha256dBind(role_tag, enc)  :=  SHA256d( role_tag ‖ enc )      role_tag ∈ BIND tags
Sha256dFs(ascii_tag, enc)   :=  SHA256d( 0xF5 ‖ ascii_tag ‖ enc )
```

**First-byte partition (MUST):**

- `D_BIND`: first byte ∈ `{0x00 … 0x3F}` ∪ `{0xB1}`.
  - `0x00` tile leaf, `0x01` tile node, `0x02` pad leaf — **unchanged** (tile-tree roots keep their bytes).
  - `0x03` receipt-tree leaf statement; `0x04` receipt-tree internal node, with the fixed-length encoding
    `0x04 ‖ u8 level ‖ le64 node_id ‖ u8 arity ‖ u8 live_mask ‖ d_child[0..3]` (vacuous slots carry the fixed constant `SHA256d(0x02‖"BTX_RC_PAD")`, never a copied live digest) — 143 bytes, fixed.
  - `0x05 … 0x3F` reserved per binding manifest type; every existing ASCII-tagged **binding** commitment (`BTX_RC_STAGE3_SHA_MANIFEST_V1`, `BTX_RC_STAGE3_DIRECT_SHA256D_V1`, `BTX_RC_COUP_*` subroot tags, `AGGREGATION_DOMAIN`, V2 transcript tags of `matmul_v4_rc_transcript.h:37–40`) is re-issued as `0xB1 ‖ old_ascii_tag ‖ enc` (one role byte prepended; tags themselves unchanged, so the registry diff is mechanical).
- `D_FS`: first byte `0xF5`. Every existing FS absorb (`kRCGkrDomainTagV7`, `kRCFsTag`, `kRCFriDomainTag`, `kRCFriBatchDomainTag`, all `BTX_RC_FRIB3ALG_*`, `ComputeRCStage3RecursiveRoleSeed` / `…ChildFsPoint` bases) gets `0xF5` prepended. **This is the transcript-breaking change**; it is acceptable under the standing hard-fork freedom and follows the repo's own rule (`matmul_v4_rc_transcript.h:25`: bump only with new domain tags, retain goldens).
- `H_HDR`: the raw 182-byte header remains untagged (wire compatibility is untouchable pre-activation, `primitives/block.h:28–34`). Because the header's first byte is the LSB of miner-grindable `nVersion`, header bytes **can** land in either first-byte class; this is harmless (next paragraph), but for hygiene the wrappers SHOULD reject any tagged preimage of total length exactly 182 (in practice: forbid `t_leaf = 181`; all other fixed encodings miss 182 already — node 65, pad 11, receipt-internal 143).

**Why first-byte disjointness is the MUST and length-182 only a SHOULD.** The separation has one load-bearing job: the ROM-modeled set `D_FS` must be disjoint from every input on which the proof relies on the *concrete* function's behavior (`D_BIND`), so the ideal-oracle hybrid never has to be consistent with a concretely-checked value. That is delivered by `0xF5 ∉ {0x00…0x3F, 0xB1}`. Aliasing *within* the binding role (e.g. a crafted manifest preimage that parses as a header) does not disturb any model: both roles are concrete, the digest still determines the preimage up to collisions, and collisions are charged to A-CR regardless of type. Cross-class collisions (`SHA256d(bind-input) = SHA256d(fs-input)`, inputs necessarily distinct at byte 0) are likewise ordinary A-CR collision events — domain separation is for **model coherence**, not a substitute for collision resistance.

**Injectivity / prefix-freeness (discharges first-collision premise (c)).** Within `D_BIND`, every encoding is injective and prefix-free per role tag: fixed-length encodings (`0x01`: 65 B; `0x04`: 143 B) are trivially so; variable-length manifest encodings are already length-prefixed field-by-field (`CommitShaManifest` uses `AppendU64(len)` before the preimage) and the typed builders refuse untyped byte strings (`matmul_v4_rc_stage3_hash_air.h:953`: "Typed preimage builders prevent a prover choosing an arbitrary direct-hash byte string with the right digest"). The registry certificate (§6, O-ENC) must enumerate this per site.

---

## 3. The input-alignment lemma (closes case iii)

### 3.1 Assumptions

- **A-CR** — SHA-256 collision resistance (standard; implies SHA256d CR).
- **A-EXACT** — the arithmetized SHA-256 fixed-program AIR is *functionally exact*: any assignment satisfying the 952-row instruction schedule + boundary pinning (`BuildFixedProgramBoundaryConstraintSystem`, external words = padded block ‖ chaining state ‖ round constants; final words = digest) + internal-SSA provenance (`BuildFixedProgramProvenanceInstance` LogUp lanes) determines a preimage `x` (its witness bytes) and digest `d` with `d = SHA256d(x)` for the *concrete* function. This is roadmap A3 (in-circuit fidelity), an equivalence-audit obligation — it was already load-bearing and is not new debt introduced here.
- **A-EXTRACT** — accepted proofs are witness-extractable within the FRI unique-decoding radius (roadmap A1/A2): the extractor reads committed columns (hence exhibited preimages) off the accepted proof. Standard for FRI-based systems.
- **A-ENC** — injective, prefix-free per-type encodings at every binding site (§2.2; first-collision premise (c)).
- **Total order** — the canonical scan order over binding sites: (tree level, node_id, slot_index, per-node SHA call ordinal). Well-defined from the shipped position structure (`RCStage3RecursivePosition`, `matmul_v4_rc_stage3_recursive.h:112`); first-collision premise (a).

### 3.2 Lemma (T-ALIGN, exhibited-evaluation consistency)

> **Lemma.** Let A be an adversary (adaptive FS, PoW grinding allowed) that outputs a root receipt the normalized verifier ACCEPTS (T-BIND well-formed, single transcript DAG). Let `E` be the exhibited-pair multiset of §1, extracted under A-EXTRACT and genuine under A-EXACT, `|E| ≤ N_E := (tape evaluations) + Σ_{v∈341 nodes}(SHA calls at v)`. Then exactly one of:
>
> **(b) Collision branch.** Two pairs `(x, d), (x′, d) ∈ E` with `x ≠ x′`. The reduction **B** below outputs an SHA256d collision.
>
> **(a) Alignment branch.** The map `d ↦ x` is a **function on E** (each digest exhibited anywhere in the accepted proof has one preimage exhibited everywhere it appears). Then for every internal node `v` and live child slot `c`: the child-digest field `d_c` inside `v`'s in-circuit preimage `p_v` has the same exhibited preimage as the digest that child `c`'s own accepted sub-verification exhibits for its committed content; by A-ENC injectivity the child view `v` bound is **byte-identical** to what `c` committed. By induction down to the leaves (whose openings are native tape evaluations against committed roots), the receipt-tree semantics collapse to the monolithic glued statement. **No case-(iii) event exists on this branch**: an adversary-authored preimage on a false child view would be a second exhibited preimage of an exhibited digest — branch (b).
>
> Consequently `Pr[accept ∧ statement false] ≤ Adv^CR_SHA256d(B) + Pr[accept ∧ false | alignment]`, and the second term contains **only** algebraic and FS events (the 341-node statistical union, link terms, FS terms) — no hash-binding events remain in it.

**The reduction B (discharges first-collision premises (b) and (d)).** B runs A **once**, straight-line: it answers nothing, reprograms nothing, and never rewinds — A's adaptive Fiat–Shamir/PoW transcript is preserved verbatim (premise 4 of `matmul_v4_rc_stage3_first_collision_audit.h:28`). On acceptance, B extracts witnesses (A-EXTRACT), assembles E, scans in the canonical total order, and outputs the **first** pair of colliding exhibited preimages — the exact `ScanFirstCollisionObservations` shape already specified in `matmul_v4_rc_stage3_first_collision_audit.h`, populated per-site with `both_preimages_extracted = true` and `digests_recomputed_from_encodings = true`. Because both preimages come out of **one** run of A's own accepted proof (the parent's in-circuit preimage columns and the child's own exhibited root computation), there is **no 1/S site-guessing loss and no forking loss** in this reduction: `Pr[B outputs collision] ≥ Pr[A forges ∧ ¬alignment]`. B's cost: A's cost + extraction + an O(S) scan.

This is the **accepted-proof two-preimage extractor** whose absence was the audit's `first_blocker` ("accepted proof has no global two-preimage extractor", `accepted_proof_two_preimage_extractor_executable = false`). The lemma specifies it; §6 lists what must be implemented for the audit flags to flip.

**What the lemma does NOT remove** (unchanged from the audit's own honesty list): the FS forking/replay loss and RO birthday dependence live entirely on the FS side (§4) and are budgeted there; PoW grinding stays charged at 2⁴⁰ under the total-work convention. T-ALIGN moves **zero** of those; it only re-homes every binding event out of the RO-query ledger and into A-CR.

### 3.3 The recovered bound — and which exponent it is

The internal-node event is a **collision** event, not a second-preimage event: the adversary chooses both sides adaptively (it authors `p_v` *and* influences the tree content the other exhibited preimage encodes). Do **not** claim the 2⁻²⁵⁶/2⁻²¹⁶ second-preimage exponents for tree nodes; those framings (roadmap P6/H3) remain valid only for binding targets fixed *before* adversary interaction (pinned protocol constants, genesis parameters).

Numerics under A-CR, reduction B with total work `T` (which upper-bounds `N_E`, since each exhibited pair costs ≥ 1 real compression of prover work under A-EXACT):

- **Generic (birthday-exact):** `Adv ≤ N_E² / 2²⁵⁷`; at the ledger envelope `T ≤ 2⁴⁰`: `≤ 2⁻¹⁷⁷`.
- **Ledger convention (linear-in-work, 128-bit collision floor):** `Adv ≤ T · 2⁻¹²⁸ = 2⁻⁸⁸` at `T = 2⁴⁰` (`kHashCollisionFloorBits = 128`, `kConservativeGrindingBits = 40`, `matmul_v4_rc_stage3_global_soundness_ledger.h:23–25`).

So the **flat 2⁻⁸⁸ term is recovered intact** — but with its justification corrected: it is `ε_bind`, the CR advantage of the straight-line exhibited-pair reduction (covering tape hashes **and** all 85 in-circuit internal nodes **and** header hashing), *not* an RO-query count. The composed union becomes

```
ε_total ≤ 341·2^(−β_node) + 2Λ·ε_link + ε_bind + ε_indiff ,
ε_bind  ≤ 2⁻⁸⁸ (convention) [ ≤ 2⁻¹⁷⁷ birthday-exact ],   ε_indiff ≤ ~2⁻¹⁷⁶ (§4).
```

Nothing numeric moves: `ε_bind` stays non-dominant, and the binding floor of the system remains P5/H2c (~67.6 bits) exactly as the roadmap reports. This resolution removes the *model incoherence*, not the arithmetic floor.

---

## 4. Reconciling with the FS/ROM side

**Coherent hybrid.** Model `H_FS := SHA256d|_{D_FS}` as a random oracle; keep `H_BIND := SHA256d|_{D_BIND}` concrete. Because `D_FS ∩ D_BIND = ∅` (first byte, §2.2), the hybrid is one well-defined function and the RO simulator is never forced to be consistent with a concretely-checked binding value; this is the standard domain-separated oracle-cloning argument (Bellare–Davis–Günther, "Separate Your Domains", EUROCRYPT 2020). The residual model-consistency cost of pretending a *restriction of a Merkle–Damgård-derived function* is an RO is the indifferentiability term for double hashing over a tagged prefix-free domain (Coron–Dodis–Malinaud–Puniya, CRYPTO 2005; SHA256d's outer call additionally kills length extension): `O(q²/2²⁵⁶) ≈ 2⁻¹⁷⁶` at `q = 2⁴⁰`. Absorbed into the union above as `ε_indiff`.

**The in-circuit FS-replay is a different animal — name it.** At the 85 internal nodes the arithmetized child verifier also *re-derives the child's FS challenges* in-circuit (the "SHA FS-replay" lane, roadmap H2b). A random oracle cannot be arithmetized; the circuit necessarily fixes the concrete function. Therefore the ROM proof applies to the **outermost** transcript only, and each recursion level converts one ROM step into an instance of:

> **A-FS-INST (named residual, standard).** SHA256d, domain-tagged per §2.2, soundly instantiates the Fiat–Shamir transform for the inner FRI/AIR protocol class used here (a correlation-intractability-style conjecture for the concrete hash).

This assumption is **not** the case-(iii) gap and is **not eliminable under standard assumptions by any deployed system**: it is precisely the caveat under which Plonky2, Boojum, and RISC0 ship. What matters for this blocker is separation of concerns: challenge *derivation* soundness rests on ROM-then-A-FS-INST; digest *binding* soundness rests on A-CR alone via T-ALIGN, needing neither oracle queries nor programmability. A forger at an internal node cannot arbitrage between the models, because the event classes are disjoint by the §1 accounting rule and the domains are disjoint by §2.

**Deployed-system precedent (the same split, same residual):**

- **Plonky2** — FS via the Poseidon "challenger" duplex, modeled as an RO; Merkle-cap binding argued from collision resistance of the concrete hash; recursion arithmetizes *that same concrete hash* to replay the inner challenger and verify inner Merkle openings, with composed security stated in the ROM and explicitly instantiated heuristically (whitepaper §recursion/security).
- **RISC Zero** — STARK recursion with SHA-256 (originally) / Poseidon2 commitments; the published soundness analysis charges Merkle binding to concrete collision resistance and FS sampling to ROM plus a grinding budget, while the recursion circuit checks the concrete hash's constraint system (their soundness/security-model docs make the CRHF-vs-ROM split explicit).
- **Boojum (zkSync Era)** — PLONK+FRI recursion, algebraic hash arithmetized in-circuit for inner verification, FS in ROM: identical pattern.
- **Theory anchors** — BCS16 (Merkle-compiled IOPs: binding via straight-line collision extraction — the exact shape of B in §3.2, inherited from Valiant '08); COS20 *Fractal* (recursion in the ROM; explicit statement that instantiating the oracle for the inner verifier is heuristic); CDMP05 (MD indifferentiability on prefix-free domains); BDG20 (domain separation/oracle cloning done right).

---

## 5. Assumption ledger (complete)

| # | Assumption | Type | Charged term |
|---|---|---|---|
| A-CR | SHA-256 (⇒ SHA256d) collision resistance | Standard, concrete | `ε_bind ≤ 2⁻⁸⁸` (convention) — now covers case (iii) |
| ROM(H_FS) | `SHA256d|_{D_FS}` ideal for outermost FS | Heuristic model, standard usage | FS subtotal ×2⁴⁰ (unchanged, `matmul_v4_rc_gkr_eval.h:290–303`) |
| ε_indiff | Double-MD ≈ RO on tagged prefix-free domain | Provable (CDMP05) given ideal compression fn | `~2⁻¹⁷⁶`, new explicit line item |
| A-FS-INST | Concrete SHA256d instantiates FS for the arithmetized inner replay | **Named residual**, shared by Plonky2/Boojum/RISC0 | Not quantifiable; per recursion level |
| A-EXACT | SHA AIR functional exactness (roadmap A3) | Equivalence-audit obligation | Gate on T-ALIGN |
| A-EXTRACT | Witness extraction in unique-decoding radius (roadmap A1/A2) | Standard FRI obligation | Gate on T-ALIGN |
| A-ENC | Injective prefix-free encodings at all binding sites | Certificate obligation (O-ENC) | Gate on T-ALIGN branch (a) |

## 6. Construction changes and remaining obligations

**Hard-fork change set (transcript-breaking; acceptable):**

1. `0xF5` role byte prepended to every FS absorb (all sites in §0.1). New golden vectors; retain old per `matmul_v4_rc_transcript.h:25`.
2. `0xB1` role byte prepended to every ASCII-tagged **binding** commitment (`CommitShaManifest` et al., `BTX_RC_COUP_*`, `AGGREGATION_DOMAIN`, V2 subroot tags).
3. New fixed-length BIND tags `0x03` (receipt leaf) / `0x04` (receipt internal, 143-byte encoding with level/node_id/arity/live-mask and pad-constant vacuous slots).
4. Compile-time SHA-call-site registry (every consensus SHA256d call = one enum entry with role, tag, encoding schema) — this is the audit artifact for O-ENC and for the H2b lane-completeness screen.
5. SHOULD: wrappers reject total preimage length 182 (`t_leaf ≠ 181`).
6. Tile-tree bytes `0x00/0x01/0x02` and the 182-byte header wire format are **unchanged**.

**Obligations that remain open after this document (tracked; none re-opens the model gap):**

- **O-EXTRACT-IMPL** — implement the §3.2 extractor + scan over extracted witnesses (flips `accepted_proof_two_preimage_extractor_executable`, `deterministic_scanner_executable`, `canonical_total_order_specified` in `AssessGlobalFirstCollisionHybrid`; `conditional_no_site_guessing_lemma_valid` then holds with premises discharged per §3.1).
- **O-EXACT** — the A-EXACT equivalence audit of the fixed-program SHA AIR (roadmap §4 item 3; `kHashRelationsComplete` is still `false` and stays so until then).
- **O-ENC** — run the registry certificate (injectivity/prefix-freeness per site; flips `all_binding_nodes_use_injective_encoding`).
- **O-VAC** — vacuous-slot rule of §2.2.3 enforced in the parent AIR (roadmap P5 last bullet): a vacuous slot folds the pad constant and never skips a live child's verification.
- **A-FS-INST** — permanent named residual; goes to external audit as a *disclosed assumption*, not a gap.

**Bottom line.** Blocker #2 is resolved as a construction + lemma, not declared open: with the §2 wrappers, the §3 T-ALIGN lemma and its straight-line two-preimage extractor charge the case-(iii) internal-node event to concrete SHA256d collision resistance at the recovered flat `ε_bind ≤ 2⁻⁸⁸` (birthday-exact `2⁻¹⁷⁷`), the FS side keeps its domain-separated ROM accounting plus an explicit `ε_indiff ≤ ~2⁻¹⁷⁶`, and the single genuine residual under standard assumptions is A-FS-INST — the same one every deployed recursive STARK carries. Numeric floors elsewhere (P5/H2c ~67.6, FRI union ~68.4) are untouched and remain the open items they were.
