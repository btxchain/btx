# In-AIR child verifier — construction spec (the certified_bits=0 core) — 2026-07-25

> **MatMul v4.7 transition status:** historical proof R&D for possible Epochs
> B–D, not current authority. Epoch A uses Profile-1 ExactReplay; mandatory
> proof data in later epochs must be durable, and Profile 2 is deferred until
> the separate Epoch-D height. See
> `doc/btx-matmul-v4.7-transition-roadmap.md`.
>
> My fable(math)+opus(soundness) construction of the missing in-AIR recursive child verifier.
> HONEST: no chip is CLOSED; the SHA256d FiatShamirAbsorb chip is unbuilt; under the deployed
> biased decoder certified_bits ≈ 20 (100+ needs a consensus-visible uniform-sampler change).
> Not activated (heights INT32_MAX). Codex mirror used read-only for study.

# IN-AIR CHILD VERIFIER — Implementable Construction Spec

**Scope.** One child verified inside its parent AIR, root emitted as a *constrained* output, and the arity‑4 tree induction. Parameters are the **shipped** ones (`kRCFri3AlgNumQueries==192`, `kRCFriBlowup=16`, `kRCFri3AlgBatchMaxColumns=16384`, `kRCFriMaxLdeLog2=24`), not the Q=144 figures the source constructions used. Nothing here is CLOSED; every flag flip is gated and stated as such.

---

## 0. Object selection (decides everything downstream)

The only child object a Poseidon `MerkleCompress` row can open is **`AirQuotientProof<Fp3, AirFriBackendAlg<Fp3>>`** (AlgHash / Poseidon2 Merkle). Family children today are `AirQuotientSplitRapRowsProof`, pinned by `child_proof_commitment = ProofCommitment(proof)` = **SHA256d over codec bytes**. There is no bounded‑degree in‑AIR relation between a SHA256d byte commitment and a Poseidon Merkle‑root limb. Therefore the single‑child verifier below is written for the **AlgBackend FRI proof**, and §2 fixes the mismatch by *re‑basing the object*, not by bridging commitments.

---

## 1. Single‑child in‑AIR FRI verifier AIR

**Lane.** `CanonicalNarrowLaneLayout(DecomposedX2X4X6)`, width **546**, one operation per row, gated max degree **3**, vertical packing. Program columns (kind one‑hot `s_K`, source/child/query/layer/step indices, level selectors `Λ_t`, `segment_end`, terminal selector `Λ_term`) are **PREPROCESSED**. Recursion LDE profile 2^23–2^24.

**New witness columns** (per child slot κ): `root_out[κ][0..4)`, `rt_out[κ][0..4)`, `fold_root_out[κ][l][0..4)` for `l<n_folds`; per Fp3 FS draw `w_i,c_i,q_i,f_i,g_i` (i<3) + 64 bit‑columns/limb; `qbit[0..d)` per query.

### Constraints by `ProgramRowKind`

| Kind (selector) | Constraint (residual, gated `s_K·R`) | Base deg → gated | Executable today? |
|---|---|---|---|
| **PoseidonPermutation** `s_P` | per S‑box: `x2−A²=0`, `x4−x2²=0`, `x6−x4·x2=0`, `y−x6·A=0` (472 templates); sponge rate wiring `rate(r+1)=Out(r)+absorbed` deg1; capacity pins deg1 | 2→3 / 1→2 | **Yes** (x^7 bijection, `air_recurse.h:143‑149`) |
| **MerkleCompress** `s_M` | `dir(dir−1)=0`; input routing `in_j−[(1−dir)acc_j+dir·sib_j]`, mirror for `in_{4+j}`; `in_8−D_node`, `in_9..11=0`; **T** `acc_j(next)−Out_j(cur)` gated `s_M`; dir/index bind `s_M(dir−Σ_t Λ_t·qbit_t)`; qbit segment constancy `(1−segment_end)(qbit(next)−qbit(cur))` | 2→3 / 1→2 | **Yes** |
| **FoldAlgebra** `s_F` | cleared identity `2·x_l·f_{l+1} − x_l(f_l(x)+f_l(−x)) − β_l(f_l(x)−f_l(−x))=0`; `x_l` is **witness** — layer‑0 anchor via d square‑and‑multiply rows `t_{j+1}−t_j(1+qbit_j(ω^{2^j}−1))`, `x_0=g_coset·t_d`, chaining `x_{l+1}−x_l²`; even/odd select with `s=qbit_{top(l)}`: `leaf_{l+1}−[(1−s)even+s·odd]`; terminal `f_{n_folds}−final_value` | 2→3 / 1→2 | **Yes** |
| **DeepAccumulate** `s_D` | `out−(a·b+c)=0`; streams `U(x_q)=Σ coeff_i·x_q^{N−ℓ_i}·P_i`, `u_s=Σ coeff_i·z_s^{N−ℓ_i}·evals[i]`; division‑free dual‑OOD DEEP `G(x_q)(x_q−z1)(x_q−z2) − w1(U−u1)(x_q−z2) − w2(U−u2)(x_q−z1)=0` in ≤6 chained `a·b+c` rows | 2→3 | **Yes** |
| **PerPointAccumulate** `s_PP` | `a−b·c=0`; `C(y)=Σ λ^k C_k(y)` (8/row), `Z_H(y)=y^N−1` by log₂N squarings; terminal `C(y)−Q(y)·Z_H(y)=0` | 2→3 | **Yes** |
| **FiatShamirAbsorb** `s_FS` | **(i) SHA256d compression chip** (bit / 16‑bit‑limb columns, all residuals deg 2) — **DOES NOT EXIST**; **(ii) biased decoder** mirroring `FromChallengeBytes3`: `w_i−c_i−q_i·p=0`, `q_i(q_i−1)=0`, `c_i−(a_i·2^32+b_i)=0` with booleanity, canonicity `c_i<p` via `f_i,g_i`; query index `qindex−Σ 2^j bit_j(c_0)=0`, `qbit_j:=bit_j(c_0)` | 2 | Decoder **Yes**; **SHA chip NO** |
| **Boundary** `s_B` | `out−a=0`; **ROOT EMISSION**: `Λ_term(acc_j−root_out[κ][j])=0` at every query's terminal Merkle row (forces all Q paths to one root), same for `rt_out` and each `fold_root_out[l]`; constancy `root_out(next)−root_out(cur)=0`; `kLastRow` bus export `export_cell−root_out[κ][j]=0` → `AuthenticatedFamilyVerifierOutputBusV1` sponge → `output_bus_root` | 2 / 1 | **Yes** given the emitted cell exists |

**Fold‑terminal correction (mandatory).** The even opening `i_l` and odd opening `i_l+N_l/2` sit under **one** tree. `Λ_term` must fire on **both** the FoldEven and FoldOdd terminal rows into the **identical** `fold_root_out[κ][l]` cell. Pinning one side lets an adversary desync subtrees. State this explicitly per layer.

**Commit‑then‑challenge.** The FS absorb rows for `AbsorbFoldRoot`/preamble must absorb the **same** `root_out`/`fold_root_out` cells the Boundary rows pin (program‑fixed placement), so `β_l/z/w` are bound to the constrained roots — this is what makes the emitted root a *verifier output* rather than a prover‑chosen constant.

### Soundness term (single node, emitted‑root statement)

```
eps_node ≤ eps_FRI(parent) + eps_bind(AlgHash) + eps_child_FS(biased) + eps_extract
```

- `eps_FRI` = per‑node FRI screen. **Shipped Q=192**: 135.21 bits/proof (107.21 after the 2^28‑site union diagnostic). If the fixed point is forced to Q=144 to fit rows, this drops to ~101.77 — state whichever Q the *re‑screened* shape actually uses; do not quote 101.77 as shipped.
- `eps_bind(AlgHash)` = Poseidon2 **128‑bit collision floor**, capacity 4 Fp = 256 bits. This is a **shared, non‑squared** term across the whole ledger: one collision breaks binding at every node, so recursion depth cannot amplify certified bits past ~128 regardless of Q.
- `eps_child_FS(biased)` = the arithmetized decoder replays `FromChallengeBytes3` **exactly**, so arithmetization adds no term. The pre‑existing bias: residues `< 2^32−1` have two 64‑bit preimages → density ratio ≤ 2/Fp‑limb, **≤ 8 per Fp3 draw**. Charge **per independent draw a bad event depends on**: single‑draw fold union → +3 bits; dual‑OOD (`z1` AND `z2`) → **+6 bits (8²)**, not +3. The FS subtotal (~2^-123 → ~2^-120) survives only because the dominant term is single‑draw.
- `eps_extract = 0` **contingently** — holds **iff** the SHA256d chip binds the preimage to the constrained roots in the exact `BuildCanonicalFiatShamirProgram` order. Absent the chip, `β/z/w/qindex` are unbound witnesses chosen *after* the roots ⇒ `eps_extract` unbounded and `root_out` is worthless.

**Honest certified figure under the *deployed* decoder:** the biased `FromChallengeBytes3` caps `eps_FS ≈ 2^-20..-22`, so **certified_bits ≈ 20**, not 101/135. The 100+ figure is reachable **only** after adopting the bounded uniform Fp3 sampler (`Fri3AlgDecodeUniformFp3Candidate`, V5‑only) — a **consensus‑visible transcript change** for recursed children, not a local AIR fix.

**Status §1.** Every algebra chip (scalar, Poseidon x2/x4/x6, Merkle glue, Fold/DEEP/PerPoint at gated deg 3, biased decoder deg 2) is **executable on‑scaffold**. The **SHA256d FiatShamirAbsorb chip is unbuilt** (`kVerifierFiatShamirAirExecutable=false`, static_assert‑pinned). Until it lands, this AIR is a **sound screen, not a certificate**.

---

## 2. Split‑RAP ↔ FRI unification — which route is soundly constructible

Three candidates; two dichotomies collapse to one honest answer.

**REJECTED — commitment‑equality bridge (vacuous).** Arithmetize `SHA256d(codec)` and `AlgHash(bus)` and prove both open a shared statement. Fails absolutely: the two hashes are over different serializations of different objects, and **commitment equality never implies child‑proof validity** — it transports unverified bytes and adds **zero** certified bits. Any framing that "adopts the child's committed root as if it were a verifier output" is this fallacy.

**SOUNDLY CONSTRUCTIBLE — Route A (re‑base the object; RECOMMENDED).** Family children are produced/proved as `AirQuotientProof<Fp3, AirFriBackendAlg<Fp3>>` (AlgBackend FRI). The §1 AIR then verifies **exactly the object consensus pins**. Existing Split‑RAP leaves get a **one‑time leaf‑boundary wrap**: verify the Split‑RAP proof inside a level‑1 AlgBackend parent, whose output proof is the homogeneous type. Interior nodes are then **strictly self‑similar** (parent proof = child proof type). This is a consensus/proving‑pipeline change (`complete_splitrap_verifier_in_air` at the leaf), **not** existing‑scaffold wiring.

**SOUNDLY CONSTRUCTIBLE — Route B (native Split‑RAP verifier chip).** Keep the `MultiRowV2SplitRapProgramV1` schedule (29 `MultiRowV2CheckKindV1` kinds); **flip `kMultiRowV2Expected0..3` from preprocessed to chip‑owned witness**, each equality‑pinned to a sub‑chip output (AlgHash Merkle = `HashOpeningLayout`/`PermLayout`, FS = SHA+decoder, scalar = `BuildVerifierScalarSystem`, root emitter = `AuthenticatedVerticalSpongeLayoutV1`). **Not sufficient by itself** — the EXPECTED‑flip must land **atomically** with **`ChildProofPayloadBus`** (`kVerifierProofRowsBoundInAir=false` today): `CLAIMED[0..3]` are host‑decoded free witnesses, so a prover can pick CLAIMED to satisfy the chips unless CLAIMED is constrained equal to the cells committed by `receipt_payload_root`. Route B carries a **larger** SHA budget (Q=192 Split‑RAP transcript) and **still** needs the canonical recursion root to become the AlgHash emitter sponge for self‑similarity.

**Recommendation.** **Route A.** It makes interior nodes self‑similar by construction and confines the Split‑RAP boundary to a single leaf wrap; Route B's benefit (verify legacy Split‑RAP without re‑proving) is paid for by a permanently larger per‑node FS chip and a second verifier chip to maintain, and it does not by itself close self‑similarity. Both need the §1 SHA chip. The commitment bridge is never an option.

---

## 3. Child‑root output equality — making `family_child_roots_sourced_from_verifier_outputs` real

**Precondition (ABI re‑base).** The family slot child identity changes from 8×u32 LE words of the SHA256d `child_proof_commitment` to the **field‑native** `(row_root‖trace_root)` Fp limbs the vcs already exports (`RowRootLimb`/`TraceRootLimb`, terminal‑Merkle `PermOutputLane`). Note the width mismatch to arithmetize: `Arity4FamilyReceiptLayoutV1.kChildRootWords=8` vs AlgHash `kAlgHashDigestLen=4` Fp — the **8:4 transport encoding is an in‑AIR equality**, not a 1:1 copy; do not assert `ChildRoot(lane)==root_out[κ]` as if same‑width. This is a **consensus‑visible ABI change** to `Arity4TerminalSlotV1`/receipt commitments.

**Wiring** (per slot `s<4`, word `w<8`, parent trace N rows):

| # | Name | Constraint | Deg / kind |
|---|---|---|---|
| C1 | `croot.constant` | `CROOT_{s,w}(next)−CROOT_{s,w}(cur)=0` (cyclic wrap, everywhere‑constant) | 1, T |
| C2 | `croot.bus_bind` | `SEL_BUS_{s,w}·(CROOT_{s,w}−BUS_c0)=0`, `BUS_c0`=`verifier_output.c0` lane | 2, everywhere |
| C2′ | `sel_bus.integrity` | `SEL_BUS_{s,w}·(tag_cols−(s,kind=8,item=w,0))=0` — **must be a constraint**, not validate‑time only (new preprocessed one‑hot columns are outside `program_key` commitment) | 2 |
| C3 | `parent_output.same_trace_alias` | `sel·(BUS_c0−PermOutputLane(terminal_perm,row,limb))=0` — **exists** in `BuildOneSlotNormalizedFriParentV1` only | 2 |
| C4 | `family_slot.child_root_read` | `ROWSEL_s·(ChildRoot(w)−CROOT_{s,w})=0` (or delete ChildRoot cols, read CROOT directly) | 2 |
| C5 | `croot.statement_absorb` | CROOT are payload lanes of the caller‑pinned `AuthenticatedVerticalSponge` → statement root commits verifier‑sourced roots | 2 |
| C6 | padding (optional) | `(1−ACTIVE_s)·CROOT_{s,w}=0` (redundant via C2) | 2 |

**Delete** the `cs.preprocessed.emplace_back` for ChildRoot in `AppendArity4FamilyReceiptSlots`.

**Semantic caveat (do not overstate).** "Sourced from verifier outputs" here means **`CROOT = terminal Merkle cell pinned by `EmitRootPin` to the child's *claimed* root, whose openings must hash to it under FS‑derived challenges`.** It is *one indirection* past the preprocessed pin — genuinely constrained, but only equivalent to "accepted" once the §1 FS chip binds the challenges. Until then it means "accepted under claimed challenges."

**Non‑vacuity (executable mutation test).** Flip one `CROOT` limb → `CountWitnessViolationsOnH ≥ 1` (C2). Flip preprocessed `SEL_BUS` → canonical‑program validator rejects (C2′ / tag mismatch). Today a substituted root only edits public preprocessing and the identical witness still satisfies every constraint — which is exactly why `certified_bits=0`.

**`eps_bind` cost.** Adding ≤160 deg‑≤2 constraints changes the batch term by `≤ 2^8·2^2·|H|/2^192 ≤ 2^-162` for `|H|≤2^20` — negligible; no new FS draws.

**Load‑bearing precondition the CROOT chain omits.** C3 and the `terminal_perm` base it aliases exist **only** in the standalone `BuildOneSlotNormalizedFriParentV1`. `BuildNormalizedUniversalParentCandidateV1` composes **no per‑slot verifier** — `AppendArity4FamilyReceiptSlots` merely SHA‑packs the commitment. So the "+64‑68 columns / <1% prover delta" is measured on top of a 4‑child‑verifying parent **that does not exist**. The real cost is embedding ~4× full FRI verifier traces; CROOT wiring is the trivial last mile.

---

## 4. Tree induction + which flags legitimately flip

**Statement per node.** `S(v) = (fixed NarrowChildShape, σ_v seed, ordered 4‑slot A_v = {(active_s, R_s)}, cancellation lanes α1/α2)`, `R_s` = 4‑limb AlgHash bus root per `ComputeFamilyVerifierOutputBusRootV1`.

**IH(v).** For every ROM adversary: `Pr[ AirQuotientVerify(π_v,σ_v) accepts AND ∃ active s: statement bound by R_s false ] ≤ eps_node(v) + Σ_{s active} IH(child_s)`. Unrolled: root‑accept ⇒ every leaf statement holds except `eps_total = Σ_nodes eps_node` — pure union bound, extraction syntactic (child transcript **is** the witness columns; `V_CS satisfiable ⇔ native verify accepts`).

**Mandatory family selectors.** `row_merkle`, `next_row`, `trace_binding` are **NOT** `VerifierAirFamilies`‑optional. `R_s` binds child_s's witness **only** because the row‑root recompute pin ties the claimed root to the terminal‑permutation output. Toggling `row_merkle` off opens the induction. State them as required.

**Interior nodes are NOT free of the base‑case gates.** The homogeneous AlgBackend child proof **also** uses SHA256d Fiat‑Shamir (`fri_ext3_alg.h:61`) with the **same unbounded OOD rejection loop**. Per‑node SHA256d compression work is **uniform across all nodes** — the claim "leaf adapter dominates row count" is false. Every node needs the FS replay + bounded OOD schedule.

**Grind‑nonce byte origin.** The recursion FRI carries a PoW grind nonce that is **none** of the four `FiatShamirShaByteOriginKindV1` kinds. A **fifth `Nonce` origin** must be arithmetized (with bounding), or the byte‑origin map is not exact and grinding is off‑circuit.

### Flags — what flips and under what checks

| Flag | Flips to | Gate |
|---|---|---|
| `family_child_roots_publicly_pinned` | **false** | ChildRoot preprocessed entries deleted (scan `cs.preprocessed`) |
| `family_child_roots_sourced_from_verifier_outputs` | **true** | C1–C6 + C2′ emitted, 4×8 bus coverage mask `0xff`/slot, **AND** a per‑slot verifier actually composed, **AND** ABI re‑base landed |
| `same_parent_verifies_child_receipt` | **true** | every Fp3 coord equal AND source is a V_CS cell |
| `self_similar_fixed_point_closed` / `self_similar_arity4_shape` / `recursive_fixed_point` | **stay false** | need FS chip at **every** node + bounded OOD + Nonce origin + `AssessCompleteFixedPointScenarios` pass at new width under caps |
| `certified_bits` | **stays 0** | until all of the above; then ≈20 under deployed decoder, ~100+ only after consensus uniform‑sampler migration |

**Never claim CLOSED.** Every flip above except the first three must remain fail‑closed behind the existing static_asserts.

### Tree soundness

Binary realization of arity‑4 (two levels/node): a binary tree over L leaves has L−1 internal nodes + L leaf adapters. `eps_total ≤ (2L−1)(eps_node + eps_FS)`. At L=2^20, Q=144 shape: ~2^-80.8 (≈17‑bit margin over 2^-64, holds to ~2^36 nodes). At shipped Q=192 the per‑node screen is stronger but the shape is larger (see §5). Charge a **separate Split‑RAP eps** for the L leaf adapters (Route A leaf wrap) — not the homogeneous screen. Arity‑2 emulation ~triples node count vs arity‑4 (+~1.6 bits union/level) — the "~89.7 bits at 2^12 nodes" figure is optimistic for the forced arity‑2 fallback.

---

## 5. Size / column budget (shipped Q=192)

**Column budget — REAL and verified.** Vertical narrow lane = **546** columns; parent = **~707** (only if the one‑hot output bus is replaced by the **4‑tag time‑multiplexed** bus — the shipped one‑hot bus adds `output_cells=2W+37` = 1,331 cols at W=647). Both are **~4.3% of the 16,384 cap**, independent of Q and LDE. Correctly avoids the ~8,088‑column wide V_CS NO‑GO.

**Row / LDE budget at Q=192 (33% more than the source's Q=144 figures):**

| Configuration | Active rows (w/ multiproof) | Trace | LDE (×16) | Verdict |
|---|---|---|---|---|
| Leaf, arity‑4 | ~263,461 | 2^19 | **2^24 (at cap)** | not the claimed 2^23 |
| Self‑similar (W=647), arity‑1 | ~254,000 | 2^18 | 2^23 | fits |
| Self‑similar, arity‑2 | ~507,195 | 2^19 | **2^24 @ 96.7%** | at cap, **no margin** |
| Self‑similar, arity‑4 | ~760,792+ | 2^20 | 2^25 | **over the 2^24 cap** |

**Conclusion:** arity ≤ 2 only, and **arity‑2 self‑similar has negative effective margin** once you add (a) the multiproof routing LogUp column + sorted‑run rows, (b) power‑of‑two padding, (c) CTL‑alias rows for Split‑RAP `C` (~1600), and (d) the **D=21 → D=23‑24 self‑consistency** correction (a self‑produced proof is at trace 2^18‑2^20 → LDE 2^23‑2^25, so its Merkle depth 21→23‑24 and folds 17→19‑20 inflate a further ~15‑20%). **The fixed point does not robustly close even at arity‑2** unless the child is normalized down to the 2^21 shape via the **chunk‑RLC PCS row‑leaf collapse** — which is **fail‑closed today** (`original_constraint_relation_bound=false`, `cross_chunk_constraint_manifest_complete=false`, `original_quotient_linked=false`).

**Multiproof caveat.** Node‑dedup routing **cannot be preprocessed**: which queries share ancestors depends on FS‑random indices unknown at build time. The item tag must be a **witnessed index‑prefix constrained to the per‑query FS index bits**, with a LogUp proving two paths share identical `(level, index_prefix, digest)` tuples. Preprocessed tags are either unsound (false sharing) or break canonical‑program independence. The worst‑case schedule `Σ_k min(Q, 2^{D−k})` fixes only size.

**SHA FS chip is the dominant row cost tree‑wide.** Inlining 4× SHA256d Q≥144 transcript replays into one node ≈ 4× child work — `AssessCompleteFixedPointScenarios` will not pass. It must be **recursively consumed as separate same‑shape sub‑proofs** (`MultiRowV2TranscriptShaPlanV1.recursive_nodes`) or staged strictly binary.

---

## 6. HONEST verdict + ordered build plan

**This is a from‑scratch subsystem, not a bounded wiring task.** The receipt/sponge/export scaffolding (§3 CROOT chain, `AuthenticatedVerticalSpongeLayoutV1`, `VerifierAirParentOutput`, `Arity4FamilyReceiptLayoutV1`, scalar chip, Poseidon/Merkle/Fold/DEEP/PerPoint, biased decoder) is the **only** part ready. The following are genuine new subsystems, in dependency order:

1. **In‑AIR SHA256d Fiat‑Shamir chip** (dominant cost; tree‑wide, every node). Consume the existing exact preimages / shard schedules (`BuildCanonicalFiatShamirProgram`, `BuildFiatShamirShaExecutionPlanV1`, `MultiRowV2TranscriptShaPlanV1`). Flips `kVerifierFiatShamirAirExecutable` → executable. **Without this, `eps_extract` is unbounded and everything below is a screen, not a certificate.**
2. **Bounded OOD schedule.** Legislate a consensus `kMaxOodRetries`; re‑emit the FS program as a fixed schedule (`rejection_loop_bounded=true`, `fixed_schedule=true`) with fail‑closed rejection rows (cap ≥ honest need for completeness). A variable‑length loop cannot be a fixed AIR.
3. **Grind‑nonce byte origin.** Add the 5th `Nonce` origin kind + arithmetized selection/bounding, else grinding is off‑circuit.
4. **Bounded uniform Fp3 sampler** (`Fri3AlgDecodeUniformFp3Candidate`) for recursed children — **consensus transcript migration**. Without it, `certified_bits ≈ 20`, capped by `FromChallengeBytes3` bias, regardless of the FRI screen.
5. **Proof‑system re‑base (Route A).** Produce/prove family children as AlgBackend FRI proofs; wrap existing Split‑RAP leaves in a level‑1 AlgBackend parent (`complete_splitrap_verifier_in_air`). Consensus‑visible.
6. **`ChildProofPayloadBus`** binding `CLAIMED` to `receipt_payload_root` (needed only if Route B is chosen; flips `kVerifierProofRowsBoundInAir`).
7. **Compose the arity‑≤2 per‑slot verifier inside `BuildNormalizedUniversalParentCandidateV1`** (port `BuildOneSlotNormalizedFriParentV1` to N slots) so each active slot yields a real `terminal_perm` base and bus cells. This is ~99% of the effort; §3's CROOT chain is the last mile.
8. **ABI re‑base** family slots 8×u32 SHA → field‑native `(row_root‖trace_root)` Fp limbs, arithmetizing the 8:4 transport equality.
9. **Multiproof routing** with witnessed FS‑index‑bound index‑prefix tags + sorted‑run LogUp.
10. **Output‑bus reshape** one‑hot → 4‑tag time‑multiplexed (to hold ~707 cols).
11. **Chunk‑RLC PCS unblock** (`original_constraint_relation_bound`, `cross_chunk_constraint_manifest_complete`, `original_quotient_linked`) — required for the fixed point to *robustly* close at arity‑2.
12. **Re‑screen** via `AssessCompleteFixedPointScenarios` at the new width, charging current+next+trace openings, under the 16,384‑col and 2^24‑LDE caps, **before** flipping `self_similar_arity4_shape` / `recursive_fixed_point`.

**Bottom line.** Sound *design/screen*; the CROOT data‑flow and all algebra chips are buildable on‑scaffold. But `self_similar_fixed_point_closed` and `certified_bits > 0` require steps 1–4 (new subsystems + a consensus transcript change) plus a fixed‑point closure (steps 5, 7, 11–12) that is **at‑cap with negative margin at arity‑2** on shipped Q=192 and does not robustly close without the currently fail‑closed chunk‑RLC PCS. `family_child_roots_sourced_from_verifier_outputs` can legitimately flip after steps 5, 7, 8 + §3; **certified_bits stays 0** until the FS chip (1) and OOD/nonce/decoder gates (2‑4) land. **Not CLOSED.**
