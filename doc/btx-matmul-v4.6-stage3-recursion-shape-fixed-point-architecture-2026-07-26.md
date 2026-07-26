# Recursion shape fixed point — does one exist by ANY construction? (arch lane, 2026-07-26)

> ANALYSIS ONLY. No source edited, no flag flipped, no height set. All numbers below are
> either MEASURED (relayed from other lanes), DERIVED IN CLOSED FORM from source read in
> `/home/administrator/stage3-build`, or COMPUTED from those two. Anything ASSUMED is
> labelled. Model scripts live under this session's `scratchpad/arch-lane/`.

---

## 0. Answers in one paragraph

**Q1 mechanism:** the ~677 columns-per-child-column is real but is *not* `Q x width`.
`Q` lives in the V_CS **rows** (`cs.n_rows = FriNextPow2(max(2,Q))`); the entire per-query
verifier circuit is unrolled **horizontally into columns**. The exact slope is
**`k * 149.25`** columns of parent per column of child (`k=4 -> 597.00`), driven by three
full-row leaf sponges at `3/8` Poseidon2 permutations per child column and **130 columns
per permutation**. The measured 677.5 is a two-point fit that conflates width growth with
Merkle-depth growth; the true slope is 597.

**Q2 fixed point:** **NO fixed point exists in the shipped (wide/horizontal) V_CS under any
parameter choice, at any arity, with any subset of verifier families — including unsound
ones.** The minimum achievable slope is 51.75 (`k=1`, row-Merkle only, no next-row/trace
binding, no fold). Contraction needs slope `< 1`. This is a closed-form impossibility, not
an extrapolation.

**Q3/Q5 route:** a fixed point **does** exist in the vertical/narrow layout — width is
constant by construction and rows converge in 2-3 levels because the only feedback is
`D = log2(n_lde)`. Whether it lands under the `2^24` LDE guard is decided by **one term**:
the in-AIR SHA256d Fiat-Shamir chip. With it, arity-2 misses by 4x even with every other
lever applied. Without it (algebraic FS), arity-2 closes at `2^24` and arity-1 at `2^23`.

---

## 1. Mechanism, derived exactly

### 1.1 Where the columns come from

`src/matmul/matmul_v4_rc_air_recurse.cpp`:

* `BuildVerifierAIRPinned` (:1505-1506) — `cs.n_rows = FriNextPow2(max(2,Q))`,
  `cs.n_columns = ComputeLayout(...).n_cols`. **One row per FRI query. Everything else is
  a column.**
* `ComputeLayout` (:737) — `AllocChildWitness` then `AllocChildPreproc`, **per child, k
  times**, no sharing.
* `AllocChildWitness` (:637) — the only `W`-dependent allocations:
  | site | count | cost |
  |---|---|---|
  | `row_merkle` leaf sponge | `RowLeafNBlocks(W)` perm blocks | `130` cols each |
  | `next_row` leaf sponge | `RowLeafNBlocksForValues(W+1)` perm blocks | `130` cols each |
  | `trace_binding` leaf sponge | `RowLeafNBlocksForValues(W)` perm blocks | `130` cols each |
  | `deep` OOD vectors | `evals_z1` + `evals_z2` | `2(W+1)` cols |
  | `deep` preprocessed | `xpow` | `W+1` cols |
* `RowLeafNBlocks(W) = (3(W+1)+1)/8 + 1` (:522) — the row-wise Merkle leaf absorbs
  `3(W+1)+1` base-field words at rate 8, i.e. **`3/8` permutations per child column**.
* `kPermCellsPerPerm = 12 + 118 = 130` (`matmul_v4_rc_air_recurse.h:95-100`) — a Poseidon2
  permutation is flattened into 130 columns of ONE row.

### 1.2 Closed-form slope

```
d(V_CS)/dW  =  k * ( 3 sponges * (3/8) perms/col * 130 cols/perm  +  2 witness + 1 preproc )
            =  k * ( 146.25 + 3 )
            =  k * 149.25
```

`k=1 -> 149.25`, `k=2 -> 298.50`, `k=4 -> **597.00**`.

### 1.3 Validation against both MEASURED points (exact, not fitted)

Re-implementing `AllocChildWitness`/`AllocChildPreproc`/`ComputeLayout` literally
(`scratchpad/arch-lane/vcs_model.py`), with `child_w = child_cs.n_columns` (:1431),
`merkle_depth = log2(n_lde)` (:1435), `n_folds = log2(n_coeffs) = merkle_depth - 4`
(blowup 16):

| child | shape | model | MEASURED | match |
|---|---|---|---|---|
| toy | `k=4, W=1, D=5, nf=1` | **16,176** | 16,176 | exact |
| real | `k=4, W=544, D=9, nf=5` | **384,052** | 384,052 | exact |

Both `(D,nf)` solutions are **unique** over `D in [4,30]`. The wrapper adds a constant
932 columns (`16,176+932 = 17,108`, `384,052+932 = 384,984`) — the four-slot receipt/
sponge scaffolding in `BuildFourSlotSelfSimilarCtlParentV1`, `W`-independent. The model
therefore reproduces the shipped code, not a curve fit.

### 1.4 Why 677.5 is wrong (a correction to tonight's fit)

The two measured children have **different Merkle depths** (`D=5,nf=1` vs `D=9,nf=5`), so a
straight line through them absorbs `~44k` columns of depth growth into the width slope.
Correct slope 597.00; the fit overstates by 13.5%. This does not change any verdict — it
changes 11.6M -> 10.4M and 261M -> 230M columns at level 2 — but the derivation should be
used, not the fit.

### 1.5 Level-2 blowup (COMPUTED, `D=15,nf=11` for the parent's own `n_lde=32768` proof)

| parent consumed as child | k=1 | k=2 | k=4 |
|---|---|---|---|
| toy-derived, `W=17,108` | 2,592,525 (2.5x cap) | 5,185,050 (4.9x) | 10,370,100 (9.9x) |
| real-derived, `W=384,984` | 57,497,953 (54.8x) | 114,995,906 (109.7x) | **229,991,812 (219.3x)** |

against `kRCFri3AlgBatchMaxColumns = 2^20`.

### 1.6 On "proof size and circuit size are the same problem"

**Partly confirmed, with the mechanism corrected.** The parent V_CS *cell* count is
`Q * k * 149.25 * W` (rows `= Q`, columns `= k*149.25*W`), and the child proof's dominant
payload is `Q * W * 24 B * (#oracles)`. Both are `Theta(Q*W)` — so yes, one product drives
both, and any fix that reduces `Q*W` fixes both. But the *column* blowup is not `Q x W`:
`Q` never enters the width. Anything that reduces only `Q` (e.g. `192 -> 136`) shrinks
proof bytes and V_CS rows but leaves the column blowup **exactly unchanged**, so it cannot
by itself produce a fixed point.

---

## 2. Does a fixed point exist in the shipped layout? — NO, provably

Recursion closes iff `f(W) <= W` has a solution below the cap, where
`f(W) = V_CS width of a parent verifying a child of width W`. Since
`f(W) = s*W + c` with `s >= 51.75` and `c > 0`, `f(W) > W` for every `W >= 0`.

| configuration | slope | verdict |
|---|---|---|
| `k=1`, all families | 149.25 | EXPANDS |
| `k=1`, drop `fold` (UNSOUND) | 149.25 | EXPANDS |
| `k=1`, drop `next_row`+`trace_binding` (UNSOUND — opens the IH, see in-AIR spec §4) | 51.75 | EXPANDS |
| `k=1`, row-Merkle + DEEP only (UNSOUND) | 51.75 | EXPANDS |

**No parameter choice closes it.** Not arity, not `Q`, not the column cap, not the field,
not grinding. Raising `kRCFri3AlgBatchMaxColumns` buys exactly one extra level per `log2(597)
~ 9.2` bits of cap and can never close a `>1` slope. This is a property of the *layout*:
one query per row + full horizontal unrolling means parent width is `Theta(k * child width)`.

**Corollaries the project should absorb:**

1. The canonical 341-node arity-4 depth-4 tree is unreachable in this layout. Confirmed.
2. Higher arity is strictly worse (slope `prop k`). Confirmed as asked.
3. **Depth-1 is also not actually a proof.** The one working level (`k=4`, `W=544`,
   `valid=true violations=0`) is a *constraint-satisfiability* result
   (`CountWitnessViolationsOnH`), not a proof-carrying one: its own `BatchCommit` would
   materialise **~303 GB** at `n_lde=32768` (stated in source at
   `matmul_v4_rc_stage3_recursive_parent_air.cpp:4728-4731`). So "recursion currently means
   a single aggregation step" is generous — it currently means a single **unproven**
   aggregation step. Do not report depth-1 as a fallback without this caveat.

---

## 3. Candidate constructions, ranked

### (b) Non-row-wise / batched-column opening — REJECT
The verifier must evaluate the AIR at the queried point, which needs every column's value
there. Any layout still delivers `W` field elements per query; the leaf hash over them is
`3W/8` permutations either way. Changing the Merkle layout to per-column would make it
`W` *paths* per query instead of one — strictly worse for both bytes and circuit. The
row-wise choice is documented as deliberate (`matmul_v4_rc_fri_ext3_alg.h:50-59`) and is
**correct**. The error is not the commitment layout; it is unrolling the leaf sponge
horizontally. **Do not re-litigate the row-wise commitment.**

### (a) `narrow_recurse` / vertical lane — PRIMARY. Ranked 1.
`CanonicalNarrowLaneLayout(DecomposedX2X4X6)`, width **546** fixed, one permutation per
row, `F_width(w) = 546` for all `w`. Width fixed point is trivially closed; the whole
question moves to rows and the `2^24` LDE guard. The planner
(`matmul_v4_rc_stage3_narrow_recurse.cpp:263-421`) and its fixed-point assessor already
exist and are correctly fail-closed (`kNarrowVcsExecutable=false`).

Replicating `BuildNarrowVcsPlan`/`NextRecursiveChildShape` exactly
(`scratchpad/arch-lane/narrow_model.py`), the iteration **always converges in 2-3 levels**
(only feedback is `D = log2(n_lde)`, logarithmic). Where it converges:

| cost model | arity 1 | arity 2 | arity 4 |
|---|---|---|---|
| planner as written (batch-8 DEEP chip + toy FS estimate) | `2^23` OK | `2^24` OK (at cap) | `2^25` OVER |
| honest DEEP (1 term/row — the chip that actually exists) | `2^25` OVER | `2^26` OVER | — |
| honest DEEP + real SHA-FS chip (forked, ~340 compressions) | `2^26` OVER 4x | `2^27` OVER 8x | — |
| honest DEEP + real SHA-FS (unforked, ~2412 compressions) | `2^28` OVER 16x | — | — |

The planner's own source flags both optimisms in comments (`:295-303`, `:250-256`); this
lane's contribution is quantifying them. **The planner's `trace_shape_fixed_point` is real;
its `backend_lde_supported` is optimistic by 4-16x.**

Lever analysis (`scratchpad/arch-lane/levers.py`), arity 2, cumulative:

| lever | `n_lde` | verdict |
|---|---|---|
| baseline (honest DEEP + forked SHA-FS, Q=192) | `2^27` | OVER 8x |
| **+ algebraic (Poseidon2) Fiat-Shamir instead of SHA256d** | `2^26` | OVER 4x |
| + batch-8 DEEP/per-point accumulator chip | `2^25` | OVER 2x |
| + Merkle cap height 4 | `2^25` | OVER 2x |
| + fold arity 4 | `2^25` | OVER 2x |
| + unify current/next openings into 2 paths | `2^24` | **FITS (at cap)** |
| + `Q = 192 -> 136` | `2^24` | **FITS**, 34% row headroom |
| + multi-table (ungated deg-2, LogUp-joined) | `2^22`-`2^23` | FITS with 2-4x margin |

Single-lever sensitivity at Q=136 with everything else applied:
* **keep SHA-FS: `2^26`, OVER 4x.** Decisive on its own.
* keep 1-term DEEP: `2^25`, OVER 2x.
* keep unbatched Merkle/fold layout: `2^24`, still fits.

Cost: soundness bits unchanged by all of the above **except** `Q`. Under the shipped
unique-decoding accounting (`FriBatchSoundnessBoundBits`, `Q*log2(32/17) - 40`), with the
341-node union (8.41 b): `Q >= 123` for 64 net bits, `Q >= 131` for the 71-bit policy
margin. **`Q = 136` (the narrow serialization lane's shipped value) gives 84.11 bits/proof,
75.69 net — the smallest round number that clears policy.** `Q = 88` and `Q = 77` do
**not** clear 64 under this convention; if another lane is quoting a `Q >= 77` floor it is
using a different accounting and the two must be reconciled before `Q` is lowered.
Implementation effort: large (this is the in-AIR verifier subsystem), but it is already the
declared plan and partly executable (`kHashOpeningAirExecutable=true`,
`kFoldHashScalarMemoryBusExecutable=true`, `kVerifierScalarAirExecutable=true`).

### (c) Different arity — CONFIRMED WORSE, as asked
Wide layout: width `prop k`. Narrow layout: rows `prop k`, so each arity doubling costs one
LDE octave (`2^23 / 2^24 / 2^25` for arity 1/2/4). Higher arity is strictly worse per node.
Total tree work is mildly *better* at high arity (`~L*k/(k-1)`), but the binding constraint
is the per-node cap, so **arity 2 is optimal** and arity 4 must be abandoned.

### (d) Two-tier / heterogeneous compression — ADOPT, but note it is the same thing
"Compress with a different, smaller proof system before consuming" is exactly Route A of
the in-AIR child verifier spec (§2) plus `narrow_recurse`: keep the wide row-wise
AlgBackend for the **leaf** (where one level demonstrably works and the child is small),
and define a **separate minimal recursion system** — narrow lane, algebraic FS, `Q=136` —
for **interior nodes only**, with a one-time leaf "lift" adapter. This is not an
alternative to (a); it is the correct framing of (a). Ranked 1 jointly.

### (e) Accept depth-1 and change the topology — NOT VIABLE AS STATED
Depth-1 with production arity would need `k = 244` shards in one parent:
`244 * 149.25 * 546 ~ 19.9M` columns, 19x over the `2^20` cap. And per §2 corollary 3, even
the working `k=4` depth-1 parent cannot be proven (303 GB). Depth-1 is a dead end, not a
fallback. The only depth-1-flavoured survivor is an **arity-1 IVC chain** (each node
verifies one previous chain proof plus absorbs one shard statement), which closes most
comfortably (`2^23`, arity 1) but serialises the prover over 244 steps.

---

## 4. What comparable systems do differently — four specific mechanisms

1. **FRI soundness accounting (biggest single factor).** BTX ships the *unique-decoding*
   bound with `kRCFriConjecturedBoundEnabled = false`: `log2(32/17) = 0.9125` bits per
   query, an asymptotic ceiling of **1 bit/query regardless of blowup**, forcing
   `Q >= 123`. Plonky2, RISC0, Boojum and StarkWare all rely on proximity-gaps /
   list-decoding, worth `log2(1/rho) = 4` bits/query at blowup 16, so they run
   `Q = 26-40`. Since narrow-lane rows are linear in `Q`, that is a **3.4-5x row factor**,
   i.e. 2 LDE octaves, obtained purely by a conjecture-acceptance policy decision. This is
   a *deliberate* BTX conservatism, not an oversight — but it should be priced explicitly,
   because it is most of the gap.
2. **Hash choice in the transcript.** BTX's recursion Merkle tree is already algebraic
   (Poseidon2/AlgHash), but its Fiat-Shamir is **SHA256d**, explicitly non-arithmetised
   because "the recursive verifier recomputes challenges natively"
   (`matmul_v4_rc_fri_ext3_alg.h:61-64`) — an assumption that is exactly false once you
   recurse. Every comparable system uses an algebraic hash end-to-end for precisely this
   reason. In-AIR SHA256d costs `next_pow2(compressions) * 1024` rows
   (`recursive_parent_air.h:879-892`): 0.5M rows/node even after midstate forking, 4.2M
   without, versus ~1 row per Poseidon2 absorb. **This one choice is the difference between
   closing and missing by 4x.** Fixable, and confined to
   `matmul_v4_rc_fri_ext3_alg.cpp` (consensus-visible, recursion path only; the SHA base
   FRI path keeps its own layout).
3. **Verifier circuit layout.** Everyone lays the recursive verifier vertically as a fixed
   program of operation tables (Plonky3 fixed-program recursion; Boojum's fixed recursion
   circuit; RISC0's recursion VM), so circuit width is a constant and the child's shape
   consumes *rows*. BTX's shipped V_CS is the transpose. This is the direct cause of §2.
4. **Nobody makes the production proof self-similar.** Plonky2: base circuit -> recursion
   circuit -> shrink circuit. RISC0: lift -> join -> resolve -> Groth16 wrapper. Boojum:
   base layer -> fixed recursion layer -> BN254 wrapper. All are **heterogeneous 2-3 tier**
   schemes with a purpose-built minimal middle tier. BTX is attempting to make its
   production system its own recursion system. That is the architectural anomaly, and it is
   **fixable** by adopting (d).

Is the difference fundamental? **No.** Items 2, 3, 4 are engineering/architecture and are
already the declared plan. Item 1 is a policy choice BTX may legitimately keep, at a
2-octave cost that the levers in §3 can just about absorb.

---

## 5. Recommendation

**Primary route: narrow/vertical lane (arity 2) as the interior-node proof system, with
the AlgBackend recursion transcript's Fiat-Shamir moved from SHA256d to the existing
Poseidon2 AlgHash sponge, at `Q = 136`.** The wide row-wise AlgBackend stays as the leaf
system behind a one-time lift. Abandon arity 4.

Order of work, by decisiveness per unit effort:
1. Algebraic FS for the recursion transcript (kills a 4x miss; also deletes the entire
   unbuilt SHA-FS chip from the critical path, i.e. removes item 1 of the in-AIR spec's
   build plan). Consensus-visible; must land in both trees.
2. Batch-8 DEEP/per-point accumulator chip (2x; pure engineering, no soundness cost).
3. Merkle cap + fold-arity-4 + unified current/next opening (~1.3x combined).
4. Only then re-run `AssessNarrowVcsReadiness` and consider flags.

### The decisive cheap experiment

Two integer measurements, no heavy prove, no build into `build-omp`:

* **A (kills or confirms the row model).** `kHashOpeningAirExecutable` is already true and
  `BuildHashOpeningWitness` already materialises the vertical hash lane **from a real child
  proof**. Measure its **actual rows per query** at `W=546` and compare to
  `RowLeafPermutationRows(546) + merkle_depth` (the planner's schedule). Also measure the
  real `DeepAccumulate`/`PerPointAccumulate` row counts from `BuildVerifierScalarSystem`
  against `ceil((W+1)/8)`. If the measured schedule is within ~1.5x of the planner, arity-2
  at `2^24` is real; if it is `>3x`, arity-2 is dead and only the arity-1 IVC chain
  survives. Cost: minutes, one small test binary in `build-arch -j2`.
* **B (decides the primary lever).** Call the existing
  `BuildFiatShamirShaExecutionPlanV1` / `MultiRowV2TranscriptShaPlanV1` for one node at
  `W=546, Q=136` and read the exact SHA256d **compression count**. Rows are then
  `next_pow2(compressions) * 1024`. If that exceeds `2^19` — which every estimate in
  `ChildFsReplayClosureV1` says it will — the SHA-FS transcript **must** be replaced, and
  that decision can be made tonight without writing a line of AIR.

Both are pure counting against code that already exists and is already executable.

### What would kill the route

If A shows the real vertical schedule is `>3x` the planner *and* `Q` cannot go below 131
under the shipped unique-decoding accounting, then arity-2 does not close and the only
surviving shape is an arity-1 chain — which is not aggregation, and would force a topology
decision (sequential IVC over 244 shards, with the prover-time consequences that implies)
rather than a tree.

---

## 5b. EXPERIMENTS A AND B — RUN. Both landed on the wrong side of my own decision rules.

Both turned out to be **pure shape functions**, computable exactly from source with no build
and no proof — the same method that reproduced §1's measured points exactly.

### Experiment B — exact SHA256d Fiat-Shamir cost per node

`BuildFiatShamirProgramImpl` (`verifier_air.cpp:695-828`) takes only a `NarrowChildShape`
and already computes both compression counts. Replicated exactly
(`scratchpad/arch-lane/expB_fs_sha.py`).

*Cross-validation against the source's own figures:* my model gives the `W=384,984` node a
**20,019,835 B** transcript and **313,425** streaming compressions -> **5.37e8** rows; the
`ChildFsReplayClosureV1` header independently states 20.02 MB / 312,801 / 5.37e8. The
`airq_lambda` 113-byte preimage gives 3 compressions, matching the header's MEASURED value.

| node | transcript | challenges | compressions (naive) | compressions (midstate-forked) | rows (forked) |
|---|---|---|---|---|---|
| narrow `W=546, nf=20, Q=136` | 29,347 B | 162 | 72,675 | **784** | **1,048,576 = 2^20** |
| narrow `W=546, nf=20, Q=192` | 29,347 B | 218 | 98,435 | 896 | 1,048,576 = 2^20 |
| production leaf `W=26, Q=128` | 2,179 B | 150 | 5,186 | 339 | 524,288 = 2^19 |

**Decision rule was "> 2^19 -> the SHA-FS transcript must be replaced." Result: 2^20 in the
best case, 2^27 naive. CONFIRMED, decisively, with a 2x margin over my own earlier estimate.**

**Additional finding, harder than the row count.** The only executable vertical SHA chip has
a *structural* cap: `kFixedProgramVerticalSemanticInstances = 63` /
`kFixedProgramVerticalScheduledInstances = 64` (`hash_air.h:323-325`), and
`BuildVerticalConstraintSystem` (`hash_air.cpp:2224-2245`) returns
`Fail("vertical_schedule_shape")` when `boundaries.size() > scheduled_instances`, with
`lane_rows` hard-asserted to 1024. **784 compressions is 12x over a hard structural limit —
the existing chip cannot even represent one node's FS transcript, at any LDE budget.** Even
the *production leaf* (339 compressions) is 5x over. This is not "over the LDE cap"; it is
"the chip refuses to build."

### Experiment A — executable vertical hash lane vs planner schedule

`BuildHashOpeningProgram` (`recursive_fixedpoint.cpp:13920-13998`) is documented and
verified proof-independent, so its row count is a shape function too
(`scratchpad/arch-lane/expA_rows.py`). Compared against `BuildCanonicalVerifierProgram`
(`verifier_air.cpp:419-510`), which emits *exactly* the planner's schedule and asserts
`active_rows == plan.active_rows`.

At `W=546, D=24, nf=20, child_constraints=1528` (= `FamilyTemplates` sum for
`DecomposedX2X4X6`: 505+494+12+12+505):

| family | planner | executable | ratio |
|---|---|---|---|
| row-leaf sponge | 206 | 617 | **3.00x** |
| Merkle path | 24 | 72 | **3.00x** |
| fold | 640 | 620 | 0.97x |
| DEEP | 69 | 547 | **7.93x** |
| per-point | 192 | 1,529 | **7.96x** |
| **rows/query** | **1,133** | **3,387** | **2.99x** |

**Decision rule was "within ~1.5x -> arity-2 at 2^24 is real; >3x -> arity-2 dead."
Result: 2.99x — on the boundary, and dead once the FS chip is included.**

Two clean, separable causes, both already flagged in the source's own comments:
1. **3.00x on hashing:** the planner counts ONE row opening per query; the executable
   emits **THREE** — current (`W+1`), next (`W+1`), trace (`W`) — each with its own full
   Merkle path. This is the *same* three-leaf-sponge term as §1.1. It is a property of the
   FRI verification, not of the layout, and it therefore appears in **both** layouts.
   Widths confirm the lane is real: `HashOpeningLayout.End() = 526` columns vs the planner's
   assumed 546.
2. **7.95x on DEEP/per-point:** exactly `kNarrowStreamBatch = 8`. The batch-8 accumulator
   is assumed by the planner and does not exist; the executable scalar chip retires one
   `a*b+c` per row. Also note `child_constraints` for a *self-similar* child is the narrow
   lane's own template count (1528), so per-point is 1,529 rows **per query** — a
   second self-consistency loop not previously modelled.

### Where the fixed point actually lands (post-experiment, arity 2, Q=136)

| configuration | rows/query | active | trace | n_lde | verdict |
|---|---|---|---|---|---|
| as-built (3 openings, 1-term chip, SHA-FS) | 3,387 | 3,018,416 | 2^22 | 2^27 | OVER 8x |
| + algebraic FS | 3,387 | 923,312 | 2^20 | 2^25 | OVER 2x |
| + batch-8 DEEP/per-point chip | 1,572 | 429,632 | 2^19 | **2^24** | **FITS** |
| + Merkle cap 4 + fold-arity 4 | 1,420 | 388,288 | 2^19 | 2^24 | FITS |
| + unify current/next into one pass | 969 | 265,616 | 2^19 | 2^24 | FITS |

Arity 1 reaches `2^24` on the algebraic-FS lever alone and `2^23` with the DEEP chip.
**My §3 lever table was optimistic by 2x on the SHA term and 3x on the hash schedule; the
ordering of the levers is unchanged, and the top two are now both mandatory rather than
merely dominant.**

---

## 5c. UNION COMPOSITION — which term applies to the per-node proximity bound

**Ruling: the ~25-bit within-proof FS-site union does NOT compose additively with the
per-node proximity term. It is already inside the `-40` deduction. Q=136 clears 64.**

### The composition argument

The source states the semantics unambiguously. `kRCFri3AlgUnenforcedRegrindBudgetBits = 40`
is *"an adversary grind-budget DEDUCTION"* for *"the un-predicated regrind"*
(`fri_ext3_alg.h:414-421`) — i.e. the accounting **grants the adversary 2^40 independent
re-draws of the Fiat-Shamir challenge**, precisely because the single-lane verifier absorbs
`pow_grind_nonce` into the FS seed but never tests the g-leading-zero condition.

Now write the two candidate charges as bounds on the same quantity. Let `B_i` = "node i's
proof is accepted but its statement is false":

```
Pr[exists i: B_i]  <=  SUM_i Pr[B_i]  <=  N_nodes * (#independent FRI trials) * alpha^Q
```

* **The node union `N_nodes` is a union over DISTINCT STATEMENTS** that must all hold
  simultaneously in one accepted artifact. Failing any one breaks the induction. It is not a
  retry. **It composes additively and must be charged.**
* **An FS "site" is a place where a challenge is derived — i.e. a place a re-draw can be
  TARGETED.** It is a retry opportunity, not a distinct statement. An adversary re-drawing
  at any of `N_sites` still performs one hash per re-draw, so the total number of
  independent trials is bounded by the adversary's hash budget, **not** by
  `N_sites x budget`. `log2(N_sites)` and the regrind budget are two bounds on the *same*
  factor and combine by **max, not sum**. Since `2^25.2 << 2^40`, the FS-site union is
  strictly subsumed. **Charging both double-counts.**

So `net(Q) = floor(Q*log2(32/17)) - 40 - log2(N_nodes)`, which is exactly the coordinator's
corrected formula. Robustness to topology: my §2 result does invalidate the 341-node
arity-4 object, but the replacement is not smaller — an arity-2 tree over 244 shards is
243 internal + 244 leaf adapters = **487 nodes, log2 = 8.93** — and the floor is unchanged:

| union object | net at Q=136 | floor for >=64 |
|---|---|---|
| 341 nodes (arity 4, unreachable) | 75.59 | Q >= 124 |
| **487 nodes (arity 2, the real topology)** | **75.07** | **Q >= 124** |
| 29 (`kRCStage3UnifiedSoundnessSiteCount`) | 79.14 | Q >= 120 |
| 2^25.2 FS sites, charged additively (double-count) | 58.84 | Q >= 143 |

**Q = 136 clears the >=64 defensible minimum by ~11 bits under the correct composition, and
the answer is insensitive to which node topology replaces the unreachable arity-4 tree.**

### The larger issue the reconciliation exposes — FLAGGED, NOT ASSERTED

My argument replaces `log2(N_sites)` with *the adversary's total regrind budget*. That
raises a question the reconciliation did not ask: **is 40 the right budget?** The constant
is the protocol's grinding parameter `kRCFriGrindingBits`, reused with the opposite sign;
the source itself half-flags this (*"numerically kRCFriGrindingBits, but a DEDUCTION here"*).
If the verifier does not check the grind, a re-draw costs the adversary **one hash**, so the
number of re-draws is bounded by their total budget `2^q` — and the threat model's own
`q* = 76`, not 40.

| deduction | net at Q=136 | floor >=64 | floor >=71 |
|---|---|---|---|
| 40 (as accounted today) | 75.07 | Q >= 124 | Q >= 132 |
| `q* = 76` | **39.07** | **Q >= 164** | Q >= 171 |

`Q >= 164` is **exactly** the codec lane's measured transport ceiling (`Q <= 164`). Under
that reading the narrow configuration would sit at both ceilings simultaneously with zero
margin on either axis. I flag this coincidence rather than assert it: whether the regrind
budget should be `g` or `q` is a soundness-lane ruling, not mine, and the two lanes'
accountings must be reconciled. **This is not a live mainnet problem** — the shipped
single-lane `Q = 192` clears 64 under both readings (126.59 and 90.59). It is a constraint
on the *recursion* parameter choice only.

### Is the Pi_JQ route realistic? YES — and it is the SAME work item as the SHA-FS finding

Moving the narrow parent onto the taxed `Pi_JQ` path converts the `-40` deduction into the
`+40` enforced credit (an 80-bit swing), dropping the floor to **Q >= 37** for 64 bits and
**Q >= 44** for the 71-bit policy margin. (Minor correction to the relayed figure: `Q = 36`
gives `floor(32.85) = 32`, net 63.59 — one bit short. The floor is 37.)

The credit is earned by the verifier actually checking `Fri3AlgCheckSqueezeGrind`. For a
*recursively verified* child that check must happen **in-AIR** — and the in-AIR spec already
flags exactly this gap: the recursion grind nonce is *"none of the four
`FiatShamirShaByteOriginKindV1` kinds"*, so a fifth `Nonce` origin must be arithmetised *"or
grinding is off-circuit."* **Therefore the Pi_JQ credit and the FS chip are the same work
item.** Rebuilding the recursion transcript as an algebraic (Poseidon2) sponge with an
in-circuit-enforced grind predicate does all of the following at once:

| effect | magnitude |
|---|---|
| deletes the SHA-FS chip | removes 2^20 rows/node and a 12x-over-cap structural blocker |
| earns the `+40` enforced credit | 80-bit swing on the proximity screen |
| drops the Q floor 124 -> 44 | 3.1x fewer rows, ~1.5 LDE octaves |
| shrinks proof bytes (payload ~ Q*W) | ~3x |

Combined effect at arity 2, computed: **algebraic FS + in-circuit grind at Q=44 lands at
300,104 active rows, trace 2^19, n_lde 2^24 — FITS, without needing the batch-8 DEEP chip at
all.** Adding the DEEP chip gives 2^23 and a full octave of margin.

**This single structural change closes the fixed point on its own.** It is the same shape as
the §4 finding and supersedes every parameter-tuning lever in §3.

---

## 5d. Pi_JQ ASSESSMENT — enableable? No. Delivers W-independence? No. Worth taking? Partly.

### Can Pi_JQ be enabled for the recursion path?

**No — it is not a config flag, and the single-lane path genuinely needs the dual-lane
binding.** g4's read of the config is correct (`joint_query` takes its `{false}` default on
`kFri3AlgQ192V3Config`; the initializer ends at `require_q192_proximity_guard`, field 10 of
13). But the blocker is structural, not a missing initializer:

* `Fri3AlgJointQSigmaCorePreimage(fs_seed, nonce, row_root, **t0, t1**)`
  (`fri_ext3_alg.cpp:6464-6480`) takes **both** lanes' terminal transcripts.
* `Fri3AlgJointQBatchVerify` takes a `Fri3AlgDualBatchProof`, requires
  `Fri3AlgDualSameStatement(lane[0], lane[1])`, requires **identical row roots**, and
  replays **both** lanes to the terminal fold to recompute `T_0,T_1` before squeezing.
* The security argument *requires* two lanes: *"the deciding squeeze sigma_Q binds BOTH
  lanes' terminal transcripts, so a per-lane last-round regrind cannot independently
  retarget one lane."* With one lane `sigma_Q = f(T_0)` and a last-round regrind retargets
  it directly — **exactly the attack Pi_JQ exists to stop.** The dual-lane binding is
  load-bearing, not incidental.
* Setting `joint_query = true` on the single-lane config would also need a live
  `joint_query_sigma`; with none, `ProtocolChallengeIndex` (`:853`) falls straight through
  its `!= nullptr` guard to the V3 draw. It would be a silent no-op.

So "enabling Pi_JQ" means **migrating the recursion child to `Fri3AlgDualBatchProof` under
`kFri3AlgJointQSuite`** (magic `'AJTQ'`, version 1, own domain tags). That is a
consensus-visible **proof-type** change to `AirFriBackendAlg`'s object — the same class and
size of change as the transcript rebuild, not a smaller one.

**Cost note:** `kRCFri3AlgDualQueriesPerLane = 128`, so the dual suite is **2 x 128 = 256**
in-circuit query verifications versus today's 192 — **1.33x MORE** parent rows, and the
parent must verify both lanes. (Naming drift worth flagging to g4: the domain tags read
`DUAL_Q136_*` while the constant is 128.)

### Does Pi_JQ deliver W-independence? No — this is the key correction

**The "93.8% of the residual" is 93.8% of the challenge COUNT, not of the W-DEPENDENCE.**
Pi_JQ makes the Q query draws self-contained, but the other 25 challenges (lambda, z1, z2,
w1, w2, and `nf` fold challenges) each still hash the full `buf`, which still contains
`4W` (column_len) + `48W` (both OOD evaluation vectors) = **52W bytes**. Removing 93.8% of
the count leaves **100% of the asymptotic W-dependence**. Pi_JQ reduces the constant factor,
not the asymptotics — it touches neither of the two W-proportional terms that
`ChildFsReplayClosureV1` names as *"BOTH must be removed or neither helps."*

Measured (`scratchpad/arch-lane/pijq.py`), W=546, nf=20:

| scenario | Q | compressions | rows | vs 63-cap |
|---|---|---|---|---|
| as-is, naive | 192 | 99,823 | 1.34e8 | 1584x |
| as-is + midstate fork | 192 | 895 | 1,048,576 | 14x |
| **+ Pi_JQ only, naive** | 192 | **12,079** | 1.68e7 | 192x |
| + Pi_JQ only, forked | 192 | 1,087 | 2,097,152 | 17x |
| **+ transcript fix (roots) only, forked** | 192 | **452** | 524,288 | 7x |
| + transcript fix + Pi_JQ, forked | 192 | 644 | 1,048,576 | 10x |
| Pi_JQ dual-lane as implemented (2x128), forked | 256 | 1,279 | 2,097,152 | 20x |

Two counterintuitive readings, both important:
1. **In the forked model Pi_JQ makes things WORSE** (452 -> 644; 895 -> 1,087). A forked
   tail costs 2 compressions; a self-contained 56-byte joint draw costs 3. **The midstate
   fork and Pi_JQ are substitutes for the same term, and the fork is strictly cheaper and
   free** (`g4_sha_chip_forks_a_shared_midstate_to_divergent_tails`, no consensus impact).
2. The transcript fix, not Pi_JQ, is what delivers W-independence.

### Does W-independence bring the transcript under the 63-instance cap? No — nothing does

**Irreducible floor: SHA256d costs >= 2 compressions per challenge draw** (one message block
plus one block for the second SHA). With `C = Q + nf + 5` draws:

| Q | draws | floor | vs 63-cap |
|---|---|---|---|
| 192 | 217 | 437 | 6.9x |
| 136 | 161 | 325 | 5.2x |
| 44 | 69 | 141 | 2.2x |
| 26 | 51 | 105 | 1.7x |

**The cap is met only if Q <= 5.** The 63-instance limit is a hard architectural
incompatibility with SHA256d Fiat-Shamir at *any* realistic Q — not a tuning problem, and
not something Pi_JQ or the transcript fix can reach. Either the cap is raised (it is a chip
constant; cost is `next_pow2(C) * 1024` rows) or SHA256d FS is replaced.

### What IS worth taking: Construction 2, not Pi_JQ

The `+40` credit is sourced from **Construction 2 — the enforced per-squeeze grinding tax**,
not from Pi_JQ. Header (`fri_ext3_alg.h:1247-1253`): *"A VERIFIER-CHECKED predicate... One
verifier hash; multiplies every grind attempt at that round by 2^g **under NO
adversary-budget assumption.** Fused into Pi_JQ's deciding squeeze here."*

* That "no adversary-budget assumption" clause **closes my §5c open question in the safe
  direction.** The `g`-vs-`q*` ambiguity that threatened to force `Q >= 164` exists only
  because the grind is *unpredicated*; an enforced predicate makes the credit `+g`
  unconditionally. **Construction 2 removes the §5c risk.**
* Construction 2 is *fused into* Pi_JQ's squeeze in the current code but is conceptually
  separable — it is one verifier hash over a squeeze input. **Whether it can be de-fused
  from the dual-lane sigma_Q and applied to a single-lane terminal squeeze is the
  highest-value open question, and I cannot settle it from the code alone**: the
  implementation only exposes it through `Fri3AlgJointQBatchVerify`.

### Why `kRCFri3AlgJointQFormalSoundnessReady = false`

**Neither incomplete nor unreviewed — false for a stated, *different* obligation.**
`fri_ext3_alg.h:1258-1259`: *"Neither flips a `*_FormalSoundnessReady` flag: >=100 still
needs wider digests and per-round field bounds. They are enforceable parameter screens
only."* Pi_JQ and the tax are described as complete and enforceable **for a >=64 screen**;
the flag is false because the **>=100** formal claim needs wider digests and per-round field
bounds, which are separate work. **For a >=64 target the flag is not a blocker; for >=100 it
is.**

### Does the fixed point close WITHOUT the algebraic rebuild?

At Q=44 (tax credit), SHA chip retained with transcript fix + midstate fork (156
compressions -> 262,144 rows):

| configuration | arity 1 | arity 2 |
|---|---|---|
| SHA chip kept, 1-term DEEP | 2^24 **FITS** | 2^25 OVER 2x |
| SHA chip kept, batch-8 DEEP | 2^24 **FITS** | 2^25 OVER 2x |
| algebraic FS, 1-term DEEP | 2^23 FITS | 2^24 **FITS** |
| algebraic FS, batch-8 DEEP | 2^22 FITS | 2^23 FITS (one octave margin) |
| Q=136 (no tax credit), SHA txfix+fork | 2^25 OVER | 2^26 OVER 4x |

**Answer: without the algebraic rebuild the fixed point closes only at arity 1 — a chain,
not a tree. With it, arity 2 closes, and with the batch-8 chip it closes with a full octave
of margin.**

### Revised route — priority order changes, destination does not

The candidates are **not substitutes**; they fix different terms:

| term | fixed by | effect |
|---|---|---|
| per-draw repetition of the prefix hash | **midstate fork** (free) *or* Pi_JQ (worse) | 99,823 -> 895 |
| the 52W transcript **length** | **transcript fix** (absorb roots) | 895 -> 452, W-independent |
| the ~2-compressions-per-draw SHA256d floor | **only** the algebraic sponge | 452 -> O(C) Poseidon2 rows |
| the -40/+40 sign on the proximity screen | **Construction 2** (enforced tax) | 80-bit swing, Q 124 -> 44 |

1. **Construction 2 first — try to de-fuse it from the dual-lane sigma_Q.** One verifier
   hash; earns +40 under no adversary-budget assumption; closes §5c; drops Q 124 -> 44, a
   3.1x row reduction everywhere. Cheapest large win; **I under-weighted it.**
2. **Midstate fork** — free, chip already supports it, strictly better than Pi_JQ.
3. **Transcript fix** (absorb roots of `column_len` and both OOD vectors) — this, not
   Pi_JQ, is what makes the transcript W-independent.
4. **Do NOT adopt Pi_JQ as a proof-type migration for the recursion path** on FS-cost
   grounds: it costs a consensus-visible proof-type change of the same class as the
   alternatives, raises in-circuit queries 192 -> 256, is a substitute for the free midstate
   fork, and does not deliver the W-independence it was hoped to. Adopt it only if the
   dual-lane suite is wanted for its own reasons — or if de-fusing Construction 2 proves
   impossible, in which case Pi_JQ becomes the *carrier* for the +40 credit and is worth its
   cost for that alone.
5. **The algebraic-FS rebuild is still required for arity >= 2**, but it is now
   **deferrable**: steps 1-3 close the fixed point at arity 1 and land only 2.2x over a chip
   cap that is itself a raisable constant.

**The coordinator's instinct is right that the fork window should not be spent on a rebuild
we did not need — but the reason is steps 1-3, not Pi_JQ.**

---

## 5e. RULING — is `kFixedProgramVerticalScheduledInstances` 64 -> 512 safe?

**Safe in both senses g4 asked. But it is a PACKAGING change, not a cost change, and it does
not make SHA256d FS survivable. I would not take 512; I would take 256 if anything.**

First, accept the correction: the cap is per-constraint-system and my "Q <= 5" line was a
statement about *one* AIR, not about the construction. g4's multi-AIR reading is right.

### Risk (b) — instance-id namespacing: SAFE, provably, and not value-dependent

`BuildVerticalConstraintSystem` (`hash_air.cpp:2366-2372`):

```cpp
const uint64_t address_stride = program.rows.back().output_address + 1;
if (address_stride * scheduled_instances >= gf::kP) return Fail(why, "vertical_address_stride");
```

The namespacing is `addr + address_stride * instance_id`, where `address_stride` is exactly
the size of **one** instance's SSA address space. Since every `addr < address_stride`, the
map `(addr, id) -> addr + stride*id` is a bijection onto `[0, stride*n_instances)` — injective
for **any** instance count, by construction, not by the value 63. The only value-dependence
is `stride * S < p`, and that is **already guarded at runtime**, not assumed. At `S = 512`
with a few-thousand-address program, `stride*S ~ 1.5e6` against `p ~ 1.8e19` — thirteen
orders of magnitude. **No hidden dependency on 64.** The absence of a `static_assert` pinning
63 is correct: the dynamic guard is strictly tighter than any constant could be.

### Risk (a) — FRI domain: not two-adicity; it lands EXACTLY on the 2^24 guard

* **Two-adicity is a non-issue.** Goldilocks 2-adicity is 32
  (`static_assert((16 << kRCFriMaxColumnLog2) == (1 << 32))`, `fri.h:279`). `n_lde = 2^24` is
  **8 octaves clear**. Risk (a) as posed does not exist.
* **The real constraint is `kRCFriMaxLdeLog2 = 24`** — which `fri.h:270-277` itself calls
  *"a deliberate memory guard, not the protocol bound."*
* **Correction to g4's arithmetic (one octave):** they assumed 524,288 rows -> 8.4M (2^23)
  LDE. The vertical AIR's max constraint degree is **3**
  (`stage3.hash.vertical.producer_inverse`), so
  `QuotientLen = dmax - n_rows + 1 = 2(n_rows-1)` -> `n_coeffs = 2*n_rows` ->
  **`n_lde = 32 * n_rows = 2^24`**, not 2^23. `S = 512` sits **exactly on** the guard with
  **zero headroom**: one degree-4 constraint added later, or one row of padding past 2^19,
  pushes it to 2^25 and it fails.

| S | semantic | n_rows | n_lde | LDE (541 cols, Fp3) | AIRs/slot @439 comps |
|---|---|---|---|---|---|
| 64 (today) | 63 | 65,536 | 2^21 | **27.2 GB** | 7 |
| 128 | 127 | 131,072 | 2^22 | 54.5 GB | 4 |
| **256** | 255 | 262,144 | 2^23 | **108.9 GB** | **2** |
| 512 | 511 | 524,288 | 2^24 | **217.8 GB** | 1 |
| 1024 | 1023 | 1,048,576 | 2^25 | 435.7 GB | OVER |

### The objection neither lane raised: peak memory goes UP, and the total is invariant

The 28-AIR chain has a **27 GB sequential peak**. The single 512-instance AIR has a
**218 GB peak** — 8x worse, and squarely in the regime that already makes the wide parent
unprovable (303 GB) and the narrow 2^24 LDE impractical (220 GB). Because the batch
commitment is **row-wise**, the LDE cannot be streamed column-by-column; it must be fully
materialised. **S=512 trades 28 buses for exactly the failure mode that killed the wide
layout.**

And more fundamentally — **raising the cap redistributes the work, it does not reduce it.**
The FS replay's total cost is set by the compression count, not the packaging:

```
439 compressions x 1024 rows x 541 cols x 24 B x 32 (LDE blowup) ~= 187 GB per node
```

That figure is **invariant** across 28 chained AIRs, one 512-instance AIR, or (since
`column_len` is per-column and the backend already carries per-column degree bounds) 28
column-groups inside one batch. Packaging changes the bus count and the proof count; it does
not change the ~190 GB.

### Therefore: this does NOT make SHA256d FS survivable

The quantity is reducible only by cutting the compression count (Construction 2's Q -> 44,
and the transcript fix) or by replacing the hash. For comparison, the **same** transcript
under an algebraic (Poseidon2) sponge — the hash the recursion Merkle **already uses**:

| | rows for one node's FS replay |
|---|---|
| SHA256d, fixed transcript + midstate fork, Q=192 | 439 comps x 1024 = **449,536** |
| Poseidon2 sponge (~125 Fp words absorbed + 217 squeezes) | **~233** |

**~1,900x.** That is the number that settles the route. The instance cap is a factor of 8 in
packaging; the hash choice is a factor of ~1,900 in quantity.

### Ruling

1. **64 -> 512 is safe** — namespacing is guarded and count-independent; two-adicity is 8
   octaves clear. **But it lands exactly on the 2^24 memory guard and raises peak LDE 8x to
   218 GB.** I would not take it.
2. **If the cap is raised, take 256**: 2 AIRs/slot (1 cross-AIR bus per slot instead of 6),
   109 GB, and one full octave of LDE headroom. Most of the bus collapse at half the peak
   memory, and not sitting on the guard. It needs the same cross-AIR CTL bus g4 has already
   built, just fewer instances of it.
3. **It does not change the recommendation.** The multi-AIR chain plus Construction 2 remains
   the route, and the algebraic rebuild remains the thing that actually removes the term
   rather than repackaging it. The fork-first ordering is now supported by three independent
   arguments (mine, g4's 196->28 AIRs, and the ~190 GB invariance above).
4. **Streaming lane's finding on Construction 2 is accepted and strengthens item 1 of §5d.**
   If the primitives are lane-agnostic (opaque buffer + nonce), then collapsing query
   derivation onto one taxed deciding squeeze — a version bump, far smaller than an AJTQ
   migration — earns +40, closes §5c, drops Q 124 -> 44, and cuts the FS compression count
   from 439 to 156 **and** the parent's query rows by 3.1x. That single change does more for
   the fixed point than any packaging decision. **It should be staffed first.**

---

## 6. Honesty ledger

| claim | status |
|---|---|
| slope `= k*149.25`; model reproduces 16,176 and 384,052 exactly | DERIVED from source, verified |
| 677.5 is a depth-contaminated fit; true slope 597 | COMPUTED (correction to a relayed number) |
| no fixed point in the wide layout under any parameters | DERIVED (closed form) |
| narrow layout always reaches a shape fixed point in 2-3 levels | COMPUTED from the shipped planner's own recurrence |
| where that fixed point lands (`2^22`-`2^28`) | COMPUTED; depends on cost-model inputs that are ESTIMATED, not measured — experiment A exists precisely to replace them |
| SHA-FS row cost `next_pow2(comps)*1024` | source-stated (`recursive_parent_air.h:879-892`); the compression counts 340 / 2412 are that header's own estimates, ASSUMED here |
| `Q>=131` for the 71-bit policy margin over 341 nodes | COMPUTED from `FriBatchSoundnessBoundBits` + `log2(341)` |
| comparable-system parameters (Plonky2 `Q~28`, RISC0 lift/join, Boojum tiers) | from general knowledge, NOT verified against those codebases tonight |
| 303 GB level-1 LDE; one working level is satisfiability not proof | source-stated |
| EXP-B: 784 streaming / 72,675 naive compressions at `W=546,Q=136` | DERIVED exactly from `BuildFiatShamirProgramImpl`; cross-validates to 0.2% against the source's own independent figures for `W=384,984` |
| EXP-B: 63-instance structural cap on the vertical SHA chip | source-stated constants + the `Fail("vertical_schedule_shape")` guard |
| EXP-A: 2.99x planner-vs-executable schedule ratio | DERIVED exactly from two shape-only builders; supersedes my §3 estimates |
| union ruling: FS-site union subsumed by the regrind budget | DERIVED from the source's stated semantics of `kRCFri3AlgUnenforcedRegrindBudgetBits`. This is a composition ARGUMENT, not a theorem; it should be confirmed by the soundness lane before it is relied on |
| the `g` vs `q` regrind-budget question (Q>=124 vs Q>=164) | FLAGGED as an open reconciliation, deliberately NOT asserted. Does not affect shipped `Q=192` |
| Pi_JQ floor `Q >= 37` (not 36) | COMPUTED; one-bit correction to the relayed figure |
| "Pi_JQ credit and the FS chip are the same work item" | **PARTLY RETRACTED (§5d).** The `+40` comes from Construction 2 (enforced tax), which is *fused into* Pi_JQ's squeeze but conceptually separable. They are the same work item only if Construction 2 cannot be de-fused — which I could not settle from the code |
| Pi_JQ is intrinsically dual-lane; not enableable as a flag | DERIVED from `Fri3AlgJointQSigmaCorePreimage(...,t0,t1)` and `Fri3AlgJointQBatchVerify`'s two-lane replay + `DualSameStatement` + equal-row-root requirements |
| Pi_JQ does NOT deliver W-independence | DERIVED: the 25 non-query challenges retain the full 52W `buf`. Corrects the relayed "93.8% become W-independent" — that is 93.8% of the *count* |
| Pi_JQ is *worse* than the midstate fork in the forked model | COMPUTED (3 comps per self-contained draw vs 2 per forked tail). Substitutes, not complements |
| 2-compressions-per-draw SHA256d floor; cap met only if Q<=5 | DERIVED (SHA256d = one message block + one second-SHA block, minimum) |
| `kRCFri3AlgJointQFormalSoundnessReady=false` is about >=100, not completeness | source-stated verbatim (`fri_ext3_alg.h:1258-1259`) |
| Construction 2 closes the §5c `g`-vs-`q*` risk | source-stated ("under NO adversary-budget assumption"); this is the clause that resolves it |
| Q_total 192 -> 256 under the dual suite | `kRCFri3AlgDualQueriesPerLane = 128` x 2 lanes |
| **"cap met only if Q<=5" — RETRACTED as stated (§5e)** | It was a per-AIR statement relayed as a global one. The cap is per-constraint-system; g4's multi-AIR reading is correct and my own 39-instance figure already presupposed it |
| 64->512 namespacing is safe | DERIVED from the `address_stride * scheduled_instances >= gf::kP` runtime guard + injectivity of `addr + stride*id`. High confidence |
| `n_lde = 2^24` at S=512, not 2^23 | DERIVED from max constraint degree 3 and `QuotientLen()`. One-octave correction to the relayed figure |
| ~190 GB FS-replay LDE is packaging-invariant | COMPUTED. Rests on the LDE being fully materialised under a row-wise commitment — stated in `fri_ext3_alg.h:50-59` |
| Poseidon2 FS ~233 rows vs SHA256d ~449,536 | COMPUTED from the fixed transcript length and one permutation per absorb/squeeze. The ~233 is an ESTIMATE, not a built schedule |
