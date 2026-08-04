# BTX MatMul v4.6 — Stage-3 complete proof construction

> **MatMul v4.7 transition status:** historical, incomplete proof-construction
> record for possible Epochs B–D; not current consensus authority. Epoch A is
> Profile-1 ExactReplay with optional shadow proof. A mandatory Epoch-B/C/D
> proof must be canonical, committed, durable, and retrievable—not an
> ephemeral sidecar. Profile 2 is reserved for Epoch D and is not an
> ExactReplay launch candidate. See `doc/btx-matmul-v4.7-transition-roadmap.md`.
>
**Date:** 2026-07-24<br>
**Repository / PR base:** `btxchain/btx`, PR #89 at `d6b445726f`<br>
**Implementation branch:** `wip/stage3-succinct`
**Status:** proof-only envelope, typed relation adapters, partial proof-only
episode/coupled AIR registries, canonical SHA-256/ChaCha instruction programs
and operation AIRs, a production GEMM/Extract coverage manifest and signed-range
AIR, proof-bound CTL child pins, durable consensus attachment, proof-aware cache
plumbing, executable dual-Q128 V5, a partial normalized V5 verifier AIR, an
exact conditional SIMD4-packed 37,488,397-site manifest and arity-four
schedule bound into unified-root V3, a real production-shape zero-polynomial
verifier fixture, 21 same-trace relation-to-CTL aliases, four-lane hash SSA
provenance, complete 48-cell V5-to-V6 proof-payload ownership, executable
recursive Merkle/fold-bus subchips, complete episode endpoint memory, and
twenty coupled relation-memory engines landed. A second closure wave added
bounded engines for the other six coupled relations, an exact episode wiring
product, and typed episode/barrier/digest root chains. The latest closure wave
adds consensus-regenerated proof products for the nine episode-parameter
cells and compact target, an exact round-seed chain, an all-byte
CoupledExtractOutput-to-barrier-input product, and the complete local
Extract-output-to-TileTree product. Exact bounded products now also cover the
complete operand counter-XOF schedule, all five Extract endpoints, and the
four GEMM A/B/Y/sumcheck endpoints, the composed builder trace, the three
remaining episode wiring endpoints, and the coupled bank/GEMM products. The
coupled exchange/permutation, mix and Extract products plus the exact digest
input seam now give all 52 endpoints a bounded local relation; nineteen are
locally complete at production shape. The consolidated audit keeps that fact
separate from transitive producer provenance: only two public-boundary
endpoints are transitively complete, and no endpoint is recursively consumed.
The latest verifier-boundary wave adds an ordered multi-row V2 RAP backend, a
bounded split-RAP AIR wrapper, an exact runtime-enforced recursive-site ledger,
and a 69-row normalized terminal transcript that locally constrains all
14 roles and 52 endpoints. It does not own recursive child proofs: zero of
14 roles and zero of 52 endpoints are cryptographically consumed by the
normalized recursive parent. Complete Fiat--Shamir recursion, the production
recursive parent, and the global soundness theorem remain fail-closed. Public
activation remains off.

This document is a historical implementation contract for completing a
succinct proof. It does not claim that the proof has been built or reviewed,
and it cannot replace ExactReplay before the distinct Epoch-B dual-validation
period and Epoch-C proof-authority activation.

## 1. Why Stage 3 is required

The profile-2 carrier checks every streamed unit but only two output tiles per
unit:

```text
units = 8 SV + 8 × 24 DOWN = 200
checked tiles = 200 × 2 = 400
possible streamed output tiles
  = 8 × [512 × (128/32) + 24 × 87,552 × (4,096/32)]
  = 2,151,694,336
```

An isolated wrong FFN tile is selected with probability:

```text
2 / 11,206,656 ≈ 1.78 × 10^-7
```

The checked tiles are recomputed exactly, but the carrier does not establish
that every unselected tile is correct. It remains useful as a relay precheck and
denial-of-service filter. It cannot be the complete consensus proof.

## 2. Public statement and witness relation

For the episode leg, public input is:

```text
x_ep = (
  canonical header projection,
  height,
  consensus-resolved episode parameters and transcript version,
  nBits-derived target,
  header.matmul_digest
)
```

The witness contains the complete deterministic episode trace:

- round seeds and round roots;
- every expanded int8 operand;
- every int64 GEMM output and pre-Extract accumulator;
- every Extract output;
- every cross-layer copy;
- the exact round stream and hash trace.

`R_ep(x_ep; w_ep) = 1` iff all of these hold:

1. The shape, profile, domain tags, and seed chain equal the consensus-resolved
   values.
2. Operand generation proves profile-2 row-block `X0` and the episode-wide
   shared `W_up` / `W_down` policy.
3. Every `QK^T`, `SV`, `UP`, and `DOWN` product is correct.
4. Every DOWN residual uses `Y_down + X_l` before Extract.
5. Every 32-element Extract transition is correct.
6. Copy wiring is exact:
   `S -> SV.A`, `X_l -> UP.A`, `H -> DOWN.A`, the residual copy of `X_l`,
   and `X_{l+1} ->` the next layer.
7. The round stream is exactly
   `Z_r || X_{r,1} || ... || X_{r,L}` with fixed geometry.
8. Every round root is the root of that stream; the episode digest is the
   digest of the ordered roots; the header digest and target check agree.

Completeness follows from the canonical episode runner. Relation soundness is
inductive: deterministic seeds fix operands; full GEMM and Extract constraints
fix each layer output; copy constraints fix the next layer; complete stream
constraints fix roots and the final digest.

## 3. Canonical signed bounds

Expanded and extracted operands lie in `[-48, 48]`. The pinned profile-2 raw
accumulators therefore satisfy:

```text
QK^T:          128 × 48^2              =       294,912
SV:        786,432 × 48^2              = 1,811,939,328
UP:          4,096 × 48^2              =     9,437,184
DOWN + X:   16,384 × 48^2 + 48         =    37,748,784
```

All valid values fit signed 32-bit arithmetic and take the existing Extract
int32 branch. Stage 3 must prove the per-kind signed bounds and canonical
representation. A field equality alone is insufficient because modular aliases
could otherwise represent an invalid integer execution.

The constants are pinned in
`matmul_v4_rc_stage3.h::kRCStage3Profile2AccumulatorBounds`.

## 4. Proof-only construction

The consensus proof must not contain full witness columns. It carries only:

- canonical public inputs;
- fixed-role commitment roots;
- openings and recursive proof objects;
- one transcript commitment derived after all primary roots are bound.

Commitment construction is two-phase and acyclic:

1. Relation engines bind the header projection, parameters, target, sigma, leg
   digests, final digest, and their locally reconstructed trace/fold roots.
2. After every relation section is encoded, the envelope transcript commitment
   binds the ordered section commitments and section hashes.

Relation statement commitments and recursive Fiat-Shamir base seeds must not
include the final `transcript_commitment`, because that value is derived from
the completed proof sections. The header projection likewise excludes
`header.matmul_digest`; `final_digest` binds that field separately.

The fixed relation registry is:

| Role | Required relation |
|---|---|
| `episode:builder` | deterministic expansion, sampler/preprocessing trace |
| `episode:gemm` | all episode product claims and committed openings |
| `episode:extract` | every Extract transition and signed range |
| `episode:wiring` | all cross-layer and residual copies |
| `episode:tiletree` | complete fixed-geometry stream/root trace |
| `episode:digest` | ordered roots, episode digest, header, target |
| `coupled:bank` | canonical page derivation and page selection |
| `coupled:gemm` | every scheduled lobe/page product |
| `coupled:exchange` | fixed segment placement and material exchange |
| `coupled:permutation` | proof-friendly permutation or a proved table |
| `coupled:mix` | every butterfly/mix stage |
| `coupled:extract` | every coupled Extract transition |
| `coupled:barrier` | complete barrier root trace |
| `coupled:digest` | bank/barrier roots and coupled digest |
| `composition:link` | episode and coupled legs linked into one final digest |

A composed envelope is structurally invalid if any role is missing, duplicated,
unknown, reordered, or empty.

Existing components can be reused only after their remaining native residuals
are converted to proof relations:

- retain the canonical `RCGkrTraceLayout` and layer product equations;
- bind every sumcheck/evaluation claim to the same committed columns;
- replace the unproved preprocessing `P_root` with a proved deterministic
  builder trace;
- replace native byte comparisons with committed copy/permutation constraints;
- replace direct full-stream `CheckTileTreeInCircuit` work with a proof-bound
  trace matching the current consensus hash semantics;
- fold all shards and claims into a bounded-shape recursive root whose public
  output pins the header, exact shape, roots, digest, and target.

The current `RCGkrProofV7`, `VerifyWinnerProofV7Compact`, and
`EpisodeAggregateProof` are inputs to this work, not authority candidates as-is.
They still carry or reconstruct full witness data, retain native residuals, or
lack a production-width self-similar recursion fixed point.

## 5. Durable block carriage

The Stage-3 foundation uses the existing durable
`CBlock::matrix_c_data` channel rather than another transient carrier:

```text
word[0] = Stage-3 block-payload magic
word[1] = exact serialized byte length
word[2..] = canonical little-endian envelope bytes
padding = zero
```

The codec rejects:

- oversized length claims before allocation;
- unknown versions, authorities, statement kinds, or relation roles;
- missing, duplicate, or reordered relations;
- truncation or trailing bytes;
- extra words or nonzero padding.

This gives full-block wire and `blk*.dat` persistence immediately. The
Stage-3-gated compact-block path requests the canonical full block when
reconstruction lacks the durable proof body.

The block hash excludes body proof bytes. Invalid or missing proof data must
therefore be classified as a body mutation, and negative verification results
must not be cached by header hash alone. Cache successful proofs only, or key
single-flight/verdict state by `(header hash, proof payload digest)`.

## 6. Consensus composition

The historical construction selected coupled **or** episode verification.
A future durable proof construction requires:

```text
sampled carrier precheck (optional)
AND complete episode proof
AND complete coupled proof when coupled is active
AND explicit link relation
```

The relay layer may reject or discard a bad sampled-carrier message early, but
process-local carrier state may never reject or accept a block. In the
canonical roadmap, Epoch A verifies Profile 1 by ExactReplay. Epoch B requires
both the durable proof and Profile-1 ExactReplay. Only after the separate
Epoch-C height may ExactReplay become diagnostic/reference code and cease to be
a fallback from a failed proof. Profile 2 remains dormant until Epoch D.

The composed public statement preserves `episode_digest` and `coupled_digest`
and binds both into one versioned final digest. Changing either leg or the link
must invalidate the proof.

## 7. Forbidden operations on the final verifier path

An accepted proof-only path must not call:

- `RecomputeResidentCurriculumReference`;
- `RecomputeCoupledPuzzleReference`;
- `BuildV7ColumnsFromWitness`;
- `BuildCoupledWires`;
- native full-state mix or Extract reconstruction;
- `CheckTileTreeInCircuit` over the full stream;
- `VerifyEpisodeFreivaldsSampledCarrier` as final authority;
- process-local proof/carrier stores;
- environment-selected arbiter or fallback logic.

## 8. Implementation order and cutover gates

1. **Foundation (landed):** fixed authority/statement/role
   registry, canonical bounded proof envelope, durable word packing, structural
   mutation and block round-trip tests.
2. **Typed episode boundary (landed, engines open):** six canonical receipts,
   obligation masks, statement/root binding, and fail-closed engine dispatch.
3. **Typed coupled boundary (landed, engines open):** eight canonical receipts,
   exact schedule coverage, root chaining, and fail-closed engine dispatch.
4. **Composition (landed):** shared public statement, acyclic final digest and
   transcript binding, explicit additive episode-plus-coupled verification.
5. **Recursive and consensus seams (landed, fixed point open):** bounded
   recursive codec, local constraint registry, `ProveAggregate` /
   `VerifyAggregate` dispatch, durable attachment, compact full-block fallback,
   positive-only proof-aware cache, and single-flight keys.
6. **Mathematical closure (partial):** complete immutable AIRs for every
   registered role, child Fiat-Shamir replay, executable bounded-width
   recursion, and at least 100-bit composed post-grinding soundness. The width,
   trace, degree, and LDE recurrence now has a closing candidate; its AIR and
   witness generator remain to be implemented.
7. **Cutover:** only after production proof size, prover resources, and verifier
   wall time are measured; adversarial relation tests pass; and independent
   review approves the complete construction.

Until all gates close:

```text
kRCStage3SuccinctAuthorityReady = false
nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX on public networks
```

## 9. Prior Stage-C handoff evaluation

The earlier handoff branch
`claude/stage-c-gkr-succinct-handoff-af23sj` at `2821194eb5db` is already an
ancestor of PR #89 at `d6b445726f9f`; no handoff commit needs cherry-picking.
The same is true of the relevant `wip/gkr-margin` work. PR #89 already contains
the useful pieces from that attempt:

- the Fp3 challenge/proximity substrate;
- algebraic row-wise Merkle commitments;
- the verifier-as-AIR recursion prototype;
- production-width multi-block row-leaf absorption;
- the compact episode verifier seam.

The current focused tests reproduce the remaining limits:

```text
base composed path, Q=128:                  76.799387 bits post-grind
recursion path, Q=148:                      ~95.0555 bits (95 integer helper)
toy N=2, W=26 verifier AIR, k=1:            3,751 columns × 256 rows
toy N=2, W=26 verifier AIR, k=2:            7,502 columns × 256 rows
production N=65,536, W=26, k=1:            62,401 columns × 256 rows
production N=65,536, W=26, k=2:           124,802 columns × 256 rows
current algebraic-FRI column cap:           16,384 columns
```

Thus Fp3 fixed the former Fiat-Shamir field-margin issue but did not make the
proof recursively self-similar. The base path is still query-proximity
dominated, and the recursion path meets its historical 92-bit per-node target
with only about three bits of margin rather than the handoff's desired
100-bit deployment target. Raising only the column cap is not a closure: using
the 62,401-column parent as another child would require roughly 23,401
row-leaf sponge blocks, or over three million permutation columns, before the
path and fold gadgets. The verifier trace must be reshaped to bounded width
across rows.

The Stage-3 implementation reuses these components only behind typed relation
adapters and a fixed local constraint registry. It does not reinterpret a
single-level aggregate, sampled tiles, or an opaque proof receipt as a complete
episode proof. Recursive authority remains fail-closed until a bounded-width
fixed point exists and production two-level proving/verifying succeeds without
raising cryptographic parameters ad hoc.

## 10. Closure experiments on the measured width and margin gaps

### 10.1 Relation fragments that now execute as proof-only AIRs

The episode registry now has immutable Fp3 constraint systems and a canonical
public-pin boundary for:

- a GEMM scalar endpoint fragment;
- the existing RcSampler Extract low-degree core;
- direct copy equality.

The adapter verifies an `AirQuotientProof` from committed column roots without
calling the episode runner or accepting a native witness. An honest Extract
trace now completes `TraceTile -> BuildRcSamplerInstance ->
AirQuotientProve -> VerifyRCStage3EpisodeAirShard`, and root/scale mutations are
rejected.

That round-trip found two construction bugs during this pass:

1. Extract must use
   `n_coeffs = NextPow2(max(N, 3N - 3))`, not the unpadded quotient length.
2. The base seed must exclude challenge-dependent LogUp roots. The statement
   and shard shape form epoch 0, the base roots derive `gamma/alpha`, and the
   quotient/FRI transcript absorbs the completed roots afterward.

The coupled registry now has local immutable kernels for:

- bank nibble acceptance and dequantization;
- dot-product accumulation;
- exchange/permutation copy equality;
- exact uint64 butterfly add/sub using range-constrained limbs;
- the existing Extract sampler core.

These are real mutation-tested local relations, but not complete role engines.
The missing schedules, table/root openings, SHA/XOF/ChaCha traces, signed
embeddings, all-instance manifests, and recursive closure are reported as typed
residual gaps. The barrier and digest SHA closures remain unavailable rather
than falling back to native checks.

### 10.2 Generic cross-table lookup seam

`matmul_v4_rc_stage3_ctl` adds the proof-facing shape needed to connect narrow
operation tables:

```text
tuple = (namespace, stage, address, value)
compressed_j = namespace + gamma_j*stage
             + gamma_j^2*address + gamma_j^3*value, j in {1,2}
```

An immutable schedule supplies signed send/receive multiplicities. Two
independent tuple-compression challenges and two independent denominator
challenges produce running LogUp sums. This v3 construction matters: two
denominator points over one compressed tuple do not amplify resistance to a
tuple collision, because the same collision defeats both points. Each recursive
child pin carries its schedule, trace and auxiliary commitments, challenge
commitment, counts, and two terminal sums. The composition root requires exact
ordered participant coverage, equal send/receive counts, and both global sums
to be zero.

V3 also removes the former `% p` challenge bias. Each Fp3 candidate uses
exactly two domain-separated SHA256d blocks, scans their eight uint64 words,
and takes the first three words below the Goldilocks modulus. Conditioned on
success the three coordinates are independent uniform Fp samples. Fewer than
three successes requires at least six rejected words, so sampler exhaustion is
below `28*2^-192 < 2^-187` per candidate and is treated only as a bounded
honest-prover failure.

The native child proof now executes the generic CTL AIR through
`AirQuotientVerify`. Its base tuple/value roots form the pre-challenge epoch;
inverse/running-sum and quotient roots form the auxiliary epoch. The verifier
re-derives both epoch commitments, the four challenges, and the AIR seed before
checking every child and then the two terminal sums. Root, auxiliary, child and
lane replay mutations are rejected. This is an executable native proof seam,
not yet consumption of the proof by the normalized recursive root.

For an exact manifest of independently separated buses, a malformed bus with
`E` signed events has at most `3(E-1)` bad compression challenges and `E-1`
bad rational-identity evaluation challenges per lane. Both lanes accepting is
therefore bounded by `[4(E-1)]^2/|Fp3|^2`; the implementation sums this
numerator per bus before charging grinding and invocation-union losses.
Denominator poles make the inverse AIR unsatisfiable and are reported as
completeness loss, not false-accept soundness.

The recursive role proof format now carries a mandatory canonical CTL child
commitment. The unified-root format carries all fourteen ordered CTL pins,
recomputes the challenge/count/terminal composition commitment, and binds the
result into each child seed and the unified statement commitment. Omission,
reordering, relabelling, nonzero terminals, or a changed edge commitment is
rejected.

This closes the native CTL proof and root binding, not the underlying dataflow
or recursive proof. The operation tables still need to bind all scheduled CTL
value roots to their producer/consumer relation roots, and the normalized root
must consume the child AIR proofs rather than only their public pins. The
current preprocessed schedule pin is O(N); production recursion needs an
offline/root-pinned preprocessed commitment.

### 10.2a Canonical SHA-256 and ChaCha operation programs

The proof-only hash layer now has executable Fp3 AIRs for:

- 32-bit addition with carry;
- XOR plus a fixed rotation;
- SHA-256 `Ch` and `Maj`;
- the SHA-256 large and small sigma families through a generic
  three-transform ROTR/SHR XOR relation.

Every word is represented by 32 boolean bits plus a recomposition column. The
largest individual gadget table is 132 columns. The selector-fixed unified
operation table has 1,024 rows, 144 columns, eleven fixed selector classes, and
maximum algebraic degree four. Honest witnesses satisfy every constraint and
the mutation tests reject altered active cells. A full unified-table
`AirQuotientProve -> AirQuotientVerify` production benchmark remains pending.

Two canonical SSA programs remove scheduler ambiguity:

```text
one SHA-256 compression:  952 instruction rows, 88 externals, 8 outputs
one ChaCha20 block:        656 instruction rows, 16 externals, 16 outputs
SHA operand CTL events:  3,616
ChaCha operand CTL events: 2,624
```

Each operation shard has a paired address-CTL schedule. The honest SHA program
matches the repository SHA-256 implementation and the ChaCha program matches
the repository implementation for arbitrary key, nonce, and counter inputs.
The fixed-program boundary AIR now also has a real
`AirQuotientProve -> AirQuotientVerify` path. It binds the program commitment,
all external values, all final words and the Fiat-Shamir seed. Substitution,
seed replay, truncation, ordering and output corruption tests reject. On this
machine, one canonical ChaCha boundary proof took about 12.6 seconds to prove
and 129 ms to verify, so native per-block verification is not a production
root strategy.

Executable manifests now cover exact multi-block SHA/SHA256d padding, big-endian
64-bit lengths, chaining and feed-forward; counter-XOF raw, E2M1-rejection and
two-bit scale streams with minimal counters; and minimal ChaCha block
consumption.

The exact byte-level manifests also cover real/padding/internal tile-tree
nodes, typed episode digests, versioned coupled barriers and digests, and the
composed-final `HashWriter` serialization, including its fixed-array trailing
NUL. Their roots match the native builders and the commitments bind versions,
counts, ordering, states, roots, and direct relation commitments.

The boundary proof does not close internal SSA dataflow by itself. An
adversarial row-local operand/result mutation still satisfies the instruction
AIR, demonstrating that producer and consumer VALUE roots must be
equality-constrained through the CTL relation export. The CTL schedules and
producer byte streams are not yet attached to actual recursive child public
pins, no recursive hash child proofs are embedded in the typed manifests, and
the unified table has not completed an end-to-end quotient/FRI benchmark.
These manifests therefore remain canonical prover witnesses rather than
verifier-native acceptance.

### 10.2b Production GEMM/Extract coverage and signed range

A canonical manifest derived from `Lambda(params)` now commits every ordered
GEMM layer and consecutive accumulator/Extract interval, including operand
references, transpose flags, chunk geometry, and A/B/Y/Extract/scale/proof/CTL
roots. At profile 2 it covers:

```text
layers:                     400
pre-Extract accumulator cells: 347,490,222,080
32-output Extract tiles:     10,859,069,440
serialized manifest:         less than 200 KiB
```

Validation reconstructs `Lambda(params)` and rejects omitted, duplicated,
reordered, resized, transposed, or relabelled intervals. The executable
signed-range AIR uses 69 columns and 143 degree-two constraints. It proves the
exact per-kind bounds in Section 3, canonical positive zero, sign/magnitude,
31-bit magnitude and difference decompositions, active-prefix length, and
canonical padding. Deterministic shards are at most `2^20` rows.

Manifest v2 additionally binds verifier-derived per-layer Extract PRF keys.
Exact scale-schedule shards cover at most `2^20` tiles each and recompute the
public PRF schedule and layer roots. Each signed-range shard now has a canonical
global bus ordinal, paired producer/consumer CTL schedules, a range-value trace
root, an Extract-input shard/root opening obligation, challenge-bound dual
LogUp terminals, and exact all-layer closure. A per-layer obligation manifest
pins A/B/Y roots and openings, sumcheck, signed-range closure, recursive
Extract, scale proof, and both CTL child commitments.

The signed-range path now executes a CTL-aligned AIR plus producer and consumer
CTL proofs on the same padded domain and requires exact equality among the
three VALUE commitments and the Extract-input shard root. That shard root is
then authenticated by a statement/layer/interval-bound ordered SHA256d Merkle
opening to the registered layer-wide Extract input root. Omission, reorder,
duplicate/path replay, root/path substitution and interval relabelling tests
reject.

This is substantially stronger binding, but not all-relation execution. The
per-shard SHA256d opening is still an R&D seam rather than a recursive hash
child or production multiproof; 331,400 individual paths would be too large.
A/B/Y opening/sumcheck, the actual Extract transformation/output root and
recursive consumption remain incomplete, and scale replay is still native
public re-derivation pending composition with the recursive SHA program.

### 10.3 Bounded-width recursive verifier result

The original `124,802`-column construction put all verifier work side by side.
The new planner schedules a fixed verifier program over operation rows and
allocates width by the largest chip. It budgets all mandatory families:
row-Merkle verification, FRI folds, dual-DEEP checks, per-point AIR checks, and
Fiat-Shamir absorption/replay. The scalar and Poseidon families described below
execute; complete SHA-based Fiat-Shamir replay does not yet execute.

The first narrow result closed width but exposed a degree/LDE problem:

```text
direct x^7 lane:
  width fixed point:     F(26) = F(192) = 192
  recursive trace:       2^18 rows
  selector-gated degree: 8
  recursive LDE:         2^25  (backend cap is 2^24; FAIL)
```

Two explicit degree-reduction tactics were modeled:

```text
x2/x4 lane:
  constraints: x2=x*x, x4=x2*x2, y=x4*x2*x
  width: 428
  selector-gated degree: 4
  vertical-child LDE: 2^25 (still fails)
  fixed two-lane binary chip: width 856, LDE 2^24 (closes)

fully quadratic x2/x4/x6 lane:
  constraints: x2=x*x, x4=x2*x2, x6=x4*x2, y=x6*x
  width: 546
  selector-gated degree: 3
  F(26)=546, F(546)=546
  Q=148 recursive trace/LDE: 2^19 / 2^24
  Q=154 recursive active rows: 333,948 -> 349,964; LDE 2^24
  Q=159 recursive active rows: 344,758 -> 361,294; LDE 2^24
  Q=160 recursive active rows: 346,920 -> 363,560; LDE 2^24
  Q=192 recursive active rows: 416,104 -> 436,072; LDE 2^24
```

The fully quadratic lane closes the original scalar-only width and LDE model.
The exact Fiat-Shamir replay audit below shows that one vertical lane does not
close once every required SHA compression is counted.

The Poseidon2 portion is now executable rather than only modeled:

```text
fixed operation table:      484 columns, 472 constraints, degree 2
selector-gated table:       485 columns, 473 constraints, degree 3
N=1,024 fixed quotient:     1,023 coefficients
N=1,024 gated quotient:     2,046 coefficients
```

It decomposes each of the 118 `x^7` S-boxes as
`x2=x*x`, `x4=x2*x2`, `x6=x4*x2`, `y=x6*x`. Sixteen differential vectors
match the native permutation, mutation of every one of the 484 witness cells
is rejected, the selector is a canonical preprocessed column, and a real
two-row `AirQuotientProve -> AirQuotientVerify` round-trip succeeds.

The non-Poseidon scalar lane is now executable as well. A canonical scheduler
expands the narrow-child shape into an exact fixed program and rejects omitted,
reordered, relabelled, or noncanonical padding rows. Its 27-column,
19-constraint degree-two AIR executes:

- Merkle left/right routing with a boolean direction bit;
- the half-domain FRI fold identity without an inverse witness;
- dual-DEEP and random-linear-combination multiply-adds;
- per-point multiplication checks;
- boundary equalities.

The exact scheduler now also emits a row-source manifest and a canonical
Fiat-Shamir event program for the outer `airq_lambda` and complete legacy
Q192/V3 algebraic-FRI transcript. A proof-derived host witness binds the
serialized batch, trace commitment, supplemental openings and siblings, every
accepted challenge, every CTL pin, and every scheduled row. An independent
host replay calls the authoritative native FRI and AIR-quotient verifiers
before building the proof-derived algebraic mirror; changed challenges,
queries, openings, CTL terminals, and row sources are rejected. This path is
explicitly typed `legacy_q192_v3_only`: its unbounded extension-point rejection
loop prevents it from being the V5 recursive program.

V5 now has a separate finite transcript program and proof-derived witness. For
each of two ordered Q128 lanes it re-derives the lane seed, all `W` independent
batching coefficients, four fixed OOD candidates and their selected `z1/z2`,
two DEEP weights, every fold challenge, and all 128 query indices. The program
has exactly

```text
uniform Fp3 draws/lane = W + 4 + 2 + log2(N)
SHA256d calls for those draws/lane = 2 * uniform Fp3 draws/lane
query-index SHA256d calls/lane = 128
```

Lane swap/copy, batching-coordinate, fold, query, master-binding, and ordered
child-binding mutations fail. This completes the host transcript
differential for V5. A joined host witness now requires both that exact replay
and the authoritative complete native dual-proof verifier; an opening mutation
can pass transcript reconstruction but is rejected by the native proof check.
It does not yet put SHA256d equations or the proof-derived rows inside the
recursive AIR.

The recursive proof API is still mixed-version and deliberately reports that
fact. `AirFriBackendAlg`, `AirQuotientProof`, `AggregateWitness`, and the
normalized whole-verifier builder carry a single Q192/V3
`Fri3AlgBatchProof`; they do not consume the dual Q128/V5 envelope. The V5 host
witness therefore sets `recursive_proof_api_supports_v5=false` and cannot be
used as recursive or consensus acceptance.

Synchronizing a SHA256 midstate with only newly absorbed transcript bytes
removes repeated prefix hashing without changing a single challenge byte.
Fifteen differential vectors cover legacy field draws, V5 uniform field draws,
and V5 index draws. For the production Q192 child shape, the exact schedule is:

```text
scalar verifier rows already scheduled:            500
Fiat-Shamir transcript bytes:                    29,315
naive prefix-rehash SHA256d compression blocks:  97,975
streaming-prefix SHA256d compression blocks:         894
streaming vertical active rows:                 416,892
streaming vertical trace/LDE:               2^19 / 2^24
streaming parallel active rows:                 208,446
streaming parallel width:                         1,092
streaming parallel trace/LDE:               2^18 / 2^23
```

Both estimated shapes now fit the backend caps. The native streaming-prefix
implementation is executable and byte-identical, but the physical recursive
SHA chip, parallel-lane column layout, and complete proof-derived witness
layout do not yet execute. Authority therefore remains false.

### 10.4 Soundness topology result

Using the repository's proximity diagnostic term
`Q*log2(32/17) - 40`:

```text
Q=148: raw  95.055499 bits
Q=154: raw 100.530722 bits
Q=159: raw 105.093408 bits
Q=192: integer per-proof diagnostic 135 bits
```

Fourteen independent role roots lose `log2(14) = 3.807355` bits under a
conservative union bound:

```text
Q=154, 14 independent roots:  96.723368 bits  (FAIL)
Q=159, 14 independent roots: 101.286053 bits  (passes this term)
```

The normalized final tree has exactly 14 ordered relation leaves, two
deterministic padding leaves, and 15 binary aggregation nodes, hence 29
final-tree proof sites. That is a useful exact submanifest, but it is not a
valid global union bound: the profile-2 manifest alone covers more than ten
billion Extract tiles before sharding and recursion. The implemented global
ledger therefore evaluates a declared candidate budget of `2^28` recursively
accumulated proof sites rather than only the 29 final-tree sites. That value is
not yet an executable cap or a derived global maximum. The algebraic-FRI
backend has an executable version-3 Q192 path and an opt-in version-4 two-lane
Q96-per-lane path:

```text
floor(192*log2(32/17)) - 40 - 28 = 107 bits
```

The schema, bounded codec, CTL-bound child pins, deterministic sixteen-leaf tree,
and root commitment execute. The soundness ledger separately names FRI
proximity/grinding, the FRI field/domain term, Fp3 trace compression, constraint
batching, CTL compression and poles, hash collision, Fiat-Shamir modeling, and
PoW/Fiat-Shamir composition, plus the final additive union of distinct
false-accept events. Because shard accumulation and the
hash/Fiat-Shamir/PoW reductions are not yet complete, the theorem object
deliberately reports:

```text
diagnostic proximity margin: 107 bits
conservative all-query dual-Q96 screen: 72 bits
theorem_complete:             false
certified_soundness_bits:     0
authority_eligible:           false
```

The recursive verifier seam consequently fails closed rather than treating the
107-bit fixed-budget diagnostic as a theorem. The unified ledger now consumes
the executable conservative BCS/repetition assessment for its FRI field/domain
term; its provisional minimum is therefore 72 bits, not a hidden zero or the
stale pre-constant 76-bit estimate.

That distinction is required by the current literature. The formal
Fiat-Shamir analysis of FRI gives a round-by-round error that is the maximum of
a field/domain term and the query-proximity term, then adds random-oracle query
loss in the BCS transformation; it is not justified by subtracting only a tree
union exponent from `Q*log2(32/17)-g`
([Fiat-Shamir Security of FRI and Related SNARKs](https://eprint.iacr.org/2023/1071.pdf)).
Likewise, LogUp's published bound charges the rational-identity degree,
sumcheck batching, and the denominator sampling domain
([Lookup Arguments based on Logarithmic Derivatives](https://eprint.iacr.org/2022/1530.pdf)).
The ten-term ledger is structured to receive those quantities once the
global shard and event manifests are executable.

The exact formal-term screen changes the preferred next experiment. Three
different quantities must not be conflated:

1. the interactive FRI round-by-round error;
2. fixed-`Q` adaptive soundness after BCS; and
3. concrete work security `log2(Q/epsilon(Q))`.

For `m=3`, `rho=1/16`, `|L|=2^24`, and `|Fp3|≈2^192`, Theorem 4.1's complete
provable field term charges

```text
log2((3.5)^7 / (3*rho^(3/2))) = 17.0665 bits
field RBR bits = 192 - 2*24 - 17.0665 = 126.9335
```

The BCS theorem gives each lane

```text
epsilon_fs(Q) <= Q*epsilon_rbr + 3*(Q^2+1)/2^256.
```

The safe two-lane route is then to repeat the already BCS-compiled NIROP over
disjoint oracle domains and require both proofs. Appendix B.2, Lemma B.1 of
[Interactive Oracle Proofs](https://eprint.iacr.org/2016/116.pdf) proves
`epsilon_repeat(Q) <= epsilon_fs(Q)^2` for exactly this construction, even
against a prover making queries across both oracle domains. Under Definition 2
of [On the Concrete Security of Non-interactive FRI](https://eprint.iacr.org/2024/1161.pdf),
the work metric after `S` proof sites is therefore:

```text
work_bits =
  log2(Q) - log2(S) - log2(epsilon_fs(Q)^2).
```

The leading `Q` work is consequently added once after the square. Subtracting
`log2(Q)` once per lane would compute fixed-`Q` success-probability bits, not
the specified expected-work security metric. This evaluates one declared
adversarial budget. Definition 2 requires the inequality for every `Q`, so the
full theorem must either minimize the bound over all `Q` or state and justify
an explicitly bounded threat model; the present `Q=2^40` calculation alone is
not a Definition-2 certificate.

For `Q=2^40`, `S=2^28`, and 96 FRI queries per lane:

```text
proximity RBR bits per lane = 96*log2(32/17) = 87.6036
BCS query term per lane     = 47.6036 bits
BCS RO-collision term       = 174.4150 bits
dual work margin            = 107.2071 bits after the 2^28 site union
dual field work margin      = 185.8670 bits
```

The former single-Q192 path still misses the full provable screen:

```text
one-lane Q192 work margin = 98.9335 bits before the batching-variant loss
```

The fixed-`Q` result is not the all-query Definition-2 result. For `Q>=1`,
write the one-lane BCS bound as `A+B`, where
`A=Q*epsilon_rbr` and `B=3*(Q^2+1)/2^kappa`. The conservative inequalities

```text
A+B <= 2*max(A,B)
B <= 6*Q^2/2^kappa
```

let the work ratio be minimized without choosing a particular adversarial
budget. After `r` repetitions and the `S`-site union, the global error
saturates when the per-lane bound reaches `S^(-1/r)`. The two resulting
all-query crossover screens are

```text
RBR branch = lane_rbr_bits - 1 - log2(S)/r
RO branch  = (kappa - log2(12) - log2(S)/r)/2.
```

For the current two-lane candidates this gives:

```text
dual Q96, independent batching: 72.6036 bits  (FAIL)
dual Q128, independent batching: 101.8048 bits (parameter screen passes)
dual Q128, one-power batching at t=2^14: 97.9336 bits (FAIL)
```

Thus dual Q96 is useful as an executable fixed-budget experiment, but cannot
support the required all-query security claim. The first two-lane parameter
candidate to clear this conservative numerical screen is Q128 with
independently sampled batching coefficients. That schedule is now executable
in the experimental V5 backend, but every reduction and common-event
obligation below remains open.

There are three remaining caveats behind the fixed-budget dual-Q96 number:

- The legacy V3 and historical Q96 row batches use
  `(1,lambda,...,lambda^(t-1))`. Lemma 5.10 of the FRI paper gives the exact
  additional field-event factor `(t-1)` for that communication-saving
  variant. At `t<=2^14` this costs `log2(16383)` bits per lane and leaves the
  all-query Q128 screen at 97.9336 bits. V5 now executes independent
  coefficients, removing that factor under Theorem 4.2; the remaining task is
  a written correspondence between the executable BTX relation and the cited
  protocol plus a manifest-derived actual `t`.
- Domain tags alone are implementation evidence, not the proof. The complete
  replay must establish disjoint random-oracle input domains for every oracle
  call, not only the Fiat-Shamir challenge calls, equality of the two public
  statements, and accept-all semantics before Lemma B.1 can be instantiated.
  The lanes currently share the same algebraic row commitment. Poseidon/AlgHash
  binding or collision is therefore a common, non-squared failure event; the
  107-bit conditional FRI screen needs a separate commitment-binding hybrid
  before it can enter the global ledger.
- Every field challenge must be uniform. The legacy
  `FromChallengeBytes3` reduction has only about a 30.4-bit statistical-distance
  bound across three limbs. Likewise, deriving a query index by reducing a
  uniform Goldilocks element modulo a power-of-two domain introduces a
  roughly 64-bit bias term.

The fixed-schedule sampler selected for the experimental lane consumes eight
lane-prefixed random-oracle `uint64` words and uses the first three words below
the Goldilocks modulus. Conditioned on finding three, the coordinates are
exactly independent and uniform in `Fp`; failure requires at least six invalid
words. The executable Q96/V4 schedule now uses this sampler for every field
challenge, uses two fixed candidates for each of two OOD points, and derives
query indices from unbiased low bits after enforcing a power-of-two domain.
At the `2^24` LDE cap its per-lane field-draw manifest is
`1 + 2*2 + 2 + 20 = 27`:

```text
Pr[fewer than 3 valid words among 8] < 2^-187.19 per draw
after 2 lanes, <=2^8 draws/lane and 2^28 sites: >150.19 completeness bits
```

Sampler exhaustion is a fail-closed completeness event, not an additive
soundness error. These implementation facts closed the local Q96 sampler
observations and were then carried into the executable Q128/V5 schedule below,
but not into a complete reduction. Full-domain separation, the
shared-commitment hybrid, adversary budget, and global site manifest remain
open. The theorem object therefore continues to report
`formal_reduction_complete=false` and `authority_eligible=false`.

The independent scenario evaluator also minimizes the displayed BCS upper
bound directly over continuous `Q>=1`. This is a rigorous lower bound for
integer-query attackers and is one bit tighter than the deliberately
conservative `A+B <= 2*max(A,B)` authority ledger:

```text
candidate                                      exact crossover  conservative
dual Fp3 Q96, LDE 2^24, independent batching       73.6036        72.6036
dual Fp3 Q128, LDE 2^24, independent batching     102.8048       101.8048
dual Fp3 Q148, LDE 2^24, independent batching     112.9330       111.9330
single Fp3 Q192, LDE 2^23, independent batching   100.9335        99.9335
single Fp4 Q192, LDE 2^24, one-power batching      113.2          backend absent
```

The selected numerical direction is therefore dual Fp3 Q128 with independent
batching as the smallest screened two-lane pass, while Q148 is the
higher-margin fallback. Q96 remains only an executable experiment. Single
Fp3/LDE23 is too close under the conservative ledger and conflicts with
current recursive LDE24 sites. Fp4 would require a new backend.

The production inventory currently derives exactly:

```text
GEMM layers:                         400
GEMM cells:              347,490,222,080
Extract tiles:            10,859,069,440
signed-range AIR shards:         331,400
paired range CTL children:       662,800
known leaf AIR invocations:      994,200
exact normalized-root sites:          29
```

Those `994,229` known sites remain a lower-level inventory, not a global upper
bound for the current computation. The executable count manifest now
enumerates all registered episode/coupled roles and charges builder XOF,
GEMM A/B/Y openings, signed range, every Extract row, the two-compression
scale SHA, Extract ChaCha, wiring, tile-tree SHA256d, coupled bank expansion
XOF and streaming commitment, page schedule, lobe initialization, material
exchange/permutation/mix XOFs, coupled relation rows, barrier/digest SHA256d,
below-root aggregation and the fifteen final-tree internal nodes.

That exercise exposed a protocol-level completeness condition: current
MxExpand and Extract rejection loops have no consensus maximum, so their
proof-site count has no finite a-priori upper bound. With an explicit proposed
Stage-3 rule of at most four 64-byte rejection blocks per 32 outputs, 2^18
relation rows per leaf, 2^20 AIR rows, four independent fixed hash programs
packed horizontally per hash proof, and the largest currently supported
recursive arity (four), the canonical manifest is:

```text
relation leaf proof sites:       28,116,241
below-root aggregation sites:     9,372,141
final-tree internal sites:               15
conditional upper-bound total:   37,488,397
enforced union cap required:           2^26
```

Binary aggregation, an eight-block rejection policy, unpacked hash programs,
six/seven-way numerical packing and arity sixteen were evaluated. Four-way
packing is the selected executable point: its direct-product boundary AIR is
608 columns, leaving 484 columns below the 1,092-column leaf budget, and a real
quotient round trip exists. Arity sixteen is smaller but exceeds the
registered four-child recursive carrier; six/seven-way packing has no
executable quotient construction and leaves materially less width. The
`2^26` result is a checked upper bound only for the proposed bounded-rejection
Stage-3 policy. Today's unbounded legacy solver still has no finite global
cap.

The compact scheduler now recomputes and enumerates every one of the 28 family
ranges, every one of the 14 role plans and every arity-four parent range. Its
paged callback receipt binds the manifest, schedule, unified root, role,
level, parent index, global site and exact child interval. Unified-root V3
commits to that exact schedule and recomputes the `2^26` cap. This closes
structural schedule accounting and paged replay checks; it does not yet prove
that one canonical execution consumed every page, or make an opaque parent
receipt an algebraic proof that its child verifier AIR accepted.

The adversarial pass found and fixed two concrete CTL transport defects:

- child verification now recomputes event/send/receive counts from the
  committed schedule, so public counts cannot undercharge the rational
  numerator;
- the unified bundle codec preflights event bytes before allocation and
  enforces its aggregate 16 MiB bound incrementally.

The native CTL bundle now carries a canonical relation-export pin for every
role. It commits the relation root, bus/schedule/count, trace dimensions, and
the exact NAMESPACE/STAGE/ADDRESS/VALUE/MULTIPLICITY roots. Verification
requires all five roots to equal the executed CTL AIR proof and recomputes the
prechallenge trace commitment from them. Omission, relabel, relation-root
substitution and VALUE-root substitution are rejected. The remaining
cross-layer obligation is narrower but still decisive: each role-specific
relation verifier must expose its actual witness VALUE root and constrain it
equal to this export. Until then, a prover can declare an export alongside an
unrelated role witness, so relation-witness readiness and authority remain
false.
The adversarial review also found that positive proof-cache insertion was a
public header API. It is now translation-unit-private and reachable only after
the complete mathematical verifier returns success. The cache key remains
body-aware `(block_hash, proof_payload_digest)`, and consensus context is
revalidated before lookup.

### 10.5 Research synthesis and selected architecture

The strongest near-term design is:

1. Retain the current Fp3, DEEP-FRI, Poseidon2, sumcheck, and evaluation-opening
   substrate.
2. Compile deterministic builder, Extract, SHA/ChaCha, stream, bank, schedule,
   and mix work into fixed operation chips whose cost grows in rows.
3. Connect chips through the proof-bound CTL/LogUp bus; keep each stage
   write-once by including `(role, stage, address)` in its namespace.
4. Normalize the fourteen leaf proof shapes into a fixed 16-leaf binary tree
   and aggregate them into one public root.
5. Keep the fully quadratic bounded-width chips, but implement the measured
   two-lane verifier schedule so exact Fiat-Shamir replay fits the LDE cap. Use
   the executable single-Q192 algebraic-FRI backend as the integration baseline,
   retain dual Q96 only as the fixed-budget/repetition comparison, and use the
   executable dual-Q128 schedule with independently sampled batch coefficients
   as the first design that clears the all-query parameter screen. Treat the
   exact `2^26` union cap as valid only under the four-block rejection rule,
   executable SIMD4 hash packing and manifest-derived arity-four schedule.

This follows the fixed-program, operation-specific chip and recursive
aggregation direction demonstrated by the
[Plonky3 recursion project](https://github.com/Plonky3/Plonky3-recursion) and
the logarithmic-derivative lookup construction in
[LogUp](https://eprint.iacr.org/2022/1530.pdf). Plonky3 is useful engineering
evidence, not production authority: its own repository says it is under active
development and unaudited. Its published Apple M4 Pro benchmark reports later
recursive layers around 109 ms and later 2-to-1 aggregation layers around
193 ms, but those parameters and fields are not BTX measurements
([benchmark](https://plonky3.github.io/Plonky3-recursion/appendix/benchmark.html)).

[STIR](https://eprint.iacr.org/2024/390.pdf) and
[WHIR](https://eprint.iacr.org/2024/1586.pdf) are credible longer-term ways to
reduce query/hash pressure. Replacing the current FRI/PCS now would add a second
major protocol migration before the relation and recursion AIRs close. Binius,
Circle-STARK, Nova/Protostar, and similar alternatives also change the
field/domain/commitment or accumulation stack. They remain research branches,
not hidden dependencies of this Stage-3 path.

### 10.6 Executable Q128 V5 backend and commitment-hybrid boundary

The experimental two-lane backend has now moved from Q96/V4 to Q128/V5
without changing the legacy single-lane Q192/V3 protocol. V5 executes:

- 128 independently sampled query sites in each of two ordered lanes;
- one independently and uniformly sampled Fp3 batching coefficient for every
  committed column, replacing the one-power
  `(1,lambda,...,lambda^(t-1))` vector;
- the bounded eight-word uniform sampler for every Fp3 draw, two fixed OOD
  candidates per point, and direct low-bit query-index sampling;
- a canonical V2 envelope committing to one shared master statement and two
  ordered lane-child bindings.

Both commitment scenarios are executable. The shared-master construction
avoids duplicated roots but leaves one common non-squared binding event. The
alternative constructs two fully duplicated AlgHash trees: every row leaf,
fold leaf, and internal node input contains a fixed lane coordinate, producing
distinct roots while retaining the same Poseidon permutation chip. The lanes
bind the same external statement/shape and may use distinct witness
commitments, as permitted by parallel proof repetition. Master/child
substitution, lane swap/copy, seed replay, batching-coordinate replay, and
noncanonical or oversized codecs are rejected.

At the deliberately coarse `2^28` site cap, neither commitment topology
reaches the 100-bit target after composing the binding and FRI errors.  The
exponents must be combined as
`-log2(2^-binding_bits + 2^-fri_bits)`; taking their minimum would overstate
the result:

```text
shared master, S=2^28:
binding                                      = 100 bits
dual-Q128 all-query FRI screen               = 101.804756 bits
composed additive union                      = 99.636852 bits

duplicated lanes, S=2^28:
binding, including two-event union           = 99 bits
composed additive union                      = 98.807030 bits
```

Using the previous unpacked conditional manifest count `S=145,974,891`, rather
than its `2^28` power-of-two cap, gave:

```text
log2(S)                                      = 27.121145
shared binding                              = 100.878855 bits
exact-site dual-Q128 all-query FRI screen   = 102.244184 bits
shared composed additive union              = 100.405696 bits
duplicated composed additive union          = 99.622964 bits
```

The selected executable SIMD4 manifest instead has:

```text
relation leaves                              = 28,116,241
below-root arity-four parents                = 9,372,141
final-tree parents                           = 15
S                                            = 37,488,397
shared composed additive union               = 102.019636 bits
```

The selected conditional architecture is therefore shared-master V5 with
about `2.020` bits of numerical headroom. Every rejection-producing
proof/witness builder enforces the same four-block V1 cap, and the structural
scheduler commits the exact site and parent enumeration. A canonical
all-page execution transcript and algebraic consumption of every recursive
child proof are still absent, so this is not yet a certified global theorem.
The duplicated backend remains executable evidence for a cleaner
oracle-domain boundary and becomes preferable only with a smaller exact
manifest or a sharper multi-target binding reduction.
Neither path is yet a completed Lemma-B.1 reduction. A written proof must map
the AlgHash/SHA domains to the repeated NIROP oracle model and compose its
binding events with the global theorem. The fail-closed gates remain:

```text
full_nirop_oracle_separation_proven       = false
common_commitment_hybrid_reduction_complete = false
independence_reduction_ready              = false
formal_soundness_ready                    = false
authority_eligible                        = false
```

The unpacked exact-site audit identified where useful margin could come from.
Its largest terms were Extract ChaCha `42,418,240`, recursive aggregation
`36,493,772`, Extract scale SHA `21,209,120`, coupled bank XOF `12,607,493`,
episode wiring `11,066,136` and GEMM openings `11,022,352`. Merely placing
multiple FRI rows in one Merkle leaf does not reduce those AIR/proof
invocations and greatly enlarges width-1,092 query openings. A genuine AIR
trace-row packing rewrite can help because it reduces actual proof sites:

```text
ideal all-family 2x trace packing: S ~= 72,987,487, composed ~= 101.248 bits
ideal all-family 4x trace packing: S ~= 36,493,791, composed ~= 102.050 bits
hash-only 2x / 4x packing:          composed ~= 100.958 / 101.358 bits
```

The four-way boundary point is no longer only a screen: four distinct CTL
namespaces and four independent boundary programs are horizontally composed,
every lane mutation and namespace alias is rejected, and the 608-column
quotient proof round-trips. It took 50.76 seconds to prove and 502 ms to verify
on the development host. The internal fixed-program SSA relation now also
executes for one lane. It commits the operation/boundary columns first, derives
two independent Fp3 `(gamma, alpha)` lanes, and proves the rational identity

```text
sum_a uses(a)/(alpha - (a + gamma*v_a))
  = sum_internal_uses 1/(alpha - (a + gamma*v))
```

for every single-assignment producer/consumer edge. The resulting ChaCha
instance has 1,024 rows, 171 columns and 488 constraints; its quotient proof
took 18.78 seconds to produce and 144.99 ms to verify. A locally valid
instruction substitution that defeated the old boundary-only AIR now fails.
The fixed masked relation exporter composes that real provenance AIR with CTL
in 180 columns for one word lane. Four independent provenance lanes now also
share one real quotient. Challenges bind all prechallenge roots, the lane
index and four distinct CTL namespaces:

```text
rows / columns / constraints:        1,024 / 684 / 1,952
prover / verifier:                         75.140 s / 567.67 ms
```

Namespace, external-value, challenge-commitment and whole-lane-detachment
mutations reject. This closes packed internal SSA provenance itself and stays
under the 1,092-column relation-child screen. Adding sixteen separate scalar
CTL traces would bring the screened parent to 828 columns but still needs an
executed combined builder. Six boundary lanes use 912 columns and seven use
1,064, but neither has a fixed complete-provenance proof API/roundtrip.
Increasing Q128 to Q148 cannot create comparable headroom because the common
binding term remains limiting.

An isolated pre-parallelization query-count experiment ran the same V5
independent-batching protocol at Q96 and Q128, changing only the number of
query openings:

```text
shape             Q96 bytes   Q128 bytes   byte ratio   Q96 verify   Q128 verify   time ratio
toy                 319,276      425,260       1.332x       42.0 ms       57.3 ms       1.363x
16 columns x 128     921,684    1,227,860       1.332x      117.9 ms      161.1 ms       1.367x
```

Outer-first parallel lane verification, synchronized SHA256 prefix midstates,
and bounded inner-query scheduling then reduced the current Q128 measurements
on this 14-core arm64 machine to:

```text
shape                         proof bytes   shared verify   duplicated verify
toy                               425,260           8.4 ms                  -
16 columns x 128                1,227,860          20.5 ms                  -
1,092 columns x 2              6,966,948          57.6 ms            57.1 ms
1 column x 65,536              3,715,700          61.1 ms                  -
```

The query indices are still derived sequentially from the exact transcript.
Only after that replay completes are the immutable query openings split into
seven chunks per outer lane, so rejection behavior and the first reported
failing query remain deterministic. The production-width probe isolates the
planned 1,092-column row-opening cost while keeping polynomial length at two.
The production-depth probe isolates a `2^16` coefficient / `2^20` LDE domain
while keeping width at one; producing that proof still took 55.8 seconds.
Adding the isolated verifier terms gave a useful 118.8 ms engineering screen.
The exact combined-dimension fixture below now supersedes that addition for
the native FRI verifier, but non-FRI root checks and the real relation prover
remain absent.

The materialized combined prover shape remains the immediate systems blocker.
For the selected 1,092 trace columns plus one quotient column,
`N=2^19`, `N_LDE=2^23`, the exact memory ledger is:

```text
all column LDEs materialized:       220,049,965,056 bytes  (204.94 GiB)
column-streaming planned peak:        1,635,778,560 bytes  (  1.52 GiB)
row-sponge working set:               1,409,286,144 bytes
full row-Merkle tree:                   536,870,880 bytes
one column recompute buffer:            213,909,504 bytes
fold recomputation peak:                744,912,864 bytes
materialization reduction:                    134.52x
```

The selected shared-master V5 path now executes the load-bearing two-pass
column-LDE schedule. Pass one recomputes one column LDE at a time into one
pending Poseidon state per row, appends the row index and exact `10*` padding,
and emits the row tree. Once all fold roots fix the query indices, pass two
recomputes one column LDE at a time and retains only queried row values. Toy
and medium proofs are byte-identical to the materialized prover and pass the
same verifier; the returned prover-side `column_lde` matrix is empty.

This removes the `W*N_LDE` matrix but is not yet the full production streaming
engine. The API still receives all source columns in memory, computes the
shared row tree once and reuses it across both lanes, but retains fold
layers/trees instead of recomputing or spilling them. A callback-backed source
column provider, fold spill/recompute and a combined production run remain
open.

Recursive aggregation now has a fail-closed checked entry point that native
verifies every child before building or proving its algebraic mirror, plus a
callback-driven one-level executor that retains at most four child proofs and
one parent witness at a time. It records child verify, witness build/scan, root
prove, proof-byte and peak-live-memory phases. This is a concrete bounded-memory
aggregation seam, but the old wide-layout two-level real-FRI diagnostic still
did not finish after 363.77 seconds and reached about 4.13 GiB RSS. The
normalized two-level fixed point therefore remains unexecuted.

### 10.7 V1 integration results and honest production boundary

The current pass closed four integration ambiguities.

First, all three rejection-producing proof paths share one V1 rule:

```text
maximum rejection blocks per 32 outputs = 4
```

The builder SHA counter-XOF, MxExpand verifier and Extract ChaCha witness stop
at that bound. An over-cap deterministic candidate remains valid for the
legacy exact computation but is unprovable in Stage-3 V1; the miner must try a
different nonce. The complete selected conditional count is now:

```text
relation leaves:               28,116,241
arity-four aggregation:         9,372,141
final normalized tree:                 15
exact sites:                   37,488,397
power-of-two validation cap:         2^26
```

Unified-root format V3 carries the exact production-site manifest commitment,
the exact aggregation-schedule commitment and the `2^26` union cap, recomputes
them from frozen production dimensions and the V1 policy, includes them in the
root Fiat-Shamir seed, and rejects substitution. The paged scheduler
enumerates every manifest range and parent work item and rejects local-page
omission, reordering, duplication and cross-root replay. This closes public
manifest binding and the structural schedule. It does not yet close a
canonical full-schedule execution or cryptographic recursive child
consumption.

Second, the two-lane V5 proof is now directly normalized into two verifier-AIR
blocks. This execution found a real defect: the verifier mirror was using the
legacy `[1,lambda,...]` batching vector even though V5 independently samples
every column coefficient. `ChildPublicInputs` now carries the proof-derived
V5 coefficient vector and the `U(X)`, `v1` and `v2` equations consume it. The
latest reduced diagnostic reports:

```text
normalized trace with opening families:
                                128 rows x 8,080 columns
native child verification:                      15.9 ms
exact V5 transcript replay:                      0.05 ms
witness construction:                          130.6 ms
constraint scan:                               215.3 ms
constraint violations:                              0
reduced parent prove:                           189.4 ms
```

The parent measurement omits full verifier families and is not a production
root benchmark. The adapter API is explicitly diagnostic because SHA256d
Fiat-Shamir derivations, master/child binding preimages, trace-root
commitment preimages and fixed constraint-registry identity are not yet AIR
equations. Host report bits are seed-bound metadata, not proof facts.

The supplemental algebraic opening families now execute. Every query
authenticates the next trace row plus quotient cell to the batch row root,
authenticates the current trace-only row to `R_T`, equality-links the current
values across both trees, and evaluates transition/first/last selectors using
the opened next row. A transition/boundary test over all families has:

```text
rows:                                      128
columns:                                12,660
honest violations:                          0
mutated next-row opening violations:       13
mutated trace-root opening violations:     13
```

This closes the formerly absent next-row and trace-root cross-opening
equations while remaining below the 16,384-column backend cap.

For the historical production child width `W=26`, the direct-opening design
now measures:

```text
one normalized child:        7,889 columns / 2,019,584 cells
two normalized children:    15,778 columns / 4,039,168 cells
backend column cap:          16,384 columns
remaining width margin:         606 columns
```

The two-child shape exceeds the old `2^21` cell optimization target, but that
number was not the backend acceptance cap. It is executable by width and still
needs prover-time/memory optimization.

Third, the relation closure ledger now fixes fourteen roles and 52 exact
semantic endpoints. The selected construction is a same-trace product AIR
`[complete relation trace | 9-column dual-lane CTL trace]` plus the exact
degree-one identity `relation[source](r) = CTL.VALUE(r)`. This proves
proof-cell provenance without adding a probabilistic term; dual-lane LogUp is
retained for equality of the cross-trace bus multisets. A lossless fixed
masked alias exports boundary streams as
`VALUE = sum_j mask_j*source_j`, with verifier-owned boolean, pairwise-disjoint
masks. Omission, relabeling, relation-root, CTL-root and source substitution
reject. Before the complete memory layer in §10.9, that direct CTL audit was:

```text
executed relation AIR cells:                       22 / 52
same-trace relation -> CTL VALUE aliases:           21 / 52
semantically complete endpoints:                    1 / 52
recursively consumed endpoints:                     0 / 52
complete recursive roles:                            0 / 14
```

The 21 aliases cover six episode cells and fifteen coupled local-kernel cells.
At that checkpoint the episode GEMM signed-range endpoint was classified as
semantically complete. The later transitive audit invalidated that
classification because the range input root was not linked to the executed
GEMM producer graph. The others lacked some combination of commitment
openings, immutable schedules, complete limbs, every-instance aggregation or
hash provenance. A
regression demonstrates that opaque proof-root/recursive-child metadata can
otherwise be replaced and rehashed while structural closure still passes.
Therefore the ledger cannot be promoted by itself.

Fourth, an exact valid zero-polynomial proof fixture exercises the real
dual-Q128 verifier at the complete production FRI dimensions without paying
for 1,092 FFTs. Leaf hashes remain index-bound, so the fixture constructs the
real Merkle nodes and canonical openings:

```text
columns W:                              1,092
polynomial coefficients N:             2^19
LDE rows:                               2^23
queries:                                2 x 128
encoded proof:                     11,687,700 bytes
real native V5 verification:          123.933 ms
fixture construction:                  32.267 s
honest index-bound Merkle nodes:      50,331,595
measured maximum resident set:          2.211 GB
attachment cap:                         16 MiB
verifier target:                        900 ms
```

This is the first exact combined-dimension evidence that the native FRI
verification path and attachment size fit their V1 budgets on this machine.
It is not an episode proof, not the recursive-root timing, and not evidence of
production prover cost: all source polynomials are zero and the fixture
deliberately skips FFTs.

### 10.8 Algebraic Fiat-Shamir V6 experiment

Arithmetizing the existing SHA256d V5 transcript remains the lowest
protocol-change route, but its measured schedule is far larger than the
algebraic alternative. A host-digest hybrid is not acceptable because the
digest provenance would remain a native assertion. The selected experimental
V6 therefore leaves SHA256d only at the block/public-statement boundary and
uses a new, explicitly versioned AlgHash transcript for recursive proof
commitments and challenges.

The executable V6 AIR proves the fully decomposed Poseidon permutation, sponge
start/continuation rules, the previous-frame digest chain, fixed framing and
public words, and equality of every proof-derived payload word to an external
child-verifier source column. For the complete production V5 event inventory
translated into V6 framing:

```text
AIR width:                              667 columns
frames:                               3,305
active Poseidon permutations:         8,253
padded trace rows:                   16,384
proof-derived payload cells:         14,331
constraints:                            664
```

The master statement, two ordered lane seeds, 1,092 independent batching
draws per lane, fixed OOD candidates, DEEP weights, nineteen folds, 128 query
candidates per query and the AIR quotient challenge are all chained inside the
transcript AIR. The fixed four-candidate sampler proves a canonical 64-bit
field decomposition, rejects the sole `p-1` residue outside the exact
power-of-two partition, selects the first valid candidate and exposes its low
`k` bits. It explicitly rejects four-candidate exhaustion; the ideal-output
union screen remains above 230.7 bits over all 37,488,397 shard-accounting
sites.

The normalized V5 verifier now publishes the required eight master-binding
cells from the actual affine outputs of its two row-Merkle terminal
permutations. Eight canonical selector columns activate those exact V6 payload
locations, eight export columns are constrained to the mapped V5 outputs, and
V6 `ExternalSource` is a literal same-column alias. There is no longer a
host/preprocessed expected-value fixture at this seam. Source-only, V5-only,
synchronized source/export, lane-swap, transcript and root mutations reject.
For a W=26 child shard the master-bus composition is 128 rows, 4,887 columns,
4,678 constraints and 625,536 cells, below the 16,384-column backend cap. The
full V5-family root-bus witness also scans with zero violations at 8,755
combined columns and 8,480 constraints, although the quotient benchmark below
uses the smaller row-root V1 profile.

V6 is not a relabeling of V5 and is not ready for consensus. The complete toy
full-transcript inventory now has named normalized-V5 witness mappings for all
48 proof-derived payload cells:

```text
ordered row-root limbs:                         8 / 8
trace-root limbs:                               8 / 8
z1 evaluation coordinates:                   12 / 12
z2 evaluation coordinates:                   12 / 12
fold-root limbs:                                8 / 8
```

Root cells are affine terminal-permutation outputs. Evaluation coordinates
are pinned V5 witness columns consumed directly by the DEEP identity. Each
payload record names its V5 source, V6 location, selector, export column and
equation consumer. Source/export, family, lane-order and synchronized swap
attacks reject. The full composition measures 4,096 rows, 8,833 columns and
8,569 constraints; witness construction and a complete constraint scan took
about 8.02 and 7.18 seconds respectively in the focused test.

This closes proof-payload ownership, not Fiat-Shamir feedback. The exact V5
consumer inventory needs 304 base-field challenge cells: six AIR-quotient,
twelve independent batch, twelve accepted OOD, twelve DEEP, six fold and 256
query-index cells. V6 now structurally exposes all 304. The twelve accepted-OOD
cells are produced by an executable selector AIR: two disjoint two-candidate
groups, inverse-backed extension-coordinate nonzero checks, `z2 != z1`
exclusion, first-valid selection and explicit accepted `z1`/`z2` state cells.
Selector, inverse and accepted-output mutations reject. Direct semantic aliases
remain 0 of 304: V5 still consumes SHA256d-derived constants while V6 produces
algebraic-transcript draws. Coincidental equal values are deliberately not
counted.

A V1 bridge now materializes every one of those 304 V5 consumer cells at a
verifier-recomputed SHA transcript public boundary. The proof is a separate
512-row, eight-column AIR with one time-multiplexed proof-owned value column
and seven fixed schedule/value columns; the honest quotient verifies, a wrong
boundary rejects, and a mutation in every challenge family rejects. This gives
complete semantic V5 consumer-cell mapping with only 4,096 trace cells, but it
does not claim equality to V6's algebraic draws. By itself this materialization
does not arithmetize SHA inside the recursive parent.

A cycle-free split-transcript bridge now also places that canonical inventory
on eight time-multiplexed proof-owned export columns which are the literal V6
`ExternalSource` columns. Each export is equality-constrained to its exact V5
equation-consumer value and absorbed in an ordered, typed, domain-separated V6
frame. This closes **304/304 committed same-trace feedback aliases** in a
1,024-row, 713-column composition (730,112 cells), and exhaustive synchronized
V6-source/export mutations reject for all 304 cells. This metric must not be
misreported as Fiat-Shamir derivation: **algebraic V6 challenge derivation
remains 0/304**. A same-parent producer now proves the complete three-block
SHA256d `AirChallengeDigest` computation in the four-lane packed fixed-program
provenance AIR, bit-decomposes the six consumed digest words, proves the
byte-order/Fp3 conversion and drives both lanes' AIR-quotient cells. Thus
**recursive SHA derivation is 6/304**. The other 298 cells still require the
uniform-Fp3 rejection and query-index samplers. The split removes a
combinational transcript cycle and fixes those samplers' eventual output bus,
but authority remains false until the remaining producers are recursively
consumed.

The next-tier planner now reconstructs the exact accepted V5 transcript rather
than extrapolating from a declared hash budget. Across the two lanes it replays
both lane-seed preimages, all 18 bounded uniform-Fp3 draws and all 256 query
preimages in protocol order, and checks every selected value/index against the
accepted proof. The exact toy-production-shape inventory is:

```text
lane-seed SHA256d calls:                              2
bounded uniform-Fp3 draws / SHA256d calls:      18 / 36
lane-seed + uniform compression blocks:             218
uniform-Fp3 consumer cells:                           42
query-index SHA256d calls / compression blocks: 256 / 2,304
query-index consumer cells:                          256
optimistic raw provenance-block capacity / parent:   90
minimum uniform / query parent shards:            3 / 26
typed uniform shard blocks:                    63 / 69 / 86
typed uniform shard consumer cells:             12 / 15 / 15
typed query shards:                 25 × (90 blocks, 10 cells)
query tail shard:                              54 blocks, 6 cells
```

The 90-block capacity deliberately excludes rejection, selection, chain-link
and recursive child-consumption columns, so 3/26 are lower bounds rather than
deployable shard counts. This executable inventory does not raise the 6/304
counter: a cell is only counted after the complete compression chain,
little-endian word parsing, bounded rejection/selection and output equality
are constrained and the shard proof is consumed by the normalized parent.
The three typed loads preserve lane-seed, individual batch, complete
four-candidate OOD-selector, paired-DEEP and fold-draw boundaries. Counters
are now reported separately: six cells are recursively consumed by the current
same-parent construction, zero additional cells merely have detached child
proof ownership, and the uniform output-root equality remains pending.
Every query call is exactly nine compression blocks at this shape, so canonical
query-order packing reaches the 26-shard lower bound exactly. Its output-root
equality and normalized consumption remain pending too.

The first typed uniform shard now has an executable vertical SHA provenance
AIR. It schedules the exact 63 lane-0 seed/batch/OOD compression blocks plus
one canonical padding instance over 65,536 rows and 174 columns. Immutable
instance-id, phase and active columns repeat the 1,024-row SHA program;
internal SSA addresses are injectively namespaced by instance before entering
one global pair of post-commit LogUp lanes. The honest 63-block witness passed
all 488 constraints, and a cross-instance substitution rejected. Construction
took roughly 5.7 minutes and 2.76 GiB RSS on this machine before quotient
proving, so this establishes an executable width-bounded construction, not a
production prover result. The generic vertical quotient prove/verify API is
implemented, but the 12-cell bounded rejection/selection conversion and its
output-root equality into the 304-cell bus remain pending; consequently those
12 cells are not yet counted as proof-owned or recursively consumed.

A subsequent combined execution adds the bounded word decomposition,
Goldilocks rejection test, canonical selector schedule and 12 output
equalities in the same 65,536-row statement (348 columns, 691 constraints).
It remains boundary-pinned evidence, not recursive proof ownership: the
current fixed-program adapter exposes final SHA words as preprocessing and the
selector schedule is verifier preprocessing. Recursive promotion requires
witness-owned SHA chaining/final buses and an algebraic prefix-count selector.
The proof-owned counter therefore remains zero for these 12 cells.

A minimal two-compression SHA256d call now also executes in a witness-owned
vertical boundary mode. Its 2,048-row AIR has 464 columns and 782 constraints:
public masks pin the 32-byte preimage while the eight first-pass digest words
remain private and are linked to every second-pass use by two domain-separated
LogUp lanes keyed by unique link IDs. The eight final words are direct witness
exports, each reconstructed from 32 boolean columns, so the same AIR exposes a
canonical 256-bit digest interface without adding source-link fan-out.
The public statement is unchanged by mutations to private intermediate/final
words and changes under a public-preimage mutation. Linked-consumer,
intermediate-source, final-export, non-boolean-bit and fully consistent
alternate-digest substitutions all reject; the focused test passes. This is a
complete local SHA256d chain and digest-bit boundary, not
yet the 63-compression sampler shard or normalized-parent consumption, so it
does not promote any of the 304 transcript-cell completeness counters.

The smallest real uniform-transcript prefix now executes in that witness-owned
mode as well. Lane 0's lane-seed SHA256d and the two SHA256d calls for its
first batch-coefficient draw occupy 13 semantic compression instances (16
scheduled), 16,384 rows, 976 columns and 1,892 constraints. Eighty unique-ID
word links close every intra-pass state and first-pass-to-second-pass digest
boundary. Because the lane-seed digest begins at byte offset 34 in each draw
preimage, 18 partially overlapping message words are instead reconstructed
bit-for-bit from the lane-seed exports plus their public bytes. The sampler
then derives all eight 64-bit candidates from the two final SHA digests,
proves the Goldilocks `< p` predicate, advances a nine-state one-hot accepted
counter and selects the first three accepted words. Those three exports are
equality-bound to the exact lane-0/item-0 normalized-V5 batch-coefficient
consumer cells. The focused execution passes with zero violations;
candidate/digest, accepted-count, output/V5, SHA-chain and
unaligned-message substitutions reject.

This 976-column prefix is below the 16,384 recursive width cap. The old
row-wise quotient path did complete a diagnostic proof:

```text
proof bytes:                       12,085,856
prover:                         4,086,370.030 ms
verifier:                             809.219 ms
wall / user / sys:            4,189.74 / 4,178.47 / 9.08 s
maximum RSS:                    8,219,672,576 B
peak memory footprint:          8,076,761,664 B
Boost assertions:                         27 / 27
proof-owned exports:                       3
recursively consumed exports:              0
```

That proof uses the sampled `R_T`-to-final-row-root bridge rejected below. It
is therefore verifier/prover performance evidence only, not a sound authority
proof. It also misses the prover target by orders of magnitude even though the
native verifier narrowly fits 900 ms. The proof-owned and recursively consumed
authority counters remain zero.

The verifier-boundary audit found an additional soundness requirement. The
witness-owned SHA AIR derives its internal-SSA and boundary-link LogUp
challenges only after committing challenge-independent base/metadata columns.
A naive receipt which commits that R0 oracle and merely compares it with a
second row commitment at the final proof's sampled query sites is insufficient:
the prover can alter one unsampled R0 leaf, change the derived challenge
globally, and evade the sampled equality with high probability. The
experimental sampled-cross-opening receipt is therefore explicitly fail-closed
with `global_oracle_equality_unproved;multi_root_fri_required`; it cannot raise
any completeness counter. The same audit applies to the older row-wise
`trace_commit` versus final trace-plus-quotient root bridge: because it is also
bound only at sampled equality sites, its completed timings remain useful
performance diagnostics but it is not an authority proof.

The replacement is specified as an exact multi-segment RAP schedule. R0
contains every challenge-independent SHA base/metadata column and is absorbed
first. SHA LogUp challenges derived from R0 construct Rdep, which contains
every remaining trace column exactly once. After absorbing Rdep, the AIR
constraint-combination challenge constructs Rq. The final independent
column-RLC, dual-OOD/DEEP, fold and query transcript absorbs ordered
`R0/Rdep/Rq` roots and opens every group at every shared current/next query
site. No trace column is recommitted and no sampled host equality is needed.
This also removes the current row-wise prover's duplicate commitment work
(W trace columns for `trace_commit`, then W+1 trace-plus-quotient columns):
the RAP backend hashes W trace columns plus the quotient exactly once, at the
cost of three authentication paths per shared query.
The first-uniform plan partitions all 976 trace columns once across R0/Rdep
and the virtual quotient once in Rq. The exact current split is
`R0=172`, `Rdep=804`, `Rq=1`; group reorder, root mutation,
duplicate/missing column, transcript-stage reorder and unearned-completion
mutations reject. An additive multi-row Q192 FRI backend is now implemented
with three ordered row roots, one degree-shifted independent-column RLC, two
OOD points, one DEEP/fold proof and shared openings of every group. Its V2
transcript fixes a critical V1 ordering bug: all individual OOD claims are
absorbed before the independent batching vector is drawn. Otherwise a prover
who already knew that vector could add nonzero kernel deltas to two or more
individual claims while preserving the aggregate evaluations consumed by
DEEP. The executable audit constructs that old-schedule kernel and requires
the V2 post-claim challenge to change and reject it. Retained row-tree cache
openings are also verified before an `ok=true` prover result, so corrupt
prover-local internal levels fail closed.

The AIR quotient/current-next wrapper now executes on a bounded
challenge-dependent relation. It validates the retained R0 against its exact
column schedule, commits the strict Rdep complement, derives a separate
uniform AIR constraint-mix challenge from ordered R0/Rdep, constructs Rq, then
derives the post-all-roots V2 FRI seed. Every query reconstructs original AIR
column order from the two current group rows, authenticates both corresponding
next rows at `i + |LDE|/N`, and checks `C(y)=Z_H(y)Q(y)`. Immutable group
widths/degree bounds, preprocessed OOD mapping and the distinction between AIR
lambda and PCS batching coefficients are enforced. Root, width, next-row,
column-order, wrong-CS and lambda-swap mutations reject. A changed Rdep can
recompute all later commitments/transcript material and emit a forced
proximity proof, but still fails the quotient identity. The backend regression
passes 41/41 assertions; the split-RAP wrapper passes 20/20.

The application-specific public-CS reconstruction, canonical proof codec,
recursive consumer and global theorem are still absent. Accordingly, this
bounded proof round trip does not promote proof-owned or recursive endpoint
counters; they remain 0/0, and global soundness remains unclaimed.

The concrete first-uniform product is now attached to that Split-RAP API in
source. Its prover reuses the exact retained 172-column R0 and labels exactly
the three first-draw V5 exports as proof-owned; recursive consumption remains
zero and the full-304 flag is fixed false. Its verifier regenerates the
canonical prefix from child public inputs, redacts every private external and
final SHA word, independently rebuilds the challenge-dependent SHA core from
program, public masks, links, seed and the proof's canonical R0, checks that
public core against the sampler-extended CS, then verifies Split-RAP and the
three export values. The former opt-in sampled-prefix prover call has been
replaced by this product. This integration was intentionally not compiled or
executed while the unrelated bounded 23-family aggregate occupied the host;
do not count it as a completed round trip until that focused build/test runs.
Version 1 also materializes the bounded canonical prefix during verification;
a descriptor-only public sampler-CS builder is the next verifier-efficiency
cut, without changing proof semantics.

The same construction now has a canonical full-transcript execution plan,
without pretending that unexecuted proofs exist. It inventories 296 SHA256d
calls: two already-closed Air-quotient calls, two lane-seed dependencies, 36
uniform-draw digest calls and 256 query-index calls. Every one of the 304
normalized-V5 consumer cells has an explicit one-to-four-call source mapping.
The schedule is 30 typed parent shards (one Air, three uniform and 26 query)
over 57 dependency-preserving vertical leaves capped at 63 compression
instances. Uniform parent loads remain 63/69/86 blocks for 12/15/15 cells;
query parents remain 25 × (90 blocks, 10 cells) plus (54 blocks, 6 cells).

Lane-seed reuse is modeled as actual fan-out rather than repeated source
overwrites: each of the 16 lane/word sources has one unique link ID and source
multiplicity balancing 146 uniform/query target calls. The generic
witness-boundary link implementation now accepts an explicit ID, aggregates
multiplicity for repeated targets of the same source, and rejects source-ID or
target collisions. Every parent has a public-only schedule statement and an
empty typed proof container ready for vertical child proofs and aggregation.
Coverage, remapping, link-collision, shard-reordering and unearned-proof
mutations are tested. Because those 57 child proofs have not executed, the
full-plan proof-owned and recursively consumed counters remain zero.

V6 also needs a canonical proof codec, a practical streaming prover and a
soundness analysis for its new algebraic Fiat-Shamir/commitment domains. The
correctness-oriented row-root combined quotient did complete:

```text
rows / columns / constraints:       128 / 2,287 / 2,228
proof size:                                  22,762,820 B
prover / verifier:                         247.378 s / 1.626 s
maximum RSS:                              1,113,194,496 B
```

It therefore misses both the 16 MiB proof-size screen and the 900 ms verifier
goal. This is execution/correctness evidence, not production performance
evidence.

The scheduler-to-proof consumption seam has also advanced from an opaque
callback receipt to a bounded artifact that carries four real dual-Q128/V5
child proofs, re-verifies them, replays their transcripts, verifies a
seed-bound normalized parent, verifies a V6 binding quotient and derives the
canonical scheduler receipt from those proof commitments. Valid-but-different
child proofs, parent proofs, work ranges, roles, levels, roots, transcripts,
V6 openings and receipts are rejected. The toy integration measured:

```text
children:                                      4
normalized parent:                128 rows x 8 columns
normalized parent constraints:                  0
parent proof bytes:                      1,184,124
V6 binding:                      64 rows x 675 columns
V6 binding constraints:                         672
V6 proof bytes:                          3,995,644
parent/V6 prove:                    0.366 s / 9.254 s
combined verification:                       0.644 s
```

This establishes proof-aware receipt plumbing, not recursive relation
authority: the test child relation and normalized parent are deliberately
constraint-free/binding-only. The V5-to-V6 master-root and full-transcript
buses now execute separately; complete production V_CS families and
Fiat-Shamir challenge feedback remain open.

The corrected recursive fixed-point screen now charges the current full-row,
next full-row and trace-root openings separately, every fold opening, DEEP,
per-point quotient, boundary/transition and Fiat-Shamir rows. It also charges
all four physical verifier lanes required by binary dual-Q128/V5 aggregation:
two logical children times two independent repetitions. Only fully-quadratic
four-lane parallel composition closes the recursive cap, at 2,184 columns:

```text
level         active rows   trace rows   parent LDE
leaf               70,186      131,072        2^22
level 1           462,988      524,288        2^24
level 2           476,558      524,288        2^24
```

The one- and two-lane screens both reach a `2^20` parent trace and `2^25`
LDE at level one, beyond the current backend LDE cap. The earlier 1,092-column
screen counted only two of the four physical V5 lanes and is superseded.

A real-child proof-derived hash-opening AIR now executes current, next, trace
and every fold Merkle family in 8,192 rows, 522 columns and 525 quadratic
constraints. A two-lane rational-identity memory bus then joins all 192
authenticated fold even/odd producer values to the scalar fold consumers and
executes the fold equation in 545 columns and 542 constraints. Operand,
address and producer-detachment attacks reject. This is a genuine recursive
subconstruction, but not the complete fixed point: DEEP, per-point,
transition/boundary and Fiat-Shamir scalar values are not yet carried by the
same bus.

### 10.9 Complete endpoint memory and flat semantic-proof V1

The endpoint work now distinguishes three facts that earlier audits conflated:

1. a canonical endpoint exists;
2. a proof owns and authenticates the endpoint's complete value vector;
3. the proof establishes the registered computation and all producer-to-
   consumer root links.

For all 26 episode endpoints, an executable memory AIR commits the exact
`(endpoint, role, address, value)` schedule. Verifier-preprocessed active,
remaining, endpoint, role and address columns prevent omission, reorder and
relabeling. The committed producer VALUE root is pinned exactly and an
in-proof `VALUE = EXPORT` identity holds on every row. The V1 flat bundle
partitions large vectors into the unique contiguous `2^20`-row schedule,
requires the caller's expected root for every shard, verifies every quotient
proof and commits their order.

The coupled side applies a direct product to every available local relation
AIR and exports every registered source column, rather than one representative
scalar. It currently supplies proof-owned full-vector memory plus exact flat
all-instance execution for 20 of 26 coupled endpoints. The six remaining
relation-memory engines are bank root, GEMM signed range, barrier input,
barrier output, digest bank/barrier input and digest public value.

Hash-heavy endpoints use a complete fixed-program provenance AIR rather than
native verifier replay. Canonical manifests enumerate every SHA-256
compression or ChaCha20 block boundary. A flat proof bundle executes one
internal-SSA provenance quotient per boundary, in order, and binds the
canonical external/final boundary vector into endpoint memory. The generic
round trip passed for a SHA compression; proof generation took about 19.5
seconds in the test build. Episode and coupled composition tests also passed.
Barrier and coupled-digest acceptance use structural-only typed validation;
they do not call the native SHA builders.

The first memory-layer audit exposed two complete local episode relations, but
neither has transitive producer provenance:

```text
registered endpoints:                             52 / 52
episode canonical memory/opening closure:          26 / 26
episode local semantic kernels:                    14 / 26
episode locally complete relations:                  2 / 26
episode transitive semantic endpoints:               0 / 26
coupled relation-memory + flat-instance engines:    20 / 26
coupled strictly complete semantic endpoints:        0 / 26
recursively consumed semantic endpoints:             0 / 52
```

The two local episode relations are the all-cell GEMM signed-range relation and
a new statement-pinned 256-bit `episode_digest <= target` borrow AIR. Neither
establishes how its manifest/public digest input was produced. The hash, GEMM,
Extract, tile-tree, barrier and digest proof engines are not promoted merely
because their local proof passes: their canonical inter-role
producer-to-consumer equality graph is still incomplete.

### 10.10 Semantic root-chain and missing-relation wave

The follow-on construction added three executable proof products without
relaxing the preceding definition of semantic completion.

First, `EpisodeWiringCopy` now executes every non-transposed A/B edge in the
verifier-derived episode layout. Each deterministic shard proves the wiring
equality, both proof-owned memory sides, exact proof-column-to-memory-root
aliases and ordered equality to the operand root registered by the layer
manifest. This closes the complete local relation, but not producer
provenance: the registered operand root still needs equality to the executed
producer/root graph. The consolidated audit therefore does not count this
endpoint as semantically complete.

Second, typed root-chain products now execute the episode digest hash, every
coupled barrier hash, ordered barrier-output-to-digest-input equality, the
coupled digest hash and equality to the outer statement. Acceptance uses the
fixed-program provenance AIRs; structural adapters do not natively recompute
SHA. The complete episode test executed three SHA provenance children in about
27 seconds, and the complete coupled test executed five in about 59 seconds.
These establish local relations at episode digest value, coupled barrier
hash/output, and coupled digest input/hash/value, while leaving tile-stream,
Extract-output and bank producer links explicit.

The round-root producer edge is now executable as a separate fail-closed
product. It enforces the verifier-supplied round count/order, executes every
per-round TileTree fixed-program proof and semantic-memory binding, requires
each proved tree root to equal the matching episode-digest round root, and
verifies the identical ordered byte vector through endpoint 23. Omission,
reorder, root substitution and proof-query mutations reject. This closes the
immediate endpoint 22→23 edge, but transitive provenance still waits on the
Extract-output→tile-stream relation and recursive consumption.

Third, the six previously missing coupled local engines now have
verifier-resolved shape APIs and reject a prover-selected substitute shape.
Bounded shapes execute all six exact schedules; production executes five. The
flat bank-root V1 is deliberately not called production-exact: its SHA manifest
has a 16 MiB preimage cap while the current production bank is roughly 96 GiB.
A streaming recursively aggregated SHA construction is required there. The
full range-plus-digest proof test passed in about 183 seconds.

The resulting fail-closed status is:

```text
registered endpoints:                                52 / 52
authenticated canonical-memory endpoints:            >=46 / 52
locally complete relations, bounded audit shape:       52 / 52
locally complete relations, production shape:          19 / 52
producer-provenance-complete endpoints:                 2 / 52
strict semantic endpoints (both conditions):            2 / 52
recursively consumed semantic endpoints:                0 / 52
complete recursive roles:                               0 / 14
```

The distinction is intentional. A proof that hashes, ranges or copies an
arbitrary committed vector is useful local machinery, but it is not yet a
proof that the vector came from the registered episode computation.

The strict public endpoints are `EpisodeBuilderParams` and
`EpisodeDigestHeaderTarget`. The verifier regenerates
all nine parameter cells from consensus, recomputes their exact ordered column
root, and executes the statement-bound semantic-memory quotient. Since its
producer is verifier-owned public data rather than another relation, it has no
open computation ancestor. The header/target product proves the exact
`nBits`/header-commitment/target vector and all 32 compact-target projection
bytes. The round-seed product executes every consensus-correct single-SHA-256
derivation and endpoint-2 memory equality, but correctly remains transitive-
incomplete because later seeds depend on open round-root ancestry.

The new endpoint-47 product covers every ordered
signed Extract-output byte and every typed barrier input and executes the flat
Extract/barrier proof product; it is locally complete, but remains transitive-
incomplete while endpoint 46's producer graph is open. Its flat all-shard
bundle does not scale to the production shape yet, so the production local
count remains one below the bounded audit. The endpoint 19--22
product executes every streamed Extract shard, exact signed-byte slice,
semantic-memory opening and TileTree leaf/internal/root hash proof; its
upstream GEMM, ChaCha, scale and nonstreamed Extract ancestors remain open.

`EpisodeBuilderOperandXof` now proves the exact unique consensus operand
schedule, tagged single-SHA seed derivations, both SHA-256 counter-XOF domains
and ordered output memory. The exact bounded Extract product proves every
input/mix AIR, sampler walk, ChaCha consumption, scale SHA, dequant output
root, and equality into endpoint 19. These six additional local endpoints are
not yet counted at production: the counter-XOF adapter retains a 16 MiB flat
output cap and the all-tile Extract vector needs recursive streaming.

The bounded GEMM product closes endpoints 5--8 locally. It enforces the full
immutable Lambda schedule, binds exact A/B/Y/residual/Extract-input openings,
and executes an 11-column Fp3 dot-product AIR for every 32-output tile. The AIR
checks every signed product, the accumulator chain, terminal Y and
`ExtractInput = Y + residual`; omission, reordering, root substitution and sum
tampering reject. This is still a flat V1 product: external builder/dequant
producer roots, production streaming and recursive consumption remain open,
so the strict semantic and production counts do not increase.

`EpisodeBuilderTrace` is now locally closed at bounded shape. It composes the
exact endpoint 1--3 products, expands every canonical Lambda leaf, executes
quadratic Fp3 dequant relations and binds each canonical leaf root to the GEMM
and wiring manifests plus endpoint-4 semantic memory. Omission, reordering,
source/root and manifest substitutions reject. Its producer provenance remains
open because endpoints 2--3 are not transitively complete, and production
still needs streamed XOF/dequant construction.

The coupled GEMM product likewise closes endpoints 30--32 at bounded shape.
Its schedule is regenerated from the public sigma and validated coupled shape;
every scheduled A/B/Y opening and ordered endpoint root is bound, and every
32-output tile executes a nine-column Fp3 product/accumulator AIR. The minimum
valid complete schedule executes four GEMMs and four quotient proofs in about
3.79 seconds, and omission, reorder, schedule-ID, opening, proof-root and bad
sum attacks reject. Bank-page/prior-state producer links, production streaming
and recursive consumption remain explicit gaps.

The bounded bank seed/page product closes endpoints 27--28 and equality-links
its page-major byte tree to endpoint 29's exact source root. It executes the
tagged root/page seed SHA proofs, all mantissa and scale counter-XOF proofs,
and a six-column Fp3 dequant AIR for every page byte. The one-page, 1,024-byte
focused round trip passed with all omission/index/byte/XOF/root/header attacks
rejected, but took 1,094.19 seconds and just over 2.0 GB RSS. Inputs exceeding
the flat 16 MiB cap reject before allocation. This is correctness-complete
bounded V1 machinery and direct evidence that the flat proof representation
cannot be the production encoding.

The endpoint 16--18 wiring product executes every verifier-derived transpose,
residual and round-order edge. Transpose uses dual indexed grand products
rather than an invalid direct-copy assumption; residual proves
`Y + residual = ExtractInput`, and round order binds every prior
Extract-output to its later A-input. All sides are proof-owned semantic
memories, and omission, reorder, transcript, permutation-root, memory-root and
source-substitution attacks reject. V1 is bounded to 2^20 values per flat
edge; producer ancestry, segmentation and recursion remain open.

The coupled exchange/permutation product closes endpoints 34--38 at bounded
shape. It executes fixed-copy segments, every material-round seed SHA256d and
counter-XOF child, XOR/index scheduling and the public balanced permutation as
proof-owned equality/indexed-permutation AIRs. The four-barrier exact optional
round trip executed 36 fixed-program SHA children and all relation AIRs in
1,723.18 seconds; the standard omission/reorder/value/root suite also passes.
The flat vector representation is intentionally not promoted at production.

The coupled mix product closes endpoints 39--41 at bounded shape. Its 293
columns prove the immutable two-pattern butterfly schedule, all 320
minimum-shape operations, complete 64-bit limb ranges, carry/borrow,
sum/difference, signed-overflow exclusion and exact stage-to-stage state
equality. The full SHA-plus-arithmetic proof passed in 384.96 seconds at about
1.95 GiB maximum RSS, and the final state agrees with the consensus tail
transform after the public permutation is inverted.

The coupled Extract product supplies the final five bounded local relations,
endpoints 42--46. It uses the exact barrier-major all-tile schedule, the
registered 256-row sampler domain, int64 mix/source aliases, exact ChaCha
consumption and scale-SHA manifests, proof-owned output memory and the signed
byte equality into endpoint 47. The final frozen-tree all-child Prove/Verify
passed in 1,042.43 seconds (1,038.82 user seconds) with maximum RSS
2,290,417,664 bytes and no swaps. The structural/adversarial suite also passes
5/5, including verifier replay of sampler challenges and malformed-root
rejection. Post-mix producer equality, streaming and recursive consumption
remain false.

Endpoint 50 is now correctly counted as locally complete: the exact ordered
bank-plus-barrier digest-input vector and its hash-boundary equality execute.
Separate composed verifiers execute either the bounded flat or expansive
streaming endpoint-29 bank proof before accepting the bank root, and the
bounded path value-compares every endpoint-28 page byte to endpoint 29's SHA
preimage after the exact domain tag. This does not close endpoint-28 or
endpoint-47 ancestry. At this checkpoint the machine-checked provenance graph
enumerated all 52 ordered nodes and 81 typed producer edges: 61 had a bounded
value-equality composition, 13 had a production-capable composition, and zero
were consumed by the normalized recursive verifier.

The bounded episode producer-link verifier closes another 14 graph edges. It
executes the builder-trace/manifest binding, recomputes every GEMM A/B/Y vector
root, checks every ordered Extract input cell against GEMM Y plus the selected
residual, verifies every memory-copy opening, and verifies the endpoint 16--18
wiring product. Cross-product substitutions of the builder trace, GEMM values,
Extract inputs, copy-memory commitment, or wiring parent commitment reject.
This raised the graph to 75 bounded value-equality edges and six open edges.
This is producer-link closure only: the local builder, GEMM, and Extract proof
products must still be verified separately, and no normalized recursive
verifier consumes these links.

The bounded coupled-chain product now composes five proof families and closes
seven external producer/consumer links using their actual proof-owned vectors:
bank pages to GEMM B (28 -> 31), prior-barrier Extract output to every later
GEMM A lobe/page-slot (46 -> 30), GEMM Y to fixed-exchange input (32 -> 34),
permutation output to mix input (38 -> 39), mix output to material-exchange
round zero (41 -> 34), zero-round mix output to Extract input (41 -> 42), and
the final material-exchange output to Extract input (36 -> 42). Consecutive
material rounds are also equality-chained internally. Each link has an exact
domain-separated vector commitment, and the combined verifier executes every
producer proof before applying equality. Independently rebuilt, internally
valid mutations at the consumer boundaries reject. The old 32 -> 42 edge was
removed because GEMM Y is not directly equal to the post-permutation/post-mix
Extract input. Together with the episode producer links this raises the graph
to 78 bounded value-equality edges and leaves three open edges. Production
streaming and normalized recursive consumption remain false for these links.

The episode Extract derivation composer closes two more edges. It verifies the
complete endpoint-2 seed/round-root proof, binds the supplied header and sigma,
derives the canonical per-layer provenance with
`RCGkrEpisodeLayerProvenance`, and requires every manifest Extract PRF to match.
It then runs the existing all-tile Extract verifier, whose scale-SHA manifests
and fixed-program proofs bind that same PRF together with the exact row and
block. Thus the correct scale ancestry is endpoint 12 -> 13, not the earlier
direct endpoint 1 -> 13 placeholder. Header, round-root proof, and PRF
substitutions reject. The current graph is 80 of 81 bounded value-equality
edges, 13 production-capable edges, and zero normalized-recursive edges. The
only remaining local provenance cut is the public header/sigma to initial
coupled lobe state (25 -> 30).

The coupled initial-state product closes that final local cut. For every lobe
it proves the exact transcript-version lobe-seed SHA preimage
`tag || sigma || LE32(lobe)`, domain-separated mantissa and scale counter-XOF
programs, the complete `W x W` dequantization relation, and a commitment to
the active first `M` rows. The cross-product join checks those rows against
every barrier-zero GEMM-A page-slot opening. Seed-preimage, XOF-output,
dequantized-cell, endpoint-root, and independently rebuilt GEMM-A mutations
reject. The machine-checked 52-node provenance graph therefore has all 81 of
81 registered producer edges backed by an executable bounded value-equality
construction, 13 backed by a production-capable composition, and zero at
normalized-recursive consumption. This is bounded immediate-edge construction
closure, not strict transitive semantic closure: the constructions are not yet
demonstrated in one accepting unified run, and the production streaming and
recursive fixed-point gates remain incomplete.

A fail-closed bounded composition entry point now sequences the 23 typed proof
families instead of accepting an opaque closure receipt. During that work two
previously overstated graph edges were found: the episode and coupled
signed-range verifiers proved range for a proof-owned `VALUE` column, but did
not require that column to be the already proved GEMM `Y` vector. Exact
proof-root joins now recompute each canonical range-shard `VALUE` root from the
corresponding proof-owned GEMM output slice. Episode and coupled positive
value-root fixtures pass; GEMM-value, range-root and omission mutations reject.
The aggregate marks an endpoint or edge executed only after its typed verifier
or exact join succeeds, then requires the executed inventory to equal all 52
endpoints and all 81 graph edges. An empty aggregate reaches the public
header/sigma/`nBits` binding and then fails at the first missing typed proof;
static flags cannot make it accept.

The new entry point is not yet counted as strict 52-of-52 evidence because a
single positive aggregate fixture has not been generated. Such a run must
rebuild every expensive child under one consistent `Composed` statement,
including the roughly 17-minute coupled Extract proof plus the bank,
exchange/permutation, mix, initial-state and complete episode families. Until
that positive round trip exists, the consolidated strict count remains 2/52,
recursive consumption remains 0/52, and every authority flag remains false.
The aggregate now has a bounded durable identity-binding seam. A canonical,
fixed-order manifest commits the identities of all 23 typed child families;
the manifest is framed into the `CompositionLink` section, its root replaces
that role's outer commitment, and the existing Stage-3 transcript absorbs both
the section bytes and root. Reordering, sidecar substitution, section/root
mutation, transcript mutation, and duplicate attachment reject. This does not
serialize the heterogeneous child proof objects themselves: the AIR, hash
boundary, memory, tree, and product bundles still need canonical codecs.
Consequently the durable-serialization capability flag remains false.

A fail-closed positive-fixture prover plan now derives the exact schedules from
the canonical public constructors and inventories all 23 families. For the
smallest current bounded fixture it reports four episode layers, 128
GEMM/Extract tiles, 64 streamed tiles, four episode range shards, and a coupled
shape with one bank page, one lobe, four GEMMs, one range shard, four exchange
and permutation stages, four mix/Extract tiles, and four root barriers. The
next prover wave added one-shard-at-a-time honest episode and coupled
signed-range orchestration from the already proof-owned GEMM Y vectors, a
generic exact all-boundary fixed-program prover, bounded episode and coupled
digest-root-chain provers, the complete coupled bank-root SHA prover, and the
all-round tile-tree producer prover. Each helper self-verifies the constructed
product; the signed-range default tests additionally reject mutations of the
source GEMM values. The final three product-wide honest reference
orchestrators now execute every episode GEMM dot AIR and wiring-copy child,
every all-tile Extract sampler/mix/ChaCha/scale child, and every streamed
tile-tree child. The plan therefore reports all 23 families available and
sets `positive_fixture_buildable` true. This means the typed family inventory
has an honest construction path; it does not by itself claim that all 23 have
yet accepted together under one statement-consistent aggregate. These
orchestration helpers are bounded reference provers, not normalized production
streaming or recursive consumption, so they do not raise the production-local,
strict-transitive, or recursive counts.

The corresponding regressions are executable rather than audit-only.
`matmul_v4_rc_stage3_episode_builder_trace_tests` builds a real toy
builder/XOF trace, all 14 joins, every copy proof, and the wiring product; it
rejects substituted trace roots, GEMM values, Extract inputs, copy-memory
commitments, and wiring commitments. The
`matmul_v4_rc_stage3_episode_builder_seed_chain_tests` derivation case builds
and verifies a real fixed-program round-seed SHA proof plus the round-root
vector proof, accepts every canonically derived per-layer PRF, and rejects
manifest PRF, serialized-header, and round-root-proof mutations.
`matmul_v4_rc_stage3_episode_extract_product_tests` checks the exact all-tile
PRF/row/block scale-manifest schedule and rejects scale substitution; the
combined derivation verifier additionally calls the existing full Extract
verifier, so successful acceptance requires every scale fixed-program proof,
not native scale replay.

The final focused regression after the bounded binding/prover-plan wave passed
15/15 cases and 2,863/2,863 assertions. This includes 52/52 assertions for the
bounded aggregate/plan, 26/26 for durable identity binding, 184/184 for the
52-node/81-edge provenance graph, 266/266 for strict semantic status, and
2,335/2,335 for the V5/V6 transcript bus. The latter maps all 48 proof payload
cells and materializes all 304 SHA-derived V5 consumer cells. A subsequent
focused wave equality-aliases 304/304 of those cells through the cycle-free V6
committed-feedback bus. Algebraic-V6 challenge derivation remains 0/304, while
the same-parent packed SHA producer raises recursive SHA derivation to 6/304.

Production `CoupledBankRoot` now has a manifest-derived streaming schedule,
64-byte source openings, fixed-program leaf verification, exact arity-four
interval/chaining AIR proofs, an executable full child-tree verifier and the
second SHA pass. This makes endpoint 29 locally executable at production
shape, removing the 16 MiB flat-manifest gap. It is not succinct: the
production expansion carries 1,610,612,737 leaf proofs and 536,870,927 parent
proofs (2,147,483,664 total), and endpoint 28 still must export the identical
bank-page byte root. At the measured roughly 500 ms leaf and 67 ms parent
verification rates, serial expanded verification is about 26.66 CPU-years.
The normalized recursive fixed point therefore remains the authority blocker.
There is now a descendant-free normalized V5 step: two bounded levels prove
and verify with a constant 128-row, two-column parent artifact in about 188 ms
proving per level, and child-pin/parent/seed mutations reject. The full-family
mirror executes row Merkle, fold, dual-OOD DEEP, quotient/per-point, next-row
and trace-root constraints with zero witness violations. A live heterogeneous
binary construction now also executes both dual-Q128 children with independent
seeds and equality-joins both lanes, contiguous interval endpoints and all
eight SHA chaining words in the same trace. That join is correct but not
yet proof-emittable: the real W=76 child relation produces 70,974 columns and
67,471 constraints at 128 rows. That trace now fits the raised 1,048,576-column
backend cap, but no parent proof artifact is emitted or verified and the
resource/performance and equivalence campaigns remain open. Row-time
multiplexing and the narrow fixed-point work below remain relevant to practical
proving. SHA Fiat--Shamir/master-binding also remains outside the AIR, so this
step does not change the recursive or authority counts.

That vertical experiment now executes the expensive hash/fold families for all
four ordered lanes through one reusable chip. It schedules 131,072 rows while
holding physical width to 526 hash columns or 575 columns including the
fold-scalar dual-LogUp bus. A separate four-row, 40-column terminal AIR consumes
proof-derived dual-OOD evaluations and enforces lane equality, interval
contiguity, all eight SHA chaining words and the 18-word parent export with
zero violations. The selected complete-parent planner is 2,184 columns, with
1,140 columns reserved for unexecuted families. This demonstrates that
vertical reuse solves the width problem for the landed families, but it is
still two proof sites rather than one emitted recursive parent and therefore
does not change authority.

The next vertical layer now executes independent-batching dual-OOD, every fold
equation/chain/final rule, and the child per-point quotient/transition
relations for all four lanes in a 512-row, 1,044-column scalar trace with 467
quadratic constraints and zero violations. The dynamic eight-column V5 SHA boundary
materializes 1,520 consumer cells in 2,048 rows with zero violations. The
combined schedule has 70,128 active rows inside a 131,072-row global trace and
keeps 1,140 columns spare under the 2,184-column planner.

Phase unification now packs two 575-column hash/fold lanes horizontally in each
of two waves and closes as one constraint system: 65,536 rows, 1,854 columns,
2,760 constraints, maximum degree four and zero witness violations. The
layout uses 1,150 reusable phase columns, 662 dedicated public fixed columns,
24 scheduler selectors and 18 carried output words. Quadratic auxiliaries split
the DEEP and per-point products, and a four-column selected-route auxiliary
removes the cubic Merkle-routing residual. Every phase boundary and
scalar/terminal output alias remains same-trace constrained, and the parent
seed binds the child proofs, SHA public boundary, dimensions and output.

The exact quotient length is 196,605, rounded to 262,144 coefficients and a
4,194,304-point LDE. Dense materialization would still require
7,780,433,920 extension-field cells, so the unchanged `2^28` screen correctly
prevents an unsafe prover launch. The executable streaming planner selects
4,096-row tiles and five read/write passes. It estimates 15,212,544 peak live
cells versus 23,341,301,760 externally read or written work cells. The plan
requires a disk-backed column store and two-pass row-Merkle construction.
`quotient_row_tiles_executable`, `fri_fold_tiles_executable`, and
`transcript_equivalence_proven` are all deliberately false: callback
implementation and byte-identical root/transcript tests remain pending.
Accordingly, this result is a zero-violation construction and resource plan,
not an emitted or verified recursive proof and not a consensus-authority
claim. Complete in-AIR SHA Fiat--Shamir replay also remains a fixed-point
blocker.

A bounded callback/equivalence fixture now narrows that pending work. On an
eight-row selector-sparse AIR it evaluates the quotient composition through
three-row callback tiles, reproduces every dense composition value and every
quotient coefficient, then runs the actual AIR prover through a dual-Q128
audit backend. That backend executes both the materialized and existing
two-pass column-streaming FRI commits and requires their serialized batch
proofs to be byte-identical; the complete supplemental next-row openings are
also identical and the streamed-audit proof verifies. This proves the
row-tile algebra and existing FRI column-streaming transcript seam on the
bounded fixture. It does not supply the production external column store,
streamed quotient accumulator, fold-layer spill callbacks, or two-pass path
replay. The three production planner booleans therefore remain false.

The bounded quotient seam now also has interchangeable memory and anonymous
temp-file column stores. Both write every composition-domain LDE column in
canonical 24-byte Fp3 cells, reload the selector-sparse quotient schedule,
and reproduce the dense composition and quotient exactly. The eight-row
fixture expands to 16 composition rows over three columns: the memory backend
retains 48 cells, while the temp-file backend retains zero store cells; both
observe a 16-cell one-column scratch peak. This is a real spill/reload and
canonical-byte round trip, but its audit currently retains the dense reference
matrix for comparison. Production peak-memory and authority flags therefore
remain unchanged, and FRI fold-layer/path spill remains open.

FRI fold spill and path replay now execute on the bounded dual-Q128 fixture.
The audit reconstructs each lane's DEEP composition from the independently
replayed batching coefficients, spills every fold-layer evaluation through
the anonymous temp-file store, reloads it, rebuilds the algebraic Merkle root,
and regenerates every queried even/odd authentication path. The reconstructed
proof is byte-identical to both the dense proof and the existing two-pass
column-streaming proof, and verifies through the ordinary dual verifier. This
capability is exposed only as
`kFri3AlgBoundedFoldSpillReplayAuditExecutable`; it is not the production
streaming flag. The audit still computes a bounded dense reference and has not
run at the 65,536-row, 1,802-column parent dimensions, so production
`fri_fold_tiles_executable` and `transcript_equivalence_proven` remain false.

The episode hash boundary path now also has a width-bounded vertical
provenance construction. A chunk proves at most 63 semantic SHA/ChaCha
instances in one namespaced internal-SSA LogUp trace; full chunks schedule 64
lanes and a partial tail canonically schedules the smallest power of two
(minimum two). The exact chunk index/count, semantic count, derived scheduled
count, endpoint, statement and aggregate manifest are Fiat--Shamir bound.
Episode Extract can replace its per-tile flat hash proofs with two canonical
all-tile vertical bundles while retaining the same per-tile semantic memory
bindings. Its verifier now rejects endpoint or outer-statement substitution
before executing a child proof.

The first 64-boundary executable run established a concrete backend limit. Its
canonical schedule was 64 plus two lanes, but the ordinary dense Fp3 FRI
backend became paging-bound inside `Fri3BatchCommit -> BuildMerkleTree` before
emitting a proof. It ran for 1,157.27 seconds wall / 1,099.17 seconds user,
reached 8,187,052,032 bytes maximum RSS and 67,074,850,504 bytes peak memory
footprint, and exited without a Boost assertion result after system swap grew
past 36 GiB. This is dense-backend resource non-completion, not a relation
counterexample or successful round trip. The older per-boundary flat episode
baseline was separately stopped after 1 hour 26 minutes with roughly 6 GiB
observed RSS; it likewise did not complete.

`AirQuotientProve` now accepts an additive checked trace-root cache for
per-column backends. Hints must have the exact trace width, null entries are
recomputed, row-wise use is rejected, challenge derivation is unchanged, and
the ordinary batched FRI commitment still recomputes every root and rejects a
mismatch before returning a proof. The vertical builder uses only roots it
already computed for its pre-challenge base columns; challenge-dependent
inverse/running columns remain uncached. On the bounded Fp3 fixture, partial
hints plus null fallbacks produced a byte-identical complete AIR proof, a
wrong non-null hint was rejected by the post-commit root equality, and a
wrong-sized cache was rejected structurally (15/15 assertions). This removes
one duplicate precommit Merkle pass but does not cure the dense BatchCommit
materialization above. A two-pass column-streaming or spill-backed backend is
still required before another production-shaped vertical run.

The ordinary SHA256d-Merkle Fp3 backend now has that same-format two-pass
column-streaming policy. Pass A constructs one column LDE/tree at a time to
obtain the unchanged ordered `Fri3BatchProof` roots and derives the existing
Fiat--Shamir transcript. After the shared DEEP/fold proof fixes the query
indices, Pass B recomputes one column LDE/tree at a time, extracts only the
requested paths, checks the recomputed root, and discards the tree.
`AirQuotientProve` uses the same policy for supplemental next-row openings,
including the quotient column root check, rather than retaining the dense
`W x LDE` matrix. The codec and verifier remain the ordinary
`Fri3BatchProof` format; this is not an algebraic-hash or row-root format
cutover. On the bounded Fp3 AIR fixture, dense, partial-root-hinted, and
streamed-column provers produced byte-identical complete AIR proof bytes and
the streamed proof verified normally (19/19 assertions, 3.32 seconds wall,
109,297,664 bytes maximum RSS).

At the 63-instance vertical shape (`N=65,536`, `W=174`, Fp3 cells of 24
bytes), the previously dominant retained column LDE matrix alone was about
4.08 GiB (`W * 16N * 24`). The streaming policy replaces it with one
24 MiB column LDE plus an approximately 64 MiB binary Merkle tree. The
retained AIR-domain matrices are each about 261 MiB; even allowing the input
witness, coefficients, shifted coefficients, composition LDE, copied batch
input, public preprocessed columns, DEEP/fold layers, proof paths and
allocator overhead gives a conservative under-3-GiB live-set estimate. This
fits the current 38.65-GiB host, but a production-shaped rerun remains held
until the other large proof processes complete. The estimate is not a
measured production peak and does not promote production or semantic status.

That held streaming run subsequently completed: the production vertical pass
passed 12/12 assertions in 1,687.28 seconds with 3,833,380,864 bytes
(approximately 3.57 GiB) maximum RSS, and
the optimized pass-2-with-step proof was byte-identical to the baseline
streaming proof. This closes the earlier resource-estimate uncertainty for
that child shape. It does not repair the sampled `R_T` equality used by the
old row-wise quotient wrapper, so it remains performance and
implementation-equivalence evidence rather than authority evidence.

### 10.11 Verified multi-root, transcript, site-cap and timing wave

This section is a frozen ledger of the focused results completed in the
verifier-boundary wave. It deliberately excludes the separately running
whole-family aggregate. Every result below is either an executed focused test,
an exact checked inventory, or an explicitly labelled model. None changes an
authority flag.

The standard SHA streaming production vertical bundle completed as follows:

```text
assertions:                              12 / 12
wall / user / sys:     1,687.28 / 1,681.66 / 3.50 s
maximum RSS:                    3,833,380,864 B
peak memory footprint:          3,779,579,552 B
page faults / swaps:                       20 / 0
```

This is one production-shaped vertical hash child emitted and verified, not
the complete 23-family aggregate or recursive authority. The smaller uniform
prefix result above also remains a performance-only result: it passed 27/27
assertions, verified in 809.219 ms and had three locally exported cells, but
its sampled trace-root bridge is not a global equality proof and zero exports
are recursively consumed.

The replacement multi-root construction passed its focused checks. The
multi-row V2 backend passed 41/41 assertions in 0.98 seconds; the whole
transcript-order audit passed 13/13 in 0.11 seconds; and the split-RAP AIR
wrapper passed 20/20 in 0.42 seconds. Its immutable transcript order is:

```text
group metadata and R0/Rdep/Rq roots
  -> z1 and z2
  -> every individual OOD evaluation pair
  -> independent batching coefficients
  -> DEEP weights, folds and shared queries
```

This ordering is security-relevant. V1 drew the independent batching
coefficients before absorbing the individual evaluations, which let a prover
choose nonzero kernel deltas in multiple claims while preserving the batched
evaluation used by DEEP. The executable attack constructs that V1 kernel. V2
changes its post-claim challenge and rejects it. The cache-opening path also
verifies retained authentication paths before a prover can return success.

The split-RAP wrapper partitions the trace exactly into R0, its strict
complement Rdep, and the virtual quotient Rq. It draws the uniform AIR
constraint-combination challenge only after R0/Rdep, separately from the PCS
batching challenge; authenticates current and next rows; fixes group widths
and degree bounds; maps preprocessed OOD columns; and checks
`C(y) = Z_H(y)Q(y)`. A self-consistent changed-Rdep proof still rejects on
that quotient identity. These are bounded backend and wrapper results, not
the application-specific recursive verifier or a global soundness theorem.

The normalized terminal transcript now maps the entire local registry:

```text
transcript rows:                                      69
witness cells / expected cells:                  58 / 58
locally constrained roles:                      14 / 14
locally constrained endpoints:                  52 / 52
recursive child-proof-owned roles:               0 / 14
recursive child-proof-owned endpoints:           0 / 52
```

The parent adds two 58-cell regions and 58 equality constraints. Omission,
reordering, substitution and witness mutation reject
(`normalized_terminal_transcript_maps_all_roles_and_endpoints`, 30/30).
The coupled-bank normalized terminal and registry fail-closed suite also
passed 2,806/2,806 assertions in 6.38 seconds. This proves local transcript
layout and equality, not cryptographic consumption of a role proof. Therefore
the strict recursive counters remain zero.

The runtime recursive-site inventory now validates a canonical 28-family
manifest and its arity-four schedule with checked arithmetic and an enforced
default runtime cap of `2^28`. Omission, overflow, family substitution and
over-cap schedules reject; the focused suite passed 42/42 assertions. Its
exact ledger is:

```text
total=37488397
hard_cap=268435456
authority_residual=37488397
global_cap_enforced=false
normalized_recursively_consumed_sites=0
```

Thus the enumerated schedule is runtime-bounded below `2^28`; that is not yet
a proof-bound global authority cap. Every one of the 37,488,397 sites remains
in the authority residual because the normalized recursive execution is
absent. The earlier exact conditional packed-union calculation remains a
`2^26` bound for its narrower manifest; it must not be conflated with this
runtime schedule cap.

The deterministic Merkle-multiproof planner passed 107/107 assertions. For
`N=2^24` and two independent Q136 lanes, it counts 4,372 internal hashes for
current-only openings and 5,755 for current-plus-next openings. Two paired
roots plus the current Rq root therefore require 15,882 internal hashes. The
uniform-index expected value is 15,791.370 and the structural worst case is
21,869.

Its normalized sponge/timing screen is only a planning model. The current
Q192, `W=1092` schedule uses 236,544 sponge permutations. A mechanically
modeled dual-Q136 split `(172,920,1)` uses 223,856 permutations, 6,528 padding
fields and 895,424 capacity-lane updates. The executable prefix split is
instead `(172,804,1)` at `W=976`; no production backend currently enforces the
modeled `W=1092` partition. Using 576.496 ms as a whole-verifier calibration
input, rather than an isolated component measurement, gives:

```text
sponge-ratio estimate:              545.573 ms
expected-path estimate:             658.540 ms
deterministic-path estimate:        662.320 ms
query-linear estimate:              816.703 ms
structural-worst-path estimate:     911.993 ms
```

The expected component screen is below 900 ms, while the structural worst
case misses it by 11.993 ms. These numbers are neither a production
measurement nor a sub-900-ms guarantee, and the Q136 source compiling does
not by itself prove independent batching, NIROP separation or production
soundness.

Finally, the conditional first-collision reduction passed its 34-assertion
implementation suite but is not applicable to the present proof system. Its
lemma requires an accepted-proof two-preimage extractor, injective encodings,
a locally binding commitment DAG, and preservation of adaptive Fiat--Shamir
and PoW losses under a total order. The scanner and canonical order execute,
but the first audit blocker remains
`no_accepted_proof_two_preimage_extractor`; not all encodings are proved
injective, the commitment DAG is incomplete, Fiat--Shamir extraction loss is
unproved, and PoW grinding loss is unaccounted. The new runtime site ledger
enforces its enumerated schedule, but does not supply the missing proof-side
global binding. The global reduction flag is therefore false and the promoted
soundness contribution is zero bits.

All consensus-authority, recursive-completeness, production-measurement and
public-activation flags remain false.

## 11. Remaining proof-epoch blockers

The implementation is materially closer, but it is not a complete succinct
authority yet. The remaining hard gates are:

- recursive child proofs and CTL/public-pin attachment for the landed
  SHA/XOF/ChaCha, padding/chaining, tile-tree, barrier, digest, and counter
  manifests; single- and four-lane internal SSA provenance and fixed masked
  export now execute, while the combined packed CTL stream, complete stream
  joins and all-instance recursion remain;
- equality-link the exact bounded GEMM A/B/Y/residual product to the external
  builder/dequant producer roots, replace its flat per-output-tile vector with
  production streaming, and consume it recursively;
- recursive execution of the landed all-cell signed-range/CTL closures,
  per-shard Extract openings, scale proofs, the actual Extract
  transformation/output root, and production multiproof aggregation;
- proof-bound global wiring, transpose, residual, stream, and schedule CTL
  values from actual operation-table columns; the endpoint memory layer now
  authenticates all 26 episode vectors and the coupled local relation layer
  now covers all 26 endpoints at bounded shapes; all 52 registered endpoints
  have a bounded local relation and nineteen have a production local
  relation, but only two public-boundary endpoints have transitive producer
  provenance and none is recursively consumed;
- AIR consumption of the exact proof-derived Fiat-Shamir/master-binding
  witness and proof/registry commitment preimages; the two-lane algebraic
  verifier mirror now executes trace-root, next-row and transition/boundary
  opening equations;
- recursively prove SHA256d plus uniform-Fp3/query-index selection as the
  producer of the now-executable 304/304 committed same-trace feedback bus;
  direct equality to V6 algebraic draws remains deliberately false, so an
  algebraic cutover would instead need a new proof format and Fiat-Shamir
  soundness analysis;
- replace the flat 16 MiB bank SHA adapter with a streaming recursive tree
  that covers the roughly 96 GiB production bank and equality-links its input
  words to the executed bank-page relation;
- an end-to-end recursive use of the executable dual-Q128 independent-batching
  backend, including full-domain NIROP separation, the shared-commitment
  binding hybrid, and an independence reduction;
- execution of the complete normalized recursive-root verifier and a complete
  shard/hash/Fiat-Shamir/PoW composition theorem for the selected FRI backend;
  the current/next/trace/fold Merkle AIR and fold memory bus execute, but the
  DEEP/per-point/transition/Fiat-Shamir bus families and recursive endpoint
  children remain unproved;
- callback-backed source/fold streaming for the new byte-identical V5
  column-LDE prover, real production relation prover resources, and <=900 ms
  complete recursive-root measurements; the exact combined native-FRI fixture
  is 11,687,700 bytes and verifies in 123.933 ms;
- independent review.

All Stage-3 authority constants and public activation heights remain disabled
until those gates close.

## 12. Production-candidate synthesis after the full-column no-go

The production-width verifier cannot be made practical by merely slicing its
124,802 columns and proving a random linear combination per slice. The
executable 512-column experiment produced 244 leaf receipts and 82 arity-four
parents, but its production model is:

```text
aggregate base witnesses:       183.17 GiB
aggregate LDE column traffic:     2.868 TiB
unaggregated leaf proofs:          1.812 GiB
final-root opening payload:        1,019,904 bytes
```

More importantly, that construction proves only each compression equation. It
does not prove the original cross-chunk verifier constraints or link their
quotient. The implementation records all three missing bindings explicitly,
keeps normalized recursive consumption at zero, and cannot become authority.

The replacement V1 construction is relation-local sharding. It extracts the
exact current/next column support of every canonical constraint-bytecode
program, partitions that support hypergraph into at-most-512-column shards,
and proves every original constraint in exactly one projected local quotient.
If a trace column occurs in more than one shard, the shards must prove equality
of `(row_index, value)` tuples with two independent post-all-commitment LogUp
lanes. Value-only multiset equality is insufficient because it permits a row
permutation. Conjunction of the local quotients is equivalent to the original
relation only after every duplicated-column equality terminal is proved and
recursively consumed.

The executable canary covers support extraction, exact SSA projection,
constraint partitioning, row-index-tagged equality obligations and arity-four
scheduling. It rejects constraint/link omission, shard reorder, untagged
equality buses, program substitution and authority/timing promotion.

The production audit remains a hard `NO-GO`:

```text
registered roles fully bytecode-migrated:       0 / 14
registered roles with canonical fragments:     14 / 14
roles retaining opaque callbacks:              14 / 14
canonical local program tables:                     21
canonical local constraints:                       751
role/table namespace columns:                      769
exact loaded support columns:                      742
exact local shards at the 512-column cap:           21
canonical-bytecode endpoint families with no residual:  0 / 52
canonical-bytecode endpoint families with residuals:   52 / 52
width-only minimum shards:                         244
width-only minimum recursive parents:               82
minimum proof instances before equality leaves:     326
normalized recursive consumption:                     0
measured production root time:                        no
```

The 742 columns are exact support for the twenty-one migrated helper tables,
not a derivation of the declared 124,802-column production verifier. Every
role still has at least one residual callback-backed family, so zero roles are
semantically complete.

The 326 figure is a width-derived decomposition of one rejected,
124,802-column monolithic verifier. It is not proof multiplicity in the
selected heterogeneous topology. The exact production manifest already
partitions the workload as:

```text
heterogeneous relation-family leaves: 28,116,241
arity-four role parents:               9,372,141
final-tree parents:                           15
total:                                37,488,397
```

Each leaf must select its canonical relation ProgramTable and public-input ABI
from one root-pinned registry. Each parent must execute one constant-width
universal bytecode/child verifier selected by that same registry. Under those
conditions there are no extra 244 width leaves or 82 width parents. The old
product remains only a regression diagnostic for the monolithic architecture:

```text
37,488,397 * 326 = 12,221,217,422 sites
log2(site count) = 33.5086689559 bits
```

The canonical external and recursive program-registry commitments, exact
per-family/site selectors, leaf statement binding, ordered-child parent
statement binding and mutation canaries now execute natively. The recursive
AlgHash registry digest is the sole program/verifying-key authority; SHA256d
is audit serialization only, so program selection does not require a
cross-hash acceptance theorem. The recursive AIR still does not execute the
universal interpreter and child verifier, so the global theorem and
certified-bit count remain zero.

The executable single-Fp3/Q192 ledger makes the consequence precise. With the
selected packed-four, 2^18-row, 37,488,397-site schedule, its conditional
additive known-term screen is 101.2031 bits. With the conservative product
diagnostic, the BCS/FRI term saturates at 93.4248 bits (the saturation point is
Q=140), the 128-bit hash term falls to 94.4913 bits, and the additive known-term
screen is 92.8544 bits. Increasing single-lane Q past 140 cannot reach 100 bits
under that rejected product. The 2^20 scenario gives 30,240,318 sites and
101.5131 bits, but remains unselected because its production peak-memory
profile is unmeasured.

The shard schedule is a complete coverage and soundness-accounting fallback,
not a credible prover-economic production topology: it would require
37,488,397 child proofs. The production-shaped alternative is one
GKR/sumcheck-plus-glue quotient/FRI receipt for each of the 28 registered
families, eight arity-four per-role reductions, and the fifteen-node final
tree—51 proof instances total. Rows and constraints become internal events in
each family proof theorem rather than independent proof-failure union terms.
No current primitive constructs one shard-indexed quotient/FRI proof per
family, so this alternative is explicitly non-selectable and the global
theorem remains open.

The endpoint-28/29 work now has proof-owned first-pass SHA word/byte exports in
`R0`, complete ordered `R0`/`Rdep` row-group root pins in SplitRAP, and the
exact signed producer relation
`u = sum(2^i*b_i)`, `s = u - 256*b_7`. A bounded bridge composes the producer
and SHA consumer through two post-root CTL lanes and pins non-bank prefix and
padding bytes even in partially private SHA words. Fast structural/range
tests pass. However, the minimum Q192 end-to-end bridge proof exceeded the
98-second bounded run and was terminated. The legacy endpoint-28 per-column
roots still do not determine the bridge's new ordered row-group root, and the
two child verifiers do not execute inside the normalized parent. Recursive
consumption and authority therefore remain false.

A bounded two-child coordinator now demonstrates the intended two-phase
protocol end to end on one CoupledBank relation and one canonical projection
receiver. Both children retain ordered `R0`, derive one shared dual-lane CTL
challenge block, commit the exact six-column `Rdep` suffix, verify through
SplitRAP, and export proof-owned terminals. A four-slot parent AIR binds the
two child proof commitments, pads two slots canonically, and proves both
terminal sums are zero. Root, dependent-column, terminal, seed, padding and
parent-trace mutations reject.

The receipt also has a collision-free fourteen-span field-cell transport map
covering both complete SplitRAP codecs, the parent proof and all public
manifest/schedule/challenge/terminal data. Both existing sixteen-column
MultiRow-V2 verifier mirrors execute natively and the exact Poseidon/SHA
schedules are counted. This is not yet recursion: none of the receipt cells
are equality-sourced by verifier chips in the normalized parent. The audit
lists eight missing families—complete proof-cell equality, the recursively
proved MultiRow verifier, AlgHash proof-row aliases, SHA Fiat--Shamir
compressions, SHA shard recursion, the arity-four parent-proof verifier, the
sixteen proof/terminal digest lanes, and registered endpoint-28/29
provenance—and keeps normalized consumption at `0/52` endpoints and `0/14`
roles. The latest focused construction/audit run took 41.74 seconds and is
not a production-root benchmark.

Consequently the exact status remains:

```text
strict transitive semantic completeness:   2 / 52
production-local relations:                19 / 52
normalized recursive consumption:           0 / 52
normalized recursively complete roles:      0 / 14
V6 -> V5 normalized challenge feedback:      0 / 304
certified global soundness:                  0 bits
production authority:                        false
```
