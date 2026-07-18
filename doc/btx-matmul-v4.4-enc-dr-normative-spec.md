# BTX MatMul v4.4 — ENC-DR (Digest-Only Recompute) + Sketch-Cache: NORMATIVE SPECIFICATION

*Status: v4.4 RELEASE-CANDIDATE NORMATIVE SPECIFICATION. This document is the
implementable consensus specification of the design fixed by
`doc/btx-matmul-v4.4-tension-resolution.md` §4–§5 (the adjudicated ENC-DR +
SKETCH-CACHE synthesis, which supersedes the ENC-SC plan of
`doc/btx-matmul-v4.4-release-candidate-architecture.md` where they conflict;
that memo's deletion inventory and flag-day framing are carried forward, as is
the M1–M4 economics analysis of
`doc/btx-matmul-v4.4-compute-reward-preservation.md`). Nothing herein is
deployed: `nMatMulV4Height = INT32_MAX` on every public network. Everything
activates at ONE height. Written 2026-07-18.*

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
MAY, and OPTIONAL are to be interpreted as in RFC 2119. Sections tagged
**[CONSENSUS]** define block validity; sections tagged **[NON-CONSENSUS]**
define policy/transport behavior that MUST NOT influence block validity.
Numbered rules are cited as `DR-n`.

---

## 0. One-paragraph overview (informative)

At `nMatMulV4Height` the committed proof-of-work object becomes **digest-only**:
the 32-byte header field `matmul_digest = H(σ‖Ĉ)` — byte-identical in
derivation to v4.3 — is the *entire* consensus commitment, and the block body
carries **zero** PoW payload bytes (`matrix_c_data` MUST be empty). A block is
valid iff its digest equals the digest of the deterministic recompute
`Ĉ_true(header)` and meets the difficulty target. Verifiers MAY decide this
predicate by exact recompute (ε = 0) or by authenticating untrusted "sketch
cache" bytes against the digest and running the unchanged v4.3 Freivalds
verifier over them (ε ≤ 2⁻¹⁸⁰); the two strategies decide the identical
predicate. An optional, best-effort, self-authenticating P2P sketch-cache
transport keeps CPU tip verification at ~200 ms in the common case. The entire
segregated-proof subsystem is deleted. The miner's per-nonce loop is
byte-identical to the measured post-PR#89 b = 4 profile (κ = 1.00), so the
no-inversion property is preserved by identity, and the load-bearing safety
property of the whole design is cross-platform bit-exact determinism of Ĉ.

---

## 1. [CONSENSUS] The committed object and the header

### 1.1 Header layout (unchanged)

**DR-1.** The v4 block header layout is UNCHANGED from v4.3: the 182-byte
serialization (`src/primitives/block.h:26-27`)

```
nVersion(4) ‖ hashPrevBlock(32) ‖ hashMerkleRoot(32) ‖ nTime(4) ‖ nBits(4)
‖ nNonce64(8) ‖ matmul_digest(32) ‖ matmul_dim(2) ‖ seed_a(32) ‖ seed_b(32)
```

No field is added, removed, reordered, or re-sized by this fork. The block
hash, header-sync rules, and the header-PoW throttle
(`nMatMulHeaderPoWDiscountBits`, `src/consensus/params.h:470-502`) apply
unchanged: `matmul_digest` remains a self-declared field at header-sync time
and the throttle remains REQUIRED wherever it is enabled today.

### 1.2 σ, seeds, and operand derivation (byte-identical to v4.3)

All derivations below are the existing normative functions in
`src/matmul/matmul_v4.h` and MUST NOT change under this fork. They are
restated here because the recompute predicate (§2) is defined in terms of
them.

**DR-2 (σ).** `σ = SHA256d(header)` over the full 182-byte serialization with
all fields as mined — `matmul::DeriveSigma` / `matmul::v4::DeriveSigma`
(`matmul_v4.h:89-93`). σ is NONCE-FRESH: it binds `nNonce64` and every other
header field.

**DR-3 (template hash).** `T = ComputeTemplateHash(header)`
(`matmul_v4.h:95-107`): the header hashed with `nNonce64`, `nNonce`, `seed_a`,
`seed_b` zeroed. T binds `nVersion`, `hashPrevBlock`, `hashMerkleRoot`,
`nTime`, `nBits`, `matmul_dim` and is constant across one template's nonce
sweep.

**DR-4 (operand scoping — invariant I1′, unchanged).**
- Operand **A** seed: derived from T under the A domain tag
  (`DeriveOperandSeed(header, Operand::A)`, `matmul_v4.h:109-125`) —
  TEMPLATE-scoped.
- Operand **B** seed: derived from the FULL header including `nNonce64`
  (`DeriveOperandSeed(header, Operand::B)`) — **NONCE-FRESH**. The per-nonce
  marginal unit (expand B, B·V, combine, serialize, digest) is therefore
  unavoidable per lottery draw; this is what difficulty prices.
- Projectors **U, V**: TEMPLATE-scoped from T under distinct domain tags
  (`DeriveProjectorSeeds`, `matmul_v4.h:127-135`).
- `seed_a`/`seed_b` header fields MUST equal their §H.4 derivations and MUST
  be non-null (existing rule, `src/pow.cpp:3633`).

**DR-5 (operand expansion).** A and B are n×n row-major balanced-s8 matrices
expanded by the pinned XOF (`ExpandOperand`, `matmul_v4.h:137-138`); U (m×n)
and V (n×m) are balanced-s8 projectors (`ExpandProjector`,
`matmul_v4.h:140-142`). At ENC-BMX4C heights the operand ENCODING is the
BMX4-C M11+E8M0 profile exactly as pinned by
`doc/btx-matmul-v4.2-bmx4c-spec.md` and the `BMX4C_*` constants
(`params.h:132-166`); ENC-DR changes commitment carriage only, never the
encoding layer.

### 1.3 The committed object Ĉ and the digest

**DR-6 (Ĉ).** The committed object is the m×m sketch
`Ĉ = U·(A·B)·V` over `F_q`, `q = 2⁶¹−1`, with every entry the unique
canonical residue in `[0, q)`. The **consensus definition** is the reference
path `ComputeSketch(U, ComputeExactProduct(A,B), V)` (`matmul_v4.h:144-159`);
`ComputeSketchOptimal` (`matmul_v4.h:161-179`, `Ĉ = (U·A)(B·V)`) is
byte-identical by exact-integer associativity and is the permitted miner/
verifier evaluation. All arithmetic on this path is exact integer; no
floating-point value may influence any committed byte (§3).

**DR-7 (serialization).** `SerializeSketch(Ĉ)`: m² canonical F_q words,
row-major, 8 bytes/word little-endian, exactly `8·m²` bytes
(`matmul_v4.h:239-241`). Non-canonical words (≥ q), wrong length, or any
non-minimal encoding MUST be rejected by `ParseSketch`
(`matmul_v4.h:243-247`).

**DR-8 (digest — BYTE-IDENTICAL to v4.3).**

```
matmul_digest = H(σ ‖ SerializeSketch(Ĉ))
```

where H is the domain-separated SHA256d of `ComputeSketchDigest`
(`matmul_v4.h:249-252`). The digest form `H(σ‖Ĉ)` is an L0-frozen item and is
PRESERVED VERBATIM: a v4.3 miner binary and a v4.4 miner binary produce
bit-identical headers for the same (template, nonce). There is no R_LDE, no
Merkle tree, no second commitment of any kind.

### 1.4 Profile shape and the scaling rule

**DR-9 (shape at activation).** The production profile shape is:

| Parameter | Value | Anchor |
|---|---|---|
| n (matmul_dim) | 4096 (`nMatMulV4Dimension`; window 4096–8192) | `params.h:369-380` |
| b (tile) | 4 (`kTileB`, `nMatMulV4TranscriptBlockSize`) | `matmul_v4.h:61`, `params.h:392` |
| m (sketch rank) | n/b = 1024 (`BMX4C_SKETCH_RANK_M`) | `params.h:154` |
| q | 2⁶¹−1 (L0-frozen) | `int8_field.h` |
| R (Freivalds rounds, cache path) | 3 (ε ≤ 2⁻¹⁸⁰) | `params.h:381-384` |

m is fixed at activation by the profile definition: `m = n / tile_b` with the
`AssertBMX4CConstructionInvariants` startup check pinning that any production
`nMatMulV4Dimension` reduces to exactly the calibrated rank. m remains a
REQUIRED computation parameter (it defines Ĉ, the digest preimage, the derived
cache size `8·m²`, and the Freivalds LHS) even though no `8·m²`-byte object is
ever stored or relayed by consensus.

**DR-10 (n-first / m-window scaling rule — normative for future retargets).**
Because the per-nonce non-GEMM floor's commitment term scales ∝ m² while GEMM
scales ∝ n²m (tension memo §2.2), shape retargets MUST follow:

1. Compute growth SHALL be taken preferentially via **n** (GEMM ∝ n²m against
   an XOF floor ∝ n²: the GEMM:hash ratio is non-decreasing in n, so n-scaling
   can never cause reward inversion), within the L0 window n ≤ 8192 and the
   O(n²) cache-path verify budget.
2. **m** MAY be raised only inside the silicon-measured window
   (m ∈ {1024…4096} at n = 4096), and each rung MUST re-pass the §K.2b
   on-silicon GO/NO-GO (wall-time tensor majority, ≥ ~60 % tensor utilization,
   frontier-over-consumer price-surviving margin) before activation. Model-based
   certification of any m increase is FORBIDDEN (the twice-burned rule).
3. When the m-window closes, n SHALL be retargeted to re-open it (with b
   retargeted in lockstep so m re-derives; e.g. n 4096→8192).

Every retarget is its own L1 hard fork with regenerated golden vectors and its
own ASERT rescale; none changes storage (consensus PoW bytes are 0 at every
shape forever).

---

## 2. [CONSENSUS] The consensus predicate

### 2.1 The predicate (the whole of it)

**DR-11.** At heights h ≥ `nMatMulV4Height` (the ENC-DR activation height,
§5), a block B is PoW-valid **iff all of**:

1. **Header structure (unchanged from v4.3):** 182-byte layout;
   `matmul_dim == nMatMulV4Dimension`; `seed_a`/`seed_b` non-null and equal to
   their §H.4 derivations; `matrix_a_data` and `matrix_b_data` empty
   (`src/pow.cpp:3632-3638` today, retained verbatim).
2. **Empty PoW body:** `matrix_c_data` MUST be empty. A non-empty
   `matrix_c_data` at ENC-DR heights makes the block INVALID
   (reject code `v4-forbidden-c-payload`). Because no PoW body bytes exist,
   the segregated MUTATED/INCOMPLETE classification collapses: there are no
   proof bytes whose mutation must be distinguished from a consensus fault,
   and a body-payload violation is an ordinary (non-permanent, per existing
   body-mutation discipline) body rule like the A/B-payload rule today.
3. **Digest correctness:**
   `matmul_digest == H(σ ‖ SerializeSketch(Ĉ_true(header)))`, where
   `Ĉ_true(header)` is the deterministic recompute defined by DR-2…DR-7 —
   a **pure function of the 182-byte header alone**.
4. **Target:** `matmul_digest ≤ target(nBits)`, with ASERT
   (`CalculateMatMulAsertTarget`, `src/pow.cpp:2189`) unchanged and the
   activation rescale `Num/Den = 1/1` exactly (§5.4).

**DR-12.** There is NO segregated proof, NO proof store, NO proof relay, and
NO proof size cap at ENC-DR heights. No consensus rule may reference any
node-local store, any peer message, or any bytes other than the block as
received. Clause 3 being header-pure is the design's D1/D3 property and MUST
be preserved by any implementation refactor.

### 2.2 Permitted evaluation strategies (consensus-EQUIVALENT)

Clause DR-11.3 admits exactly two evaluation strategies. Both are conforming;
they decide the identical predicate and MUST agree (DR-16).

**DR-13 (RECOMPUTE — the reference strategy; defines clause 3).**
1. Derive σ, T, seeds (DR-2…DR-4); XOF-expand A, B, U, V (DR-5).
2. Evaluate `Ĉ = ComputeSketchOptimal(U, A, B, V, n, m)` (or any
   mining-eligible accelerated backend that has passed the §3 bit-identity
   harness — the result MUST be byte-identical to the CPU reference).
3. `SerializeSketch`, `ComputeSketchDigest(σ, payload)`, compare to
   `matmul_digest`, then check target.

Error: **ε = 0** (exact). Cost: W = 4n²m + 2nm² MACs + ~393k SHA-256
compressions (ms on GPU; 0.1–0.25 s at 16 CPU threads; 0.8–2 s single-thread
at m = 1024).

**DR-14 (CACHE-ASSISTED — the fast path).** Given candidate sketch bytes
`P` from ANY source (peer cache message, local rolling cache, the node's own
miner):
1. **Authenticate:** `ComputeSketchDigest(σ, P) == matmul_digest`. One hash
   over 8·m² bytes (~4 ms at m = 1024). On mismatch the CACHE is garbage:
   discard `P`, apply peer discouragement (§4), and fall back to DR-13. A
   cache authentication failure is NEVER evidence about the block (DR-15).
2. **Canonicality:** `ParseSketch(P, m, sketch)` MUST pass (exact length
   8·m², every word < q). Failure ⇒ same disposition as step 1 (under SHA256d
   collision resistance this cannot occur for an authenticated payload of an
   honestly-mined block; treat as cache garbage, fall back).
3. **Freivalds:** `SketchFreivalds(A, B, U, V, sketch, σ, P, n, m, R = 3)`
   (`matmul_v4.h:254-271`), challenges from `H(σ‖H(payload))` (Fiat–Shamir,
   invariant I7) — the v4.3 verifier byte-identical. Per-round error ≤ 2/q;
   R = 3 ⇒ **ε ≤ (2/q)³ ≈ 2⁻¹⁸⁰**.
4. **Target:** `matmul_digest ≤ target(nBits)`.
5. Accept the block.

If step 3 FAILS on an authenticated (step-1-passing) payload, the
implementation MUST reject the block as a PERMANENT consensus fault: under
collision resistance, `P` is the unique digest preimage the miner committed,
so a Freivalds failure implies (except with probability ≤ 2⁻¹⁸⁰ + ε_SHA) the
miner committed some Ĉ′ ≠ Ĉ_true — and DR-13 rejects the same block.
An implementation MAY instead fall back to DR-13 for defense in depth before
finalizing the reject; the outcome MUST be identical.

**DR-15 (cache failures never touch block validity).** Absence of cache
bytes, timeout, truncation, or authentication failure MUST NOT delay a
validity verdict indefinitely, MUST NOT produce any INCOMPLETE-like pending
state, and MUST NOT be recorded against the block or its miner. A node
lacking cache bytes MUST decide the block by DR-13. Liveness is independent
of the cache by construction.

**DR-16 (equivalence — normative).** DR-13 and DR-14 decide the identical
predicate DR-11.3–4:
- A block accepted by DR-13 is accepted by DR-14 whenever an authenticated
  payload exists (false-reject impossible: the authenticated payload of an
  honest block IS `SerializeSketch(Ĉ_true)`, which passes Freivalds with
  certainty).
- A block rejected by DR-13 is rejected by DR-14 except with probability
  ≤ 2⁻¹⁸⁰ plus SHA256d collision probability — the same equivalence class the
  chain accepts today for the v4.3 verifier itself.

Implementations MUST NOT expose any configuration in which the two paths can
disagree on a block's finalized validity (e.g. a Freivalds round count other
than the consensus R at ENC-DR heights, a non-reference XOF, or a re-derived
challenge schedule). Divergence between the paths on any input is a
consensus-critical bug and a mandatory adversarial-vector class (§6).

### 2.3 DoS posture (informative constraints, normative knobs)

Rejecting a garbage block on the recompute path costs O(W). The following
existing mechanisms MUST remain enabled and be re-tuned to the recompute
cost:
- the header-PoW throttle (`params.h:470-502`) — every body-verify attempt
  costs the attacker difficulty-proportional SHA header-PoW;
- the verify budgets `nMatMulV4{Global,Peer}VerifyBudgetPerMin`
  (`params.h:403-410`) — values re-tuned to recompute wall time on the
  reference validator (informational bench, §5.5); budgets are policy and
  MUST NOT reject an otherwise-valid connected block, only rate-limit
  speculative verification;
- cache-first policy where bytes are available: a garbage cache is rejected
  by one 8·m²-byte hash (~4 ms) and the supplying peer discouraged — the
  cache path is fail-fast even though recompute is not.

---

## 3. [CONSENSUS-CRITICAL] Determinism requirements

This section is the load-bearing safety property of ENC-DR. Under v4.3 a
wrong Ĉ produced by a buggy backend yields an invalid block that the network
rejects while honest nodes agree; under ENC-DR the *verifier itself* may
recompute Ĉ, so any nondeterminism in the recompute path is a direct
chain-split vector. Every rule below is consensus-critical.

**DR-17 (bit-identity).** `Ĉ_true(header)` MUST be bit-identical — every
serialized byte — across every conforming implementation and every execution
backend (CPU reference, CUDA, Metal, HIP, any future backend), on every
supported platform, for every valid header. The CPU reference
(`ComputeSketch` ≡ `ComputeSketchOptimal`, DR-6) is the definition; all other
evaluations are conforming only if byte-equal to it.

**DR-18 (exact integer F_q).**
- All committed-path arithmetic is exact integer. Floating-point values MUST
  NOT influence any committed byte ("no rounding on the committed path",
  C-1′/L0).
- F_q residues are the unique canonical representatives in `[0, q)`,
  q = 2⁶¹−1; the `int8_field` `FqFromInt32`/`FqMul`/`FqAdd` reduction path is
  normative.
- **128-bit multiply requirement (backend authors).** `FqMul`/`FqReduce`
  (`int8_field.cpp`) form the full ~122-bit product of two `[0, q)` operands in
  `unsigned __int128` before reducing mod q = 2⁶¹−1. `__int128` is a GCC/Clang
  extension, not ISO C++; the reference and all current consensus builds target
  GNU-family compilers, so it is available. The reduction is *mathematically
  exact* modular arithmetic, so the committed bytes are bit-identical on ANY
  correct 128-bit (or wider) unsigned multiply — no specific compiler intrinsic
  is normative, only the exact 122-bit-product-then-reduce result. A future
  non-GNU consensus port (MSVC, a formal-methods backend, an FPGA/HDL verifier)
  MUST therefore supply an equivalent full-width unsigned multiply (e.g. MSVC
  `_umul128`, a 64×64→128 double-word routine, or a bignum) that reproduces the
  same `[0, q)` residue; a 64-bit-truncating multiply is non-conforming and a
  chain-split vector (DR-17).
- Accelerated GEMM paths MUST satisfy the true ≥ 32-bit integer accumulator
  eligibility invariant (`int8_field.h`, `kRequiredAccumulatorBits`;
  `BMX4C_NATIVE_PATH_PROVEN_T = 24` for the native block-scaled path,
  `params.h:165-166`): the limb-pair GEMMs accumulate to 2²⁴–2²⁵ on exactly
  the production dimension window, so FP32-mantissa-bounded accumulators are
  never bit-exact and MUST fail closed down the fallback ladder (native →
  INT8 fallback → CPU) — mine slower, never mine or verify wrong.

**DR-19 (pinned accumulation order).** The canonical element order is pinned:
index-major A/B/U/V expansion, row-major C/Ĉ, the fixed sequential
accumulation order of the reference (`matmul_v4.h:26-37`). Integer addition
is associative so tiling/batching is permitted, but the committed
serialization order (`SerializeSketch`) and the limb-combine semantics
(`ComputeCombineModQ` ≡ `ComputeCombineLimbTensor` ≡ column blocks of
`ComputeCombineLimbTensorStacked`, byte-for-byte) are fixed and MUST NOT be
reordered in any way observable in the output bytes.

**DR-20 (the XOF).** Operand/projector expansion is the pinned
domain-separated SHA-256 XOF producing balanced-s8 (ENC-S8) or BMX4-C
M11+E8M0 (ENC-BMX4C) operands. The rejection-sampling/mapping rules, domain
tags, and byte order are frozen per the existing profile specs; any deviation
defines a different profile (= a different hard fork).

**DR-21 (backend eligibility — extended to the verify path).** The existing
mining-eligibility rule (cross-backend bit-identity vs the CPU reference,
enforced by the `backend_capabilities_v4` self-test harness and
`matmul_v4_backend_determinism_tests` before a backend may mine) is EXTENDED:
a backend is **verify-eligible** for DR-13 recompute only under the same
gate. A node whose accelerated backend fails or has not run the self-test
MUST perform DR-13 on the CPU reference path. Backend mismatch counters and
the fail-to-CPU fallback posture of `accel_v4.h` apply to the verify path
identically.

**DR-22 (conformance obligation — both paths).** A conforming implementation
MUST reproduce the golden vectors (§6) on BOTH:
- the **mine path**: header → σ/T/seeds → operands → Ĉ → serialized bytes →
  digest, on every backend it can mine with; and
- the **verify/recompute path**: the same pipeline invoked from block
  validation (DR-13), plus the cache path (DR-14) transcript — Freivalds
  challenges, per-round LHS/RHS values, accept/reject — on the CPU reference.

Mine-path and verify-path evaluations of the same header MUST be
byte-identical to each other; the harness MUST exercise a verify-side entry
point, not only the miner's (this is the one new determinism-harness
requirement ENC-DR adds).

---

## 4. [NON-CONSENSUS] Sketch-cache transport (best-effort)

The sketch cache is a policy-layer accelerator for DR-14. It has **no
consensus edge**: no rule in §2 references it, and full nodes interoperate
with zero cache support.

### 4.1 Messages

**DR-23.** Two new P2P messages (protocol version bump; names normative):

- `getmmsketch(block_hash: uint256)` — request the sketch bytes for the
  block with the given hash.
- `mmsketch(block_hash: uint256, bytes: vector<u8>)` — response;
  `bytes` is the `8·m²`-byte `SerializeSketch(Ĉ)` payload for that block,
  uncompressed, in one message where transport limits allow.

At m = 1024 the 8 MiB payload fits every transport (below the 16 MiB BIP324
v2 packet ceiling). At shapes where `8·m² ` exceeds a transport's message
limit, a node MAY chunk opportunistically with a simple offset/length
extension or MAY simply not serve — requesters MUST NOT depend on either.
Neither message may be flagged as required protocol support; unknown-message
tolerance rules apply.

**DR-24 (no trust role).** Sketch serving MUST NOT be advertised via a
`NODE_*` service bit and MUST NOT create an archive/availability obligation.
There are no "sketch archive nodes" in the protocol's trust model; any peer
MAY serve, any node MAY drop everything at any time.

### 4.2 Authentication (the whole of it)

**DR-25.** A received `mmsketch` payload `P` for block header `H` is
authenticated by exactly the DR-14 step 1 check:
`ComputeSketchDigest(DeriveSigma(H), P) == H.matmul_digest`, preceded by the
trivial length pre-check `|P| == 8·m²` (reject oversized payloads before
hashing). Authenticated payloads are trustworthy under SHA256d collision
resistance regardless of source; unauthenticated payloads MUST be discarded
and the peer discouraged (misbehavior score / disconnect per existing
policy). No signature, no provenance, no peer reputation is needed or
permitted as an acceptance criterion.

### 4.3 Serving rules and anti-amplification (REQUIRED for implementations that serve)

**DR-26.** A node that serves `mmsketch` MUST enforce all of:
1. **Request-for-known-block only:** respond only for blocks in its active
   chain or recently-validated set; silently ignore unknown hashes.
2. **Token buckets:** a per-peer serve budget and a node-wide egress byte
   budget (defaults on the order of a few payloads/min/peer and a global
   cap sized to a small multiple of block cadence; exact defaults are
   implementation policy). Requests over budget are dropped, not queued.
3. **Dedup window:** at most one in-flight/served response per (peer,
   block_hash) per window.
4. **No unsolicited push:** `mmsketch` MUST only be sent in response to
   `getmmsketch` from that peer (exception: a miner MAY announce-push the
   sketch of its own new block to peers that have negotiated it; a receiving
   node MAY drop unsolicited payloads unread).
5. **Requester-side cap:** a requester MUST cap concurrent outstanding
   `getmmsketch` requests and MUST time out and fall back to DR-13 recompute;
   it MUST NOT stall block validation waiting for cache.

Because every response is `8·m²` bytes against a 40-byte request, serving is
an amplification surface; the budgets in (2) are REQUIRED, not advisory, for
any serving implementation.

### 4.4 Sources and retention

**DR-27.** Serve sources (all optional): (a) a miner's own materialized
sketches (the winning miner computed the bytes anyway and is
incentive-aligned to serve them — its block propagates against rivals'
recompute); (b) an optional rolling regeneration window,
`-mmsketchcache=<blocks|0>` (default suggestion 2016 blocks ≈ 15.8 GiB at
m = 1024; 0 disables); (c) on-demand GPU regeneration by volunteer nodes.
Cached bytes are not ledger data: every byte is regenerable from the
182-byte header by anyone, forever, so retention is pure local policy and
pruning needs no protocol coordination.

**DR-28 (best-effort semantics, restated as the invariant).** For every
block, at every node, at every time:
`validity_decision(block) = f(header)` — never
`f(header, cache availability)`. The cache changes only *which* conforming
evaluation strategy runs and how fast; §2's predicate and §3's determinism
guarantee the answer is the same. A node MUST always be able to, and by
default DOES, fall back to recompute.

---

## 5. Activation

### 5.1 Single-height flag day

**DR-29.** One knob: `nMatMulV4Height`. At that height, in one block: the
DR-11 predicate applies (empty `matrix_c_data`, digest-vs-recompute, target),
and every deleted subsystem (§5.3) is already absent from the tree — the
change series lands the new predicate and the deletions together so the tree
never holds two live carriage paths. `INT32_MAX` on every public network
until ratified (§5.5); regtest keeps a low height for CI. Below the height,
v3 rules apply unchanged. There is no dual-profile window, no grace period,
and no migration: nothing is deployed anywhere.

### 5.2 Profile parameters (final form)

**DR-30.** `MatMulProfileParams` (`src/consensus/params.h:178-184`) takes its
final form:

```cpp
enum class MatMulCommitmentScheme : uint8_t {
    FLAT_SKETCH_INBLOCK = 1,  // regtest vector-replay only (legacy v4.2 carriage)
    DIGEST_RECOMPUTE    = 2,  // ENC-DR: zero consensus payload; cache-assisted
                              // Freivalds or exact recompute
};

struct MatMulProfileParams {
    MatMulEncodingProfile  profile;      // ENC_DR = 4 (ENC_SC id retired unused;
                                         // ids 1-3 RESERVED, regtest-historical)
    MatMulCommitmentScheme commitment;   // DIGEST_RECOMPUTE on production nets
    uint32_t tile_b;                     // 4  (unchanged)
    uint32_t sketch_rank_m;              // 1024 (unchanged; REQUIRED for
                                         // computation: defines C_hat, the digest
                                         // preimage, the Freivalds LHS, and the
                                         // derived cache size 8*m^2)
};
```

RETIRED fields: `sketch_payload_bytes` (no consensus payload exists to size —
the cache size derives as `8·sketch_rank_m²` where transport code needs it)
and `proof_segregated` (nothing is ever segregated). `sketch_rank_m` is KEPT:
m is a consensus computation parameter (DR-9), not a storage parameter.
`GetMatMulProfileParams(height)` collapses to: v4 active ⇒ the ENC-DR params
above; the regtest-keyed legacy replay path may select
`FLAT_SKETCH_INBLOCK` for differential vector testing only, never on public
networks. The BMX4C/BMX4CD activation heights and their ASERT rescale pairs
(`params.h:429-469`) are deleted (folded into `nMatMulV4Height`, which the
chainparams asserts already forced equal for C; D never activates anywhere).
The `BMX4C_*` encoding constants (`params.h:132-166`) are RETAINED — they
define the operand encoding ENC-DR commits.

### 5.3 What is DELETED (from the tree, not height-gated off)

**DR-31.** Deleted outright (inherited from the RC-architecture memo's
inventory, unchanged; nothing here has ever executed on a public network):

- `src/matmul/matmul_proof_store.{h,cpp}` — the entire segregated proof
  store (memory/disk modes, singleton, `Sync()` and its
  `FlushStateToDisk` coupling, archive role, prune window).
- P2P: `GETMATMULPROOF`/`MATMULPROOF`/`MATMULPROOFCHUNK` message types and
  handlers; `NODE_MATMUL_PROOF_ARCHIVE`; the whole Stage 2b/2c/2d complex in
  `net_processing.cpp` (pending queues, byte budgets, TTL/eviction sweeps,
  serve token buckets for proofs, archive-peer preference, reassembly).
- `src/pow.cpp`: `GetMatMulProofSizeCap` + `MATMUL_SEGREGATED_PROOF_OVERHEAD`
  (:3651-3655), `CheckMatMulV4SegregatedProof` (:3657-3713),
  `OffloadMatMulV4SegregatedProofToStore` (:3715+),
  `MatMulSegregatedProofStatus` and the tri-state INCOMPLETE handling in
  `ContextualCheckBlock`.
- `src/consensus/params.h`: `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY` (:225)
  and its Stage-2 coupling comment block (:186-224); the ENC_BMX4CD
  activation fields; `sketch_payload_bytes`/`proof_segregated`.
- ENC-BMX4CD as a profile with its own carriage (`VerifySketchBMX4D`,
  `kTileBMX4D`, D domain tags, `BMX4CD_SKETCH_RANK_M` as an activation
  target — D's economic content, deeper m, survives as the DR-10 m-window).
- The `matrix_c_data` in-block sketch packing in the miner
  (`GenerateBlock`); `IsMatMulV4PayloadSizeValid`'s non-empty requirement
  inverts into DR-11.2's empty requirement.
- Everything the ENC-SC plan would have added (`matmul_v4_sc.*`, circle-FFT,
  F_{q²}, `fri_*` parameters, the 256 KB cap, SC vectors and kernels):
  never merged, now not planned. Corrected ENC-SC (F1+F2) remains the filed
  successor design, not part of this release.
- Segregated-path tests and the `-regtestbmx4cdheight` plumbing, with their
  subject.
- The assumevalid buried-proof trust special-case for segregated proofs
  (`src/validation.cpp:10315` rationale): retargeted, not reinvented — below
  `assumevalid`, DR-11.3 digest recomputation is skipped under exactly the
  trust ConnectBlock already extends to buried scripts; above it, full
  verification per §2. Deep history is strictly stronger than before: every
  block is forever re-auditable from its header alone.

Net: the v4.4 diff is deletion-dominated; the added consensus surface is
approximately zero (DR-11.2's empty-body rule and the dispatch restructure
are the only consensus edits; DR-14 reuses the existing verifier unmodified).

### 5.4 ASERT

**DR-32.** The activation rescale is `nMatMulV4AsertRescale{Num,Den} = 1/1`
**exactly**: the per-nonce work unit is byte-identical to the measured v4.3
b = 4 profile (κ = 1.00), so there is nothing to rescale. This is the first
committed-object change in the program's history requiring no ASERT
calibration measurement. ASERT itself (`src/pow.cpp:2189`), the half-life,
anchoring, and timestamp hardening are untouched.

### 5.5 Gates: what replaces the fail-closed relay-ready flag

**DR-33 (no relay-ready gate — with the argument).**
`BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY` existed to prevent activating a
profile whose proof bytes a node might be unable to OBTAIN (the Stage-2b
BIP324 failure made that concrete: a v2 peer could receive a block and stall
forever on its 32 MiB proof). That failure mode is **structurally
impossible** under ENC-DR: verification is recompute-based and always
available — the only input is the 182-byte header the node already has by
definition of having the block. There are no proof bytes to obtain, no
INCOMPLETE state, no fetch, no stall; the cache (§4) is an accelerator whose
total absence changes nothing but latency (DR-15/DR-28). A fail-closed
*relay*-readiness gate would therefore guard a dependency that no longer
exists, and none SHALL be carried. (Corollary: the sketch-cache transport
needs no readiness flag either — it is not load-bearing.)

**DR-34 (what gates activation instead).** Activation on any public network
(setting `nMatMulV4Height` below INT32_MAX) is gated on, and only on:

1. **The §K.2b silicon no-inversion measurement (GO/NO-GO)** — the gate
   already required to activate v4 at all, unchanged in content because this
   fork does not move one per-nonce byte or compression: on H100/B200-class
   parts, (a) tensor wall-time strict majority at batch Q ≥ 32, (b) ≥ ~60 %
   tensor utilization, (c) frontier parts above the top consumer part by a
   price-surviving nonce-throughput margin. Run once on the unchanged
   pipeline. No NEW silicon campaign is required or permitted to substitute
   for it.
2. **Hard-fork ratification via the L0 amendment process** — smaller in
   scope than ENC-SC's: the digest form `H(σ‖Ĉ)`, q, exact-integer
   committed path, σ/nonce-freshness, Freivalds structure (as the cache
   path), and price-independence all SURVIVE; what is amended is (i) the
   mandatory Θ(m²) in-block carriage (removed) and (ii) the verify-budget
   wording, from "< 1 s single-thread from consensus bytes" to "< 1 s
   single-thread cache-assisted; recompute fallback budgeted on a reference
   parallel/GPU validator". Supermajority process per the longevity doc.
3. **Ordinary code review** of the dispatch restructure and the cache
   transport. No external cryptographic review is required: no new
   cryptography exists (the only primitives are the already-audited SHA256d
   digest and the already-audited Freivalds verifier).
4. **Informational (non-blocking) recompute-verify bench** on reference
   validator hardware, to set the re-tuned DR-DoS budgets (§2.3). This bench
   informs policy values only and MUST NOT be construed as an activation
   precondition.

The startup invariant checker (`AssertBMX4CConstructionInvariants`'s
successor, `AssertENCDRConstructionInvariants`) SHALL hard-block any public
network from configuring a non-INT32_MAX `nMatMulV4Height` until gates 1–2
are recorded as passed in the release (regtest exempt) — the same fail-closed
*mechanism* as the retired flag, protecting the correct object: ratification
and measured no-inversion, not relay readiness.

---

## 6. Golden vectors and test obligations (conformance)

**DR-35 (retained vectors — unchanged objects).** The following existing
golden-vector families remain normative and MUST pass byte-identically,
because their objects are unchanged: operand/projector expansion (per
encoding profile); Ĉ at regtest and production shapes; σ/template-hash/seed
derivations; `SerializeSketch` bytes; `matmul_digest`; the full Freivalds
transcript (challenges, per-round LHS/RHS, accept); the adversarial
wrong-limb, non-canonical-residue (word ≥ q), wrong-length, and
tampered-payload rejection vectors.

**DR-36 (new vector families — REQUIRED for v4.4).**
1. **Empty-body rule:** a block with any non-empty `matrix_c_data` at ENC-DR
   heights MUST be rejected (vectors: 1-byte, exact-8·m²-byte, and oversize
   payloads).
2. **Cache-path accept:** authenticated true payload ⇒ DR-14 accepts;
   transcript pinned.
3. **Cache-path garbage:** (a) random bytes of correct length — fails DR-14
   step 1, block subsequently ACCEPTED via recompute (the paths' independence
   is the assertion); (b) truncated payload; (c) single-word-tampered payload
   — fails step 1; (d) a payload for a DIFFERENT valid block — fails step 1
   (σ binding).
4. **Wrong-commit consensus fault:** a header whose digest commits Ĉ′ ≠
   Ĉ_true (one tile corrupted before serialization at mine time) MUST be
   rejected by BOTH paths: DR-13 digest mismatch AND DR-14 Freivalds failure
   on the authenticated Ĉ′ payload — the DR-16 agreement vector, run as a
   mandatory regression.
5. **Recompute-path equality across backends:** the existing cross-vendor
   determinism harness extended with a **verify-side entry point** (DR-22):
   for each eligible backend, block validation's DR-13 recompute of the
   golden headers MUST equal the CPU reference and the mine-path output
   byte-for-byte.
6. **Target-boundary:** digest exactly at, one-below, one-above target.

**DR-37 (test-suite obligations).**
- Unit: all DR-35/36 vectors; `ParseSketch` fuzzing; `mmsketch`
  deserializer fuzzing (it is net-facing); DR-14/DR-13 differential fuzz
  (random headers, random cache corruptions — the two paths' verdicts MUST
  never diverge on finalized validity).
- Functional (regtest): mine → validate → reorg end-to-end with empty
  bodies; cache serve/request between two nodes including budget exhaustion,
  timeout-fallback-to-recompute, and garbage-cache peer discouragement;
  IBD with and without `-mmsketchcache`; assumevalid skip-and-resume.
- Bench (informational): `matmul_v4_stage_bench` gains a recompute-verify
  stage (used for §5.5 gate 4 and DoS budget tuning; not an activation
  gate).
- CI MUST run the regtest legacy `FLAT_SKETCH_INBLOCK` replay differentially
  against ENC-DR on shared vectors: both must accept the same Ĉ and produce
  the same digest (any divergence is a spec bug found cheap).

A release MUST NOT ship with any DR-35/36 vector failing on any supported
platform, and a backend MUST NOT be marked mine- or verify-eligible (DR-21)
without passing family 5 on the release binaries.

---

## 7. Anchors

**Code:** `src/primitives/block.h:26-27` (182-B header);
`src/matmul/matmul_v4.h` (:61 kTileB, :89-142 σ/template/seeds/I1′, :144-179
sketch reference/optimal, :198-237 combine reference/limb/stacked, :239-252
serialize/digest, :254-271 SketchFreivalds); `src/pow.cpp` (:2189 ASERT,
:3512-3531 payload size (inverted by DR-11.2), :3543-3618 verify dispatch +
digest/target tail, :3620-3649 in-block carriage, :3651-3713 segregated path
(deleted)); `src/consensus/params.h` (:96-166 profiles + BMX4C constants,
:178-184 MatMulProfileParams, :186-225 relay-ready flag (deleted), :368-410
v4 heights/dimension/R/b/rescale/budgets, :429-469 BMX4C/D fields (deleted),
:470-502 header-PoW gate); `src/matmul/matmul_v4_batch.h`;
`src/matmul/backend_capabilities_v4.h`; `src/validation.cpp:10315`
(assumevalid).
**Docs:** `btx-matmul-v4.4-tension-resolution.md` (THE design; §2 κ metric,
§4 normative sketch, §5 gates); `btx-matmul-v4.4-release-candidate-architecture.md`
(deletion inventory, flag-day framing);
`btx-matmul-v4.4-compute-reward-preservation.md` (M1–M4, §L.2.1 neutrality);
`btx-matmul-v4-design-spec.md` (§E, §I, §K.2b, §L);
`btx-matmul-v4.2-bmx4c-spec.md`; `btx-matmul-v4.2-longevity-threat-model.md`
(L0); `btx-matmul-enc-sc-adversarial-review-and-required-fixes.md`.
