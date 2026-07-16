# BTX MatMul v4.2 — Solver Evolution Design (segregated-proof deeper-commit profile)

*Status: DESIGN pass. NOT a consensus-code change, NOT an activation. This document
specifies how to EVOLVE the MatMul solver in response to the on-silicon measurements
reported by the external reviewer ("vanities"), within the lead decisions already fixed
(segregated prunable proof carriage; C stays the base profile; O(n²) Freivalds / q = 2⁶¹−1 /
M11+E8M0 encoding / determinism / price-independence all FIXED). Companion docs it builds on
without re-deriving: `btx-matmul-v4-design-spec.md` (§0.3, §0.7, §K.2, §L.4),
`btx-matmul-v4.2-consolidated-design.md` (the ENC-BMX4C object + §8 profile architecture),
`btx-matmul-v4.2-compute-bound-redesign.md` (the b=2 deeper-commit analysis, previously PARKED
on the in-block-payload transport blocker this document removes). Per §0.7-(4) no market price
is an input to any parameter; every throughput-ordering claim is measurement-gated. Written
2026-07-16.*

---

## 0. Executive summary

1. **Target (recommendation).** Ship the **per-CARD datacenter ordering** — option (a). Adopt
   the deeper-commit profile at **b = 2, m = 2048, 32 MiB sketch** (the measured D operating
   point: B200 leads a 5090 by **1.54× per card**). A per-DOLLAR datacenter advantage is
   **structurally unreachable** with a linear-sketch PoW and is not a target (the consumer 5090
   still wins ≈ 13× per rental-dollar; §1 proves why no transport-feasible m closes a 15–20×
   price gap). We recommend the best *achievable* target: maximize the per-card slope and the
   cost floor, and disclose the per-dollar residual honestly.

2. **Evolved committed object.** Ship **m = 2048** (b = 2) as the additional versioned L1
   profile. Do **not** ship m = 4096 (b = 1, 128 MiB) at launch: both Blackwell parts are already
   near their achievable combine utilization at m = 2048 (B200 543 vs 5090 377 achieved INT8
   TOPS on the 25-GEMM combine reference), so the per-card separation is at the knee of the
   curve; larger m spends transport and verify budget for diminishing ordering gain and rests on
   an *un*measured extrapolation. Because the proof is now off-block, m is promoted from a frozen
   constant to a **per-profile L1 parameter with a governance ladder** (m = 2048 launch; m = 4096
   / n = 8192 variants reserved, each gated on its own measured verify-time and propagation).

3. **Segregated prunable proof (3–4 sentences).** No new in-block field is needed: the header's
   existing `matmul_digest = H(σ‖Ĉ)` (σ = SHA256d(header)) *already* cryptographically binds the
   exact sketch bytes, and the block hash commits to the header — so the block carries only that
   32-byte commitment and the ~32 MiB sketch is removed from `CBlock` serialization entirely. The
   sketch is relayed as a **witness-like proof artifact** over a new `getmatmulproof` /
   `matmulproof` P2P exchange, size-capped at `8·m²` bytes; a receiving node binds it by checking
   `H(σ‖proof) == matmul_digest` **before** running Freivalds, so a wrong or substituted proof is
   rejected and cannot be credited. Verified proofs are cached and **pruned below a rolling depth**
   (`nMatMulProofPruneDepth`); IBD and pruned nodes re-fetch proofs above their assumevalid height
   from **archive peers** that retain full history, and trust buried-below-assumevalid blocks under
   the same model the chain already uses for historical signatures.

4. **Top 3 risks.** (i) **Difficulty mis-calibration via Strassen/LCMA on the larger square
   combine** — the m = 2048 combine is a fatter, *more* Strassen-reducible GEMM; the ASERT rescale
   MUST be calibrated to a measured LCMA-accelerated cost, not the schoolbook `16nm²` count, or the
   enforced work is overpriced. (ii) **Segregated proof widens the header-forgery / data-availability
   surface** — with the work proof off-body, a header claims work the body no longer carries; mitigated
   by the existing header-PoW throttle + proof-verified-before-full-validity + assumevalid + archive
   serving, but IBD liveness now depends on proof availability. (iii) **32 MiB full-network
   propagation is unproven at scale** and the per-card ordering (1.54×) was measured on one kernel
   generation — both must be re-confirmed at the final combine kernel and difficulty before activation;
   two prior *model* orderings in this program were already falsified by measurement, so nothing here
   is claimed from MAC/byte counts alone.

---

## 1. Target recommendation — accept per-card ordering; per-dollar is unreachable

### 1.1 What the measurements actually say

Per-nonce marginal throughput (n = 4096, window Q = 32, byte-exact-gated), from vanities:

| profile | 5090 (sm_120) | H100 (sm_90) | B200 (sm_100) | B200/5090 | B200/H100 |
|---|---|---|---|---|---|
| C (b=4, m=1024, 8 MiB) | 623 | 183 | 661 | **1.06×** (tie) | 3.61× |
| D (b=2, m=2048, 32 MiB) | 353 | 79 | 545 | **1.54×** | 6.90× |

Combine INT8 utilization (achieved TOPS, 25-GEMM reference combine), C→D:
5090 192→377 (1.96×), H100 46→74 (1.61×), B200 169→543 (**3.21×**). The utilization *ratio*
B200/5090 inverts across the profiles: **0.88× at C → 1.44× at D**. This is the whole mechanism:
the C profile lets the high-clock consumer Blackwell tie the datacenter Blackwell because the
8 MiB combine is small enough to be launch/bandwidth-limited on both; the D profile's 4× larger,
squarer combine lets the B200 convert its bigger tensor budget into achieved TOPS (3.2× more)
while the 5090 only doubles, so per-nonce throughput drops on *both* cards (5090 to 0.57×, B200
to 0.82×) but drops **less** on the B200 — the ordering emerges from *taxing consumer Blackwell*,
not from the datacenter card getting faster.

Three load-bearing caveats are adopted verbatim: the real axis is **Blackwell-vs-Hopper** (both
Blackwell parts handle it; the tie is 5090≈B200 at C); **Hopper's 0.29×/0.22× is likely an
IMMA-layout / cuBLASLt-12.4 artifact**, not its true ceiling (no strong claim rests on it); and
**per rental-dollar the consumer card still wins ≈ 13×** (1180 vs ~90 nonce/$·hr at D).

### 1.2 Why per-dollar is structurally unreachable with a linear sketch

The question posed is whether option (b) — a per-*dollar* datacenter advantage — is achievable.
It is not, and the reason is exactly §L.4 (verifier-linearity collapse) intersected with the
price gap:

- To invert per-dollar ordering, the datacenter part must beat the consumer part **per card by
  more than the hardware price ratio**, i.e. by **> 15–20×** (B200 costs 15–20× a 5090). §L.4's
  economic corollary independently puts the rental-price gap a miner must overcome at **≈ 4.55×**;
  a purchased-hardware inversion needs the full 15–20×.
- A **linear** commitment Ĉ = U·C·V verified in O(n²) can never deny the consumer card the
  `(U·A)(B·V)` factoring shortcut — that shortcut *is* the verifier's own cheap check (§L.4 L1).
  So the 5090 always runs the committed object on its full INT8 + FP4 pipes at its high clock; it
  is never *excluded*, only *taxed*. The per-card gap is therefore bounded by the achievable
  tensor-utilization ratio, **not** by any residency or capacity cliff.
- That ratio's ceiling is small. Measured marginal per-card gap at D is **1.54×**. The datasheet
  INT8 *peak* ratio B200/5090 is ≈ 5.4×, and even driving m → n (full-C, shortcut → 1.5×, §1.3)
  the achievable ratio is capped by how much of that peak the combine can extract on each card —
  the utilization-ratio trend (0.88× → 1.44× from m=1024→2048) is climbing toward, but bounded by,
  that ~5.4× peak, and 5.4× ≪ 15–20×.

**Conclusion.** No transport-feasible m — indeed no m at all, up to full-C — makes a linear-sketch
PoW win per-dollar against a 15–20× price gap. §L.4's three lemmas cap any residual "cliff" well
below the price gap, and the linearity collapse guarantees the cheap-clock consumer card always
participates. Per-dollar inversion would require a *nonlinear, incompressible* work function, which
by §L.4-(b/b′) forces the verifier to O(n³) and blows the < 1 s budget — a FIXED constraint. We do
**not** pursue it and we do **not** claim it. This is consistent with §L.4's price-independent
restatement of the goal: *datacenter wins per card and per joule at every price; consumer wins per
rental-dollar at every price.* The solver's job is to maximize the **slope of the per-card ordering**
and the **cost floor of the cheapest eligible producer** — which shipping D does — not to control
which class shows up at a given price (that is a market outcome, and reading it back into a parameter
is forbidden by §0.7-(4)).

**Recommended target: (a) — ship D (m = 2048), delivering the measured 1.54× per-card datacenter
ordering, as the best achievable target.** Frame it exactly as §L.4 requires.

### 1.3 The m-vs-shortcut endpoint, for completeness

| b | m | enforced marginal MACs | combine share | (U·A)(B·V) shortcut vs full-recompute | sketch payload 8m² |
|---|---|---|---|---|---|
| 4 | 1024 | 1.25 n³ | 80% | 4.2× | 8 MiB |
| **2** | **2048** | **4.5 n³** | **89%** | **2.3×** | **32 MiB** |
| 1 | 4096 | 17 n³ | 94% | 1.5× | 128 MiB (raw-C alt: 64 MiB) |

The shortcut factor walks monotonically toward — but never reaches — 1 as m → n (it is exactly
`(n³ + n²m + m²n)/(n²m + m²n)`; the factored advantage `n²(n−m) → 0`). D halves C's shortcut
(4.2× → 2.3×) and triples the enforced tensor-dominant work (1.25 → 4.5 n³). Full-C reaches 1.5×
but its 64–128 MiB payload and the O(m²) verify growth make it the theoretical endpoint, not a
launch candidate.

---

## 2. The evolved committed object — ship m = 2048, promote m to a governed L1 parameter

### 2.1 Ship D as-is on the object; the only change vs the PARKED design is carriage

On every encoding axis, the evolved profile is **byte-for-byte the compute-bound-redesign D
profile** already implemented as non-consensus reference (`ComputeDigestBMX4D` /
`VerifySketchBMX4D` / `ValidateDimsBMX4D`, `kTileBMX4D = 2`): M11 mantissas, E8M0 power-of-two
block scales (L = 32, S = 3, E_max = 48), scale-free M11 U/V, base-2⁶ remainder-top limb combine,
q = 2⁶¹−1, R = 3, digest H(σ‖Ĉ), and **distinct V4.2-D domain tags** so C and D operand streams
are cryptographically independent. The *only* thing that changes relative to the PARKED redesign
is that the 32 MiB sketch is no longer carried in-block — which removes the sole blocker that
parked it (the 24 MiB block ceiling / 16 MiB P2P limit; redesign §6 P1/P3). Re-designate it a
live-candidate profile **ENC-BMX4C-D** (enum value 3, reinstated) — an *additional* versioned L1
profile above ENC-BMX4C, per the lead decision that C stays the base live profile.

### 2.2 Why m = 2048 and not larger, now that payload is unclamped

Segregating the proof lifts the transport clamp, so the natural question is whether to go past
m = 2048. The measured utilization curve answers it:

- From m = 1024 → 2048, B200 achieved-TOPS on the combine went 169 → 543 (3.2×) — the profile is
  successfully moving the B200 up its roofline. But 543 achieved TOPS is where the B200's combine
  *lands* under this kernel at m = 2048; the 5090 lands at 377. The per-card ratio (1.44× util,
  1.54× nonce/s) is the *product* of the B200 pulling ahead **and** the 5090 being taxed — and the
  5090 is now firmly in the regime where its clock advantage no longer hides the larger combine.
- Going to m = 4096 (b = 1) quadruples payload again (128 MiB; raw-C alternative 64 MiB), grows the
  O(m²) verify term 4× (4M → 16M field-mults/round — still sub-dominant to the n² = 16.7M matvecs,
  so verify survives) and the O(nm) projection 2×, and pushes the shortcut only 2.3× → 1.5×. Whether
  it widens the **per-card** gap materially is **unmeasured**, and the two prior model-based orderings
  in this program were falsified. Shipping m = 4096 on an extrapolation would repeat that mistake.

**Recommendation: launch at m = 2048 — the measured knee of the curve — and reserve m = 4096 (and
the n = 8192 / b = 4 dimension-hold variant that keeps m = 2048 at 32 MiB across a dimension retarget)
as governance-raisable rungs, each activated only after its own §6 measurement.** Because the proof
is off-block, the transport ceiling on m is no longer the 24 MiB block limit but (i) the O(m²) verify
term staying sub-dominant to the O(n²) matvecs — comfortable to m ≈ n — and (ii) measured
full-network propagation time of the `8m²` proof message under the §3 relay (the real ceiling; must
be measured per rung).

### 2.3 Consequence — m becomes a per-profile parameter, not a frozen constant

Today `BMX4C_SKETCH_RANK_M = 1024` is a compile-time constant with a construction assert
(`AssertBMX4CConstructionInvariants`) that forces any production-scale n to reduce to exactly
m = 1024. That is correct for a single-m world and wrong for a two-profile (C at 1024, D at 2048)
world — it is precisely the hardcoded rank the reviewer flagged. §4 specifies the parametric fix;
the design intent here is: **m is an L1 profile parameter** (like the tile b, the alphabet, the
domain tags), pinned per profile and validated per profile, never a single global rank.

---

## 3. The segregated prunable proof mechanism (full spec)

### 3.1 In-block commitment format — reuse the existing 32-byte digest, add nothing

The binding already exists. The header field `matmul_digest` is defined as
`H(σ ‖ Ĉ)` with `σ = SHA256d(header)` (`ComputeSketchDigest(sigma, sketch_payload)` in
`pow_v4.cpp`), i.e. it is a collision-resistant commitment to the **exact serialized sketch bytes**,
salted by the header. The block hash `GetHash()` commits to the header, which contains
`matmul_digest`. So the binding chain is already complete and free:

```
blockhash ──(header)──► matmul_digest = H(σ‖Ĉ) ──(SHA256)──► the exact 8m² sketch bytes
```

**Therefore the in-block commitment is the 32-byte `matmul_digest` that is already in the 182-byte
header.** No new coinbase output, no new header field, no Merkle branch. The change to block body
carriage is purely *subtractive*: for the segregated-proof profile, `CBlock::matrix_c_data` is **no
longer serialized** and MUST be empty on the wire and on disk (§3.6). This is the cleanest possible
form of the lead's "commit only a small binding hash in the block."

(Contrast the status quo: `matrix_c_data` holds the sketch inside `CBlock`, serialized by
`SERIALIZE_METHODS(CBlock)`, and validated by the `missing-product-payload` /
`bad-matmul-v4-payload` path in `ContextualCheckBlock`. That path moves to the proof-relay layer.)

### 3.2 The proof-relay P2P message

Two new messages, modeled on witness/compact-block relay:

- `getmatmulproof(block_hash)` — request the sketch for a block whose header/body the peer holds.
- `matmulproof(block_hash, sketch_bytes)` — response carrying the raw serialized sketch
  (`8·m²` bytes for the active profile at that height).

Relay flow (a validating, non-archival node):
1. Receive the block (header + body, body no longer contains the sketch) via normal block or
   compact-block relay. The block is **PoW-incomplete** until its proof verifies: `matmul_digest`
   is self-declared (audit C1), so a body without a verified proof is not yet creditable work.
2. Issue `getmatmulproof(block_hash)` to the announcing peer (and, on timeout, to others /
   archive peers, §3.5).
3. On `matmulproof`: enforce the **size cap first** (§3.4), then the **binding** (§3.3), then
   **Freivalds** (§3.3). Only after all three pass is the block fully valid and creditable.
4. Cache the verified proof for onward relay and serve it to peers that request it, until it is
   pruned (§3.5).

Proofs are **request/response and cached**, never gossiped unsolicited, so a 32 MiB artifact never
rides the compact-block fast path (redesign §6 P3 concern) — it is fetched on demand exactly like
block bodies behind headers-first sync.

### 3.3 Proof ↔ block binding (a wrong/substituted proof is rejected)

On receiving a `matmulproof` for `block_hash`, with the header already in hand:

```
σ            = SHA256d(header)                    // header-derived, attacker cannot change it
if  H(σ ‖ proof_bytes) != header.matmul_digest:   // BINDING CHECK — cheap, O(payload) SHA
        reject proof, do NOT credit, penalize peer, re-request from another
if  !VerifySketchBMX4C/D(header, n, R, proof_bytes, digest_out):  // O(n²) Freivalds, R=3
        // digest matched but Freivalds failed => the committed object is not U·C·V:
        // this is a real, PERMANENT PoW failure for THIS header (BLOCK_CONSENSUS)
        mark block invalid
accept: block fully valid, proof verified
```

The binding check is the substitution defense: because `matmul_digest` is fixed by the header and
covered by the block hash, **the only byte-string that passes `H(σ‖·) == matmul_digest` is the
sketch the miner committed to.** A substituted or corrupted proof fails the SHA binding and is
discarded as a body/relay mutation (non-permanent, so it cannot poison the honest block — mirrors
the existing `BLOCK_MUTATED` vs `BLOCK_CONSENSUS` split in `ContextualCheckBlock`). Only a proof
that *does* reconstruct the digest yet fails Freivalds (or whose digest is over target) is a
permanent consensus fault. This is the identical soundness logic the in-block path uses today
(`MatMulV4PayloadMatchesCommitment` → `BLOCK_MUTATED`; Freivalds/target fail → `BLOCK_CONSENSUS`),
relocated to the proof-relay layer with no weakening.

### 3.4 Payload size bound (the proof cannot exceed limits)

The security review's first concern — the payload must not exceed limits — is enforced at two
independent points:

- **Block side:** the block no longer contains the sketch, so `MAX_BLOCK_SERIALIZED_SIZE`
  (24 MB) is unaffected by m; the 32 MiB (or larger) sketch never counts against block capacity
  (§3.6). This *removes* the ceiling breach the redesign was parked on.
- **Proof side:** the `matmulproof` message has its **own** hard cap
  `MAX_MATMUL_PROOF_SIZE = 8·m² + overhead`, computed from the **active profile's m at that
  height** (8 MiB for C, 32 MiB for D), enforced **before allocation/deserialization**. A message
  exceeding the cap is dropped and the peer penalized — no unbounded-allocation DoS. Because the
  cap is derived from consensus profile params (not attacker-chosen), it is exact: a well-formed
  sketch is exactly `8m²` bytes and `ParseSketch` already range-checks shape against m.

### 3.5 Verify-then-prune policy, IBD, and pruned nodes

**Prune policy.** A verified proof is retained until the block is buried by `nMatMulProofPruneDepth`
(reactivated from its current RESERVED/non-functional state; default 10 000 blocks ≈ 10.4 days at
90 s). Below that depth a default node discards the proof bytes. The block's validity survives
pruning because it was verified once, and the **header's `matmul_digest` is retained forever** as
part of the header — nothing about chain state is lost, only the (large, redundant-after-verify)
witness. Annual proof-storage at D is ~11.6 TiB/yr if retained forever; pruning to a 10 k-deep
window bounds it to ~32 GiB resident, making proof-aware pruning a **hard prerequisite** that this
design delivers rather than reserves.

**Node roles.**
- **Archive nodes** (`-matmulproofarchive`, analogous to `-txindex`/archival full nodes) retain
  **all** proofs and answer `getmatmulproof` for any historical block. A small population of these
  suffices to serve IBD, exactly as archival nodes serve historical blocks today.
- **Default (pruned-proof) nodes** keep only the rolling window and serve proofs within it.

**IBD / re-validation.** An initial-block-download node must re-establish PoW for each block:
1. Above its `defaultAssumeValid` height (or `-assumevalid=0` for a fully-verifying node): fetch
   each block's proof via `getmatmulproof` from an **archive peer**, run the §3.3 binding +
   Freivalds, and only then credit the block's work. This is the same on-demand fetch as block
   bodies, just for the witness-like sketch.
2. Below `defaultAssumeValid`: trust the buried chain without re-fetching proofs, under the
   **identical trust model the chain already applies to historical signatures/scripts** — a
   supermajority-validated, deeply-buried prefix. `assumevalid` is exactly the escape hatch for
   "validation data pruned network-wide"; a from-scratch, trustless sync sets `-assumevalid=0`
   and requires archive peers (which must exist for that mode, as with archival blocks).

**Reorg.** A reorg into the rolling window replays verification from cached proofs; a reorg deeper
than the window re-fetches proofs from archive peers for the disconnected/connected blocks. Because
the binding is header-derived, a re-fetched proof for an old header is verifiable identically.

### 3.6 Block-size accounting change

- Remove `matrix_c_data` from `SERIALIZE_METHODS(CBlock)` for segregated-proof heights (keep the
  legacy in-block path for pre-segregation heights, height-gated — history is never rewritten).
- The block-serialized-size consensus check (`validation.cpp` ≈ L9784,
  `serialized_block_size > nMaxBlockSerializedSize`) now sees a block **without** the sketch, so
  `nMaxBlockSerializedSize` stays 24 MB and the 32 MiB (or larger) sketch is **excluded from
  MAX_BLOCK_SERIALIZED_SIZE by construction** — directly satisfying the lead decision.
- The `ContextualCheckBlock` v4 path changes from "require non-empty `matrix_c_data` in the body"
  to "require **empty** body sketch and a **verified proof** bound to `matmul_digest`" at
  segregated-proof heights. `IsMatMulV4PayloadSizeValid` moves to the proof-relay size cap (§3.4).

**Activation coupling (honesty).** Enabling the segregated-proof profile is a header/relay-protocol
change (new P2P messages, body-serialization change) exactly like the `BTX_HEADER_NONCE_ON_WIRE`
coupling already asserted in `AssertBMX4CConstructionInvariants`. It must ship as one coordinated
change: the D height, the proof-relay messages, the body-serialization gate, and the archive/prune
plumbing activate together, or a node that receives a segregated block cannot obtain its proof and
stalls. This is asserted at construction, not left implicit.

---

## 4. The b-agnostic (per-profile) validator

The reviewer's flag — "D's b = 2 shape can't satisfy the generic b = 4 validator" — is caused by
three hardcoded-for-C assumptions: `kTileB`/`kTileBMX4D` compile constants, the single
`BMX4C_SKETCH_RANK_M = 1024`, and the §0.3 construction assert that forces production n to reduce
to m = 1024. Make the validator parametric in the profile:

### 4.1 A per-profile parameter block

Introduce a consensus-normative struct returned by the existing profile selector:

```cpp
struct MatMulProfileParams {
    MatMulEncodingProfile profile;   // ENC_S8 | ENC_BMX4C | ENC_BMX4C_D
    uint32_t tile_b;                 // 4 (S8/C) | 2 (D)
    uint32_t sketch_rank_m;          // n / tile_b at production n  (1024 | 2048)
    uint64_t sketch_payload_bytes;   // 8 * m^2  (8 MiB | 32 MiB)
    bool     proof_segregated;       // false (in-block) | true (relayed+prunable)
    // + domain-tag selector, magnitude constants (all m-independent, §5), golden-vector set id
};
MatMulProfileParams GetMatMulProfileParams(int32_t height) const;   // extends GetMatMulEncodingProfile
```

`GetMatMulEncodingProfile(height)` already exists and dispatches the ladder ENC_S8 → ENC_BMX4C →
(now) ENC_BMX4C_D. `GetMatMulProfileParams` wraps it and attaches the per-profile shape.

### 4.2 Every rank/tile/size call site reads the profile, never a global constant

- `ValidateDims(n, params.tile_b, m_out)` — already takes `b` as an argument; the fix is to stop
  passing the `kTileB` constant and pass `params.tile_b`. `m = n / tile_b` is then correct per
  profile with no hardcoded rank. (`ValidateDimsBMX4C` / `ValidateDimsBMX4D` collapse into one
  b-parametric `ValidateDimsBMX4(n, b, m_out)`; the D variant's structural gates — n % 32 == 0,
  `CheckCombineLimbBoundBMX4C`, b | n, s32 accum — are identical, only b differs.)
- `VerifySketch` / `ComputeDigest` — select the digest/verify routine and (b, m, domain tags) from
  `params`, not from `IsBMX4CActive` + a constant. `SketchFreivalds` is already **rank-agnostic**
  (it takes m as a runtime argument), so the O(n²) verifier needs *no* change — it validates C and
  D against their own committed shapes automatically.
- Payload/size validation — the expected size is `params.sketch_payload_bytes = 8·m²`, so C
  validates against 8 MiB and D against 32 MiB with no shared magic number. For segregated profiles
  this is the §3.4 proof cap; for in-block profiles it stays the body-size check.

### 4.3 Generalizing the §0.3 dimension-invariant guard

Replace the single `AssertBMX4CConstructionInvariants` rank pin ("any production-scale
`nMatMulV4Dimension` must reduce to exactly m = 1024") with a **per-profile** assert:

> For each configured profile P live at some height, `nMatMulV4Dimension` at production scale MUST
> reduce to exactly `P.sketch_rank_m` under `P.tile_b` (i.e. `tile_b · m == n`), and
> `P.sketch_payload_bytes == 8 · P.sketch_rank_m²`. A dimension retarget not matched by a lockstep
> per-profile `tile_b` change fails LOUD at startup.

So C pins (b=4 → m=1024 → 8 MiB) and D pins (b=2 → m=2048 → 32 MiB) independently; a future profile
pins its own (b, m, payload) triple; and no profile can silently commit a different-shaped object.
The guard generalizes from "one rank" to "each profile's own rank," which is exactly what the
two-profile world requires. The §2.2 dimension-hold discipline (if n → 8192, D's b → 4 to keep
m = 2048 / 32 MiB) is enforced by this same per-profile assert.

---

## 5. Determinism / soundness / vendor-neutrality impact

### 5.1 M-t24 exactness — preserved verbatim (m-independent)

Every accumulator bound is a function of n and the encoding, **never of m**: base product
`|C̄| ≤ 2304·n`, projections `|P|,|Q| ≤ 288·n`, limb-pair GEMM `|S_ij| ≤ 1024·n`. m enters only the
sketch's *output* dimension (m×m) and the payload, never a contraction length or a per-MAC
magnitude. So the whole M-t24 apparatus — the odd-target near-2²⁴ discriminator (16,777,145), the
t-discrimination / boundary-pin vectors, the native-vs-INT8 admissibility classification — is
**inherited byte-for-byte** from ENC-BMX4C (machine-checked as
`d_profile_accumulator_bounds_are_m_independent`). M-t24 PASSES on the 5090 today; growing m to
2048 changes nothing on this axis. Growing m spends payload, never precision.

### 5.2 Freivalds soundness — unchanged ≤ 2⁻¹⁸⁰

The Schwartz–Zippel bilinear test is degree-2 in the F_q challenges regardless of the sketch rank;
per-round error ≤ 2/q, R = 3 → **≤ 2⁻¹⁸⁰**, identical to C. The soundness proof (redesign §2 P1–P3)
never uses the U/V distribution or m — it uses only (canonical F_q object, bilinear identity,
nonce-fresh challenges), all preserved. The segregated proof does **not** touch soundness: the
committed object and the Freivalds check are byte-identical; only *where the sketch travels* changes,
and the §3.3 binding ensures the verifier checks the same bytes the digest commits to. Full-rank
work-binding of U/V holds identically (i.i.d. 11-symbol matrices are rank-m except w.p. 2^−Ω(n)).

### 5.3 Cross-vendor byte-identity — preserved

The committed bytes depend only on (seeds, encoding, m), all deterministic and m-independent in
magnitude. The three miner schedules (factored / full-C / limb-tensor) are byte-identical at the D
rank (`d_profile_all_schedules_are_byte_identical`). The dispatcher re-verifies every device digest
via `VerifySketch*` and falls back to CPU on any mismatch, so a mis-rounding device can only lose
throughput, never split the chain — unchanged.

### 5.4 Native-path integration reality (disclosed; consensus stays vendor-neutral)

Honest disclosure, not a consensus claim: the native block-scaled **MXFP4 path does not dispatch on
any current NVIDIA card via cuBLASLt** (`CUDA_R_4F_E2M1` + `VEC32_UE8M0` returns zero algorithms);
the native tier is reachable only via **CUTLASS block-scaled MXF4 / tcgen05 / a hand-written
`mma.sync.kind::mxf8f6f4` kernel** — which compiles and passes M-t24 on a 5090. The **combine**
shared by both tiers runs on the **INT8/IMMA** pipe, not the FP4 pipe, and is the majority of the
per-nonce work (89% at D). Consensus remains vendor-neutral: the committed object is OCP-MX
(E2M1/E8M0), the universal fallback is the hand-written INT8 s8→s32 path available on every
IMMA/MFMA/TensorOps device, and vendor kernels are pure L2 optimizations behind the identical
committed object. No claim rests on a library; the native path is a hand-written kernel or it is not
used.

### 5.5 The one genuinely new surface — segregated-proof data availability

Segregating the proof does not weaken any cryptographic property, but it **does** move the work
proof off the block body, so a node holding only a header+body has a valid-looking block whose work
is unconfirmed until the proof arrives. Because `matmul_digest` is self-declared (audit C1, OPEN),
a header alone remains non-authoritative; the mitigations are (i) the header-PoW spam throttle
(rate-limits header forgery), (ii) **proof-verified-before-creditable** (a block contributes chainwork
only after §3.3 passes), and (iii) assumevalid + archive serving for buried history. This is a real,
disclosed cost of the reversal from in-block proof, and it is why activation is gated on measured
propagation and archive availability (§6), not on arithmetic alone.

---

## 6. Activation gating & honesty

Everything stays **activation-disabled** (`nMatMulBMX4CDHeight = INT32_MAX` on every network) until
all of the following are measured/proven — no MAC/byte-count argument substitutes for a measurement,
because two prior model orderings in this program were already falsified:

**Must be measured/proven before activation:**
1. **Two-vendor M-t24 exactness at m = 2048** — the odd-target near-2²⁴ discriminator + boundary-pin
   vectors reproduced bit-for-bit on ≥ 2 vendors' frontier parts (5090 already PASSES; add a
   datacenter Blackwell / a second vendor). Emits `DEVICE_HIGH_MAGNITUDE_PASS`.
2. **Per-card ordering re-confirmed at the chosen m** on the *final* combine kernel — the D 1.54×
   B200/5090 figure was measured on the 25-GEMM reference combine; re-confirm it survives the
   production kernel and does not regress toward the C tie.
3. **Strassen/LCMA-aware difficulty (ASERT) calibration** — the m = 2048 combine is a larger,
   *more* Strassen-reducible square GEMM; `nMatMulBMX4CDAsertRescale{Num,Den}` MUST be calibrated to
   the **measured** LCMA/Strassen-accelerated combine cost on the path rational miners run, not the
   schoolbook `16nm²` count, or the enforced work is overpriced (audit F2). Non-uniform Strassen
   levels across the ladder slightly flatten the very ordering we engineer — disclosed, priced, not
   denied.
4. **32 MiB proof full-network propagation** under the §3 relay — request/response fetch latency,
   archive-peer availability, IBD re-fetch behavior, prune-window correctness, reorg replay.
5. **Difficulty rescale + fork calibration** — the D marginal nonce/s differs from C's; the one-time
   rescale is a single-population calibration (no reward tiering — the ladder is EMERGENT from
   throughput under one uniform difficulty, §0.7-(4)).

**Explicitly NOT claimed (honesty clause):**
- **NO per-dollar datacenter advantage.** The consumer 5090 wins ≈ 13× per rental-dollar at D; §1.2
  proves per-dollar inversion is structurally unreachable with a linear-sketch PoW against a 15–20×
  price gap. We ship per-*card* ordering and say so.
- **NO strong Hopper claim.** H100's 0.29×/0.22× is consistent with an IMMA-layout / cuBLASLt-12.4
  artifact, not a proven architectural ceiling; we do not assert Hopper is structurally excluded and
  do not price against it.
- **NO escape from §L.4.** The linear commitment's shortcut factor is 2.3× at D and can never reach
  1 at any transport-feasible m; the per-card gap is bounded by achievable tensor utilization
  (≤ ~5.4× peak), not by any residency/capacity cliff (which §L.4 proves does not exist).
- **NO claim from counts alone.** Enforced-MAC and payload figures are analytic; the *ordering* is a
  measurement-gated hypothesis until (2) re-confirms it on the production kernel.

---

## 7. Summary of concrete recommendations

| # | Decision | Value |
|---|---|---|
| Target | Ship per-card ordering; per-dollar unreachable | option (a) |
| Committed object | Deeper-commit profile, byte-identical to D encoding | b = 2, m = 2048, 32 MiB, ENC-BMX4C-D (enum 3, reinstated as live candidate) |
| m ladder | Launch point + reserved governed rungs | m = 2048 launch; m = 4096 / n = 8192-hold reserved, each measurement-gated |
| Proof carriage | Segregated prunable proof; commitment = existing `matmul_digest`; new `getmatmulproof`/`matmulproof`; binding `H(σ‖proof)==matmul_digest` before Freivalds; prune below `nMatMulProofPruneDepth`; archive peers + assumevalid for IBD; sketch excluded from `MAX_BLOCK_SERIALIZED_SIZE` | §3 |
| Validator | Per-profile `MatMulProfileParams{tile_b, sketch_rank_m, payload_bytes, …}`; b-parametric `ValidateDimsBMX4`; per-profile construction assert | §4 |
| Determinism/soundness | M-t24 (m-independent) and Freivalds ≤ 2⁻¹⁸⁰ preserved; vendor-neutral object; native path hand-written (not cuBLASLt), disclosed | §5 |
| Activation | Disabled until 2-vendor M-t24, re-confirmed ordering at m = 2048, LCMA-aware ASERT, 32 MiB propagation, prune/IBD tested | §6 |
