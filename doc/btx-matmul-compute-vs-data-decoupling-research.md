> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX MatMul — Decoupling Verified Compute Growth from On-Chain Data: Research Memo

*Status: RESEARCH MEMO (design study, not a spec edit, not an activation decision).
Companion to `doc/btx-matmul-v4-design-spec.md` (§D/§E/§I), `doc/btx-matmul-v4.2-consolidated-design.md`,
`doc/btx-matmul-v4-committed-object-redesign.md` (operand format; orthogonal to this memo),
`doc/btx-matmul-v4.2-longevity-threat-model.md` (the L0/L1 constitution this memo must be honest about),
and `doc/btx-matmul-v4.2-relay-hardening-design.md` (the 32 MiB relay problem this memo dissolves).
Written 2026-07-18.*

---

## 0. The question and the one-line answer

**Question.** BTX requires (1) per-block PoW compute that can grow indefinitely to track
frontier AI accelerators, and (2) total chain data — archive nodes included — that stays
~flat forever. Today these conflict: the stored/relayed proof is the sketch
`Ĉ = U·C·V ∈ F_q^{m×m}`, `8·m²` bytes, and `m` is precisely the knob that scales per-nonce
tensor work. Can compute and stored data be decoupled without breaking soundness or
determinism?

**Answer.** Yes, and the decoupling is structural, not a trick: **the sketch is a
deterministic function of the 182-byte header alone** (all of A, B, U, V derive from
header seeds — there is no external witness data in this PoW). The `8·m²` bytes are
therefore not *ledger data* at all; they are a **verification-cost cache**. The block
needs to carry only (a) the existing 32-byte commitment `matmul_digest` and (b) a
constant-size bundle of **Merkle-authenticated spot-check openings** (~15–31 KB,
independent of `n` and `m` up to log factors) that lets a CPU verifier check the
commitment in O(k·n²) without the full sketch. Under that change, `m` (and `n`, and
instance count) become pure compute-difficulty knobs with **zero effect on chain size**,
and archive storage can be driven to **O(headers)** in steady state by pruning even the
openings after burial, because any pruned proof is recomputable from the header forever.
Section 5 gives the migration sketch; Section 7 states exactly what is given up.

---

## 1. Codebase grounding: what is stored today, and why it is Θ(m²)

### 1.1 The committed object and its dual role

The header (182 bytes, `src/primitives/block.h:26,46-50`) carries
`nNonce64`, `matmul_digest` (32 B), `matmul_dim`, `seed_a`, `seed_b`. The consensus
digest is `matmul_digest = H(σ ‖ Ĉ)` where `σ = SHA256d(header-with-digest-zeroed…)`
and `Ĉ = U·C·V ∈ F_q^{m×m}`, `q = 2^61−1`, serialized as canonical little-endian
8-byte words — `8·m²` bytes total (`src/matmul/matmul_v4.h:152-159` `ComputeSketch`,
`:239-241` `SerializeSketch`, `:249-252` `ComputeSketchDigest`). The difficulty target
is applied to `matmul_digest` (`src/matmul/pow_v4.h:15-20,64`), so **the lottery ticket
is a hash over all m² sketch words**: a miner must materialize every entry of `Ĉ` per
nonce to learn its ticket. Marginal per-nonce work is
`W = 4n²m + 2nm² ≈ 2n³·(2/b)` integer MACs (design spec §I.4, line 992) —
≈ 7.7×10¹⁰ MACs at the mainnet point `n = 4096, b = 4, m = 1024`.

### 1.2 What is stored/relayed per block

- **ENC-S8 / ENC-BMX4C profiles (live):** the sketch travels **in-block** in the
  trailing `matrix_c_data` words (`src/pow.cpp:3641-3648`,
  `CheckMatMulProofOfWork_V4ProductCommitted`), i.e. every block body is ≥ 8 MiB
  (`m = 1024`, `sketch_payload_bytes = 8·m²` = 8,388,608 B). At 90 s spacing
  (`src/kernel/chainparams.cpp:330`, 350,400 blocks/yr) that is **≈ 2.67 TiB/yr** of
  chain growth from proofs alone. Headers are 182 B → 60.8 MiB/yr; the proof stream
  is ~44,000× the header stream.
- **ENC-BMX4C-D profile (parked):** `m = 2048`, 32 MiB, `proof_segregated = true` —
  carried out-of-band via the proof store (`src/matmul/matmul_proof_store.h:20-56`),
  chunked P2P relay (Stage 2d, because a 32 MiB `matmulproof` overflows the 24-bit
  BIP324 packet ceiling — `src/consensus/params.h:199-205`), prunable by default
  nodes but **retained in full by archive nodes** (`MatMulProofStore::OpenDiskBacking(…, archive=true)`,
  `IsArchive()`, `matmul_proof_store.h:66-79`). Archive growth: **≈ 10.7 TiB/yr**.

The per-profile shape is pinned in `Consensus::MatMulProfileParams`
(`src/consensus/params.h:178-184`): `tile_b`, `sketch_rank_m`,
`sketch_payload_bytes = 8·m²`, `proof_segregated`; instantiated by
`GetMatMulProfileParams(height)` (`params.h:805-841`) from the compile-time profile
constants `BMX4C_SKETCH_RANK_M = 1024` (`params.h:154`) and
`BMX4CD_SKETCH_RANK_M = 2048` (`params.h:161`). The DoS caps are sized to the same
quantity: `GetMatMulProofSizeCap = sketch_payload_bytes + overhead`
(`src/pow.cpp:3651-3655`) and `MATMUL_V4_MAX_PAYLOAD_WORDS = 2·(8192/4)²`
(`src/pow.cpp:189-197`).

### 1.3 Why the verifier needs all m² words (the exact coupling)

`CheckMatMulV4SketchVerifies` (`src/pow.cpp:3543-3614`) — reached from the in-block
path or, for segregated profiles, from `CheckMatMulV4SegregatedProof`
(`src/pow.cpp:3657-3713`, which first binds the store bytes via
`H(σ‖proof) == matmul_digest`) — consumes the full payload twice:

1. **Digest recompute:** `H(σ ‖ payload)` must equal `header.matmul_digest`
   (`pow_v4.h:76-77` `VerifySketch`). A hash over 8·m² bytes cannot be recomputed
   from fewer than 8·m² bytes.
2. **Freivalds LHS:** each of the R = 3 rounds (`pow_v4.h:35`) checks the bilinear
   identity `xᵗᵀ·Ĉ·yᵗ == (Uᵀxₜ)ᵀ·A·(B·(V·yₜ))` over F_q
   (`matmul_v4.h:254-271` `SketchFreivalds`) with Fiat–Shamir challenges from
   `H(σ‖H(payload))`. The RHS is O(n²) matvecs that never form C — but the **LHS
   is a full m×m bilinear form: it reads every sketch word.**

So the Θ(m²) storage is not an accident and not (for its current verification
algorithm) over-committing: the payload is simultaneously (i) the preimage of the
lottery ticket and (ii) the object the O(n²) verifier probes. **The knob that grows
compute (`sketch_rank_m`) is the same knob that grows `sketch_payload_bytes = 8·m²`.**
That is the entire conflict. Note the second knob, `n`, is *already* decoupled from
storage by design: spec §E.1/§0.3 mandates `m` stay fixed as `n` grows (`b` tracks
`n`; `params.h:143-153` and `AssertBMX4CConstructionInvariants` enforce it), so
`n: 4096 → 8192` quadruples W at constant 8 MiB. The D profile exists precisely
because the designers wanted more per-nonce tensor work *without* raising `n` — and
paid 4× storage for it.

### 1.4 The constitutional constraint this memo must flag

`doc/btx-matmul-v4.2-longevity-threat-model.md` (L0/L1 table, lines 351-352) pins as
**L0 — "fixed forever"**: the `SketchFreivalds` verifier structure and its O(n²) cost,
`q = 2^61−1`, R = 3, **the digest form `H(σ‖Ĉ)` and the Fiat–Shamir rule**, and the
single-thread verify budget (< 100 ms target / < 1 s ceiling) that caps `n ≤ 8192`
(design spec §D.5, lines 136-144, 436-437; `n ≥ 16384` excluded). Every option in
§3 that achieves flat storage changes what the digest is computed *over* — i.e., is
formally an **L0 amendment**, which the constitution equates with "a different coin."
This memo's position: requirement (2) as now stated (flat archive storage under
unbounded compute growth) was not an input to the L0 freeze; the freeze predates it
and enshrines the very coupling at issue. Adopting any option below is a
constitution-level hard fork (v5-class) and should be labeled as such, not smuggled
in as an L1 format version.

---

## 2. The two requirements, made quantitative

- **Compute growth (req. 1):** frontier AI compute stock grows ≈ 3.4×/yr
  (Epoch-class figure cited by the longevity doc, line 388). Difficulty (nBits →
  target on `matmul_digest`) absorbs *throughput* growth continuously without any
  size change. But the *work-shape* knobs — `n` (operand size, VRAM footprint) and
  `m` (per-nonce tensor volume / GEMM arithmetic intensity, `AI ∝ m`) — must also
  be able to rise so the workload keeps exercising frontier tensor cores rather
  than degenerating into a SHA/memory-bound job (the PR #89 lesson: at too-small
  `m`, H100/5090 = 0.40×, consumer silicon won — spec §K.2b, line 862).
- **Data flatness (req. 2):** target is O(1) bytes/block independent of `n, m`,
  ideally O(headers) for archives. Today: 8 MiB/block (2.67 TiB/yr) growing to
  32 MiB/block (10.7 TiB/yr) at the *first* compute-shape upgrade, and Θ(m²)
  thereafter — plus a P2P relay that already broke once at 32 MiB (BIP324 24-bit
  ceiling) and needed a chunking subsystem.

---

## 3. The decoupling techniques, evaluated

Throughout: `n = 4096, m = 1024, W ≈ 7.7×10¹⁰` MACs per nonce; verifier XOF
expansion of B is O(n²) ≈ 17 MB of SHA output (~50–150 ms single-thread with
SHA-NI, spec line 468) and is common to every option; F_q soundness per random
bilinear probe is ≤ 2/q ≈ 2^-60 (Schwartz–Zippel, spec §E.2).

### Option 1 — Re-derivable verification, store nothing ("digest-only + recompute")

Because A, B, U, V all expand from header fields, a verifier can recompute the
entire sketch via the miner's own optimal path
`ComputeSketchOptimal` (`matmul_v4.h:161-179`): cost W ≈ 7.7×10¹⁰ MACs, then check
`H(σ‖Ĉ) == matmul_digest` and the target. Store **zero** proof bytes; the chain is
headers + transactions.

- **Soundness:** perfect (deterministic equality) — strictly stronger than
  Freivalds. Error 0.
- **Prover cost:** unchanged (no proof to build at all; miner path is already this).
- **Verifier cost:** ≈ one nonce of mining work per block. GPU: sub-millisecond
  GEMM + XOF (trivial for any miner-class or datacenter validator; whole-chain IBD
  of 500k blocks ≈ 4×10¹⁶ MACs ≈ tens of seconds of GEMM on one H100 — the XOF
  SHA stream, ~8.5 TB, dominates at minutes-to-hours). CPU single-thread:
  ~1–2 s/block at n = 4096, ~4–8 s at n = 8192 — **violates the L0 < 1 s verify
  ceiling**, and scales linearly with the very knob (`m`) we want to grow.
- **DoS:** an invalid header costs O(n²m) to reject; the existing SHA header-PoW
  gate (`doc/btx-matmul-v4.2-header-pow-gate.md`, nBits-relative throttle) and the
  global expensive-verify budget (`nMatMulV4GlobalVerifyBudgetPerMin`, spec line
  599) bound the damage but the per-item cost is ~1000× today's.
- **Consensus/determinism:** trivial — pure integer, already the reference path.
- **PQ posture:** SHA-256 only. Perfect.
- **Invasiveness:** smallest possible (delete payload carriage; keep digest).
- **Precedent:** this is exactly the verification style of Komargodski–Weinstein,
  *Proofs of Useful Work from Arbitrary Matrix Multiplication* (2025) — proof is
  `(A, B, z)` with z a transcript hash below a threshold; the verifier *recomputes*
  z, O(n²·r) — i.e., the literature's newest matmul-PoUW also stores O(1) and pays
  verification in recompute. <https://eprint.iacr.org/2025/685.pdf>,
  <https://arxiv.org/html/2504.09971v3>

**Verdict:** sound and maximally simple, but as the *only* mechanism it breaks the
CPU-verifiability budget and makes tip validation GPU-classist. Keep it as the
**fallback layer** (it is what makes pruning-after-burial safe in every other
option), not the tip path.

### Option 2 — Succinct proofs (sum-check/GKR/STARK) over the matmul

The right benchmark is Thaler's special-purpose MatMult interactive proof
(CRYPTO 2013), not a general-purpose zkVM: for `C = A·B` it costs the prover
**T + O(n²)** (additive overhead only), communication **O(log n) field elements over
log n rounds**, verifier **O(n²)** (two χ-weighted vector–matrix–vector passes to
evaluate the multilinear extensions Ã, B̃ at the sum-check's random point) —
Table 1 of the lecture notes
(<https://people.cs.georgetown.edu/jthaler/OptimalMatMult.pdf>;
paper: <https://eprint.iacr.org/2013/351.pdf>, <https://arxiv.org/pdf/1304.3812>).
Applied to BTX's projected relation `Ĉ = (U·A)(B·V)`: sum-check over log(m)+…
rounds reduces a claim `C̃(r₁,r₂)` to evaluations `P̃(r₁,r₃), Q̃(r₃,r₂)` which the
verifier computes itself in O(n² + nm) from the seed-derived U, A, B, V (an MLE
evaluation of a product matrix is just a weighted vecᵀ·M·vec). Fiat–Shamir over
SHA-256 makes it non-interactive; soundness ≈ (2·log m)/q ≈ 2^-56; all arithmetic
is exact F_q integers — deterministic.

The catch is the **left end of the reduction**: the verifier needs the claimed
`C̃(r₁,r₂)` to be *bound to the header commitment*. That requires the per-nonce
committed object to be a polynomial commitment to Ĉ (hash-based to stay PQ:
FRI/BaseFold-family), whose opening proof is ~50–150 KB in practice (measured
STARK/FRI proof sizes: 45–150 KB across 2024–25 systems; Circle-STARK/Stwo ≈ 107 KB
— <https://arxiv.org/html/2512.10020v1>, <https://eprint.iacr.org/2025/1741>). And
the commitment itself (RS-encode + Merkle at blowup 2–8×) must be built **per
nonce** to produce the lottery ticket — multiplying the per-nonce non-GEMM
hash/NTT floor several-fold, which directly erodes the wall-time-GEMM-majority
the whole v4.1 profile fights for. A general SNARK/zkVM route is strictly worse:
10²–10⁵× prover overhead would convert the PoW into a proof-generation contest
(hash/NTT-bound), inverting the economic thesis; pairing-based SNARKs additionally
fail the PQ-conservative posture. GKR (<same lecture notes, "Other Protocols">)
becomes relevant only if depth-chained matmuls (Option 5c) are ever adopted.

- **Soundness:** full (every accepted block committed the true Ĉ everywhere),
  ~2^-50–2^-60 per FRI/sum-check parameters. Provable, standard (ROM).
- **Prover:** +O(n²)–O(m² log m) per *winning* block (fine) but 2–8× per-nonce
  commitment hashing (the real cost).
- **Verifier:** O(n²) + ~10⁵ hashes. Inside budget.
- **Storage:** ~60–160 KB/block, O(polylog) in n, m. Flat in the required sense.
- **Invasiveness/consensus risk:** highest of all options — a full FRI stack
  (NTT domain over F_q, folding parameters, queries) becomes consensus-normative;
  large new determinism/implementation surface; hardest to audit.

**Verdict:** the theoretically complete answer, and the only one giving *full*
(non-probabilistic) work-object soundness at O(polylog) size — but it is the most
invasive, and its per-nonce commitment overhead works against the GEMM-share goal.
Hold as the eventual upgrade if Option 4's probabilistic enforcement is ever judged
insufficient; do not build first.

### Option 3 — Optimistic verification / fraud proofs

Store only `matmul_digest`; accept blocks unverified; allow a challenger to
trigger an interactive bisection dispute (Arbitrum-style: multi-round dissection
makes on-chain dispute cost roughly independent of computation length; challenge
window ≈ 6.4 days on Arbitrum One —
<https://docs.arbitrum.io/how-arbitrum-works/optimistic-rollup>,
<https://docs.arbitrum.io/how-arbitrum-works/bold/gentle-introduction>,
<https://medium.com/l2beat/fraud-proof-wars-b0cb4d0f452a>).

**Verdict: reject for base-layer PoW.** Fraud proofs presuppose an already-agreed
ordering/settlement layer to adjudicate the dispute; here the disputed object *is*
chain selection itself. A fork-choice rule that cannot classify a tip as valid at
acceptance time is not Nakamoto consensus: miners would build on unverified work,
reorg risk becomes unbounded within the window, and the challenged witness (the
8–32 MiB sketch) still needs guaranteed availability — reintroducing the very data
problem, now adversarially timed. The only salvageable fragment is unobjectionable
and subsumed by Option 1: any node may *lazily* verify deep history because the
witness is recomputable from headers.

### Option 4 — Fixed-size commitment + spot-check openings (RECOMMENDED)

**First, the prompt's sharpest question, answered against the code: is the m×m
sketch over-committing? Could the block store only k Freivalds inner products
(O(k) field elements) whose challenges the verifier re-derives?** Not naively.
Freivalds' per-round error is 1/|F| independent of n (Freivalds 1979; see
<https://arxiv.org/pdf/1705.10449> for the classical analysis) — so k scalars
`s_r = x_rᵀ·Ĉ·y_r` would indeed certify *correctness* with error (2/q)^k. But in
this PoW the sketch is not only a correctness witness; it is the **work object**:
the lottery ticket `H(σ‖Ĉ)` forces the miner to materialize all m² entries per
nonce. If the block stored only k inner products with challenges derived from the
header/σ (pre-commitment), a miner would compute each `s_r` directly as
`(Uᵀx_r)ᵀ·A·(B·(V·y_r))` — O(k·n²) matvecs, **never computing Ĉ at all** — and
grind a fake digest for free. Fiat–Shamir requires commitment-before-challenge,
and the commitment must cover all m² entries. So: Θ(m²) is *not* over-committing
as a commitment; it **is** over-committing as *relayed/stored data*. The fix is to
relay the commitment (32 B, already in the header) plus a constant number of
**authenticated openings**, not the object.

**Construction (concrete).**

- Lay out Ĉ (row-major m×m F_q words, exactly today's `SerializeSketch` bytes) as
  a grid of **8×8 tiles** (512 B each; 16,384 tiles at m = 1024). Build a binary
  SHA-256 Merkle tree over the tiles with domain-separated leaf/node tags and the
  tile index bound into each leaf (excludes CVE-2012-2459-class mutations).
  Root `R_Ĉ` (32 B).
- **Header commitment (same field, new preimage):** `matmul_digest = H(σ ‖ R_Ĉ)`.
  Target check unchanged, applied to `matmul_digest`.
- **Challenge derivation (Fiat–Shamir, post-commitment):** k tile indices from a
  domain-tagged XOF of `matmul_digest` (which already binds σ — nonce-fresh — and
  every leaf through R_Ĉ). Deterministic; duplicates deduped canonically.
- **Stored/relayed proof (the entire out-of-band object):**
  `R_Ĉ ‖ k × (tile bytes ‖ Merkle path)`. At m = 1024, depth 14:
  k = 16 → 32 + 16·(512 + 448) = **15.4 KB**; k = 32 → **30.8 KB**. Small enough
  to carry **in-block forever** (no segregated path, no chunking, no proof store).
- **Verification cascade** (replaces `SketchFreivalds` for this profile):
  1. `H(σ‖R_Ĉ) == matmul_digest` (one hash) and target check — instant.
  2. Merkle-verify the k openings against R_Ĉ (k·14 hashes ≈ microseconds).
  3. For each opened 8×8 tile at block-row I, block-col J: expand rows
     `u_{8I..8I+7}` of U and columns `v_{8J..8J+7}` of V from the template seeds
     (O(n) each), compute the 8 P-rows `u_iᵀ·A` and 8 Q-columns `B·v_j`
     (16 vec–mat products, O(n²) each), combine to the 64 true entries mod q
     (O(64n)), and compare **exactly** to the opened tile. Any mismatch →
     consensus-fail; abort on first failure (DoS-bounds a garbage block to
     ~2.7×10⁸ MACs + the XOF, ≈ today's rejection cost).

**Costs.**

- **Verifier:** k = 16 tiles → 256 vec–mat passes ≈ 4.3×10⁹ MACs ≈ 50–200 ms
  single-thread AVX-512 VNNI, plus the unchanged ~50–150 ms XOF — total within
  the same envelope as today's ≈ 95–200 ms (spec line 430/476), inside the < 1 s
  L0 ceiling with margin. **Crucially, this cost is O(k·n²) — independent of m.**
- **Prover, per nonce:** GEMM unchanged (W); hashing = tile-leaf hashing of the
  same 8·m² bytes (131k compressions) + 16,383 internal nodes ≈ **1.12×** today's
  flat 8 MiB digest hash. The per-nonce SHA floor is essentially unchanged (this
  is why leaves are 512 B tiles, not single words — single-word leaves would be
  ~15× today's hashing and damage the GEMM-majority goal).
- **Prover, per winning block:** assemble k openings — microseconds.

**Soundness (what is provable vs. what is an assumption).**

- *Correctness at opened positions:* exact (recomputed ground truth over F_q),
  error 0. No Schwartz–Zippel term remains; the 2/q Freivalds bound is replaced
  by deterministic equality on a random subset.
- *Work enforcement (probabilistic — the honest caveat):* the chain no longer
  guarantees every unopened entry is correct. A miner who correctly computes a
  fraction f of tiles (e.g., computes f·m of the Q = B·V columns, garbage
  elsewhere) still pays the full hashing per nonce, wins the lottery at the
  normal rate, but survives the k post-commitment spot checks with probability
  f^k. Expected cost per accepted block scales as
  `[f·C_var + C_fixed]/f^k`, minimized at f = 1 for any k ≥ 2; at k = 16,
  shaving 10% of the variable work (f = 0.9) multiplies effective difficulty by
  0.9^-16 ≈ 5.4× — cheating is strictly and steeply unprofitable. Adaptive
  attacks fail structurally: indices derive from the digest, which derives from
  every leaf, so "fix the opened tiles after winning" changes the root, the
  digest, and the lottery draw itself. This f^k argument is standard
  (sampling-based verification, same family as data-availability sampling and
  Ligero-style column checks) and is *provable* under the random-oracle model
  for the index derivation; the residual assumption — "computing true Ĉ entries
  requires doing the GEMM" — is exactly today's §E.3 work-binding assumption,
  unchanged (see redesign doc §2, "what Freivalds does NOT certify").
- *Commitment binding:* SHA-256 collision resistance (Grover-only quantum
  degradation). **PQ posture: identical to today — SHA-256 only, no new
  assumptions.** (Contrast pairing-SNARKs: excluded; FRI/STARK: PQ-fine but
  heavier.)

**Determinism/consensus risk:** low — every operation is existing integer/hash
machinery (`MatVecMul`-style F_q passes, SHA-256); no floats, no new field, no
NTT. New golden vectors required (hard fork), as with any committed-object change
(redesign doc §6 classification).

**Invasiveness:** moderate and *subtractive* on net: `ComputeDigest` gains a tree
build; `VerifySketch` is replaced by the 3-step cascade; the entire segregated
relay (Stage 2b/2d chunking, proof store as a consensus dependency, 24-bit-packet
workaround, `GetMatMulProofSizeCap` sizing) collapses into ordinary in-block
carriage of ~15–31 KB.

### Option 5 — Scaling compute without scaling the committed object

Orthogonal knobs, all compatible with (and mostly requiring) Option 4:

- **(a) Grow n at fixed m** — already the design's own rule (b tracks n,
  `params.h:146-153`): W ∝ n², payload flat even today. Capped by the O(n²)
  verify/XOF budget at n ≤ 8192 (L0), independent of storage. Keep.
- **(b) Grow m at fixed n** — today: +Θ(m²) storage (the D profile's 4×); under
  Option 4: **zero** storage growth (path depth +2 hashes per doubling), **zero**
  verifier growth (spot checks are O(n²) regardless of m), prover W ∝ m. This is
  the knob the decoupling unlocks. Its true ceiling becomes the per-nonce hash
  floor, not storage: hashing the 8·m² sketch bytes grows ∝ m² while GEMM grows
  ∝ m, so GEMM MACs per hashed byte = n²/(2m) + n/4 — at n = 4096 the hash stage
  overtakes GEMM wall-time on frontier parts somewhere around m ≈ 8–16k. Practical
  window m ∈ {1024 … 4096} at n = 4096; retarget n upward to re-open it.
- **(c) Instance aggregation** — j independent (A_i, B_i) per nonce, one tree
  over j·m² tiles: W ∝ j, storage flat, verifier unchanged (k spot checks total).
  Equivalent to (b) with better hash scaling (floor ∝ j·m², same as b) and
  smaller working-set granularity; also the natural way to scale *within* a
  profile without touching tile geometry. The existing CRT k-lane variant (spec
  §B.3, line 982) is the same idea but was rejected because it scaled *verify*
  cost ×k — under Option 4 it no longer does.
- **(d) Iterated/depth-chained matmuls** (C₁ = A·B, C₂ = f(C₁)·B′, …): W ∝ depth
  at constant commitment, but a spot-checked entry of layer t is no longer
  O(n²)-recomputable (it depends on the full previous layer); verification needs
  GKR-style layer reduction (Option 2 machinery). **Speculative — park.** Only
  worth revisiting if sequential (latency-bound) work is ever wanted, which cuts
  against the parallel-GEMM thesis anyway.

### Comparison table

| | Stored/blk | Grows with n,m? | Verifier (1-thread) | Prover Δ/nonce | Soundness | PQ | Invasiveness |
|---|---|---|---|---|---|---|---|
| Today (C / D) | 8 / 32 MiB | **Θ(m²)** | ~95–200 ms | — | 2^-180 F-S Freivalds + full digest | SHA-256 | — |
| O1 recompute | **0** | no | **1–8 s** ✗ (GPU: ms) | none | exact | SHA-256 | tiny |
| O2 sum-check+FRI | ~60–160 KB | polylog | ~100–300 ms | 2–8× hash/NTT floor | full, ~2^-50 | hash-based ✓ | very high |
| O3 optimistic | ~32 B (+DA) | no | lazy | none | breaks fork choice ✗ | — | high |
| **O4 Merkle spot-check** | **15–31 KB** | **O(log): +64 B/opening per m-doubling** | ~100–350 ms | **1.12× hash** | exact at k spots; work-enforcement f^k (k=16→ steep) | SHA-256 ✓ | moderate |
| O5b/c on top of O4 | +0 | no | +0 | W ∝ m·j (intended) | inherits O4 | ✓ | small |

---

## 4. Ranked options

1. **Option 4 (Merkle-committed sketch + k Fiat–Shamir spot-check openings), with
   Option 1 as the historical/fallback layer and Option 5(a,b,c) as the compute
   knobs.** Best joint fit: flat storage, budget-compliant CPU verify, per-nonce
   overhead ~12% hashing, no new cryptographic assumptions, and it *deletes* the
   segregated-relay subsystem.
2. **Option 2 (sum-check + hash-based PCS)** as a designed successor if full
   soundness of the committed object is later required (e.g., if the sketch ever
   acquires downstream consumers beyond PoW). Do not build first.
3. **Option 1 alone** — acceptable only if CPU tip-verification is abandoned as a
   requirement; keep as the pruning/IBD backstop regardless.
4. **Option 3** — rejected for base-layer consensus.

---

## 5. Recommendation and migration sketch

**Adopt Option 4 as profile family "ENC-*-MC" (Merkle-committed), a v5-class hard
fork** (it amends L0 items: digest preimage and verifier structure; say so
openly). Concretely:

1. **`Consensus::MatMulProfileParams` (`params.h:178-184`):** replace
   `sketch_payload_bytes` / `proof_segregated` with
   `commitment{FLAT_SKETCH, MERKLE_TILED}`, `tile_rows=tile_cols=8`,
   `spot_checks_k` (16 mainnet; 4 regtest), `proof_size_cap` (≈ 40 KB constant).
   `sketch_rank_m` stays but no longer implies a payload; add
   `instances_j` for Option 5c. `GetMatMulProfileParams` keys the new profile off
   a height gate exactly like ENC-BMX4C today.
2. **Header: unchanged layout (182 B).** `matmul_digest = H(σ ‖ R_Ĉ)` — same
   field, new preimage. σ derivation, seeds, nonce rules, I1′ template scoping
   all untouched.
3. **Miner (`ComputeDigest`, `pow_v4.h:64` / `matmul_v4_batch`):** after the
   existing sketch serialization, hash 512-B tiles → Merkle root → digest.
   Batched miner fuses tile-leaf hashing into the existing per-nonce digest
   pass (same bytes, +12% compressions).
4. **Verifier:** new `VerifyCommittedSketch(header, n, k, proof, digest_out)`
   implementing §3-Option-4's cascade; wired where
   `CheckMatMulV4SketchVerifies` (`pow.cpp:3543`) routes by profile today. The
   O(n²) building blocks (`ExpandProjector` rows/cols, F_q vec–mat, mod-q
   combine) already exist. Fail-fast ordering: binding → target → paths → tiles.
5. **Carriage:** proof travels in-block in `matrix_c_data` (~15–31 KB — under
   every message limit); `MATMUL_V4_MAX_PAYLOAD_WORDS`, `GetMatMulProofSizeCap`
   shrink to the constant cap. **Retire** the segregated path at MC heights:
   proof store, `getmatmulproof`/`matmulproof`/`mmproofchunk`, Stage 2c/2d — the
   D profile's 32 MiB rationale disappears (an "MC-D" profile with m = 2048
   stores the same 15–31 KB).
6. **Difficulty/economics:** ASERT unchanged on the digest target. One-time
   rescale for the +12% hash floor per the standard B2b procedure. The
   frontier-GEMM thesis is preserved by construction: per-nonce work remains the
   same dense GEMM W (now growable via m/j without storage penalty), the
   non-GEMM floor moves ~1.12×, and no proof-generation workload is added to the
   inner loop (the k openings are per-winner, not per-nonce).
7. **Golden vectors, C-1/HM vectors, cross-vendor re-pin, external review of the
   f^k enforcement analysis** — full redesign-§6 migration discipline applies.
8. **Retarget cadence (req. 1 over time):** difficulty absorbs throughput
   continuously; every ~2–4 years a *shape* retarget (L1-style reviewed fork)
   raises m or j (storage-free under MC) and, when VRAM/verify budgets allow,
   n — tracking the ~3.4×/yr frontier envelope in W while bytes/block stay
   constant. A pre-pinned height ladder n(h)/m(h) is possible but not
   recommended; hardware forecasts in this program have been falsified twice
   (§K.2b) — keep shape retargets measurement-gated.

---

## 6. Explicit answer: can archive storage be O(headers)?

**Yes — in steady state, exactly O(headers) (+ transactions), independent of
compute scale — because this PoW's witness is uniquely recomputable.** The
decisive structural fact: Ĉ is a deterministic function of the header (seeds,
σ, U, V, A, B all header-derived — `matmul_v4.h:89-142`). Unlike transaction
data, the proof carries **zero information** not already in the 182-byte header;
it only saves verification work. Therefore:

- **Under Option 4:** nodes keep openings for a rolling window (fast CPU
  validation at the tip and for reorgs); after burial depth D (e.g., 2016
  blocks), even archives may drop them. A historical block is re-auditable
  forever at O(n²m) recompute (Option 1; ms on any GPU, ~1–2 s CPU) — or
  cheaply at O(k·n²) if anyone retained/regenerates the openings (they are
  reproducible too: recompute Ĉ → rebuild tree → re-derive the same indices).
  Steady-state archive = headers + txs + O(window). Chain growth from PoW:
  **60.8 MiB/yr** (headers) vs 2.67–10.7 TiB/yr today — a ~10⁴–10⁵× reduction.
- **Even today, without any fork,** the same holds in principle: an archive
  node could prune every sketch and re-derive on demand — nothing is lost;
  `MatMulProofStore`'s archive role is a bandwidth/CPU courtesy, not a ledger
  necessity. The fork is needed only to keep *cheap* verification available
  once m grows and to shrink relay.
- **What is given up:** (i) *cheap CPU-only re-audit of arbitrary deep history*
  — a full-chain CPU-only re-verification becomes days of VNNI GEMM (or
  minutes-to-hours on one GPU; or nodes retain the 5–10 GiB/yr of openings and
  keep it cheap — an optional role, not a consensus one); (ii) *unconditional
  per-entry soundness of unopened sketch regions* (Option 4's f^k enforcement
  replaces Freivalds' global 2^-180 — quantified in §3; recoverable later via
  Option 2); (iii) *the L0 freeze as written* — this is an honest constitutional
  amendment. Nothing about data availability is given up, because there is no
  data to make available.

---

## 7. Sources

**Code (pinned in this memo):** `src/consensus/params.h:143-225, 805-841`;
`src/pow.cpp:184-226, 3543-3743`; `src/matmul/matmul_v4.h`; `src/matmul/pow_v4.h`;
`src/matmul/freivalds.{h,cpp}`; `src/matmul/matmul_proof_store.h`;
`src/primitives/block.h:26-77`; `src/kernel/chainparams.cpp:330`.
**Repo docs:** `btx-matmul-v4-design-spec.md` (§D.5, §E.1-E.3, §I.4, §L.4),
`btx-matmul-v4-committed-object-redesign.md`, `btx-matmul-v4.2-longevity-threat-model.md`,
`btx-matmul-v4.2-relay-hardening-design.md`, `btx-matmul-v4.2-header-pow-gate.md`,
`freivalds-algorithm-analysis.md`.

**External:**
- J. Thaler, *Time-Optimal Interactive Proofs for Circuit Evaluation* (CRYPTO'13):
  <https://eprint.iacr.org/2013/351.pdf>, <https://arxiv.org/pdf/1304.3812>;
  MatMult protocol lecture notes (Table 1: O(log n) comm., log n rounds, V O(n²),
  P T+O(n²)): <https://people.cs.georgetown.edu/jthaler/OptimalMatMult.pdf>;
  survey: <https://people.cs.georgetown.edu/jthaler/blogpost.pdf>
- I. Komargodski, O. Weinstein et al., *Proofs of Useful Work from Arbitrary
  Matrix Multiplication* (2025): <https://eprint.iacr.org/2025/685.pdf>,
  <https://arxiv.org/html/2504.09971v3>
- M. Ball, A. Rosen, M. Sabin, P. N. Vasudevan, *Proofs of Useful Work* (2017):
  <https://eprint.iacr.org/2017/203.pdf>; *Ofelimos* (CRYPTO'22):
  <https://link.springer.com/chapter/10.1007/978-3-031-15979-4_12>
- Freivalds' algorithm background and Gaussian variant:
  <https://arxiv.org/pdf/1705.10449>,
  <https://www.geeksforgeeks.org/dsa/freivalds-algorithm/>
- zkMatrix (batched proofs for committed matmul):
  <https://eprint.iacr.org/2024/161.pdf>
- STARK/FRI proof-size and PQ data: <https://arxiv.org/html/2512.10020v1>
  (45–150 KB), <https://eprint.iacr.org/2025/1741> (on-chain STARK+PQC
  measurement, ~107 KB Stwo proofs)
- Optimistic fraud proofs / dispute games:
  <https://docs.arbitrum.io/how-arbitrum-works/optimistic-rollup>,
  <https://docs.arbitrum.io/how-arbitrum-works/bold/gentle-introduction>,
  <https://medium.com/l2beat/fraud-proof-wars-b0cb4d0f452a>
