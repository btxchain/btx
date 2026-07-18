# BTX MatMul — Deterministic Next-Generation Committed Object: Design Memo

*Status: DESIGN MEMO (v5-class proposal study; not a spec edit, not an activation
decision). Successor to `doc/btx-matmul-compute-vs-data-decoupling-research.md`
(whose Option 4 is REJECTED here — see §2.3 for the disqualification and §2.4 for
the commitment-grinding break that makes it not merely weak but broken). Companion
to `doc/btx-matmul-v4-design-spec.md`, `doc/btx-matmul-v4.2-consolidated-design.md`,
`doc/btx-matmul-v4.2-longevity-threat-model.md` (L0 constitution — this memo
proposes an L0 amendment and says so openly, §8.8). Written 2026-07-18.*

---

## 0. Scope and the one-line answer

**Question.** Design the next-generation PoW committed object such that ALL of the
following hold simultaneously: (1) deterministic/exact work-enforcement — block
acceptance implies the full required computation was performed, exactly or with
cryptographically negligible error; (2) flat on-chain data (O(1) per block,
O(headers) archive) as compute scales; (3) compute that keeps scaling toward
frontier GEMM hardware; (4) verification much cheaper than mining; (5)
PQ-conservative, consensus-deterministic cryptography.

**Answer.** All five are simultaneously achievable. The recommended committed
object (**"ENC-SC", §7**) replaces the relayed 8 MiB sketch with a **canonical
hash commitment to the low-degree extension of Ĉ** (32-byte root in the existing
`matmul_digest` preimage) plus a **~64–200 KB, whole-object, Fiat–Shamir
sum-check + Circle-FRI proof** carried in-block and prunable after burial —
soundness error ≈ 2⁻⁸⁰ (cryptographic, tunable), verifier ≈ 150–400 ms
single-thread CPU (O(n²+nm), *independent of the compute knob m up to an O(nm)
term*), SHA-256-only assumptions, and archive storage O(headers) because every
byte remains recomputable from the header forever. The price is a measured
+30–45 % per-nonce SHA floor and the largest consensus-normative surface BTX has
ever added. The fallback that never breaks is digest-only full recompute (§4.A):
exact, zero bytes, but verify = one nonce of mining work. §9 states the trade
honestly.

---

## 1. The determinism bar for work-enforcement

### 1.1 Three separable properties called "deterministic"

The word is overloaded; the requirements use all three senses. A candidate must
satisfy all three:

- **D1 — Consensus determinism.** The verifier is a *pure function* of
  (header, relayed bytes): every honest node computes bit-identical accept/reject.
  No floats, no platform-dependent reduction order, no interactive randomness —
  all challenges via Fiat–Shamir from committed data. (The current v4 verifier
  already satisfies D1: `SketchFreivalds` challenges derive from
  `H(σ‖H(payload))`, `src/matmul/matmul_v4.h:254-271`.)

- **D2 — Exact-or-negligible work-enforcement soundness.** Define the soundness
  error ε as the maximum, over all provers whose committed object deviates
  anywhere from the unique consensus-mandated value, of the probability (over the
  random-oracle instantiation of the Fiat–Shamir hash) that the verifier accepts.
  The bar: **ε must be cryptographically negligible — ε ≤ ≈2⁻⁶⁰, and improvable
  exponentially by raising a security parameter whose marginal verifier cost is
  O(1)–O(polylog), not O(n²) per increment.** "Exact" (ε = 0, deterministic
  recompute) trivially qualifies.

- **D3 — Full-object lottery binding (the invariant Option 4's break teaches,
  §2.4).** Every bit of the lottery-ticket preimage must be either (a) derived
  from the header by consensus rule, or (b) constrained by the verifier to its
  **unique** consensus-mandated value with error ≤ ε. Corollary: the map
  `(header, nonce) → valid lottery ticket` is a *function* (zero prover degrees
  of freedom — no salts, no zk blinding, no unopened free positions), and
  evaluating it costs the full per-nonce work W. Without D3, a miner grinds the
  free bits at SHA speed and the PoW ceases to price GEMM at all.

### 1.2 Why 2/q-Freivalds and STARK-negligible pass, and f^k fails

- **Today's Freivalds:** per-round error ≤ 2/q ≈ 2⁻⁶⁰ (Schwartz–Zippel on a
  total-degree-2 bilinear identity over q = 2⁶¹−1); R = 3 rounds → ε ≤ 2⁻¹⁸⁰.
  Each extra round costs O(n²) — expensive per increment, but the bound is
  *already* negligible at fixed tiny R because the error base is 1/q, a
  **field-size** quantity. The verifier also reads *all* m² committed words
  (digest recompute + the m×m bilinear LHS), so D3 holds. **Passes D1+D2+D3.**
  The current design is not the problem; its Θ(m²) relay is (requirement 2).

- **FRI/STARK/sum-check:** ε ≈ 2⁻λ where λ is set by query count/grinding/field
  extension; each unit of λ costs O(1) extra hashes for the verifier. The check
  constrains the committed polynomial **everywhere** (proximity + evaluation
  binding), so D3 holds. **Passes.** The distinction that matters: a FRI "query"
  costs the verifier a few Merkle paths (~KB, ~20 hashes), so λ = 80–128 is
  cheap; a recompute-spot-check "query" costs the verifier O(n²) ground-truth
  recomputation, so k is verify-budget-capped at ~16–32 forever.

- **f^k spot-checks (prior memo Option 4):** a miner computing fraction f of the
  object passes with probability f^k — at f = 0.9, k = 16: **0.185**; at
  f = 0.99: **0.85**. This is a *constant*, not a negligible function of any
  affordable security parameter, because k cannot grow past the verify budget.
  It is an economic deterrent ("cheating is unprofitable in expectation"), not a
  soundness bound; Bitcoin's validity rule is not an expectation. **Fails D2.**
  And it fails D3 far more catastrophically — §2.4.

**Restated bar, precisely:** *acceptance of a block must imply, except with
probability ≤ 2⁻⁶⁰-class negligible over the FS oracle, that the committed
object equals the unique value determined by (header, nonce) — i.e., that the
full mandated computation was performed. No constant-probability
"compute-less-and-get-lucky" path may exist, and no lottery-preimage bit may be
grindable without redoing the full per-nonce work.*

---

## 2. Code grounding, prior work, and the disqualification

### 2.1 What exists (pinned)

- Committed object: `Ĉ = U·C·V ∈ F_q^{m×m}`, `q = 2⁶¹−1`, computed as
  `(U·A)(B·V)` (`ComputeSketchOptimal`, `src/matmul/matmul_v4.h:161-179`);
  serialized 8·m² B (`SerializeSketch`, `:239-241`) = **8 MiB** at mainnet
  n = 4096, b = 4, m = 1024 (`Consensus::MatMulProfileParams`,
  `src/consensus/params.h:178-184`, `GetMatMulProfileParams` `:805-841`).
- Lottery: `matmul_digest = H(σ‖Ĉ)` vs nBits target
  (`ComputeSketchDigest` `:249-252`; target check `src/pow.cpp:3614-3615`).
  σ = SHA256d(header) binds `nNonce64` (`DeriveSigma`, `matmul_v4.h:89-93`);
  operand B is **nonce-fresh**, A/U/V template-scoped (I1′,
  `DeriveOperandSeed`/`DeriveProjectorSeeds`, `:109-135`; seeds
  `DeterministicMatMulSeedV2/V3`, `src/pow.cpp:76-115`).
- Verifier: `CheckMatMulV4SketchVerifies` (`src/pow.cpp:3543-3618`) — payload
  canonicality, digest recompute over all 8·m² bytes, R = 3 Fiat–Shamir
  Freivalds rounds, O(n²), ≈ 95–200 ms single-thread. Per-nonce miner work
  W = 4n²m + 2nm² ≈ **7.73×10¹⁰ MACs**.
- Storage today: 8 MiB/block in-block (ENC-S8/BMX4C) ≈ 2.67 TiB/yr at 90 s
  spacing; 32 MiB segregated for the parked D profile (m = 2048) ≈ 10.7 TiB/yr
  archive. Headers: 182 B → 60.8 MiB/yr.

### 2.2 The two structural facts everything below builds on

1. **The proof carries zero information not in the header.** A, B, U, V, σ, and
   hence Ĉ are deterministic functions of the 182-byte header
   (`matmul_v4.h:89-142`). Whatever is relayed is a *verification-cost cache*,
   never ledger data. Archive-O(headers) is therefore always achievable in
   principle; the only question is the cost of *cheap* verification.
2. **Commit-then-challenge is mandatory, so the miner must materialize Θ(m²)
   per nonce regardless.** If challenges were derivable pre-commitment (from σ
   alone), a miner would evaluate the k probed values directly in O(k·n²)
   without any GEMM (prior memo §3-Option-4 intro). So the *computation* of the
   full object per nonce is non-negotiable; only its **relay** is negotiable.

### 2.3 Disqualified up front: sampled-opening designs (prior memo Option 4)

Merkle root + k Fiat–Shamir recompute-openings has work-enforcement gap f^k —
a constant (0.185 at f = 0.9, k = 16). **Fails D2. Disqualified** per the bar in
§1.2 regardless of anything else. But the situation is strictly worse:

### 2.4 The commitment-grinding break (why Option 4 is broken, not just weak)

The lottery in Option 4 is `H(σ‖R)` where **R is a miner-supplied Merkle root
whose unopened leaves are unconstrained**. Attack, at fixed nonce:

1. Compute the true sketch ONCE (one unit of GEMM work W). Build the tree.
2. Pick one tile (512 B of 8 MiB; 1 of 16,384 leaves) and fill it with garbage.
3. Grind the garbage bytes: each tweak → new leaf → new root R′ → new
   `H(σ‖R′)` → a **fresh lottery draw AND freshly re-derived challenge
   indices**, at SHA speed (≈15 compressions per draw: one 512-B leaf + a
   14-deep path + the digest), with **zero additional GEMM**.
4. When a draw wins, the k = 16 uniformly-drawn openings miss the single garbage
   tile with probability (1 − 1/16384)¹⁶ ≈ **99.90 %**. Even conditioning on
   winning draws, almost every winner is acceptable.

Effective cost per accepted block: ≈ 1 GEMM unit + pure hashing, versus the
honest ≈ 1/p GEMM units. **The PoW collapses to hash-grinding one tile.** The
f^k analysis in the prior memo silently assumed the miner grinds *nonces*
(re-doing the nonce-fresh work per draw); it missed that the miner-controlled
commitment itself is a second, GEMM-free grinding channel through its
unconstrained positions. Adaptivity of the challenge indices does not help —
the indices move with every tweak, but 99.9 % of index sets are winners for the
attacker.

**Design principle (elevated to invariant D3, §1.1):** the lottery ticket must
be bound to a **full-object** work check — every committed word enforced to its
unique value, exactly or with negligible error — so that no fresh valid lottery
ticket exists without fresh full per-nonce compute. Today's Freivalds has this
(it reads every word, and any deviation is caught with 1−2⁻¹⁸⁰). A sampled
check over a miner-controlled commitment with free unopened positions does not,
**and can never be repaired by raising k**: any k < m² leaves free bits, and k
recompute-openings cost the verifier k·O(n²). Sampling may only ever be *added
to* a retained full-object check, never substituted for it.

The two required invariants for every candidate below:

- **I-N (nonce-fresh operands):** the per-nonce marginal work includes the full
  B-dependent pipeline (expand B, B·V, combine, commitment) — the existing I1′
  rule, unchanged.
- **I-F (full-object lottery binding = D3):** the committed object is a
  **canonical, deterministic function of (header, nonce)** and the verifier
  constrains **all** of it with error ≤ ε. One nonce → one valid ticket.

### 2.5 L0 status

The longevity constitution (`btx-matmul-v4.2-longevity-threat-model.md:351`)
freezes as L0: the `SketchFreivalds` verifier structure and O(n²) cost,
q = 2⁶¹−1, R = 3, the exact-integer commitment, the digest form `H(σ‖Ĉ)` and
FS rule, and the <100 ms/<1 s single-thread verify budget. Every candidate here
changes the digest preimage and/or verifier structure ⇒ **every candidate is an
L0 amendment ⇒ a v5-class hard fork**, which the constitution equates with "a
different coin." This memo does not smuggle; it proposes the amendment openly,
with the flat-data requirement as the new constitutional input that the L0
freeze predates (prior memo §1.4). What this memo *preserves* from L0
deliberately: q = 2⁶¹−1, the exact-integer commitment ("no operation on the
committed path may ever round"), σ nonce-freshness, price-independence, the
verify budget, and the hardness floor.

---

## 3. Cost model (shared by all candidates)

Mainnet point n = 4096, m = 1024, q = 2⁶¹−1. Per nonce, honest miner:

| Stage | Cost | Nature |
|---|---|---|
| Expand B (nonce-fresh XOF) | n² B = 16.8 MB SHA ≈ 262k compressions | SHA |
| B·V, combine (P template-cached) | W ≈ 7.73×10¹⁰ MACs | GEMM (tensor) |
| Commitment/digest over Ĉ | 8·m² = 8.4 MB SHA ≈ 131k compressions | SHA |
| **Total non-GEMM floor** | **≈ 393k compressions ≈ 25.2 MB SHA** | |

Verifier today: XOF A+B ≈ 50–150 ms + 3×O(n²) Freivalds ⇒ ≈ 95–200 ms
single-thread. CPU int8 throughput (AVX-512 VNNI): ~10¹¹ MAC/s-thread ⇒ full
recompute of W ≈ 0.8–2 s/thread (+ overheads); H100-class: W ≈ 40–80 µs of
tensor time, SHA/XOF-bound in practice. Frontier compute stock grows ≈ 3.4×/yr;
difficulty absorbs *throughput*; the shape knobs (n, m) must keep arithmetic
intensity (AI ∝ m) high enough that datacenter GEMM parts stay dominant
(the PR #89 lesson: models were wrong twice; silicon measurement is the gate).

---

## 4. Candidates

### Candidate A — Digest-only + full deterministic recompute

Store **zero** proof bytes. `matmul_digest = H(σ‖Ĉ)` stays exactly as today;
verifier re-derives A, B, U, V from the header, runs `ComputeSketchOptimal`
(W MACs), recomputes the digest, checks equality + target.

- **D1/D2/D3:** ε = **0** — the strongest possible. I-F holds by construction:
  there is no miner-supplied object at all; the ticket is a *computed function*
  of (header, nonce), so a fresh ticket costs exactly W by definition.
  Commitment grinding is structurally impossible.
- **Flat data:** perfect. 0 B/block; archive = O(headers) immediately
  (60.8 MiB/yr). Retires the segregated relay/proof store entirely.
- **Compute scaling:** perfect — m, n, instance count all scale W with zero
  data or verifier-structure consequence (the verifier *is* the miner path).
- **Asymmetric verify: LOST — stated plainly.** Verify = one nonce of mining
  work: **7.73×10¹⁰ MACs ≈ 0.8–2 s single-thread CPU at m = 1024, scaling
  linearly in m** (m = 4096 ⇒ 3–8 s; m = 8192 ⇒ 6–16 s) — breaches the <1 s
  L0 verify ceiling at the first shape retarget and grows with the very knob
  we want to grow. GPU verify: sub-ms GEMM + XOF (trivial for any node with a
  ~$300 consumer GPU, but "buy a GPU to validate at the tip" is a
  decentralization regression vs today's CPU-only 200 ms). Full-chain IBD
  audit, no assumevalid: 500k blocks × W ≈ 3.9×10¹⁶ MACs ≈ minutes-to-hours
  on one H100 (XOF-dominated: ~12.6 TB of SHA), ≈ **9–23 CPU-days**
  single-thread. With `assumevalid`-style trust for deep history + parallel
  verify, IBD is fine; *tip* verification is the real cost.
- **DoS:** an invalid header costs O(W) to reject — ~10³× today. Mitigated but
  not removed by the existing SHA header-PoW pre-gate
  (`btx-matmul-v4.2-header-pow-gate.md`) and the global verify budget.
- **PQ / consensus risk:** SHA-256 only; the verifier is the existing reference
  path — minimal new surface. Precedent: Komargodski–Weinstein PoUW verifies by
  recompute-style O(n²·r) checks and stores O(1)
  (<https://eprint.iacr.org/2025/685.pdf>).

**Verdict:** meets requirements 1, 2, 3, 5 *perfectly* and fails only
requirement 4, by a factor of ~10–100× CPU wall-time at the tip (and growing
∝ m). Unbeatable as the **archival/fallback layer** of any design; acceptable
as the *sole* mechanism only if CPU tip-verification is explicitly abandoned.

### Candidate B — Whole-object succinct proof: sum-check + Circle-FRI (RECOMMENDED CORE)

**Statement proved.** `Ĉ = P·Q` with `P = U·A` (m×n), `Q = B·V` (n×m), all
seed-derived. Multilinear-extension form: for the committed
`C̃ : F_q^{2·log₂ m} → F_q`,

    C̃(r_a, r_c) = Σ_{k ∈ {0,1}^{log₂ n}} P̃(r_a, k) · Q̃(k, r_c)

This is exactly Thaler's optimal MatMult interactive proof (CRYPTO'13): prover
T + O(n²) *additive* overhead, log₂ n rounds of degree-2 sum-check, verifier
O(n²) for the two end-point MLE evaluations — which BTX's verifier computes
**itself, from the header seeds, with no relayed operand data**:
`P̃(r_a, r_k) = (eq(r_a)ᵀU)·A·eq(r_k)` and
`Q̃(r_k, r_c) = (eq(r_k)ᵀB)·(V·eq(r_c))` — two O(n²) + O(nm) vec–mat–vec
passes over the XOF-expanded s8 operands
(<https://people.cs.georgetown.edu/jthaler/OptimalMatMult.pdf>,
<https://eprint.iacr.org/2013/351.pdf>; sum-check: Lund–Fortnow–Karloff–Nisan,
<https://dl.acm.org/doi/10.1145/146585.146605>; textbook treatment: Thaler,
*Proofs, Arguments, and Zero-Knowledge*,
<https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf>).

**Binding the left end (the crux, per §2.4).** The claimed evaluation
`v = C̃(r_a, r_c)` must be bound to the lottery preimage over the **whole
object**. That requires the per-nonce committed object to be a **polynomial
commitment** to Ĉ, hash-based for PQ: Merkle root over the Reed–Solomon
low-degree extension of Ĉ, opened via FRI
(Ben-Sasson–Bentov–Horesh–Riabzev, <https://eccc.weizmann.ac.il/report/2017/134/>;
STARK: <https://eprint.iacr.org/2018/046>; out-of-domain evaluation via DEEP:
<https://eprint.iacr.org/2019/336>; soundness: proximity gaps,
<https://eprint.iacr.org/2020/654>; multilinear-via-FRI: BaseFold,
<https://eprint.iacr.org/2023/1705>; smaller-query successors: STIR
<https://eprint.iacr.org/2024/390>, WHIR <https://eprint.iacr.org/2024/1586>).

**Field fit — a decisive technical detail.** q−1 = 2·(2⁶⁰−1) has 2-adicity
**1**: classical radix-2 NTT does not exist over F_{2⁶¹−1}, so vanilla FRI does
not apply. But q ≡ 3 (mod 4) and the **circle group** x²+y²=1 over F_q has
order **q+1 = 2⁶¹ exactly** — perfectly smooth. Circle-FRI/Circle-STARK
(Haböck–Levit–Papini, invented for Mersenne-31 and production-proven in Stwo)
transplants verbatim to Mersenne-61: <https://eprint.iacr.org/2024/278>.
(Alternative for arbitrary fields: ECFFT, <https://arxiv.org/abs/2107.08473> —
strictly more machinery; not needed given the circle fit.) **BTX keeps
q = 2⁶¹−1 — the L0 field survives the amendment.**

**Canonicity (I-F, the grinding-immunity condition).** The committed object is
the Merkle root `R_LDE` of the RS/circle-encoding of Ĉ at consensus-pinned rate
ρ, domain, ordering, and leaf format — **a deterministic function of
(header, nonce): no salts, no zero-knowledge blinding, no prover-chosen
parameters, no unconstrained positions.** Lottery: `matmul_digest = H(σ‖R_LDE)`
(same header field, new preimage).

**Why commitment grinding fails here (the §2.4 immunity argument).** Suppose a
miner tweaks any committed position(s) and grinds for a winning
`H(σ‖R′)`. A winning draw is *usable* only if an accepting proof exists for
R′. The verifier's FS chain (all challenges from `H(σ‖R_LDE‖…)`, binding the
root) enforces: (i) FRI/DEEP — the committed word is within the proximity
radius of a *unique* low-degree polynomial and the claimed v is that
polynomial's evaluation (else accept w.p. ≤ ε_FRI); (ii) sum-check — v equals
the **true** product's MLE at (r_a, r_c), where the end-point values P̃, Q̃ are
computed by the verifier from the header seeds, not supplied by the prover
(else accept w.p. ≤ ε_sc); (iii) Schwartz–Zippel — if the committed polynomial
differs from the true C̃ *anywhere*, they agree at the random point w.p.
≤ 2·log₂(m²)/|F_challenge|. Hence any commitment other than the canonical
encoding of the true Ĉ yields an accepting proof w.p. ≤ ε ≈ 2⁻⁸⁰ **per winning
draw** — a grinder needs ~2⁸⁰ winning draws, i.e. ~2⁸⁰/p total draws, to slip
one forgery through: cryptographically negligible, D2-compliant. Conversely the
canonical commitment for a given nonce is unique, so **fresh usable ticket ⇒
fresh nonce ⇒ (I-N) fresh B ⇒ fresh full W**. Every committed word is
enforced; there are no free bits. I-F holds.

**Soundness accounting (ε budget).** Challenges (r_a, r_c, sum-check r_k,
batching γ) drawn from the quadratic extension F_{q²} (|F| ≈ 2¹²²; extension
arithmetic only on the thin challenge path — the per-nonce GEMM and the
committed data stay base-field integers): SZ term ≤ 20/q² ≈ 2⁻¹¹⁷; sum-check
≤ 2·12/q² ≈ 2⁻¹¹⁷; FRI term set by rate/queries/grinding — at ρ = 1/2,
~80 queries + 20-bit grind: ε_FRI ≈ 2⁻⁸⁰ under the proven Johnson-bound
regime for these parameters (up-to-capacity conjecture would give more; we do
**not** rely on it — flagged: proof sizes below quote the *proven* setting;
conjectured settings shrink them ~2×). Fiat–Shamir of the multi-round protocol
is sound in the ROM because sum-check and FRI are round-by-round sound —
proven, not folklore (BCS transform: <https://eprint.iacr.org/2016/116>;
FS-security of FRI/batched-FRI: <https://eprint.iacr.org/2023/1071>). Total
**ε ≈ 2⁻⁸⁰**, every term negligible-cryptographic, none constant. **Passes the
§1 bar.**

**Sizes and costs (concrete, n = 4096, m = 1024, N = m² = 2²⁰, ρ = 1/2,
codeword 2²¹, SHA-256 tree depth 21, arity-4 folding ⇒ ~8 FRI layers):**

- **Relayed proof:** sum-check transcript 12 rounds × 3 F_{q²} elements ≈
  0.6 KB + DEEP/OOD values ≈ 0.5 KB + ~80 queries × (~8 layers × (4 values +
  ~16 path hashes)) ≈ 60–180 KB after path-dedup — **call it 64–200 KB;
  consensus cap 256 KB, constant.** Growth in m: tree depth +2 and one FRI
  layer per m-doubling ⇒ **+~10–20 KB per doubling of m — O(log² m), flat in
  the practical sense** (m: 1024→8192 ≈ +40–60 KB). Independent of n entirely.
- **Verifier:** (i) 2 hashes: `H(σ‖R_LDE)` = digest, target check; (ii) FRI +
  sum-check transcript: ~2–4×10⁴ SHA compressions + ~10³ F_{q²} ops ≈
  **5–15 ms**; (iii) end-point evaluations: XOF-expand B (nonce-fresh,
  16.8 MB SHA ≈ 50–150 ms; A/U/V template-cached) + 2n² + O(nm) ≈ 4.2×10⁷
  mod-q mult-adds ≈ **100–250 ms** single-thread. **Total ≈ 150–400 ms —
  within the <1 s L0 ceiling; ~parity with today's 95–200 ms.** Scaling: the
  O(nm) term reaches ≈ n² at m = n; verify at m = 8192, n = 4096 ≈ 1.5–2×
  today — still sub-second. **Verify is O(n² + nm + λ·log²N) while mining is
  O(n²m): the asymmetry ratio is ≈ m ≈ 1000×, preserved (requirement 4 ✓).**
- **Prover, per nonce (the metric that can sink this — measurement-gated):**
  GEMM W unchanged. Circle-FFT of 2²¹ F_q elements ≈ 4.4×10⁷ mod-q mults ≈
  **0.06 % of W's MAC count** — noise, and integer-ALU work that overlaps
  tensor-core GEMM on every target part. Hashing: leaves 16.8 MB (2× today's
  8.4 MB digest stage) + 2²¹ interior/64-B compressions ⇒ per-nonce non-GEMM
  floor 393k → **≈ 557k compressions ≈ ×1.42** (ρ = 1/4: ×1.9, but ~40
  queries ⇒ ~80–100 KB proofs — a knob to tune on silicon). Wall-time GEMM
  share erodes accordingly; per project discipline (two model-based estimates
  wrong before — §K.2b) this **MUST be confirmed on H100/B200 with
  `matmul_v4_stage_bench` before any activation parameter is pinned.**
- **Prover, per winning block only:** DEEP quotients + FRI folding
  O(N log N) ≈ 5×10⁷ field ops + ~4 MB hashing + sum-check prover O(n·log n)
  with the two O(n²+nm) end-vector computations ⇒ **≪ 1 s GPU, ~1–3 s CPU** —
  once per 90 s block, no orphan-risk concern.
- **DoS:** fail-fast cascade (digest/target → FRI transcript → sum-check →
  O(n²) end evaluations last): a garbage block is rejected after **~ms of
  hashing**, *before* any O(n²) work — an attacker must do real
  commitment-scale work to force the expensive stage. Strictly better than
  today (which always runs XOF + Freivalds).
- **PQ posture:** SHA-256 + ROM only. No pairings, no discrete log, no
  lattices needed. Grover: generic √ speedup on hash grinding — same posture
  as Bitcoin's SHA PoW and today's BTX digest; FRI/STARK is the PQ-standard
  transparent proof family. **✓**
- **Consensus/determinism risk (the honest cost):** the circle domain,
  twiddle/ordering conventions, folding schedule, query derivation, F_{q²}
  arithmetic, and path-dedup serialization all become consensus-normative —
  the largest new surface in BTX's history, all pure-integer (D1-clean, no
  floats/NTT-nondeterminism since every butterfly is exact mod-q) but a major
  audit and golden-vector burden. Round-by-round-soundness of the *exact
  combined* protocol must be written out and externally reviewed as part of
  the v5 spec.

**Verdict:** the only candidate meeting **all five** requirements at once.
Requirement 1: ε ≈ 2⁻⁸⁰ cryptographic + I-F grinding immunity. 2: ≤ 256 KB
in-block, prunable to O(headers) (§7.5). 3: GEMM untouched; m becomes a
storage-free knob. 4: ~10³× verify asymmetry retained. 5: SHA-only, exact
integers.

### Candidate C — Exact algebraic sub-recompute verification: what is known / impossible

Is there a **deterministic, zero-error** check of `C = A·B` (or of the sketch
relation) cheaper than recompute?

- **Over the integers, with C given: yes.** Korec–Wiedermann (SOFSEM 2014)
  verify integer `A·B = C` deterministically in quadratic time
  (<https://link.springer.com/chapter/10.1007/978-3-319-04298-5_33>): evaluate
  both sides against power vectors x = (β⁰, β¹, …), β larger than any entry —
  the products become huge-integer arithmetic whose injectivity replaces
  randomness, and fast integer multiplication keeps total bit-cost Õ(n²·t)
  (t = per-entry bits). Derandomization of Freivalds in the general/black-box
  setting remains a recognized open problem with fine-grained-complexity
  consequences (Künnemann, ESA 2018, <https://arxiv.org/abs/1806.09189>); the
  coding-theoretic view of what verification randomness buys: Bennett et al.,
  RANDOM 2024,
  (<https://drops.dagstuhl.de/storage/00lipics/lipics-vol317-approx-random2024/LIPIcs.APPROX-RANDOM.2024.42/LIPIcs.APPROX-RANDOM.2024.42.pdf>).
- **Why it does not help BTX:** (i) the verifier does not *have* C or Ĉ —
  relaying Ĉ is the Θ(m²) problem, and relaying C is Θ(n²·32 b) ≈ 64 MiB;
  (ii) applying the trick to the *sketch* relation `Ĉ = (U·A)(B·V)` without
  forming P, Q forces the injective big-integer encodings through the O(n²)
  matvec pipeline with (m·t)-bit intermediates: cost Θ(n²·m·t) bit-ops ≈
  4096²·1024·70 ≈ **1.2×10¹² bit-ops ≈ the mining work itself.** The
  determinism is bought precisely by making the "challenge vector" injective —
  i.e., as wide as the whole object — which is the same reason the relayed
  object is Θ(m²) today. Freivalds' 61-bit challenge *is* the compression;
  remove the randomness and the compression goes with it.
- **Does seed-derivability of the operands help?** No. Under Fiat–Shamir the
  verifier is already deterministic (D1); the operands' pseudo-randomness
  provides no verifier shortcut (a shortcut exploiting operand structure would
  equally be a *miner* shortcut — cf.
  `btx-matmul-v4-bmx4-shortcut-cryptanalysis.md` — and its absence is the
  hardness assumption). What seed-derivability *does* buy is Candidates A and
  B's ability to evaluate end-points from 64 B of seed material — already
  exploited.

**Verdict:** no known deterministic zero-error sub-recompute verification of
the sketch relation with O(1) relay exists; the Korec–Wiedermann line shows the
only known determinism mechanism costs recompute-scale here. **Not a viable
standalone candidate.** (This is the honest justification for accepting
cryptographic-negligible rather than zero error in Candidate B.)

### Candidate D — Hybrids and depth scaling

- **D1: per-nonce Merkle (cheap) + winner-only STARK that the SHA-committed
  leaves equal true Ĉ.** Keeps the per-nonce loop at ×1.12 hashing (prior
  memo's only redeeming number) and moves all proof cost to the winner. Killed
  by quantification: binding a *SHA* commitment to an algebraic claim means
  proving ~131k SHA-256 compressions (plus the 262k-compression XOF if operands
  are in-circuit) inside a STARK — ~10⁸–10⁹ trace rows, minutes-class proving
  per block on serious GPU hardware, 10³–10⁴× prover overhead, all
  hashing-bound (violates the spirit of requirement 3), plus recursion to keep
  the proof small. Orphan-risk latency at 90 s spacing. **Rejected on
  numbers.** (General zkVM routes are strictly worse: 10²–10⁵× overhead.)
- **D2: depth scaling — iterated mod-q GEMM chain.** `C_d = A·B₁·B₂·⋯·B_d
  (mod q)`, all B_i nonce-fresh XOF expansions; commit the final sketch
  `U·C_d·V`. Compute ∝ d at fixed n, m, commitment size; each F_q layer runs
  as limb-decomposed s8 tensor GEMMs (the existing C-13 machinery), so the
  work stays GEMM-shaped. Verification: linear chains collapse under
  Freivalds/sum-check — `xᵀC_d y` via d sequential O(n²) vec–mats, or GKR-style
  chained sum-checks (<https://dl.acm.org/doi/10.1145/2699436>) reducing layer
  t to layer t−1 for O(d·polylog + n²) verify under Candidate B's machinery.
  Adds *sequentiality*, which cuts against the batched-GEMM economics (I1′
  amortization) and utilization of wide parts; and with B's design, m already
  scales storage-free, so depth is not needed. Note: classical VDFs
  (<https://eprint.iacr.org/2018/601>) are excluded — Wesolowski/Pietrzak
  need RSA/class groups (non-PQ) and are not GEMM. **Park as the reserve knob
  if m and n both ever saturate; spec via GKR extension of §7, not as a
  separate system.**
- **D3: recursive proof composition** (fold each block's proof into one
  constant-size chain proof): attractive asymptotically (O(1) archive
  *including* proofs at the tip), but recursion multiplies exactly the
  in-circuit-hashing cost that killed D1, and IVC-of-FRI recursion is the
  bleeding edge of 2025–26 proof engineering. **Not consensus-grade yet;
  revisit ≥ 2028.** Archive-O(headers) is achieved without it (§7.5).

---

## 5. Comparison table

Point of comparison: n = 4096, m = 1024 mainnet; "ε" = work-enforcement
soundness error (§1); "I-F" = grinding-immune full-object lottery binding.

| | Relayed/blk | Archive steady-state | Growth in m | Verify (1-thread CPU) | Per-nonce miner Δ | Per-winner prover | ε | I-F | PQ | Req 3 (GEMM) | New consensus surface |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Today (v4.2)** | 8 MiB | 2.7 TiB/yr | **Θ(m²)** ✗ | 95–200 ms | — | — | ≤2⁻¹⁸⁰ ✓ | ✓ | SHA ✓ | ✓ | — |
| **A: digest-only recompute** | **0 B** | **O(headers)** | none ✓ | **0.8–2 s, ∝m** ✗(req 4) | none | none | **0** ✓✓ | ✓ (structural) | SHA ✓ | ✓✓ | ~none |
| **B: sum-check + Circle-FRI** | 64–200 KB (cap 256 KB) | **O(headers)** (§7.5) | O(log² m) ✓ | **150–400 ms** ✓ | ×1.4 SHA floor (measure!) | ≪1 s GPU | **≈2⁻⁸⁰** ✓ | **✓ (proved §4.B)** | SHA ✓ | ✓ (~0.06 % ALU) | **very large** |
| C: deterministic algebraic | — | — | — | ≈ recompute ✗ | — | — | 0 | — | ✓ | — | — (no construction) |
| D1: Merkle + winner-STARK-of-SHA | ~100 KB | O(headers) | ✓ | ~ms–100 ms | ×1.12 | **minutes** ✗ | ≈2⁻⁸⁰ | ✓ | SHA ✓ | ✗ (hash-bound prover) | extreme |
| D2: depth chain (+GKR) | as B | as B | none (knob=d) | +O(d·polylog) | ∝d (intended) | as B | as B | ✓ | ✓ | ✓ but sequential | as B + layers |
| ~~Prior Option 4: Merkle+f^k spot-check~~ | 15–31 KB | O(headers) | ✓ | ~100–350 ms | ×1.12 | µs | **f^k ≈ 0.185 ✗ AND broken by §2.4 grinding** | **✗✗** | ✓ | ✗ (collapses to SHA) | moderate |

## 6. Ranking

1. **Candidate B — sum-check + Circle-FRI whole-object proof ("ENC-SC"), with
   Candidate A permanently underneath it as the archival/fallback layer.** The
   only design meeting all five requirements simultaneously. Its two real
   costs — ×1.4 per-nonce SHA floor and the audit surface — are priced in §9.
2. **Candidate A alone.** Chosen if, and only if, the project decides B's
   consensus surface is unaffordable. Perfect on requirements 1, 2, 3, 5;
   gives up requirement 4 by ~10–100× CPU tip-verify (quantified in §4.A) —
   effectively "GPU-recommended full nodes."
3. **Candidate D2 (depth chain)** — reserve compute knob, only ever as an
   extension of B's machinery. Parked.
4. **Candidate D1 / D3 (STARK-of-SHA, recursion)** — rejected on prover
   numbers today; recursion revisit ≥ 2028.
5. **Candidate C** — no construction exists; recorded as the justification for
   accepting negligible-vs-zero error.
6. **Prior memo Option 4 (Merkle + f^k)** — disqualified (fails D2) and
   **broken** (fails D3, §2.4). Must not ship in any form; sampling may only
   ever supplement a full-object check.

---

## 7. Recommended design: profile family **ENC-SC** (sum-check-committed), v5

### 7.1 Committed object and header

- Header layout unchanged (182 B). Seeds, σ, I1′ template scoping, nonce
  rules: **unchanged** (I-N preserved verbatim).
- Per nonce, the miner computes Ĉ = (U·A)(B·V) exactly as today
  (`ComputeSketchOptimal`), then the **canonical LDE commitment**: circle-FFT
  of the m² canonical residues to the pinned rate-ρ circle domain (ρ = 1/2
  initial; silicon-tunable pre-activation), leaves = 512-B tiles in pinned
  order, domain-separated SHA-256d Merkle tree → root `R_LDE`.
- **Lottery: `matmul_digest = H(σ ‖ R_LDE)`** — same field, same target rule,
  new preimage. Canonicity rule (consensus): the tree has **no salts, no
  blinding, no prover choices**; R_LDE is a function of (header, nNonce64).
  This is the I-F condition — §4.B's immunity argument is normative text.

### 7.2 Relayed object (constant size)

`proof = R_LDE ‖ sum-check transcript (12 rounds × 3 F_{q²}) ‖ OOD/DEEP values
‖ FRI folding roots + ~80 query openings with dedup'd paths` — **64–200 KB,
hard consensus cap 256 KB**, carried **in-block** in `matrix_c_data` (well
under every message limit — the 24-bit BIP324 issue and the entire segregated
relay/chunking/proof-store subsystem are **retired** at ENC-SC heights).

### 7.3 Verify cascade (replaces `SketchFreivalds` at ENC-SC heights)

1. `H(σ‖R_LDE) == matmul_digest`; target check. (2 hashes — instant.)
2. FS transcript replay from `H(σ‖R_LDE‖…)`; verify FRI folding + queries +
   DEEP consistency against R_LDE (~2–4×10⁴ hashes, 5–15 ms).
3. Sum-check replay (12 rounds, F_{q²}, µs).
4. End-point check: XOF-expand B (A/U/V template-cached), compute
   `P̃(r_a,r_k)` and `Q̃(r_k,r_c)` via two O(n²)+O(nm) vec–mat–vec passes,
   compare to the sum-check's final claim. (100–250 ms — deliberately LAST for
   DoS fail-fast.)

Total ≈ 150–400 ms single-thread — today's envelope, <1 s L0 ceiling, and
step 4 is the only stage that grows (as O(nm)) when m is retargeted.

### 7.4 Compute scaling, storage-free

- **Difficulty (continuous):** unchanged ASERT on the digest target.
- **m (primary shape knob, newly free):** m: 1024 → 8192 multiplies per-nonce
  tensor work W by 8 and arithmetic intensity by 8, with **zero** relay growth
  beyond +40–60 KB of proof and +O(nm) verify (§7.3-4). The D-profile's 4×
  storage price disappears.
- **n (secondary):** 4096 → 8192 within the L0 verify budget: W ×4.
- Combined shape headroom ×32 before any further idea is needed; difficulty
  absorbs throughput growth indefinitely. Reserve knobs: instance batching
  (verify ∝ j — budget-capped, same as today) and the D2 depth chain.
- All shape retargets remain **measurement-gated** (H100/B200
  `matmul_v4_stage_bench`), per the twice-burned rule.

### 7.5 Archive = O(headers)

Nodes keep proofs for a rolling window (tip validation + reorg depth, e.g.
2016 blocks ≈ 0.4–0.5 GB at 200 KB); beyond burial depth **even archives drop
them**: every proof is recomputable from the header forever (§2.2 fact 1 —
regenerate Ĉ at W MACs, re-encode, re-derive the same FS transcript
byte-for-byte), and any deep block is directly re-auditable by Candidate A
recompute (ms on GPU, seconds on CPU). Steady-state archive = headers + txs:
**60.8 MiB/yr of PoW data vs 2.67–10.7 TiB/yr today (~10⁴–10⁵×).** Deep
history additionally rides `assumevalid`-class policy exactly as Bitcoin's
script checks do — with the stronger property that here the skipped data is
*re-derivable*, not merely re-checkable.

### 7.6 Soundness & determinism argument (summary)

- **D1:** every verifier operation is integer SHA/mod-q/mod-q² arithmetic with
  pinned order; circle-FFT butterflies are exact mod-q (no floats, no
  approximate NTT — determinism identical in kind to today's field code).
- **D2:** ε ≤ ε_SZ(2⁻¹¹⁷) + ε_sc(2⁻¹¹⁷) + ε_FRI(2⁻⁸⁰) ≈ **2⁻⁸⁰**, all terms
  cryptographic, all improvable at O(1)-per-bit verifier cost (queries/grind),
  FS-sound in ROM via round-by-round soundness (BCS 2016/116; FRI-FS
  2023/1071). No f^k term exists anywhere in the design.
- **D3/I-F:** the committed object is canonical per (header, nonce); the proof
  constrains it *everywhere* (proximity + evaluation + true-product equality
  with verifier-computed end-points); grinding any committed bit invalidates
  the proof except w.p. ε. Fresh ticket ⇒ fresh nonce ⇒ fresh full W (I-N).
- **PQ:** SHA-256d + ROM. Nothing else. (ML-KEM-class assumptions not even
  needed; pairings nowhere.)

### 7.7 Migration sketch (v5 hard fork)

1. `MatMulProfileParams`: add `commitment = {FLAT_SKETCH, LDE_SUMCHECK}`,
   `fri_rate`, `fri_queries`, `fri_fold_arity`, `grind_bits`,
   `proof_size_cap = 256 KB`; retire `proof_segregated`,
   `sketch_payload_bytes` at ENC-SC heights; `GetMatMulProfileParams` height
   gate as with ENC-BMX4C today.
2. New `src/matmul/matmul_v4_sc.{h,cpp}`: circle domain + FFT (exact mod-q),
   F_{q²} arithmetic, canonical tree, transcript; miner-side
   `ComputeCommitmentSC` fused into `matmul_v4_batch` (per-nonce: FFT + tree);
   winner-side `ProveSC`; verifier `VerifySketchSC` wired at the
   `CheckMatMulV4SketchVerifies` dispatch (`src/pow.cpp:3543`).
3. Delete-at-height: proof store as consensus dependency,
   `getmatmulproof`/`matmulproof`/`mmproofchunk`, size-cap plumbing
   (`GetMatMulProofSizeCap` → constant).
4. One-time ASERT rescale for the ×1.4 hash floor (standard B2b procedure);
   golden vectors incl. adversarial (wrong-limb, non-canonical residue,
   tampered-codeword, grind-attempt vectors); cross-vendor re-pin; C-1
   accumulator eligibility unchanged (GEMM path untouched).
5. **External review gates (blocking):** (i) RBR-soundness writeup of the
   combined protocol; (ii) H100/B200 silicon measurement of per-nonce GEMM
   share under the new floor; (iii) cryptanalysis review of Circle-FRI-over-M61
   parameter choices; (iv) the constitutional (L0-amendment) supermajority
   process itself — this is a **different-coin-class change per the L0 text**
   and must be ratified as such, with the flat-data requirement recorded as
   the new constitutional input.

---

## 8. (Reserved) — merged into §7.7 gates.

## 9. The honest trade

**Deterministic (D1–D3) + flat data + cheap asymmetric verify ARE
simultaneously achievable — Candidate B achieves all three — but not for
free. Nothing in the five requirements must give; what gives is outside
them:**

1. **Per-nonce miner overhead:** non-GEMM floor ×~1.4 (SHA) + 0.06 % ALU
   (FFT). If silicon measurement shows this tips wall-time GEMM-share below
   the datacenter-favoring threshold, the knobs are rate ρ (hash ↔ proof-size
   trade) and leaf width — and the hard fallback is Candidate A (zero
   overhead, GPU-class tip verify). This is the single measurable risk to the
   frontier-GEMM thesis, and it is bounded and tunable.
2. **Complexity/audit surface:** the FRI stack is by far the largest
   consensus-normative machinery ever added to BTX. This is the real cost of
   refusing both Θ(m²) relay and the f^k shortcut. It is a one-time cost, and
   the machinery is the 2024–26 industry-standard transparent-proof toolchain
   (M31 Circle-STARKs run in production), not research code.
3. **Zero-error is unattainable below recompute cost** (§4.C): the residual
   2⁻⁸⁰ is not a compromise but the mathematical price of sub-recompute
   verification with O(1) relay — the same class of bound (and better than)
   the 2/q-per-round standard the chain already accepts, and categorically
   different from a constant f^k gap.
4. **Proof bytes are ~200 KB, not 0** — "flat" means O(log² m), 10⁴× smaller
   than today and prunable to exactly O(headers); if even 200 KB offends,
   Candidate A's 0 B is available at the price of requirement 4.
5. **L0 as written does not survive** — any solution to requirement 2 amends
   it (§2.5). The amendment preserves q, exact-integer commitment, σ/nonce
   rules, the verify budget, and the hardness floor; it replaces the digest
   preimage and verifier structure. That is a v5 hard fork and should be
   ratified, named, and shipped as one.

---

## 10. Sources

**Code (pinned):** `src/matmul/matmul_v4.h` (ComputeSketch/Optimal :152-179,
SerializeSketch :239-241, ComputeSketchDigest :249-252, SketchFreivalds
:254-271, seeds/σ :89-142); `src/pow.cpp` (seeds :76-115,
CheckMatMulV4SketchVerifies :3543-3618, in-block carriage :3620-3649,
segregated path :3651-3713); `src/consensus/params.h` (MatMulProfileParams
:178-184, L0 note :90, GetMatMulProfileParams :805-841);
`src/matmul/matmul_v4_batch.h`; `src/matmul/matmul_proof_store.h`.
**Repo docs:** `btx-matmul-compute-vs-data-decoupling-research.md` (cost model
reused; its Option 4 rejected here); `btx-matmul-v4-design-spec.md` (§D.5,
§E, §I.4, §K.2b); `btx-matmul-v4.2-longevity-threat-model.md` (L0/L1);
`btx-matmul-v4.2-relay-hardening-design.md`;
`btx-matmul-v4.2-header-pow-gate.md`;
`btx-matmul-v4-bmx4-shortcut-cryptanalysis.md`;
`freivalds-algorithm-analysis.md`.

**External (all URLs verified in family; proven vs conjectured flagged in
text):**
- Sum-check: Lund–Fortnow–Karloff–Nisan, *Algebraic Methods for Interactive
  Proof Systems*, JACM 1992 — <https://dl.acm.org/doi/10.1145/146585.146605>
- Thaler, *Time-Optimal Interactive Proofs for Circuit Evaluation* (MatMult
  protocol): <https://eprint.iacr.org/2013/351.pdf>; lecture notes:
  <https://people.cs.georgetown.edu/jthaler/OptimalMatMult.pdf>; book:
  <https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf>
- GKR: Goldwasser–Kalai–Rothblum, *Delegating Computation* —
  <https://dl.acm.org/doi/10.1145/2699436>
- FRI: Ben-Sasson–Bentov–Horesh–Riabzev —
  <https://eccc.weizmann.ac.il/report/2017/134/>; STARK:
  <https://eprint.iacr.org/2018/046>; DEEP-FRI:
  <https://eprint.iacr.org/2019/336>; proximity gaps (proven soundness
  regime): <https://eprint.iacr.org/2020/654>
- Fiat–Shamir security: BCS transform <https://eprint.iacr.org/2016/116>;
  *Fiat–Shamir Security of FRI and Related SNARKs*:
  <https://eprint.iacr.org/2023/1071>
- Circle STARKs (Mersenne-prime FRI; M61 circle group has order 2⁶¹):
  Haböck–Levit–Papini — <https://eprint.iacr.org/2024/278>; ECFFT
  alternative: <https://arxiv.org/abs/2107.08473>
- BaseFold (multilinear PCS from FRI-style folding):
  <https://eprint.iacr.org/2023/1705>; STIR:
  <https://eprint.iacr.org/2024/390>; WHIR:
  <https://eprint.iacr.org/2024/1586>
- Deterministic matmul verification: Korec–Wiedermann, SOFSEM 2014 —
  <https://link.springer.com/chapter/10.1007/978-3-319-04298-5_33>;
  Künnemann, *On Nondeterministic Derandomization of Freivalds' Algorithm*,
  ESA 2018 — <https://arxiv.org/abs/1806.09189>; Bennett et al., *Matrix
  Multiplication Verification Using Coding Theory*, RANDOM 2024 —
  <https://drops.dagstuhl.de/storage/00lipics/lipics-vol317-approx-random2024/LIPIcs.APPROX-RANDOM.2024.42/LIPIcs.APPROX-RANDOM.2024.42.pdf>;
  Freivalds background: <https://arxiv.org/pdf/1705.10449>
- Matmul PoUW precedent (recompute-style verify, O(1) storage):
  Komargodski–Weinstein et al. — <https://eprint.iacr.org/2025/685.pdf>
- VDFs (flagged non-PQ, excluded): Boneh–Bonneau–Bünz–Fisch —
  <https://eprint.iacr.org/2018/601>
