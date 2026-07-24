> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX MatMul v4.4 — Tension Resolution: ENC-DR (Digest-Only Recompute) + Sketch-Cache

*Status: v4.4 RELEASE-CANDIDATE DESIGN (synthesis; supersedes the ENC-SC-based
recommendation of `btx-matmul-v4.4-release-candidate-architecture.md` and
`btx-matmul-v4.4-compute-reward-preservation.md` §2 where they conflict; both
memos' economics analysis (§1/M1–M4) and deletion inventory are carried
forward). Adjudicates and closes
`btx-matmul-enc-sc-adversarial-review-and-required-fixes.md` (BREAK #1,
BREAK #2, OPEN RISK). Nothing in this branch is deployed anywhere
(`nMatMulV4Height = INT32_MAX` on every public network); everything below
activates at ONE height. Written 2026-07-18.*

---

## 0. Priority order and the one-line answer

**Ranking criteria (project-lead directive, highest first — this order is
normative for every verdict below):**

1. **NO REWARD INVERSION.** Per-nonce *wall time* must stay GEMM/tensor-bound
   so that progressively more powerful AI compute earns progressively more
   expected blocks — frontier datacenter accelerators must win, on real
   silicon. The failure mode is PR #89 measured verbatim: at b = 8 a consumer
   RTX 5090 out-earned an H100 (H100/5090 = 0.40× nonce throughput) — rewards
   ran *backwards* to compute strength. Anything that re-creates that is
   disqualified, not "risky." Non-negotiable: it is why the project exists.
2. **Bitcoin-alignment virtues:** deterministic + exact (or cryptographically
   negligible, never constant/f^k) verification; decentralized; no trusted
   setup; consensus-deterministic pure-integer verification.
3. **Flat storage:** no Θ(m²) relay/archive bloat; O(headers).
4. **Cheap asymmetric verify:** desirable but **sacrificable** — it may never
   be bought at a price charged against #1.

**Answer.** **Adopt Candidate A as the consensus rule — the lottery and
committed object of v4.3, byte-identical, with ZERO relayed/stored consensus
proof bytes — and keep today's Freivalds verifier alive as a non-consensus
fast path over untrusted, self-authenticating, prunable "sketch cache" bytes
that any peer may supply and any node may drop.** Call the profile **ENC-DR**
("digest-only, re-derivable") **+ SKETCH-CACHE**. On the four criteria in
order: (1) the miner loop is byte-identical to the post-PR#89 b = 4
batched-GEMM configuration — added per-nonce floor **×1.00, exactly zero** —
so the wall-time split, the frontier ladder, and the no-inversion property are
preserved *by identity*, the only candidate for which this holds without a
fresh silicon campaign (§2.0 quantifies); (2) ε = 0 on the recompute path and
≤ 2⁻¹⁸⁰ = (2/q)³ on the cache path — field-size class, never f^k; no trusted
setup, pure-integer SHA-256-only, the strongest D1 possible (the predicate is
a pure function of the header); (3) archive = O(headers) = 60.8 MiB/yr; (4)
verification stays cheap in the common case (95–200 ms CPU, the v4.3 verifier
verbatim over cache bytes) and degrades to one nonce of recompute (ms on GPU,
0.8–2 s single-thread CPU at m = 1024) only when no cache is available —
and, decisively, the cheap path is **verifier-side only**: it adds nothing to
the miner's nonce loop, so #4 is obtained without spending one cycle of #1.
Both ENC-SC breaks are structurally impossible (no second commitment to
grind, no FRI to under-size). The one property partially sacrificed — the
sacrificable #4, stated plainly in §7 — is the *guarantee* of sub-second
single-thread CPU verification from consensus bytes alone. ENC-SC as drafted
is **DISQUALIFIED under criterion 1** (×1.42–2.4 per-nonce hash floor);
corrected ENC-SC (F1+F2, floor ×1.04) is ranked second and kept on file as
the designed successor if #4 is ever promoted — subject to its own silicon
gate.

---

## 1. The tension, restated precisely

What we like (v4.2/v4.3, `btx-matmul-v4.4-compute-reward-preservation.md` §1):
progressive block rewards for progressively more powerful AI compute, carried
by four mechanisms — M1 the digest lottery `H(σ‖Ĉ) ≤ target`
(`ComputeSketchDigest`, `src/matmul/matmul_v4.h:249-252`; target check
`src/pow.cpp:3614-3618`), M2 the GEMM-dominant work shape
(W = 4n²m + 2nm² ≈ 7.73×10¹⁰ MACs/nonce at n = 4096, b = 4, m = 1024;
AI_opt = 2n/b = 2048 above every device ridge; the measured frontier ladder,
`btx-matmul-v4.2-consolidated-design.md` §6), M3 price-free ASERT
(`src/pow.cpp:2189`), M4 measurement-gated shape retargets (§K.2b, twice-burned
rule). What we hate: the committed object is *relayed* — 8·m² bytes/block
(8 MiB at C, 32 MiB at parked D) ⇒ 2.67–10.7 TiB/yr archives and a segregated
relay subsystem that already broke once (BIP324 24-bit ceiling).

ENC-SC (nextgen memo §7) fixed the bytes and broke other things. The
consolidated adversarial review found:

- **BREAK #1** — lottery keyed on the *evaluation codeword* root `R_LDE`:
  FRI's proximity slack leaves unqueried codeword leaves as free bits ⇒
  commitment-grinding at SHA speed, the §2.4 Option-4 collapse verbatim.
  Fix F1: key the lottery on the **message** commitment.
- **BREAK #2** — FRI sized on the disproved capacity conjecture and without
  the PoW-grinding model (every nonce a fresh FS instance): proven soundness
  at the draft params is 2⁻⁴⁰–2⁻⁶⁰, forgeable-with-grinding at
  thin-to-negative margin on low-difficulty networks. Fix F2:
  `grind_bits + proven λ_FRI ≥ ~120`, which couples (cap 256 KB, rate ρ,
  hash floor, λ) into a four-way constraint.
- **OPEN RISK** — the per-nonce commitment-hash floor scales ∝ m² while the
  GEMM marginal scales ∝ m (at fixed n): "grow m storage-free" erodes the
  frontier-GEMM thesis in wall time; the drafted ENC-SC floor (×1.42–×2.4
  vs today) makes it worse; unprovable without silicon.

The task: flat storage AND preserved GEMM-dominance AND determinism, without
new problems.

---

## 2. The no-inversion criterion made quantitative, and three observations that dissolve the tension

### 2.0 The acceptance test: per-nonce wall-time split, and κ (the floor multiplier) as the inversion metric

Reward inversion is a *wall-time* phenomenon. Expected blocks ∝ nonce
throughput ν_g (M1); ν_g is set by the per-nonce critical path
`max(t_GEMM, t_nonGEMM)` under pipelining. The per-nonce unit at n = 4096,
m = 1024 splits into:

- **GEMM (the part frontier silicon wins):** W = 4n²m + 2nm² = 7.73×10¹⁰
  MACs. H100 ≈ 1979 INT8 TOPS peak → t_GEMM ≈ 40–80 µs sustained; B200 FP4
  ≈ 7702 TOPS → ≈ 10–20 µs; 5090 ≈ 838 INT8 / 1676 FP4 → ≈ 90–190 µs.
  Tensor throughput per dollar is steeply frontier-favoring — this term IS
  the ladder.
- **Non-GEMM floor (the part that flattens the ladder):** 393k SHA-256
  compressions = 25.2 MB (XOF expand B 16.8 MB + digest over Ĉ 8.4 MB) +
  scheduling overheads. SHA throughput per dollar is nearly flat across
  device classes (and is exactly what a SHA-ASIC/high-clock hybrid buys
  cheaply), so every unit of wall time spent here compresses the ladder
  slope toward 1 — and past parity, *inverts* it (cheap consumer/ASIC SHA +
  modest GEMM out-races expensive tensor silicon). PR #89's b = 8 inversion
  was precisely this mechanism: per-nonce GEMMs too skinny, SHA operand
  floor too large ⇒ H100/5090 = 0.40×.

Define **κ = (candidate's per-nonce non-GEMM floor) / (v4.3's 393k
compressions)**. Since the GEMM term is identical across all candidates
(every one keeps `ComputeSketchOptimal` untouched), κ is the complete
first-order inversion-risk statistic: κ = 1.00 means the wall-time split is
*the* split the post-PR#89 b = 4 batched profile was engineered and
measurement-gated to make datacenter-winning; κ > 1 moves an already
SHA-tight budget (the nextgen memo concedes the baseline is "SHA/XOF-bound
in practice" on H100 before pipelining) further toward the flat-SHA regime,
by an amount no model can certify — the project's own twice-burned rule
(§K.2b: two model-based orderings falsified) forbids certifying any κ > 1
without a fresh H100/B200 stage-bench campaign.

| Candidate | κ (per-nonce floor multiplier) | Verdict under criterion 1 |
|---|---|---|
| **ENC-DR (this memo)** | **1.00 — byte-identical loop** | **No-inversion preserved by identity; no new silicon gate; the existing K.2b GO/NO-GO (already required for v4 activation) remains the on-silicon acceptance test, unchanged** |
| ENC-SC corrected (F1: message-tree lottery) | ≈ 1.04 | Small but nonzero; re-opens the silicon gate; acceptable in principle, dominated by κ = 1.00 |
| ENC-SC as drafted (codeword-keyed lottery, F2-sized) | 1.42–2.4 | **DISQUALIFIED** — deliberately multiplies the exact term that produced the PR #89 inversion, ∝ m², in exchange for criterion-4 goods; forbidden by the priority order |

The corollary that shapes the whole recommendation: **verification cost has
zero coupling to inversion** — it is paid once per block by validators, not
per nonce by miners, and never enters ν_g. Therefore cheap verify is worth
exactly as much as it costs in *miner floor*: at κ = 1.00 (cache-assisted
Freivalds, §2.3) it is free and we take it; at κ = 1.42–2.4 (per-nonce FRI
commitment) it is bought with criterion 1 and we refuse it; if the only
cheap-verify route required any κ > 1, the correct choice per the priority
order would be full recompute — which is exactly what ENC-DR's fallback path
already is.

### 2.1 F1's endpoint, taken to its limit, IS Candidate A's digest

F1 says: key the lottery on a commitment to the *message* (the m² canonical
residues of Ĉ), not to any encoding of it. The **maximally rigid message
commitment already exists and is already L0**: the flat hash
`H(σ‖SerializeSketch(Ĉ))` — today's `matmul_digest`. It has, by construction,
the exact property F1 restores by repair: *every* preimage bit is a canonical
residue of the true Ĉ; there are no redundancy leaves, no unqueried
positions, no salts, no second object requiring a consistency argument.
D3/I-F holds structurally: `(header, nNonce64) → ticket` is a pure function
whose only evaluation algorithm is the full pipeline (expand B, B·V, combine,
serialize, hash) — commitment grinding is not "caught", it is *undefined*.
ENC-SC-with-F1 approximates this object and then must additionally prove that
its Merkle message tree and its FRI polynomial commit to the same thing (the
review's "explicit consistency argument" — new, unreviewed cryptography).
Candidate A needs no such argument because it has one commitment, not two.

### 2.2 The m² hash floor is not ENC-SC's problem to solve — it is v4.3's own, and every candidate has it equally

Any design that makes the lottery bind all m² words must, per nonce, pass
Θ(m²) bytes through a hash (that is what "commitment over the object" means;
nextgen §2.2 fact 2 shows the materialization itself is non-negotiable). The
per-nonce non-GEMM floors, measured in SHA-256 compressions at n = 4096,
m = 1024 (XOF expand B = 262k everywhere):

| Design | Commitment stage | Total floor | vs v4.3 |
|---|---|---|---|
| v4.3 (flat digest over 8.4 MB) | 131k | 393k | ×1.00 |
| **ENC-DR (this memo)** | **131k (identical bytes)** | **393k** | **×1.00** |
| ENC-SC corrected (F1: per-nonce message tree, 512-B leaves + interior) | ~148k | ~410k | ×1.04 |
| ENC-SC as drafted (per-nonce codeword tree, ρ = 1/2 … 1/8 under F2) | 295k–1.2M | 557k–1.5M | ×1.42–×2.4 |

Two consequences. First, the review's OPEN-RISK escalation ("F2 makes it
worse, ×1.9–2.4") applies to the *drafted* codeword-keyed lottery — the
variant §2.0 disqualifies; once F1 moves the codeword tree to win-time, the
corrected ENC-SC floor is κ ≈ 1.04 — we adjudicate the review's §3 table as
a constraint on the win-time prover, not the nonce loop. Second: the
residual m²-vs-m erosion (GEMM:commit-hash ≈ n²/(2m) + n/4, crossover
m ≈ 8–16k at n = 4096; decoupling memo §3-O5b) is a property of committing
an m×m object at all, present since v4.2 and priced into the measured b = 4
ordering. Under criterion 1 it becomes a standing **scaling rule**, not a
new risk: grow compute preferentially via **n** (GEMM ∝ n²m against an XOF
floor ∝ n² — the GEMM:hash ratio is non-decreasing in n, so n-scaling can
never cause inversion) and via **m only inside the silicon-measured window**
(m ∈ {1024…4096} at n = 4096, each rung re-passing the K.2b wall-time-
majority gate), then retarget n to re-open the window. So the surviving
candidates do **not** differ materially on criterion 1 (κ 1.00 vs 1.04);
they differ on criterion-2 surface and the cost/trust profile of
*verification* — which is where the next observation lands.

### 2.3 Cheap verification never needed consensus bytes — because the cache is self-authenticating

The decoupling memo's structural fact: *the proof carries zero information not
in the header*. Its unnoticed corollary: **any peer can serve the 8·m² sketch
bytes as an untrusted cache, and one hash authenticates them** —
`H(σ‖bytes) == matmul_digest` proves (under SHA-256 collision resistance) that
the bytes are exactly the preimage the miner committed. Then today's verifier
runs unchanged: `ParseSketch` canonicality + R = 3 `SketchFreivalds` rounds
(`matmul_v4.h:254-271`) checks `bytes == Ĉ_true` with error ≤ (2/q)³ ≈ 2⁻¹⁸⁰,
in O(n²) ≈ 95–200 ms single-thread. That is *the v4.3 verifier, verbatim* —
but the bytes it consumes no longer need to be in the block, in the ledger,
or on anyone's disk. If no peer serves them, the verifier recomputes Ĉ from
the header (`ComputeSketchOptimal`, W MACs) and checks the digest exactly.
Both strategies decide the same predicate (`matmul_digest == H(σ‖Ĉ_true)`) up
to 2⁻¹⁸⁰/collision-resistance — the same equivalence class the chain already
accepts today. Cheap verify is thus obtained at **zero consensus bytes**, with
no FRI, no new field arithmetic, no new soundness argument, and liveness never
hostage to cache availability.

One negative result completes the picture (answering the "O(1) hint →
deterministic O(n²) check" question): no such hint can exist. Pre-commitment
challenges (derivable from σ) let a miner evaluate the checked functional in
O(k·n²) with no GEMM (nextgen §2.2 fact 2 / Option-4 intro); post-commitment
challenges require committing all m² positions, and *cheaply verifying that a
commitment binds* without relaying it is precisely the polynomial-commitment
problem — the FRI stack. Deterministic zero-error sub-recompute verification
is Candidate C, shown impossible below recompute cost (Korec–Wiedermann line,
nextgen §4.C). The cache path is the honest version of the "hint": Θ(m²)
untrusted bytes, zero consensus bytes.

---

## 3. Evaluation and ranking (in the §0 priority order)

### 3.1 RANK 1 — ENC-DR + SKETCH-CACHE (RECOMMENDED; the v4.4 RC)

Consensus = Candidate A; transport = optional cache; verifier = today's
Freivalds when cached, exact recompute when not. Scored against the brief:

**(i) Compute-reward thesis / NO INVERSION — preserved IDENTICALLY, not
approximately (criterion 1, the acceptance test).** κ = 1.00 (§2.0). The
miner's per-nonce pipeline is byte-for-byte v4.3: same seeds/σ/I1′
(`matmul_v4.h:89-142`), same GEMM (`ComputeSketchOptimal`, batched
`matmul_v4_batch`), same serialization, same digest, same 393k-compression
floor, same W. Every measured economic quantity — the b = 4 batched profile,
the B200/5090 = 1.54× D-point margin, AI_opt = 2048, the ladder ordering, the
work-unit-neutrality theorem §L.2.1 — transfers with **no new measurement**:
the silicon gate that blocked ENC-SC (review §5-5) does not apply because
nothing in the nonce loop changed. `800·T_g/TOPS_net` BTX/hr, ASERT tracking
the 3.4×/yr frontier envelope, M1–M4 all intact by identity, not by argument.
The on-silicon acceptance test for no-inversion remains exactly the K.2b
GO/NO-GO already required to activate v4 at all — (a) tensor wall-time
strict majority at Q ≥ 32, (b) ≥ ~60 % tensor utilization, (c) H100/B200
above 5090 by a price-surviving margin — run once on the unchanged pipeline,
and its result is not put at risk by this fork, because this fork does not
move a single per-nonce byte or compression. Every quantity in that gate is
about the *miner*; the cache fast path below is verifier-side only and
appears nowhere in it.

**(ii) Storage — flat, the strongest form.** Consensus bytes per block for
PoW: **0** (the block body's `matrix_c_data` becomes *forbidden non-empty*).
Archive = headers + txs: 60.8 MiB/yr of PoW data vs 2.67–10.7 TiB/yr,
m-invariant and n-invariant forever. The optional cache is not ledger data:
a node MAY hold a rolling window (2016 blocks × 8 MiB ≈ 15.8 GiB) to serve
CPU peers, and every byte of it is regenerable from headers by anyone.

**(iii) Determinism — exact or field-size-negligible.** Recompute path:
ε = 0. Cache path: ε ≤ (2/q)³ ≈ 2⁻¹⁸⁰ (Schwartz–Zippel over q = 2⁶¹−1,
Fiat–Shamir challenges from `H(σ‖H(payload))` — the already-audited I7 rule).
No f^k term exists anywhere; no constant-probability compute-less path exists.
D1: the consensus predicate is a pure function of the header alone — the
purest D1 any candidate can have. D3/I-F: structural (§2.1).

**(iv) The two breaks — avoided, not fixed.** BREAK #1 cannot occur: the
lottery preimage is the message itself; there are no unopened positions and
no proximity slack. BREAK #2 cannot occur: there is no FRI, no query phase,
no grind nonce, no proof-size/rate/λ constraint system, and no
Fiat–Shamir-per-nonce forgery surface beyond SHA-256 itself. The review's
entire §5 corrected-construction burden (consistency argument, four-way
parameter co-design, circle-FFT determinism pins, M61 Circle-FRI
cryptanalysis, RBR-soundness writeup) is deleted, not discharged.

**(v) m-scaling / compute-scaling, storage-free.** Identical knobs, now
priced honestly: raising m raises W ∝ (4n²m + 2nm²) at zero consensus bytes
(cache grows ∝ m² but is optional; recompute-verify grows ∝ W). The erosion
window (§2.2) is v4.3's own: m ∈ {1024…4096} at n = 4096, then retarget n
(4096 → 8192 ⇒ W ×4, floor-neutral in ratio). Shape headroom ×32 before any
further idea, every rung measurement-gated per §K.2b, none of it touching
storage. The D-profile's 1.54× frontier margin costs +0 consensus bytes
instead of 32 MiB/block.

**(vi) Verify cost — quantified, and why it is acceptable.**

| Path | m=1024 (now) | m=2048 | m=4096 | n=8192, m=2048 |
|---|---|---|---|---|
| Cache: digest over 8m² B + 3×O(n²) Freivalds, 1-thread CPU | 95–200 ms | ~110–250 ms | ~130–300 ms | ~300–600 ms |
| Recompute, 1-thread CPU (VNNI ~10¹¹ MAC/s) | 0.8–2 s | 1.7–4 s | 4–10 s | 6–15 s |
| Recompute, 16-thread CPU | 0.1–0.25 s | 0.2–0.5 s | 0.5–1.2 s | 0.7–1.8 s |
| Recompute, one datacenter/consumer GPU | 1–3 ms | ~ms | ~ms | ~ms |

(GPU recompute is XOF-bound: 25.2 MB SHA ≈ 0.5–2 ms at 10–50 GB/s device
SHA; GEMM ≈ 0.1 ms. Cache-path growth is the 8m²-byte digest re-hash — 4 ms
at m = 1024, 67 ms at m = 4096 — plus the O(m²) Freivalds LHS; both stay
sub-second through m = 8192.) IBD: below `assumevalid`, PoW bodies are
skipped under the identical trust ConnectBlock already extends to buried
scripts (`src/validation.cpp:10315` — the mechanism exists in-tree today for
segregated proofs and is retargeted, not invented). Above assumevalid
(~3 months ≈ 87,600 blocks): one H100 ≈ 2–4 min (2.2 TB XOF SHA dominates);
16-thread CPU ≈ 1.2–2.5 h; or cache-assisted ≈ 700 GiB download + 200 ms/blk
(≈ 5 h single-thread, parallelizes). Full trustless audit (`-assumevalid=0`,
500k blocks, 3.9×10¹⁶ MACs + 12.6 TB SHA): one H100 ≈ 10–25 min; 32-thread
server ≈ 4–14 h (comparable to a Bitcoin full-verify IBD); single-thread
9–23 days (the only genuinely bad cell, and the one no one runs). Why
acceptable: (a) the verify:mine asymmetry is not lost — verification costs
exactly 1 nonce of the ~10⁹–10¹²+ the network grinds per block; what changes
is the currency it is paid in; (b) the target validator population is
datacenter-class *by thesis* — the chain's stated purpose selects for
operators to whom recompute is ms; (c) CPU-only nodes keep a ~200 ms path
whenever *any* peer — including the winning miner, who materialized the bytes
anyway and is incentive-aligned to serve them — supplies the cache; (d) an
eclipse attacker who withholds all cache degrades a CPU node to a ~1–2 %
verify duty cycle (1–2 s per 90 s block), not to a halt. Block *propagation*
strictly improves: the consensus block shrinks from ≥ 8 MiB to
headers + txs, and GPU miners validate a rival's block by recompute in ~ms —
faster than today's 8 MiB transfer + 100 ms verify — reducing orphan
pressure at the tip.

**(vii) Activation — one flag day, nothing deployed.** §5. Notably, this is
the first committed-object change in the program's history requiring **no
ASERT rescale** (`Num/Den = 1/1` exactly, since the work unit is unchanged)
and **no pre-activation silicon calibration**.

**DoS (the flip side of (vi), bounded):** a garbage block now costs O(W) to
reject on the recompute path (~10³× today's O(n²)). Defenses, all existing:
the header-PoW pre-gate (`nMatMulHeaderPoWDiscountBits`,
`params.h:470-502`) makes every body-verify attempt cost the attacker
real SHA header-PoW; the v4 verify budgets
(`nMatMulV4{Global,Peer}VerifyBudgetPerMin`, `params.h:403-410`) are re-tuned
to the recompute cost; cache-first policy applies where bytes are available
(a garbage *cache* is rejected by one 8 MiB hash ≈ 4 ms and the peer
banned — cache verification is fail-fast even though recompute is not).
Residual exposure is a rate-limited GPU-ms/CPU-s per header-PoW-paying
attempt: bounded, and priced in.

### 3.2 RANK 2 — Corrected ENC-SC (F1 + F2): sound, deferred, kept on file
### (ENC-SC AS DRAFTED: DISQUALIFIED under criterion 1 — not ranked)

First the disqualification, for the record: the drafted §7 design keys the
lottery on the per-nonce evaluation-codeword tree, so its floor is
κ = 1.42 (ρ = 1/2) rising to κ = 1.9–2.4 once F2's proven-regime sizing
forces ρ ≤ 1/4 to fit the 256 KB cap. That multiplies, ∝ m², exactly the
flat-across-classes SHA term whose excess produced the measured PR #89
inversion, in exchange for a criterion-4 good. Under the priority order this
is not a tunable risk; it is disqualifying (§2.0). No proof-carrying design
whose commitment must be built per-nonce at κ materially > 1 may ship.

With F1+F2 folded in, however, ENC-SC becomes a coherent rigid construction
whose nonce loop is nearly clean: lottery `H(σ‖M)`, M = Merkle over the m²
message residues (κ ≈ 1.04); win-time codeword at ρ = 1/4, ~90 proven-Johnson
queries
(1.0 bit/query) + grind_bits = 30 ⇒ forge cost ≈ 2¹²⁰; proof ≈ 150–250 KB
under the 256 KB cap; verify ≈ 150–400 ms from 200 KB with **no cache and no
GPU ever needed**. That last clause is its entire remaining advantage over
ENC-DR, and it is bought with: (a) the largest consensus-normative surface in
BTX history (circle-FFT over M61, F_{q²}, canonical transcript/serialization,
~2k lines of new consensus-critical reference code + golden vectors); (b) a
*new, unreviewed* cryptographic component — the M ↔ FRI-polynomial
consistency argument (systematic encoding + opened message positions) that F1
requires and no cited literature provides in this exact composition; (c) the
external review gates (RBR-soundness writeup of the combined protocol,
Circle-FRI-over-M61 cryptanalysis) as blocking dependencies; (d) win-time
prover latency (codeword FFT + tree + 2³⁰-grind ≈ 1 s GPU but ~30–60 s
single-thread CPU — an orphan-risk cliff for any non-GPU winner); (e) even
κ = 1.04 re-opens the silicon gate: under the twice-burned rule the 4 %
cannot be waved through on paper, so activation re-acquires the H100/B200
measurement dependency that ENC-DR uniquely avoids; (f) the same m²
message-tree floor and hence the same erosion window as ENC-DR — it does
**not** solve the OPEN RISK, it matches ENC-DR on it (§2.2). Verdict:
adopting this now is paying the maximum-complexity price, plus a nonzero
draw against criterion 1, to upgrade the *fallback* verify path from "8 MiB
cache or GPU or seconds" to "200 KB always" — an upgrade to the explicitly
sacrificable criterion 4, with negative expected value while the validator
population is the one the thesis itself selects. **Disposition: keep as the
designed successor** (the §5.3 trigger), with F1/F2 and this memo's floor
adjudication (§2.2) as its corrected starting point — and with its own
silicon gate as a permanent activation condition.

### 3.3 RANK 3 — Pure Candidate A (no cache path)

Everything in §3.1 except the ~200 ms CPU common case. Strictly dominated:
the cache path costs no consensus surface (it *is* the v4.3 verifier +
one authentication hash), ~300 lines of optional P2P code, and removes the
only regression pure-A has (CPU tip verify). There is no reason to ship A
without the cache layer. Ranked only to make the dominance explicit.

### 3.4 Rejected hybrids (with reasons, so they stay rejected)

- **Per-nonce Merkle-root lottery + cache** (tiled message tree instead of
  flat digest): enables nothing — Freivalds reads all m² words anyway, so
  partial-cache verify does not exist; costs +16k compressions/nonce and a
  golden-vector regeneration; flat `H(σ‖Ĉ)` is also the L0-frozen form.
  Rejected: pays for optionality no verifier can use.
- **O(1)-hint deterministic O(n²) verify**: impossible (§2.3 negative
  result). Rejected: no construction exists; this is Candidate C.
- **Scale only via n to dodge m²**: directionally right, already policy
  (n-scaling is erosion-free), but n is VRAM- and O(n²)-verify-bounded
  (n ≤ 8192 L0 window) and m is the arithmetic-intensity knob (AI ∝ m via
  2n/b); abandoning m forfeits the measured 1.54× frontier margin. Adopted
  as a *rule* (n preferred where budgets allow; m inside its window), not as
  the design.
- **Probabilistic/sampled tip verification, fraud proofs, recursion**:
  fail D2 / fork choice / 2026 engineering reality respectively, per the
  prior memos' standing rejections (nextgen §4.D, decoupling §3-O3).

---

## 4. The v4.4 construction (normative sketch)

### 4.1 Consensus predicate (the whole of it)

At heights ≥ `nMatMulV4Height`, a block's PoW is valid iff:

1. Header rules unchanged: 182-B layout, seeds non-null, `matmul_dim ==
   nMatMulV4Dimension`, σ = SHA256d(header with digest zeroed), I1′ scoping,
   `matrix_a_data`/`matrix_b_data` empty.
2. **`matrix_c_data` empty** (a non-empty PoW payload is invalid; the
   MUTATED/permanent classification collapses — there are no body proof
   bytes to mutate).
3. `matmul_digest == H(σ ‖ SerializeSketch(Ĉ_true(header)))` where
   Ĉ_true = (U·A)(B·V) over F_{2⁶¹−1} exactly as defined by the existing
   reference (`ComputeSketch` ≡ `ComputeSketchOptimal`, `matmul_v4.h`), with
   the ENC-BMX4C operand encoding unchanged.
4. `matmul_digest ≤ target(nBits)`; ASERT unchanged; rescale 1/1.

Clause 3 is a pure function of the header: the strongest possible D1/D3.
The digest form `H(σ‖Ĉ)` — an L0-frozen item that ENC-SC amended — is
**preserved verbatim**.

### 4.2 Permitted evaluation strategies (implementation, consensus-equivalent)

- **RECOMPUTE (reference; defines clause 3):** XOF-expand operands, run the
  deterministic solver (CPU reference or any mining-eligible accelerated
  backend — the existing cross-vendor bit-identity + eligibility harness,
  `backend_capabilities_v4`, already guarantees byte-equality), serialize,
  hash, compare. ε = 0.
- **CACHE-ASSISTED (fast path):** given candidate bytes from any source:
  (a) `H(σ‖bytes) == matmul_digest` — one hash over 8m² B (≈ 4 ms; on
  mismatch the *cache* is garbage: discard, penalize the supplying peer,
  fall back to recompute — a cache failure is NEVER evidence about the
  block); (b) `ParseSketch` canonicality; (c) `SketchFreivalds`, R = 3,
  challenges from `H(σ‖H(payload))` — all existing code, byte-identical to
  the v4.3 verifier; (d) accept. False-accept ≤ 2⁻¹⁸⁰; false-reject
  impossible (a digest-matching payload failing Freivalds implies, whp, the
  miner committed Ĉ′ ≠ Ĉ_true, so clause 3 rejects too — the paths agree).

### 4.3 Sketch-cache transport (non-consensus, best-effort)

New P2P pair `getmmsketch(blockhash)` / `mmsketch(blockhash, bytes)`:
pull-based, token-bucketed per peer and globally, served from (a) a miner's
own materialized sketches, (b) a node's optional rolling regeneration window
(default 2016 blocks ≈ 15.8 GiB, `-mmsketchcache=<blocks|0>`), (c) on-demand
GPU regeneration by volunteer nodes. Properties that make this a fraction of
the deleted Stage-2b/2c/2d subsystem: no consensus edge, no INCOMPLETE state,
no stall (fallback = recompute), no availability obligation, no archive role,
self-authenticating payloads (one hash), and at m ≤ 1024 a single message fits
every transport (8 MiB < 16 MiB BIP324 v2 ceiling); at m ≥ 2048 either chunk
opportunistically or simply don't serve — CPU peers then use parallel
recompute. Explicitly NOT `NODE_*`-service-bit-advertised as a trust role.

### 4.4 What is deleted (inherited from the RC architecture memo, unchanged)

The entire segregated-proof complex — `matmul_proof_store.{h,cpp}`,
`GETMATMULPROOF`/`MATMULPROOF`/`MATMULPROOFCHUNK`, the Stage 2b/2c/2d
pending/serve/eviction machinery in `net_processing.cpp`,
`CheckMatMulV4SegregatedProof`, `GetMatMulProofSizeCap`,
`BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY`, ENC-BMX4CD as a profile,
`sketch_payload_bytes`/`proof_segregated` in `MatMulProfileParams` — plus,
relative to the ENC-SC plan, everything ENC-SC would have added
(`matmul_v4_sc.*`, circle-FFT, F_{q²}, fri_* parameters, the 256 KB cap, SC
golden vectors, SC backend kernels). Net: the v4.4 diff is dominated by
deletions; the added consensus surface is approximately **zero** (clause 2's
empty-body rule and the dispatch restructure are the only consensus edits;
the cache path reuses the existing verifier unmodified).

### 4.5 `MatMulProfileParams` (final form)

```cpp
enum class MatMulCommitmentScheme : uint8_t {
    FLAT_SKETCH_INBLOCK = 1,  // regtest vector-replay only (legacy v4.2 carriage)
    DIGEST_RECOMPUTE    = 2,  // ENC-DR: zero consensus payload; cache-assisted
                              // Freivalds or exact recompute
};
struct MatMulProfileParams {
    MatMulEncodingProfile  profile;      // ENC_SC id retired unused; ENC_DR = 4
    MatMulCommitmentScheme commitment;   // DIGEST_RECOMPUTE
    uint32_t tile_b;                     // 4 (unchanged)
    uint32_t sketch_rank_m;              // 1024 (unchanged; cache size = 8*m^2 derives)
};
```

---

## 5. Migration and gates

1. **Single flag day** at `nMatMulV4Height` (INT32_MAX everywhere until
   ratified; regtest low for CI): clauses §4.1 in, deletions §4.4 out, in one
   change series so the tree never holds two live carriage paths.
2. **Golden vectors: substantially retained.** Ĉ, σ, digest, Freivalds
   transcript and the adversarial wrong-limb/non-canonical vectors are
   unchanged objects; new vectors cover only the empty-body rule,
   cache-path accept/reject (garbage-cache, tampered-word, truncated), and
   recompute-path equality across backends (the existing determinism harness
   extended with a verify-side entry point).
3. **Gates (all lighter than ENC-SC's):** (i) code review of the dispatch +
   cache transport (no external cryptographic review needed — no new
   cryptography exists); (ii) an informational (non-blocking) bench of
   recompute-verify wall time on reference validator hardware to set the
   re-tuned DoS budgets; (iii) the L0 amendment process — smaller in scope
   than ENC-SC's: the digest form survives, the Freivalds structure survives
   (as the cache path), q/exact-integers/σ/price-independence survive; what
   is amended is the mandatory Θ(m²) in-block carriage and the verify-budget
   *wording* (from "<1 s single-thread from consensus bytes" to "<1 s
   single-thread cache-assisted; recompute fallback budgeted on a
   reference parallel/GPU validator"). No ASERT rescale; **no new silicon
   gate** — the K.2b H100/B200 GO/NO-GO already required to activate v4 at
   all remains the no-inversion acceptance test, and it measures a pipeline
   this fork does not touch.
4. **Successor trigger (recorded policy):** if a future requirement demands
   trustless sub-second verification from O(1) bytes with no cache and no
   GPU — e.g. consensus-external consumers of the sketch, or a validator
   population inversion — activate corrected ENC-SC (F1+F2, §3.2) as the
   designed upgrade. Its per-nonce floor (×1.04) is now known not to disturb
   the thesis, so the decision is purely about complexity vs the new
   requirement, exactly as it should be.

---

## 6. Quantitative summary

| | v4.2 today | ENC-SC drafted (DISQUALIFIED) | ENC-SC corrected | **v4.4 ENC-DR** |
|---|---|---|---|---|
| **κ — per-nonce floor vs the measured no-inversion config (criterion 1)** | ×1.00 | **×1.42–2.4 ⇒ inversion channel re-opened** | ×1.04 (silicon gate re-opened) | **×1.00 — byte-identical; no-inversion by identity** |
| Consensus bytes/block (PoW) | 8–32 MiB | 64–200 KB | 150–250 KB | **0 B** |
| Archive/yr (PoW) | 2.67–10.7 TiB | 60.8 MiB | 60.8 MiB | **60.8 MiB** |
| Miner GEMM path | — | unchanged | unchanged | **byte-identical** |
| Soundness ε | 2⁻¹⁸⁰ | ~2⁻⁴⁰–⁶⁰ grindable (BREAK #2) | ~2⁻¹²⁰ (grind-adjusted) | **0 / 2⁻¹⁸⁰** |
| Lottery grinding channel | none | BREAK #1 | closed by F1 + consistency arg. | **structurally none** |
| Verify, common case (1T CPU) | 95–200 ms | 150–400 ms | 150–400 ms | **95–200 ms (cache)** |
| Verify, worst case | 95–200 ms | 150–400 ms | 150–400 ms | **W: ms GPU / 0.1–0.25 s 16T / 0.8–2 s 1T** |
| New consensus surface | — | very large | largest ever + new crypto | **~zero (net-negative LOC)** |
| Blocking external gates | — | 2 crypto + silicon | 2 crypto + silicon | **none (L0 process only)** |
| ASERT rescale at fork | — | measured | measured | **1/1, none** |
| Reward curve (M1–M4) | baseline | preserved *conditional on soundness review* | preserved conditional | **preserved by identity** |

---

## 7. The honest trade

What is sacrificed, plainly — and it is a slice of criterion 4, the one the
priority order marks sacrificable: **the guarantee that a node can verify the
tip in under a second, single-threaded, from consensus data alone.** Under
ENC-DR that guarantee becomes conditional — on a peer serving 8·m² cache
bytes (common case, incentive-aligned, self-authenticating, ~200 ms), or on
parallelism (~0.1–0.25 s at 16 threads), or on any GPU (~ms), with the
unconditional single-thread floor at 0.8–2 s today and growing ∝ W at each
shape retarget (≈ 11–22 s single-thread at the m = 8192 horizon — by which
point the cache path still runs in well under a second). Criteria 1–3 are
paid nothing: the compute-reward object is byte-identical (κ = 1.00 — the
only candidate for which no-inversion is preserved by *identity* rather than
by fresh measurement, which is precisely what the priority order demands of
the top criterion), determinism is exact-or-2⁻¹⁸⁰ with no trusted setup and
a header-pure predicate, storage is exactly O(headers). Both adversarial
breaks are structurally impossible rather than repaired, the m² floor risk
returns to its already-measured v4.3 baseline governed by the n-first
scaling rule, block propagation gets lighter (headers + txs instead of
≥ 8 MiB), ~2k lines of consensus-adjacent relay/store/FRI surface are
deleted, and the release gates shrink from two external cryptographic
reviews plus a fresh silicon campaign to ordinary code review, the
already-scheduled K.2b measurement of the unchanged pipeline, and the L0
process. The review's own fallback clause — "Candidate A: zero prover
overhead, GPU-class tip verify, still deterministic + flat" — is hereby
promoted to the primary design, completed with the cache path that removes
its one regression in the common case at zero cost to the miner loop. This
memo is the v4.4 release candidate; ENC-SC as drafted is disqualified;
corrected ENC-SC (F1+F2) is the filed successor, not the ship vehicle.

---

## 8. Sources

**Code:** `src/matmul/matmul_v4.h` (:89-142 σ/seeds/I1′, :152-179 sketch
reference/optimal, :239-252 serialize/digest, :254-271 SketchFreivalds);
`src/pow.cpp` (:2189 ASERT, :3512-3531 payload size, :3543-3618 verify
dispatch + target, :3620-3649 in-block carriage, :3651-3713 segregated path);
`src/consensus/params.h` (:96-166 profiles, :178-184 MatMulProfileParams,
:186-225 relay-ready flag, :403-410 verify budgets, :470-502 header-PoW gate,
:517-532 subsidy); `src/validation.cpp` (:10315 assumevalid buried-proof
trust); `src/matmul/matmul_proof_store.{h,cpp}`;
`src/matmul/matmul_v4_batch.h`; `src/matmul/backend_capabilities_v4.h`.
**Docs:** `btx-matmul-enc-sc-adversarial-review-and-required-fixes.md`
(BREAK #1/#2, OPEN RISK, F1/F2, §4 fallback clause);
`btx-matmul-deterministic-nextgen-design.md` (§1 D1–D3 bar, §2.2 structural
facts, §2.4 grinding break, §4.A/§4.C, §7, §9);
`btx-matmul-compute-vs-data-decoupling-research.md` (§1.3 coupling, §3-O1/O5,
§6 O(headers)); `btx-matmul-v4.4-compute-reward-preservation.md` (M1–M4,
§L.2.1 neutrality, ladder anchors);
`btx-matmul-v4.4-release-candidate-architecture.md` (deletion inventory,
flag-day framing); `btx-matmul-v4-design-spec.md` (§E.3, §I.4, §K.2a/b, §L);
`btx-matmul-v4.2-consolidated-design.md` (§6 ladder);
`btx-matmul-v4.2-longevity-threat-model.md` (L0);
`btx-matmul-v4.2-asert-calibration.md`; `btx-matmul-v4.2-header-pow-gate.md`;
`freivalds-algorithm-analysis.md`. **External:** Komargodski–Weinstein,
*PoUW from Arbitrary Matrix Multiplication* (recompute-verify, O(1) storage
precedent) — <https://eprint.iacr.org/2025/685.pdf>; Korec–Wiedermann
(deterministic-verify impossibility line) — SOFSEM 2014; Diamond–Gruen
2025/2010 + SoK 2026/1367 (capacity-conjecture disproof, per the review);
FRI/Circle-STARK citations as in the nextgen memo §10 (relevant to the filed
successor only).
