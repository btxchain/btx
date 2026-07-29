# BTX ENC_RC v4.6 — Profile-2 Sampled-Carrier Anti-Grind Construction (DESIGN SPEC)

Status: **FVT IMPLEMENTED** (§4's chosen construction is now consensus code; see
§8). No activation heights changed; int64 reference untouched; no digest/wire/
carrier-version change. Activation heights remain `INT32_MAX` (nothing live).
CAP (the fallback in §2/§3) remains unimplemented design-only, kept as the
tunable alternative if a full terminal-round recompute ever overruns the 900 ms
verify budget (λ retune is the first lever; see §8's verify-time note).

Scope note on names: the code entry point the break was demonstrated against is
`matmul::v4::rc::VerifyEpisodeFreivaldsSampledCarrier`
(`src/matmul/matmul_v4_rc_freivalds_sampled.cpp`), reached from
`CheckMatMulProofOfWork_RC` under `params.nMatMulRCProfile == 2`
(`src/pow.cpp:4204-4259`). The task statement calls it "VerifyEpisodeFreivalds-
SampledCarrier"; same function.

---

## 0. The confirmed break (restated precisely, with code anchors)

Deterministic episode structure (`RunEpisode`, `src/matmul/matmul_v4_rc.cpp:686-753`;
mirrored in the GKR/carrier gates, `matmul_v4_rc_gkr.cpp` / `_freivalds_sampled.cpp`):

- `sigma = DeriveSigma(header)` and `DeriveSigma` hashes every header field
  **except** `matmul_digest` (`matmul_pow.cpp:220-254`, via `ComputeMatMulHeaderHash`).
- `seed_0 = H(kRCRoundTag, sigma, 0)`; for `r>0`,
  `seed_r = H(kRCRoundTag, round_roots[r-1], r)`
  (`matmul_v4_rc.cpp:700-710`; `RCGkrRoundSeed`, `matmul_v4_rc_gkr.cpp:2075`).
- Round `r` is computed **only** from `seed_r` and `sigma` (Phase1/Phase2 regenerate
  their operands by PRF from the seed — rounds do **not** pass activation tensors
  forward; the sole inter-round dependency is the 32-byte seed).
- `round_roots[r]` = Merkle root of round `r`'s streamed output tiles.
- `digest = SHA256d(kRCEpisodeTag ‖ round_roots[0..R-1])` (`matmul_v4_rc.cpp:737-745`;
  `EpisodeDigestFromRoots`). This is written to `header.matmul_digest`.
- Fiat–Shamir sample coin: `base_seed = RCGkrFsSeedV7(header, height, params, target,
  claimed_digest, sigma, round_roots)` (`matmul_v4_rc_gkr.cpp:1278-1335`), which
  absorbs `claimed_digest` and the **full** `round_roots` vector. The λ sampled unit
  indices and the per-tile `SegPos` / Freivalds challenges all derive from `base_seed`
  (`FreivaldsSampleLayers`, `TilePositions`/`SegPosU64`,
  `matmul_v4_rc_freivalds_sampled.cpp:712-956`).
- Profile-2 acceptance runs **only** the sampled carrier check
  (`src/pow.cpp:4204-4259`): cheap gates (`CheckGatesAndSeed`,
  `_freivalds_sampled.cpp:565-590`) that byte-verify the seed chain, the
  digest-from-roots identity and `digest ≤ target`, then λ=512 sampled units each
  opening `kRCFreivaldsSegOutTiles=2` tiles and recomputing those tiles from anchored
  operands. **No exact replay** on the hot path (ExactReplay is retained only as an
  async, off-hot-path arbiter).

### The free variable

The last round root `round_roots[R-1]` is **terminal**: it is read by `digest` and by
`base_seed`, but it feeds **no** downstream `seed_r` (the chain seeds round `r` off
`round_roots[r-1]`, so nothing consumes the last root). The verifier binds a round's
output only at the **λ·2 sampled tiles**; every other tile of every round — in
particular of the last round — is a **free byte string** as far as consensus is
concerned. Per-unit sample coverage is `2 / (m·n / (32·T_leaf))` tiles ≈ **4.8e-7**.

Therefore an adversary who has run **one** honest episode can:

1. Mutate unopened output tiles of the terminal round (any bytes outside the current
   sample). Rebuilding that one round's Merkle tree costs ≈ **0.7 % of an episode**
   (measured; one round's hash pass, **no GEMM**).
2. This yields a fresh `round_roots[R-1]` → fresh `digest` → fresh `base_seed` → a
   fresh, independent sample set (grinding the Fiat–Shamir coin).
3. Accept the trial iff `digest ≤ target` **and** none of the mutated tiles land in
   the new sample (holds w.h.p. at coverage 4.8e-7).

The AI-PoW collapses to *one honest episode, then hashcash over a 0.7 %-cost Merkle
re-roll*. With `G` cheap trials the true acceptance bound is `P_accept ≈ G·p`, not the
advertised single-shot `(1-f)^384`. Verified four ways (code read; a grinding PoC that
made the carrier verifier accept a wrong last-round tile after **one** grind; two
external audits).

### The two levers (both must be neutralized)

- **L1 — cheap digest re-roll.** A fresh `digest` costs one round's *Merkle* rebuild
  (no GEMM), because the terminal output is a free suffix with no cascade.
- **L2 — free fresh challenge per re-roll.** `sample = f(digest)`, so every L1 re-roll
  hands the adversary a fresh independent challenge to dodge.

L2 alone is the classic "grind the FS challenge"; it is only dangerous because L1 makes
each fresh challenge nearly free. **Kill L1 (make each fresh `digest` cost real,
non-amortizable field work) and L2 collapses**: `G` expensive trials, with `G` bounded
by honest hashrate, restores `P_accept ≈ G·p` at `G ≈ (real work)/(per-trial work)`.

---

## 1. Formal property (the grinding-resistance lemma the fix must make TRUE)

**Adversary model.** A probabilistic algorithm that fully controls: the header
(`nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nNonce64, matmul_dim,
seed_a, seed_b, matmul_digest`), and **every** committed episode value it relays — all
`round_seeds[r]`, all `round_roots[r]`, the `claimed_digest`, and every byte of every
carried tile (`RCFreivaldsSampledTile`), subject only to the checks the verifier
actually runs. It may precompute one (or a constant number of) honest episodes.

**Commit point.** `header.matmul_digest` is the block-level commitment; a block is
mined the instant `UintToArith256(matmul_digest) ≤ target`. The FS coin `base_seed` is
derived *after* the commitment (`RCGkrFsSeedV7` absorbs `matmul_digest` + `round_roots`),
so the challenge is post-commitment (unbiasable) **by construction** — the defect is not
that the coin is biasable but that the commitment it is drawn from is cheap to re-roll.

**Cost metric.** *Fresh non-amortizable field work* `W` = the number of GF(p)/int8
multiply-accumulate operations that must be executed **for this trial and cannot be
copied from any previous trial** (Merkle/SHA re-hashing of already-computed tiles is
*amortizable* and is explicitly **not** counted toward `W`; that is exactly the work the
current attack abuses).

**Lemma (grinding-resistance — the target).**
> Let `A` be any adversary strategy that outputs a **fresh** accepted pair
> `(digest', challenge-set')` — i.e. `digest' ≤ target`, the carrier verifier accepts,
> and `digest'` differs from every digest `A` has previously had accepted. Then `A`
> performs `W ≥ Ω(W_round)` fresh non-amortizable field work per such output, where
> `W_round` = the MAC count of one production round's GEMMs.
>
> **Ideal (stretch) form:** `W ≥ Ω(W_episode)` = all `R` rounds' GEMMs.

**Why `W_round`, not `W_episode`, is the honest in-budget bar (impossibility note).**
A strictly sublinear verifier binds a round's output only at `O(λ)` sampled tiles; every
other tile is intrinsically unconstrained (that ignorance *is* sublinearity, and is the
priced `ρ*` deterrence residual). It follows that the only way to *force* the adversary
to have executed a full round's GEMM for a value that feeds `digest` is for the verifier
itself to fully recompute that round — i.e. **forced-mining-per-trial = verifier-cost-of
-the-fully-checked-unit** (proved informally in §3, the *cost law*). Under the 900 ms
budget the verifier can fully recompute at most `O(one round)` (a full-episode recompute
is exactly the ExactReplay that profile 2 exists to avoid). Hence **`Ω(W_round)` is the
maximum in-budget bar; `Ω(W_episode)` requires ExactReplay-class verify** (retained as the
async arbiter — see §2 candidate AFB-R). The construction below meets `Ω(W_round)` and is
explicit that the interior remains `ρ*`-deterrence.

---

## 2. Candidate constructions

Notation: `R` rounds; per-round GEMM MAC cost `W_round`; `W_episode = R·W_round`;
sublinear-relay = carrier bytes independent of `m,n,k` (the 12 MiB ceiling,
`kRCFreivaldsCarrierMaxSerializedBytes`); sublinear-verify-compute = `O(λ·log N)`.

### FVT — Fully-Verified Terminal round (recompute-from-seed) — **CHOSEN**

Make the terminal round's root **unforgeable** by having the verifier fully recompute
round `R-1` from its seed, and bind acceptance to it. Because rounds regenerate all
operands by PRF from `seed_{R-1}` (no forward-carried tensors), the verifier needs **no
extra relay**: it deterministically re-executes Phase1+Phase2 of the last round from the
32-byte `seed_{R-1}`, rebuilds `round_roots[R-1]`, and requires equality with the carried
root. The digest formula is unchanged (`H(round_roots)`).

Soundness argument. After FVT, any digest change forces changing ≥1 root; the seed chain
is byte-checked (`CheckGatesAndSeed`), so changing any `root_j (j ≤ R-2)` propagates
(cheaply, by hashing) to `seed_{R-1} = H(root_{R-2})`, and the verifier's mandatory
recompute of round `R-1` under the **new** `seed_{R-1}` forces the adversary to have run
that round's GEMMs to produce a matching `round_roots[R-1]` (a stale root fails the
equality; a forged root fails because it must equal the deterministic recompute). The
cheapest fresh-digest path is therefore *(pick any interior root freely → one forced
terminal-round GEMM)* = **`Ω(W_round)`, with a real GEMM, non-amortizable** (each trial's
`seed_{R-1}` differs, so no tile is reusable). L1 is closed; L2 collapses. Not
incrementally updatable: a 1-tile interior change moves `seed_{R-1}` and forces a full
fresh round recompute — there is no O(1) fold shortcut.

Cost: verify gains **one deterministic round recompute**; relay unchanged (sublinear).
Miner: **no change** (honest mining already computes every round). This is the sole
candidate that is both sound and keeps sublinear **relay**; it trades one-round verify
**compute** (§3, mitigated by re-budgeting λ or right-sizing the forced unit).

### AFB-R — Always-checked full Freivalds on every round (ideal, rejected on perf)

Fully bind every round (full-contraction Freivalds or recompute for all `R` rounds).
Soundness: reaches the ideal `Ω(W_episode)` — the whole chain is forced from the nonce.
But full per-round binding needs the full operands/activations for every round; with no
forward-carried tensors the verifier must **regenerate every round** = a full-episode
recompute = **ExactReplay by another name**, which is exactly what profile 2 exists to
avoid (cannot fit 900 ms at datacenter dims). **This is the retained async ε=0 arbiter**,
not an in-budget hot-path fix.

### CAP — Low-cost contraction capstone round (candidate (c); tunable, needs re-pin)

Append a small extra round `R` whose seed `= H(round_roots[R-1], R)` (giving the
previously-terminal root a consumer) and whose (reduced-dim) output is **fully verified**;
bind `digest` to include `round_roots[R]`. This is FVT with a **right-sized** forced unit:
the capstone dims are chosen so its full verification spends exactly the residual verify
budget, maximizing forced work under 900 ms. Soundness identical to FVT (forced unit is
unforgeable; interior cascades into it), at the forced level `Ω(W_capstone) ≤ Ω(W_round)`.
Cost law (§3) binds `W_capstone` to the budget spent. **Downside:** it changes the episode
structure (rounds `R→R+1` or a capstone flag) → changes `digest` → **re-pins episode
golden vectors and the carrier version** (acceptable pre-activation; see §6). Kept as the
tunable alternative to FVT when a full terminal round overruns budget.

### TFOLD — Terminal-consumer algebraic fold into the digest (REJECTED — instructive)

Give the terminal root a consumer by folding a fingerprint `Φ` of the final output into
`digest` and `base_seed`, with a post-commit challenge `γ = H(all round_roots)`:
`Φ = Σ_i e_i·γ^i` over GF(p³) (Horner/Schwartz–Zippel of the final stream at `γ`).

Two independent failures, both matching the task's incremental-update warning:
- **If `γ` is fixed:** `Φ` is linear/homomorphic → a 1-element change updates `Φ` in
  **O(1)** (`Φ += (e'−e)·γ^i`) → the grind survives unchanged. **FAILS.**
- **If `γ` floats with the commitment** (as above, forcing an Ω(N) re-fold per trial —
  the intended defense): `Φ` is a value over the **full** final output that the sublinear
  verifier **cannot recompute** (it never reads all `N` tiles) and cannot bind without a
  polynomial-commitment opening (no FRI/KZG is wired on the RC stream — the RC path is
  Merkle tile-trees + Freivalds, not a codeword commitment). An unbound `Φ` in the digest
  is a **new free 24-byte grind variable at zero cost** → strictly **worse**. **FAILS.**

Conclusion: an algebraic fold cannot be made both non-homomorphic and sublinearly
bindable on this transcript without a polynomial commitment. Documented so the later
implementer does not re-derive it. (candidate (d) "include `matmul_digest` in `sigma`" is
also rejected: `digest` depends on the episode which depends on `sigma`, so folding the
digest back into `sigma` is a fixpoint/circular dependency — infeasible as a forward
construction.)

---

## 3. Cost analysis (900 ms budget; production dims rounds=8, L_lyr=24, d_ff=16384,
b_seq=32768, n_ctx=786432; current sampled verify ≈ 700 ms @ 32 threads)

**The cost law (informal proof).** For a value `v` that feeds `digest`, the verifier can
*force* the adversary to have executed computation `C` to produce `v` only if the verifier
itself checks `C` end-to-end for `v` (sampling checks only `O(λ)` positions, which the
adversary can satisfy in `O(λ)` — deterrence, not forcing). Hence
`forced_mining_per_trial = Θ(verifier_cost_of_the_fully_checked_unit)`. Budget spent on
the forced unit converts 1:1 into per-trial mining floor.

Let `V_int = 700 ms` (interior sampling, unchanged), `V_tail` = cost to fully verify the
forced unit, `B = 900 ms`. Feasibility: `V_int' + V_tail ≤ B`, where `V_int'` is interior
sampling after any λ retune.

| Candidate | Forced `W`/trial | Verify Δ (hot path) | Relay | Miner Δ | Golden re-pin | In budget? |
|---|---|---|---|---|---|---|
| **FVT (existing terminal round)** | `Ω(W_round)` real GEMM | `+V_tail = one round recompute` | unchanged (sublinear) | none | **none** (digest formula same) | only if `V_int' + one-round ≤ 900 ms` → retune λ |
| **CAP (right-sized capstone)** | `Ω(W_cap) ≤ Ω(W_round)` | `+V_tail = capstone recompute` (tuned to `B−V_int'`) | +capstone tile data | none | **yes** (episode/digest change) | **yes, by construction** |
| AFB-R (all rounds) | `Ω(W_episode)` | `≈ full ExactReplay` (≫ B) | needs all operands | none | n/a (arbiter) | **no** (this *is* the arbiter) |
| TFOLD | 0 (unbound) or Ω(N) unverifiable | +Ω(N) or unbound | — | — | — | **rejected** |

Quantifying `V_tail` for FVT. One production round ≈ `W_episode / R = 1/8` of a full
episode recompute. A full-episode recompute is precisely the workload profile 2 declares
too heavy for the block-verify budget, so `V_tail ≈ (episode_recompute)/8` is a **budget
risk**: if a full ExactReplay is ~5 s at 32 threads then `V_tail ≈ 0.6 s`, and
`700 + 600 = 1300 ms > 900 ms`. Two levers restore feasibility, both no-consensus-risk
retunes of *deterrence* parameters (they weaken only `ρ*`, never a soundness check):

1. **Retune interior λ down** for the non-terminal rounds to free budget: interior cost
   scales ~linearly in `λ`, so `λ: 512 → ~256` roughly halves `V_int` to ~350 ms, leaving
   ~550 ms for `V_tail` (one round if the episode recompute is ≲ 4.4 s; else use CAP).
   `ρ*_interior ≈ ln κ/λ` doubles (0.13 %→0.27 %) — still the documented deterrence tier.
2. **CAP: right-size the forced unit** to `V_tail = B − V_int' `. This is the robust,
   budget-guaranteed choice; it sacrifices "no re-pin" for a provably in-budget forced
   work of `Ω(W_cap)` with `W_cap` = the largest GEMM whose full verify fits the residual.

**Ranking (soundness ∧ in-budget ∧ minimality):**
1. **FVT** (chosen) — sound, zero miner change, zero digest re-pin, sublinear relay;
   only risk is `V_tail` fit, resolved by λ retune. Falls back to CAP if a full terminal
   round cannot be squeezed under budget.
2. **CAP** — sound, budget-guaranteed by construction, but re-pins the episode/digest.
3. **AFB-R** — sound and ideal, but = ExactReplay ⇒ out of budget ⇒ the async arbiter.
4. **TFOLD** — rejected (unsound or unbindable).

---

## 4. Chosen construction — exact algorithm

**FVT: Fully-Verified Terminal round, digest formula unchanged, interior λ retuned to
hold 900 ms; CAP as the drop-in fallback if a full terminal round overruns budget.**

### 4.1 What feeds what (unchanged vs new)

Unchanged: `DeriveSigma`, the round seed chain, per-round Phase1/Phase2, tile-tree roots,
`digest = H(round_roots)`, `base_seed = RCGkrFsSeedV7(...)`, the interior sampled-carrier
checks (a)–(d). **No mining-path change. No digest-format change.**

New verifier obligation (profile 2 only), inserted in `CheckMatMulProofOfWork_RC`
immediately after `CheckGatesAndSeed` succeeds and before returning accept:

```
# Inputs available with no extra relay: carrier.episode (consensus-pinned dims),
# carrier.round_seeds, carrier.round_roots, sigma.
r_last := episode.rounds - 1
seed_last := carrier.round_seeds[r_last]            # already byte-verified == H(root[r_last-1], r_last)
# Deterministic, operand-free-of-relay recompute of ONLY the terminal round:
p1 := Phase1AssociativeRecall(seed_last, sigma, episode)      # regenerates its own operands by PRF
p2 := Phase2MicroTraining   (seed_last, sigma, episode, gemm) # int64 reference GEMM path
root_recomputed := StreamRoundIntoMerkle(p1, p2, episode, ... , /*stream_out=*/nullptr)
if root_recomputed != carrier.round_roots[r_last]:
    return REJECT("v7fs:terminal_root_forged")
# interior rounds 0..R-2 remain the sampled deterrence check (unchanged)
```

`StreamRoundIntoMerkle` with `stream_out == nullptr` is the existing consensus
streaming-Merkle path (no full-round buffer; `matmul_v4_rc.cpp:717-725`), so the terminal
recompute has the same memory profile as one honest mining round. The int64 reference
(`GemmGXtInt64`) is used verbatim — **no new numeric kernel, no ε drift**.

### 4.2 Why it is sound (recap, tied to the lemma)

- `round_roots[R-1]` is now recomputed, hence **unforgeable**: the adversary cannot set
  terminal-round tiles freely.
- The seed chain is byte-checked; to change `digest` the adversary changes some root,
  which (via `seed_{R-1} = H(root_{R-2})`) forces one **fresh** terminal-round GEMM whose
  output must equal the recompute. That is `Ω(W_round)` of non-amortizable field work per
  fresh accepted `digest`. L1 closed ⇒ L2 collapses.
- Interior rounds keep exactly today's `ρ*` deterrence (explicitly *not* upgraded to
  soundness — matching the owner-authorized deterrence posture in the module banner).

### 4.3 Wire-format / serialization deltas

- FVT (chosen): **none.** The carrier already carries `episode`, `round_seeds`,
  `round_roots`; the terminal recompute reads only those. `kRCFreivaldsSampledCarrier-
  Version` is **unchanged**; digest/`base_seed` formats unchanged. The only "delta" is a
  new consensus constant gating the behavior and (optionally) a retuned interior λ:
  - `nMatMulRCProfile2FullyVerifyTerminalRound` (bool, default true at the profile-2
    activation height) — a consensus flag, not a wire field.
  - Optional `kRCFreivaldsInteriorSampleCount` (interior λ, if retuned from 512) — a
    deterrence constant; the *terminal* round is always fully verified regardless.
- CAP fallback (only if adopted): bump `kRCFreivaldsSampledCarrierVersion 3 → 4`; add the
  capstone round to `RCEpisodeParams` (either `rounds+1` or an explicit
  `capstone_dims`), extend `EpisodeDigestFromRoots` to include `round_roots[R]`, and add
  the capstone's fully-relayed output to the carrier. `RCGkrFsSeedV7` absorbs the extra
  root automatically (count-prefixed loop).

---

## 5. Isolated pure-algebra kernel (for the separate math-performance pass)

**For the CHOSEN construction (FVT): none — the sound terminal-round binding is a
byte/int8 recompute.** The forced unit is verified by re-executing the existing int64
reference GEMM (`GemmGXtInt64` / the `RCDenseRowBlockExactI8` int8 row×32-block path) and a
SHA256 streaming-Merkle root equality. There is **no new finite-field (GF(p)/GF(p³)) inner
loop** in the sound core; its hot loop is the existing int8 GEMM, which already has its own
optimization track (`RCDense*` / ARM I8MM kernels in
`matmul_v4_rc_freivalds_sampled.{h,cpp}`) and needs no new algebra spec here.

**Adjacent (optional) kernel — only relevant to the deterrence-tightening / budget-
freeing track, not to the sound fix.** If the implementer widens the interior deterrence
(more Freivalds contraction coverage) to compensate for a retuned λ, the field inner loop
that dominates is the **Goldilocks Freivalds mat-vec fold**, already present as
`FreivaldsCheckGemm` / `FreivaldsCheckGemmSegments`
(`matmul_v4_rc_freivalds.h`). Stated as a pure-algebra problem, with **zero** reference to
its consensus use:

> **Kernel: batched GF(p) / GF(p³) matrix–vector "project-and-compare" fold.**
> - Field: Goldilocks `p = 2^64 − 2^32 + 1` (`gkr_field::Fp`,
>   `matmul_v4_rc_gkr_field.h`); challenge scalars drawn from the degree-3 extension
>   `F_{p^3} = F_p[x]/(x^3 − 2)` (`gkr_field::Ext3`, `matmul_v4_rc_gkr_field_ext3.h`).
> - Inputs per instance: `A ∈ {−128..127}^{m×k}` (int8, row-major), `B ∈
>   {−128..127}^{k×n}` (int8, row-major), `Y ∈ ℤ^{m×n}` (int64, row-major, `|Y_ij|`
>   bounded by the embedding argument so each entry is a canonical `F_p` residue), and a
>   challenge vector `r ∈ F^{n}` (`F = F_p` for reps in the base field, `F = F_{p^3}` for
>   the extension reps).
> - Output: the boolean `A·(B·r) == Y·r` in `F^{m}`, computed as three mat-vecs and one
>   vector compare, **never** forming `A·B`:
>   `u := B·r ∈ F^{k}` (cost `k·n`), `w := A·u ∈ F^{m}` (cost `m·k`),
>   `y := Y·r ∈ F^{m}` (cost `m·n`); accept iff `w == y` elementwise. All arithmetic is
>   `Add/Mul/Reduce128` over `F_p` (int8 operands lift exactly to `F_p`), extension reps
>   use the `Ext3` `Mul`.
> - Segment form (`FreivaldsCheckGemmSegments`): given a partition of `[0,k)` into
>   segments `p`, compute `Σ_p A[:,p]·(B[p,:]·r)` and compare to `Y·r`; same field ops,
>   contiguous slices.
> - Performance target: the whole-instance fold is `Θ(mk + kn + mn)` field ops with a
>   working set of the two int8 operands + three `F`-vectors; the goal is to drive the
>   per-op cost toward one `Reduce128` (SIMD/`__int128`-batched Goldilocks multiply,
>   lazy reduction across the `k`-accumulation) and to fuse the `B·r`/`A·u` passes so the
>   int8 operands stream once. Batch dimension: hundreds of independent `(A,B,Y,r)`
>   instances (embarrassingly parallel across 32 threads). Correctness bar: bit-identical
>   accept/reject to the scalar reference for every `(seed, reps)`; no wall-clock-varying
>   verdict.

(This kernel is offered only because the math pass asked for a field loop to optimize; it
is the interior-deterrence hot loop, and faster it becomes, the more coverage the
implementer can afford under 900 ms — but it is **not** the FVT soundness mechanism.)

---

## 6. Re-pin impact

Baseline: heights are `INT32_MAX` (nothing live), so any re-pin is free to land at the
profile-2 activation commit; no reorg/compat concern.

### FVT (chosen) — minimal

- **Golden vectors:** **unchanged.** `digest = H(round_roots)`, per-round roots,
  `base_seed`, and the carrier wire format are all identical; existing episode/digest and
  carrier round-trip goldens still pass.
- **Consensus constants / flags added:** `nMatMulRCProfile2FullyVerifyTerminalRound`
  (bool, true at activation); optionally `kRCFreivaldsInteriorSampleCount` (interior λ,
  e.g. 512→256) — a *deterrence* constant, gated to the profile-2 activation height.
- **Wire versions:** `kRCFreivaldsSampledCarrierVersion` **unchanged (3)**.
- **No existing check weakened:** the terminal recompute is a **strictly added**
  accept-gate; `CheckGatesAndSeed`, digest-from-roots, `digest ≤ target`, seed-chain,
  interior sampled openings, and the retained ExactReplay arbiter all remain. `ρ*` for the
  interior is unchanged (or, with the λ retune, changes only within the documented
  deterrence tier — still no soundness claim on the interior).
- **Sublinear-relay verify:** **preserved** — the terminal recompute needs no carrier
  bytes beyond the 32-byte seed already present; the 12 MiB relay ceiling and the carrier
  size bound are untouched. **Tradeoff (explicit):** verify **compute** gains one
  deterministic round recompute (`Θ(W_round)`), held under 900 ms by the λ retune (or by
  CAP). Relay stays sublinear; verify compute is `O(λ·log N) + one round`.

### CAP (fallback) — larger

- **Golden vectors re-pinned:** episode digest changes (extra root), so episode/digest
  goldens and carrier goldens re-pin.
- **Consensus constants:** capstone dims + `kRCFreivaldsSampledCarrierVersion 3→4`;
  `RCEpisodeParams` gains the capstone shape; `EpisodeDigestFromRoots` and
  `ValidateRCEpisodeParams` extended.
- **No existing check weakened** (same added-gate property); sublinear relay preserved
  except the capstone's small fully-relayed output (bounded, budget-sized).

### Confirmation

Neither variant removes or loosens any current check, and neither touches the int64
reference, activation heights, or the ExactReplay ε=0 arbiter. The fix is monotone: it
**adds** a forcing gate that converts the terminal free variable into `Ω(W_round)`
non-amortizable field work per fresh accepted digest, closing L1 and thereby collapsing
the L2 FS-grind, while keeping profile 2's sublinear **relay** property.

---

## 7. Analysis harness

`contrib/matmul-v4/antigrind_cost_model.py` (standalone, no build) computes, for the
production dims: the current attack's per-trial cost and coverage, `P_accept ≈ G·p` vs the
advertised `(1−f)^384`, the FVT/CAP forced-work floor, and the verify-budget feasibility
(`V_int' + V_tail ≤ 900 ms`) across λ retunes and capstone sizes. It is a cost model, not a
PoC, and imports nothing from the tree.

---

## 8. Implementation record (FVT, this pass)

FVT (§4) is now wired into consensus code, unchanged from the chosen construction above.
Strictly additive: it only adds a rejection condition to the profile-2 accept path; an
honest carrier's terminal round always recomputes identically (byte-identical to the
streaming path the miner itself used), so no honest carrier is newly rejected, and no
digest/wire-format/carrier-version/golden vector changed. Heights remain `INT32_MAX`.

**Code locations.**

- `Consensus::Params::nMatMulRCProfile2FullyVerifyTerminalRound` (bool, default `true`) —
  `src/consensus/params.h`, declared immediately after `nMatMulRCProfile`. Gates the FVT
  check; active whenever profile 2 is selected (safe pre-activation: it can only ever
  *reject* a dishonest terminal round, never accept anything the pre-FVT verifier would
  have rejected).
- `matmul::v4::rc::RecomputeRCRoundRoot(seed_r, sigma, params, options, gemm)` —
  declared in `src/matmul/matmul_v4_rc.h`, defined in `src/matmul/matmul_v4_rc.cpp`
  immediately after `MineRCEpisode`. This is the reusable single-round primitive: it runs
  exactly one iteration of `RunEpisode`'s per-round loop body — `Phase1AssociativeRecall`
  + `Phase2MicroTraining` + `StreamRoundIntoMerkle` with `stream_out=nullptr` (the same
  streaming path the consensus episode path already uses) — and returns that round's
  Merkle root. No new numeric kernel; malformed params return a null root so the caller
  fails closed rather than asserting.
- The FVT gate itself — `CheckMatMulProofOfWork_RC`, `src/pow.cpp`, in the
  `params.nMatMulRCProfile == 2` branch, immediately after
  `VerifyEpisodeFreivaldsSampledCarrier` succeeds and before the profile-2 `return
  finish(true)`. It recomputes `round_roots[R-1]` via `RecomputeRCRoundRoot` fed from the
  carrier's own `round_seeds[R-1]` / `episode_sigma` / `episode` (already byte-verified
  against the seed chain by `CheckGatesAndSeed`, which ran inside the carrier-verify call
  just above), and rejects with reason `v7fs:terminal_round_root_mismatch` (or
  `v7fs:terminal_round_bounds` on a malformed carrier that would index out of range) on
  any mismatch — matching the `v7fs:`-prefixed reason convention already used throughout
  `matmul_v4_rc_freivalds_sampled.cpp`.

**Confirmed unchanged (re-verified for this pass).** `DeriveSigma`, the round seed chain,
per-round `Phase1AssociativeRecall`/`Phase2MicroTraining`, `StreamRoundIntoMerkle`,
`EpisodeDigestFromRoots`/`digest = H(round_roots)`, `RCGkrFsSeedV7`/`base_seed`, the
interior sampled-carrier checks (a)–(d), `kRCFreivaldsSampledCarrierVersion` (still 3),
and every activation height (`nMatMulRCHeight`, profile-2 selection) are all byte-identical
to before this change — FVT reads only carrier fields the sampled carrier already carries
(`episode`, `round_seeds`, `round_roots`, `episode_sigma`) and adds a pure comparison; it
writes nothing new to the wire and re-derives no digest.

**Regression coverage.** `src/test/matmul_v4_rc_datacenter_tests.cpp` adds an FVT test pair:
(1) an honest datacenter-profile carrier still verifies end-to-end through
`CheckMatMulProofOfWork_RC`'s profile-2 path with FVT active (the recomputed terminal round
equals the carried one), and (2) the same carrier's carried `round_roots[R-1]` is corrupted
post-hoc (the exact scenario the last-round-grind PoC exploited: mutate the terminal round's
committed root without redoing that round's GEMM) — pre-FVT this passed
`VerifyEpisodeFreivaldsSampledCarrier` outright (the sampled checks never touch an unopened
root byte); post-FVT it is rejected by the new gate.

**Verify-time note (not tuned in this pass).** Per §3, a full terminal-round recompute adds
`V_tail ≈ (episode_recompute)/rounds` to the profile-2 hot path. Whether this fits the
900 ms budget alongside the existing ~700 ms of interior sampling at production dims is a
λ-retune (or CAP-fallback) decision, deliberately **out of scope here** — this pass only
adds the gate and leaves `kRCFreivaldsSampleCount` and all budgets untouched, per the task
instruction to keep λ/budget tuning a separate decision.
