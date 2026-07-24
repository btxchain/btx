> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# ENC_RC P2.1 — Validation model evidence (shrink vs fraud-proof)

*Date: 2026-07-20. Tip: `79d3564` (`claude/matmul-v4-design-spec-af23sj`). Status: **evidence only** — owner decides. Does **not** raise `nMatMulRCHeight`. Does **not** enable §R.7 growth / segment leaves.*

## Question

Consensus verify for Resident Curriculum must choose a validation model before any activation. Two candidates:

| | **(a) Shrink the episode** | **(b) Genuine fraud-proof protocol** |
|---|---|---|
| Idea | Size the episode so **exact full-node CPU replay** fits a safe fraction of the block interval on commodity CPUs | Keep a large miner episode; put **round roots in-block**; serve segment openings on demand; **optimistic accept**; compact fraud proofs; full recompute **only on challenge** |
| Consensus predicate | Always ε=0 full int64 recompute | Optimistic accept under commitment + openings; ε=0 recompute as dispute resolution |

This note records **what the code does today**, a **minimal sketch of (b)**, **measured** toy/medium wall-clock (production dims unmeasured), and a **provisional leaning** explicitly marked non-binding.

---

## 1. Facts from current code

### 1.1 Consensus verify = full CPU recompute

`CheckMatMulProofOfWork_RC` (`src/pow.cpp`) is the only consensus RC verify entry. It:

1. Resolves episode params (`ResolveRCEpisodeParams`).
2. Calls `RecomputeResidentCurriculumReference` with the **empty** ExactGemm backend (CPU int64 oracle).
3. Compares the result to `header.matmul_digest` and the nBits target.

There is **no** call to `VerifyRCTranscriptSpotCheck`, no round-root check, and no Merkle opening on the consensus path. Validation / async worker dispatch (`src/validation.cpp`, `src/node/matmul_verify_worker.cpp`) likewise invoke only `CheckMatMulProofOfWork_RC`.

Ground-truth comments in `src/matmul/matmul_v4_rc.h`: consensus REJECT / spot-check MUST use the CPU reference only; accelerated backends are miner/self-qual paths.

### 1.2 Spot-check is not wireable from the block

Wire/header surface for PoW commitment remains digest-only:

- `CBlockHeader` carries `matmul_digest` (+ seeds / dim); see `src/primitives/block.h`.
- No `round_roots[]`, leaf bytes, or Merkle sibling paths exist in the header or block body for ENC_RC.

`VerifyRCTranscriptSpotCheck` (`matmul_v4_rc.{h,cpp}`) is a **local helper / unit-test surface**. Even as written it:

- Recomputes the **full** CPU episode to obtain streams and `round_roots`.
- Then opens Fiat–Shamir (or caller-supplied) leaf indices against those recomputed roots.

So today’s “spot-check” is **not** a cheap wire verifier: peers cannot open against in-block commitments, and the helper still pays full recompute. Unit coverage (`src/test/matmul_v4_rc_tests.cpp`, `rc_t8_spot_check_*`) exercises the helper offline.

### 1.3 Merkle sampling alone with `q=8` is unsound (grindable)

`kRCSpotCheckQueries = 8` (`matmul_v4_rc.h`). Challenges are Fiat–Shamir over `sigma ‖ claimed_digest ‖ q` (`DeriveFSChallenges` in `matmul_v4_rc.cpp`).

Standing analysis (same failure mode as prior f^k memos; see also `doc/btx-matmul-deterministic-nextgen-design.md` §1): if a miner honestly materializes only fraction `f` of the committed stream and grinds the FS-bound header/digest until the `q` challenges land in that fraction, acceptance probability is `f^q` per grind attempt — a **constant**, not a negligible function of an affordable security parameter. With `q=8`, even `f≈1/2` yields `~1/256` success per grind; transcript-grinding to ≥2⁶⁴ work is **not** achieved by sampling alone.

Therefore: **Merkle leaf sampling with q=8 cannot be the sole consensus validity rule.** Spec §R.5.3 already states that a **reject** requires full CPU recompute (R1); optimistic accept needs a **fraud-proof / dispute** completion, not sampling-as-proof.

### 1.4 Segment-partial leaves and growth are PARKED

From `src/matmul/matmul_v4_rc.h`:

```text
kRCSegmentLeavesEnabled = false   // §R.7 STOP-AND-STABILIZE — pending P2.1
kRCGrowthScheduleEnabled = false  // always epoch-0 dials
```

`nMatMulRCHeight` remains `INT32_MAX` (NO-GO). This document does not flip either flag.

---

## 2. Minimal prototype sketch for (b)

*Non-normative sketch — enough to price engineering, not a consensus PR.*

### 2.1 In-block fields (header or fixed-size extension)

For `R = kRCRounds` (epoch-0: 4):

| Field | Size | Role |
|---|---|---|
| `round_root[r]` for `r = 0..R-1` | `R × 32` B | Commitments to each round’s tile-tree (existing `BuildTileTreeRoot` / `RoundMerkleStream`) |
| `episode_digest` | already `matmul_digest` | `SHA256d("BTX_RC_EPISODE_V1" ‖ round_roots…)` — must match today’s digest construction in `RunEpisode` |

Optional later (only if segment leaves are unparked): domain-separated segment-root tips inside the same stream layout so a challenge can name `(round, phase, segment_id, leaf)`.

**Not** in the block: full streams / segment bodies (too large). Those are **served on demand** (peer protocol or cache), authenticated by Merkle paths to the in-block `round_root[r]`.

### 2.2 What a challenge looks like

1. **Optimistic tip accept:** structural header checks + `matmul_digest` binds claimed `round_roots` + target. No full recompute on the happy path.
2. **Challenge window:** a peer that doubts the tip issues a challenge `(block_hash, round, leaf_index)` (or a small vector of indices). Miner/serving node must return `(leaf_bytes, Merkle siblings)` verifying to `round_root[round]`.
3. **Local check:** challenger verifies the path (cheap hashes) and optionally recomputes **only the named segment / stage** that produces that leaf (requires segment leaves or stage-tagged leaves — today PARKED).
4. **Fraud proof:** if opening fails, or recomputed leaf ≠ opened bytes, broadcast compact proof `(block_hash, round, leaf_index, claimed_opening, counter-opening-or-recompute-digest)`. Nodes verify the Merkle contradiction (or ε=0 segment mismatch) without full episode replay.
5. **Unresolved / non-response:** treat as invalid (or force full recompute for that block only — policy knob). Full `RecomputeResidentCurriculumReference` remains the **ultimate** oracle for disputes and for archival “trustless sync” modes.

### 2.3 Soundness sketch

- **Binding:** SHA-256 collision resistance ⇒ forged openings cannot match an honest `round_root` for a different leaf.
- **Completeness:** honest miner who computed the episode can open any leaf.
- **Soundness vs sampling-only:** consensus validity is **not** “passed q FS checks.” Optimistic accept is provisional; **any** successful fraud proof (or timeout policy) removes the block. Sampling is a **bandwidth DoS pre-filter**, not the finality rule.
- **Grinding:** because acceptance no longer equals “lucky FS hits,” grinding challenges does not create a permanent invalid tip; it only delays detection until a challenger opens a bad leaf. Pin challenge/response timeouts and fraud-proof size caps separately (B3 pricing — still open).

Segment-partial leaves (`kRCSegLen`, §R.7.4) become useful **after** (b) is chosen: they make the *challenged* recompute `O(kRCSegLen · …)` instead of full `n_ctx` / `b_seq`. Enabling them without (b) does not help consensus verify today (digest-only full recompute).

---

## 3. Measured verify-cost

**Host:** `cymacpro-linux`, Intel Xeon W-3245 @ 3.20 GHz, 32 CPUs.  
**Binary:** `./build/bin/matmul-v4-rc-harness` (present; `stub:false`).  
**Command pattern:** `/usr/bin/time -v ./build/bin/matmul-v4-rc-harness [--toy|--medium] --episodes 1 --backend cpu`.

Consensus / production dims (`n_ctx=786432`, …) are **refused** by the harness (`--no-toy` without `--medium`). **Production-dim wall-clock is NOT measured.**

### 3.1 Toy (`MakeToyRCEpisodeParams`)

| Metric | Value |
|---|---|
| Params | `R=1, d_head=32, n_q=32, n_ctx=64, L=2, d_model=32, b_seq=32, T_leaf=64` |
| Episode wall (chrono, harness `phase_wall_s.total`) | **0.00257 s** (p1≈0.00082, p2≈0.00125, p3≈0.00047) |
| Process elapsed (`/usr/bin/time`) | **0.01 s** |
| Max RSS (`/usr/bin/time`) | **4756 KiB ≈ 4.6 MiB** |
| Evidence kind | `toy_chrono_measured` |
| Working-set estimate (harness) | 10240 B |

Consensus verify = same full episode recompute ⇒ **toy verify ≈ toy episode wall** on this host (~few ms).

### 3.2 Medium (`MakeMediumRCEpisodeParams`)

| Metric | Value |
|---|---|
| Params | `R=1, d_head=32, n_q=32, n_ctx=64, L=1, d_model=32, b_seq=8192, T_leaf=64` (wgrad K>2²⁴) |
| Episode wall (chrono) | **0.0835 s** (p1≈0.00083, p2≈0.0680, p3≈0.0146) |
| Process elapsed | **0.35 s** |
| Max RSS | **7040 KiB ≈ 6.9 MiB** |
| Evidence kind | `chrono_measured` |
| Working-set estimate | ~1.05 MiB |

Still far below production residency/capacity targets (~192 MiB KV / ~2 GiB activations). Treat as **medium harness evidence only**.

### 3.3 Production dims — unmeasured

Verifier-floor (§R.7.6) requires full-episode + full-verify wall-clock at **production** dims. That run was not performed here (harness refuses; intentional NO-GO).

### 3.4 MAC counts — **NOT EVIDENCE**

Structural counts from `TotalRCEpisodeMacs` (`matmul_v4_rc.cpp`): `rounds × (2·n_q·n_ctx·d_head + 3·L·b_seq·d_model²)`.

| Profile | MACs | Note |
|---|---|---|
| Toy | 327 680 | measured wall above |
| Medium | 25 296 896 | measured wall above |
| Epoch-0 consensus | ≈ 5.32×10¹³ | **NOT EVIDENCE for wall-clock** |

Naive MAC-ratio extrapolations of medium/toy times to consensus (tens of hours on this CPU) are **explicitly labeled NOT EVIDENCE** and MUST NOT gate height. Bandwidth, cache, checkpoint policy, and ExactGemm inject dominate real time; only a production-dim harness run counts.

---

## 4. Comparison: (a) vs (b)

| Dimension | (a) Shrink episode | (b) Fraud-proof protocol |
|---|---|---|
| Matches current wire (`matmul_digest` only) | Yes | Needs new committed roots (+ serving protocol) |
| Matches current consensus code | Yes (already full recompute) | Requires new accept / challenge / fraud paths |
| Commodity full-node verify | By construction: size until replay ≪ block interval | Happy path cheap; dispute path can still be heavy |
| Preserves RC hardware-economics thesis (residency + capacity levers) | **At risk** — shrinking `W_res`/`W_cap` dilutes the separation the design exists for | **Preserves** large miner episode |
| Spot-check / segment leaves | Unnecessary for consensus if always full replay | Segment leaves become the challenged unit; sampling alone still insufficient |
| Engineering / review cost | Low protocol risk; redesign dims + re-measure economics | Higher: wire format, DoS budgets, challenge timeouts, archival policy |
| Activation readiness | Still blocked on production-dim **verify** measurement at the *shrunk* size | Still blocked on protocol design + fraud-proof pricing (B3) + measurements |

---

## 5. Recommendation (provisional leaning — **owner decision**)

**No decision is made by this document.** Height stays `INT32_MAX`. §R.7 growth/segments stay PARKED.

**Provisional leaning (non-binding):** prefer **(b) Genuine fraud-proof protocol** as the *target* validation model if ENC_RC is to keep production-scale residency/capacity levers; treat **(a) Shrink** as the fallback if owner prioritizes “digest-only full recompute forever” and accepts re-tuning (or abandoning) the original hardware-economics envelope.

Rationale for the leaning (still provisional):

1. Current code already proves the **simple** model (a’s verify shape) works at toy/medium — but production-dim full replay is the binding §R.7.6 risk, and MAC extrapolations are not evidence that it fits a block interval.
2. Sampling with `q=8` cannot be promoted to consensus without a fraud-proof completion; shipping “optimistic spot-check” on digest-only blocks would be **unsound**.
3. Segment leaves are correctly PARKED: they help (b)’s challenged recompute, not today’s (a)-shaped consensus path.

**Owner should explicitly choose** (a), (b), or a sequenced plan (e.g. ship shrunk (a) for activation research; migrate to (b) before unparking growth). Until that choice, do not enable `kRCSegmentLeavesEnabled` / `kRCGrowthScheduleEnabled`, and do not raise `nMatMulRCHeight`.

---

## Addendum (2026-07-20) — Stage E DECIDED

**Owner decision recorded:** winner-only GKR/sumcheck supersedes the provisional
leaning above. Fraud-proof is deferred; shrink remains the fallback if GKR
verify cost fails the Stage-I budget. See:

- `doc/btx-matmul-v4.5-rc-stage-e-winner-gkr-decision-2026-07-20.md`
- `doc/btx-matmul-v4.5-rc-verify-bakeoff-stage-e.md` (E5 DECIDED)

`nMatMulRCHeight` remains `INT32_MAX`. Decision alone does not raise height.

---

## 6. Pointers

- Normative episode + PARKED §R.7: `doc/btx-matmul-v4.4-resident-curriculum-unified-proposal-2026-07-20.md`
- Prior f^k / grinding disqualification: `doc/btx-matmul-deterministic-nextgen-design.md`
- Code: `src/matmul/matmul_v4_rc.{h,cpp}`, `src/pow.cpp` (`CheckMatMulProofOfWork_RC`), `src/primitives/block.h`
