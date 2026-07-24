> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# ENC-DR v4.4 — Consolidated Red-Team Verdict & RC Acceptance Checklist

Two independent Opus red-team lenses attacked the ENC-DR release candidate:
one on the consensus predicate / determinism / no-inversion, one on the
sketch-cache DoS / liveness. They **converged**: ENC-DR is consensus-sound and
no-inversion-preserving *in principle* — a net simplification that deletes more
attack surface (FRI, the segregated relay, the MUTATED/permanent classification,
the relay-ready gate, the INCOMPLETE-hold/busy-loop class) than it adds — and its
soundness reduces to **one decisive invariant (R1)** plus a bounded, disclosed
new DoS cost. This is the acceptance checklist the implementation MUST meet
before the RC is considered complete.

## Verdicts (what's proven vs assumed)

- **Lottery work-binding — PROVEN, unchanged from v4.3.** `(header,nonce)→digest`
  is a pure function whose only evaluation is the full pipeline (σ/seed_B rebind
  nNonce64 → fresh B → fresh Ĉ; digest binds all m² words). Deleting the in-block
  payload does not weaken it — the miner already materialized Ĉ to compute the
  digest; carriage was post-solve packaging. No compute-less/O(1) path; no FRI
  slack (ENC-SC's BREAK #1 cannot recur).
- **No-inversion κ=1.00 — PROVEN by identity.** The per-nonce pipeline is
  untouched; only post-solve carriage is deleted, so κ ≤ 1.00. n-scaling never
  inverts (GEMM/floor ∝ n, monotonic); the m-window rule is sound. Caveat
  (pre-existing, not an ENC-DR regression): κ=1.00 preserves the b=4 split, itself
  an unconfirmed silicon hypothesis — the standing K.2b GO/NO-GO remains the test.
- **Recompute determinism — THE REAL EXPOSURE.** The CPU pure-integer reference is
  bit-identical across compilers by construction (no float, integer associativity,
  no signed-overflow UB, canonical LE XOF) — ε=0 is real. BUT ENC-DR puts the GEMM
  on the validity-decision path for the first time and removes mining's Freivalds
  fallback: mining is fail-SAFE (wrong device Ĉ → digest fails → discard), naive
  verify-recompute is fail-DANGEROUS (wrong device Ĉ at verify → digest mismatch →
  a device node REJECTS a block CPU nodes ACCEPT → consensus split). Closed by R1.
- **Liveness — improved.** No INCOMPLETE/hold/pending/busy-loop class: a block
  reaches a terminal accept/reject from the header alone, cache is truly optional.
- **New cost — asymmetric DoS, disclosed.** Rejecting a garbage block rises from
  O(n²) Freivalds to O(W) recompute (~10³×), budget-capped (~0.5 core/node), not a
  halt. The cache/recompute paths also carry a **2⁻¹⁸⁰ divergence surface**
  (cache-only node could accept a block recompute rejects) — cryptographically
  negligible + grind-resistant, but architecturally real, so recompute is canonical.

## Acceptance checklist (MUST all hold before the RC ships)

### Consensus-critical (correctness)
- [ ] **R1 — CPU-reference-anchored rejection.** The CPU pure-integer reference
  recompute is the SOLE arbiter of block INVALIDITY. An accelerated backend may
  recompute to ACCEPT fast (digest MATCH proves Ĉ correct under SHA
  collision-resistance), but ANY digest MISMATCH from a non-reference backend MUST
  fall back to the CPU reference before the block is rejected. No GPU/Ozaki/FP path
  may emit a "reject." (Restate accel_v4.h's mining "device never trusted" rule for
  the verify path.)
- [ ] **Recompute = the consensus definition** (ε=0); cache+Freivalds (ε≤2⁻¹⁸⁰) is
  an accept-side optimization. Document the 2⁻¹⁸⁰ cache false-accept as a local risk
  the recomputing majority heals — NOT "the same equivalence class as today."
- [ ] Recompute reference named against the ACTIVE profile: `bmx4::ComputeDigestBMX4C`
  (ENC_BMX4C), not ENC_S8 `ComputeSketch`.
- [ ] Ozaki (`matmul_v4_exact_float`) and all FP backends EXCLUDED from the
  verify-reject path.
- [ ] Empty-body rule enforced: `matrix_c_data` MUST be empty at ENC-DR height.
- [ ] Reference guards preserved before recompute: `CheckAccumulationBound`,
  `CheckCombineLimbBound`, the little-endian `static_assert`.
- [ ] assumevalid buried-proof trust (`validation.cpp:~10314-10341`) PRESERVED /
  retargeted (skip recompute below assumevalid) — it is the SOLE bound on
  deep-history recompute cost.

### Determinism / conformance
- [ ] New VERIFY-SIDE recompute entry point + golden-vector gate (distinct from the
  mine-side `ComputeDigest`-vs-backends test) asserting verify-recompute byte-equality
  vs the CPU reference; `verify-backend.sh` hard-fails divergence on high-magnitude
  vectors for the verify path.
- [ ] Golden vector: a block whose header digest ≠ H(σ‖Ĉ_true) MUST be rejected by
  the CPU-reference recompute.

### DoS / serving / liveness
- [ ] Port ALL THREE serve limits to `getmmsketch`: per-peer token bucket; node-wide
  egress byte budget (all-or-nothing, ~8 MiB/s, negative-allowed — the real
  anti-amplification); per-(peer,block) dedup window (silent-skip). Serve only
  `Have()`; no unsolicited gossip; no `NODE_*` bit.
- [ ] Budget the recompute path SEPARATELY from the fail-fast cache path
  (cache-authenticated blocks must never queue behind attacker-forced recomputes).
  Keep the concurrency-slot cap.
- [ ] **Re-tune the verify budget in CPU-SECONDS, not check-count — RELEASE-BLOCKING.**
  (Adversarial round, DoS lens Finding 1, sharpened.) The current
  `nMatMulV4{Global,Peer}VerifyBudgetPerMin` are sized for the O(n²) Freivalds
  fast path (~0.14–0.28 s/check → the chainparams "~4.8 CPU-s/min" comment), but at
  an ENC-DR height a forged block (guaranteed cache+accel miss) is decided by the
  O(n³) **recompute** (~10³× costlier). The same count budget therefore admits
  ~32–64 CPU-s/min, not 4.8. Give the recompute path its OWN small budget
  (e.g. 1–2/min) distinct from the Freivalds budget. Bench on a reference validator.
- [ ] **Move the recompute OFF the single message-handler thread — RELEASE-BLOCKING.**
  (Same finding.) `ProcessMessage→ProcessBlock→ProcessNewBlock` runs the recompute
  synchronously on the one net thread; a forced multi-second GEMM stalls ALL peer
  relay/ping for its duration → P2P livelock even though total CPU is ~1 core.
  G.1 (cs_main release) does NOT fix this — it frees other cs_main takers, not the
  net thread's own occupancy. Use an async worker with a bounded queue.
- [ ] **Global-budget exhaustion must DEFER, not disconnect honest peers.**
  (DoS lens Finding 2.) Once an attacker drains the 16/min global budget with forged
  blocks, an honest peer relaying a REAL block in that minute is refused +
  `fDisconnect`. Prefer deferral so a shared global limit never punishes a peer for
  others' spend.
- [ ] Verify the IBD/fast-phase global-budget relaxation (per-peer → 200 000/min,
  global skipped) does not open an unbudgeted recompute firehose during sync;
  assumevalid-trust + too-far-ahead bound but do not eliminate it.
- [ ] Enable the SHA header spam-gate (`nMatMulHeaderPoWDiscountBits`) at activation
  with its wire prerequisite (`BTX_HEADER_NONCE_ON_WIRE`), so header/block delivery
  is not free — it is `UINT32_MAX` (disabled) in EVERY chainparams today, leaving the
  mispriced verify budget as the SOLE throttle. C1 (SHA ≪ matmul) remains open —
  inherited, not introduced; either enable the gate before activation or explicitly
  remove it from the threat model.

### Activation
- [ ] Single-height flag day; profile at `nMatMulV4Height` INT32_MAX on mainnet
  until GO. Relay-ready gate deleted; replacement gate = K.2b silicon no-inversion
  GO/NO-GO (κ=1.00) + L0 ratification, enforced by a startup invariant.
- [x] **DR-34 fail-closed activation guard IMPLEMENTED.** `AssertBMX4CConstructionInvariants`
  now aborts node startup if any public network (regtest exempt) is built with a live
  (non-INT32_MAX) `nMatMulV4Height` while `Consensus::BTX_MATMUL_NO_INVERSION_GATE_RATIFIED`
  is false (its default). Flip that flag only in the reviewed release that ships
  activation, AFTER the K.2b GO + L0 ratification are recorded — the same fail-closed
  mechanism as the retired relay-ready flag, retargeted to measured no-inversion.
  (Adversarial round, PoW-soundness lens Finding 2.)

## Bottom line
Ship only with **R1 wired** and the **verify-side golden-vector gate** in place;
those two close the single consensus-split surface. The rest bound DoS and pin
determinism. With the full checklist met, ENC-DR is consensus-sound, live
(no wedge), no-inversion-preserving (κ=1.00), and flat-storage — the v3
Bitcoin-alignment virtues plus no reward inversion, without the data bloat.
