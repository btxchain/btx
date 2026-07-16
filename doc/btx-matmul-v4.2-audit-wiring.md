# BTX MatMul v4.2 / ENC-BMX4C — Wiring-Layer Independent Security Review

- **Scope:** the newly-wired ENC-BMX4C consensus code landed in commit `c5282ef`
  (branch `claude/matmul-v4-design-spec-af23sj`), unreviewed at the C-15 audit.
  Files: `src/matmul/accel_v4.cpp`, `src/matmul/matmul_v4_bmx4_batch.cpp`,
  `src/pow.cpp` (ENC-BMX4C seed + solve branches), `src/validation.cpp`
  (profile-dispatched verify + dim invariants), `src/kernel/chainparams.cpp`
  (`AssertBMX4CConstructionInvariants`).
- **Lens:** one panel reviewer. READ-only; no code edited. Methodology:
  consensus-split, profile-transition, verify+fallback soundness,
  malleability/canonical.
- **Date:** 2026-07-16. **Reviewer:** independent panel lens (verified by lead).

---

## Verdict (summary)

- **Verify+fallback soundness (accel_v4 dispatch): SOUND, closed with strong
  margin.** No device result that fails the CPU/consensus verifier can be
  accepted, and the sealed winner is additionally re-derived byte-for-byte
  through the single-nonce reference.
- **Profile transition (v4 ENC_S8 → ENC_BMX4C): SOUND.** The `>=` height
  selector is a single shared function used identically by seed derivation,
  verify, and the dim check; no off-by-one, no cross-profile replay.
- **Highest-value finding: `W-1` (HIGH, latent-critical) — the ENC-BMX4C header
  seed derivation is NOT idempotent, so the `bad-matmul-seeds`
  recompute-and-compare rejects EVERY honestly-mined ENC-BMX4C block on an
  enforcing network.** This is a consensus-liveness / conformance defect, not a
  fork. It is latent today only because mainnet + testnet4 leave
  `nMatMulBMX4CHeight == INT32_MAX` (inert). **Testnet is enforcing and activates
  ENC-BMX4C at height 250,000** — that chain halts at the fork under the current
  code.

---

## Findings by severity

### W-1 — HIGH (latent-critical): ENC-BMX4C header seed derivation is not idempotent; `bad-matmul-seeds` rejects every honest BMX4C block

**Class:** consensus liveness / conformance (uniform rejection → no fork, but the
chain cannot advance past the ENC-BMX4C activation height on an enforcing
network). Proven.

**Where:**
- `src/pow.cpp:144-147` — `SetDeterministicMatMulSeeds`, ENC-BMX4C branch:
  ```cpp
  block.seed_a = matmul::v4::bmx4::DeriveOperandSeedBMX4C(block, matmul::v4::Operand::A);
  block.seed_b = matmul::v4::bmx4::DeriveOperandSeedBMX4C(block, matmul::v4::Operand::B);
  ```
- `src/matmul/matmul_v4_bmx4.cpp:185-194` — `DeriveOperandSeedBMX4C(header, B)`
  hashes `matmul::ComputeMatMulHeaderHash(header)`.
- `src/matmul/matmul_pow.cpp:239-240` — `ComputeMatMulHeaderHash` **includes
  `header.seed_a` and `header.seed_b`** in its preimage.
- `src/validation.cpp:10018-10028` — the recompute-and-compare:
  `expected_header{block}` (copies the committed seeds), re-runs
  `SetDeterministicMatMulSeeds`, then requires
  `block.seed_b == expected_header.seed_b`.

**Root cause.** The map applied to the header field is
`seed_b ↦ f(HeaderHash(header with that seed_b))` where `f`/`HeaderHash` are
SHA-256. Because `HeaderHash` reads `seed_b`, the map is a random-oracle over its
own output slot and has **no findable fixed point**. ENC-S8 avoids this: its
header seed fields come from `DeterministicMatMulSeedV3`
(`src/pow.cpp:90-105`), whose preimage does **not** include `seed_a/seed_b`, so
`SetDeterministicMatMulSeeds` is idempotent there and the recompute matches. The
ENC-BMX4C branch reuses the operand-seed derivation (which is seed-field-
dependent) as the header-field setter, breaking that idempotency.

**Concrete case (state → bad outcome).**
1. Miner (`SolveMatMulV4BMX4C`, `src/pow.cpp:4231-4239`): `candidates[i] = block`
   (so `candidate.seed_b = X`, the template's value), sets the nonce, calls
   `SetDeterministicMatMulSeeds`. Result committed:
   `Y = DeriveOperandSeedBMX4C(candidate{seed_b=X}, B)`.
2. Verifier (`src/validation.cpp:10018`): copies the block (`seed_b = Y`),
   recomputes `Z = DeriveOperandSeedBMX4C(block{seed_b=Y}, B)`.
3. `Y = f(HeaderHash(…,seed_b=X))`, `Z = f(HeaderHash(…,seed_b=Y))`; since
   `X ≠ Y` and `HeaderHash` depends on `seed_b`, `Y ≠ Z` → `state.Invalid(…,
   "bad-matmul-seeds")`. Every honestly-mined ENC-BMX4C block is rejected.

Structural confirmation (SHA-256, same derivation shape) — `Y ≠ Z`:
```
miner-committed seed_b  Y = fb9f59a5c8580776…
verifier recompute      Z = 18f01e2bc3e4d343…
bad-matmul-seeds PASS?   False
```

**Blast radius.** `fMatMulPOW=true` on all real networks; `fSkipMatMulValidation`
defaults false and is only forced true on regtest-without-`-test=matmulstrict`
(`src/kernel/chainparams.cpp:1166`) and one custom net (`:1583`). **Testnet
(`:566`, no skip) enforces this check and sets `nMatMulBMX4CHeight = 250'000`
(`:620`).** So the moment testnet reaches 250k (or any enforcing net activates
BMX4C), the recompute rejects all blocks → the chain cannot advance past the
fork. Mainnet (`:152-538`) and testnet4 (`:765-1137`) never set
`nMatMulBMX4CHeight` → INT32_MAX → inert, which is why this has not surfaced. The
default-skip on regtest also explains why unit/functional coverage did not catch
it.

**Note — this is NOT a fork.** Every enforcing verifier rejects uniformly, and
the *digest* path (`CheckMatMulProofOfWork_V4ProductCommitted` →
`VerifySketchBMX4C`) is internally consistent because miner and verifier both use
the committed `seed_b = Y`. The failure is confined to the separate
`bad-matmul-seeds` gate, which demands idempotency the BMX4C branch does not
provide. (A configuration split is possible only between skip and non-skip nodes
on the same net; not a production concern.)

**Fix (any one).**
1. Set the committed ENC-BMX4C header seed fields with a **seed-field-independent**
   derivation (the ENC-S8 pattern), e.g. a V4.2 domain-tagged hash over the same
   fields `DeterministicMatMulSeedV3` binds (which excludes `seed_a/seed_b`) but
   keeps `nNonce64` for B; or
2. Derive both the committed field and the operand-B seed from a **nonce-bound
   pre-seed header image that zeroes `seed_a/seed_b`** (analogous to
   `ComputeTemplateHash`, but retaining the nonce). Then a single application is a
   fixed point and the recompute matches.

Add a regression test that mines a block at a BMX4C height on an **enforcing**
config and runs it through `ContextualCheckBlockHeader` (not just the matmul unit
reference), so the recompute-and-compare is actually exercised.

---

### W-2 — LOW: `AssertBMX4CConstructionInvariants` not invoked on every network constructor

**Class:** conformance / misconfig defense-in-depth. Argued.

The invariant assert is called from the **testnet** (`src/kernel/chainparams.cpp:726`)
and **regtest/opts** (`:1289`) constructors only. The **mainnet** and **testnet4**
constructors do not call it. Today this is harmless (both leave BMX4C inert, and
the function early-returns for `INT32_MAX`), and the assert body itself is
correct: it pins strict fork ordering (`nMatMulBMX4CHeight > nMatMulV4Height`, so
no dual-profile window), the combine-bound (`288 * MaxDim ≤ 2^23-1`), and
`dim % 32 == 0`. **Risk:** a future release that enables BMX4C on mainnet/testnet4
by only setting the height, without also wiring the assert call into that
constructor, would ship a misconfig with no startup guard. **Fix:** call
`AssertBMX4CConstructionInvariants` unconditionally from `CChainParams`
construction for every network (or from a shared post-construction validation
step), so it cannot be forgotten.

---

### W-3 — INFO: `nMatMulV4FreivaldsRounds == 0` makes the dispatch-layer verify vacuous (no exploit)

**Class:** conformance. Closed.

`SketchFreivalds` returns `true` unconditionally when `rounds == 0`
(`src/matmul/matmul_v4.cpp:520-522`), so with `rounds == 0`
`VerifySketchBMX4C` in the dispatcher (`accel_v4.cpp:595`) would accept any
shape-valid device payload whose digest self-matches, **without** checking the
product commitment. This is not reachable as a consensus fault: (a) the miner
re-derives the winner through `ComputeDigestBMX4C` and requires
`ref_payload == payload` before sealing (`src/pow.cpp:4260-4266`), discarding any
non-true payload; and (b)
`CheckMatMulProofOfWork_V4ProductCommitted` rejects the whole block when
`nMatMulV4FreivaldsRounds == 0` (`src/pow.cpp:3194`). Configured rounds are ≥1 on
all networks. Left as INFO.

---

### W-4 — INFO: ENC-BMX4C seeds bind the parent via `hashPrevBlock`, not parent-MTP (unlike ENC-S8)

**Class:** hardness / grinding. Argued sound.

`SetDeterministicMatMulSeeds` keeps the `parent_median_time_past.has_value()`
fail-closed guard for BMX4C (`src/pow.cpp:130-134`) but the ENC-BMX4C derivation
does not consume the MTP value; the parent is bound through `hashPrevBlock`
inside `ComputeTemplateHash`/`ComputeMatMulHeaderHash`. Binding the exact parent
hash is strictly stronger than binding its MTP, so there is no pre-mining or
grinding downgrade relative to ENC-S8. The fail-closed guard still correctly
rejects seed derivation when parent context is unavailable. No action.

---

## Detailed soundness analysis (the explicitly-scoped checks)

### A. accel_v4 — verify-every-result-then-fall-back (`ComputeDigestsBMX4CDispatched`)

- **Every returned `(digest,payload)` re-verified before acceptance:** YES.
  `accel_v4.cpp:588-610` loops all `i`, sets
  `verify_header.matmul_digest = accel_digests[i]`, calls
  `VerifySketchBMX4C`, and requires `verified && verify_digest ==
  accel_digests[i]`. The single acceptance site is guarded by `all_verified`
  (`:612`); every other path (device false, wrong window size, any exception,
  any single verify failure with `break`) routes to
  `RecordBatchFallback` + `ComputeBatchCpuReferenceBMX4C` (`:622-623`). No error
  path accepts. Partial/short windows are caught by the size equality check
  (`:567-571`). Empty input returns false (`:545-549`).
- **Can a device result NOT byte-identical to the CPU reference be accepted?**
  No, with margin. `VerifySketchBMX4C` accepts iff the payload passes
  deterministic (Fiat-Shamir) Freivalds over `q = 2^61-1` AND the digest equals
  `H(sigma‖payload)`; `ParseSketch` rejects non-canonical residues
  (`matmul_v4.cpp:471`). The true `Chat` is unique and canonical, so a payload
  that differs from the CPU reference is a wrong product and fails Freivalds
  except with negligible (~`2·m/q ≈ 2^-52`) probability per round. Even that
  residual is closed by the winner re-derivation in the solver
  (`src/pow.cpp:4260-4266`), which seals ONLY when
  `ref_digest == digests[i] && ref_payload == payloads[i]` (byte-identity to the
  single-nonce reference). And because the accepted verifier is the *same
  deterministic function* the network runs, anything accepted here is accepted
  network-wide → no miner↔verifier disagreement.
- `ComputeBatchCpuReferenceBMX4C` fast path (`accel_v4.cpp:291-301`) trusts the
  batched miner without a per-nonce cross-check against `ComputeDigestBMX4C`; a
  hypothetical batched-miner divergence would be a **miner-only self-DoS** (the
  winner reseal discards it; validation never calls this function — it uses
  single-nonce `VerifySketchBMX4C`). See B for why no such divergence exists.

### B. matmul_v4_bmx4_batch — `BatchedSketchMinerBMX4C`

- **base-2⁷ stacked combine == base-2⁶ reference for 288·n magnitudes:**
  CONFIRMED, closed with margin. The batched miner calls
  `ComputeCombineLimbTensorStacked` (base-128 / base-2⁷,
  `matmul_v4.cpp:351`); the single-nonce reference `ComputeDigestBMX4C`
  uses the **direct** `ComputeCombineModQ` (`matmul_v4_bmx4.cpp:388`). Both equal
  `P·Q mod q` as exact integers **provided the digit decomposition is total**.
  ENC-BMX4C entries are `|P|,|Q| ≤ 288·n`; the base-2⁷ decomposition is total for
  `|x| ≤ 133,160,895` (positive extreme), i.e. `n ≤ 462,364`, while
  `ValidateDimsBMX4C` already caps `n ≤ 29,127` (`288·n ≤ 2^23-1`). At the real
  consensus dim `n = 4096`, `288·4096 = 1,179,648` — ~113× inside the base-2⁷
  window and ~7× inside base-2⁶. Limb-pair accumulators stay `≤ n·64·64 < 2^31`
  (exact int32) for all BMX4C-valid `n`. Equivalence holds at every supported `n`.
- **Template-cache staleness:** CLOSED. `Mine` fails closed on any header whose
  `ComputeTemplateHash` differs from the cached `m_template_hash`
  (`matmul_v4_bmx4_batch.cpp:64-67`). Cached `A/U/V/P` depend only on the
  template hash; `sigma` and `seed_B` (nonce-fresh) are recomputed per header
  (`:68-71`). A stale `P/U/V` cannot combine with a fresh nonce.
- **Byte-identity to `ComputeDigestBMX4C`:** structurally holds (same operands,
  same projections, combine equivalence above, same `SerializeSketch` /
  `ComputeSketchDigest`), and is the invariant the solver's reseal enforces at
  runtime regardless.

### C. pow.cpp — ENC-BMX4C seed + solve

- **Seed self-reference:** see **W-1** (the one real defect). `seed_a` derivation
  is idempotent (`ComputeTemplateHash` zeroes `nNonce`/`seed_a`/`seed_b`); only
  `seed_b` is self-referential.
- **`bad-matmul-seeds` recompute-and-compare:** structurally correct mechanism,
  but W-1 makes it reject valid BMX4C blocks.
- **Parent-MTP fail-closed:** present and correct (W-4).
- **Winner reseal can seal a digest the verifier would reject?** No —
  `ComputeDigestBMX4C` and `VerifySketchBMX4C` are consistent (same operands /
  sigma / `Chat`), so the resealed `(digest,payload)` is exactly what the digest
  verifier recomputes. (It is nonetheless gated out by W-1 upstream.)
- **`ComputeMatMulHeaderHash`/template hash exclude nonce-derived fields for the
  template scope?** `ComputeTemplateHash` correctly zeroes `nNonce64/nNonce`
  and the nonce-derived `seed_a/seed_b` before hashing (`matmul_v4.cpp:84-89`),
  so A/U/V are genuinely template-scoped. The full header hash (for B/sigma)
  intentionally includes the nonce — correct for nonce-freshness — but its
  inclusion of `seed_b` is exactly what breaks W-1's idempotency.

### D. validation.cpp — profile-dispatched verify + `n%32==0`

- **Profile selection by height / off-by-one:** CLEAN. `GetMatMulEncodingProfile`
  → `IsBMX4CActive` uses `height >= nMatMulBMX4CHeight`
  (`consensus/params.h:565-583`); the identical selector governs seed setting
  (`pow.cpp:144`), the verify route (`pow.cpp:3210`), and the dim check
  (`validation.cpp:10005`). Miner and verifier both key on the block's own height
  (`nHeight = pindexPrev->nHeight + 1`). No boundary disagreement.
- **v4(ENC_S8) payload accepted at a BMX4C height (or vice-versa):** NO. At a
  BMX4C height the verify routes to `VerifySketchBMX4C`, which regenerates
  M11+E8M0 operands via V4.2 domain tags and a different `Chat`; an ENC_S8 payload
  fails Freivalds and the digest check. The height fixes the profile for all
  parties, so a block cannot be replayed under the other profile.
- **dim / bound checks:** `n%32==0` enforced both at the header
  (`validation.cpp:10005-10011`) and inside `ValidateDimsBMX4C`; the combine bound
  (`CheckCombineLimbBoundBMX4C`) and the full-C `2304·n` int32 bound are checked
  ahead of the O(n²) verify (`pow.cpp:3217-3221`). Reject codes reuse the existing
  `bad-matmul-dim` / high-hash / product-committed set (no new codes; consistent
  with spec §8.2).

### E. chainparams.cpp — `AssertBMX4CConstructionInvariants`

- **Can a misconfig slip past?** The assert body is sound (fork ordering, combine
  bound over `MaxDim`, `dim%32`), but it is not wired into every constructor
  (W-2). Mainnet inertness is confirmed: mainnet leaves `nMatMulBMX4CHeight ==
  INT32_MAX` (never assigned in `CMainParams`), so ENC-BMX4C is fully inert there.

---

## Report-back answers

1. **Doc path:** `doc/btx-matmul-v4.2-audit-wiring.md`.
2. **Findings:** W-1 HIGH (latent-critical, consensus-liveness); W-2 LOW
   (misconfig defense-in-depth); W-3 INFO; W-4 INFO.
3. **Real accept-wrong / replay / split path:** none found. The verify+fallback
   contract is sound and the profile transition has no replay/off-by-one. The
   highest-value finding (W-1) is the opposite failure mode: a *reject-all*
   liveness break on enforcing networks (testnet at height 250,000), latent while
   mainnet/testnet4 keep BMX4C inert.
4. **Verify+fallback soundness verdict:** SOUND, closed with strong margin
   (every device result re-verified by the consensus verifier; winner
   additionally byte-identical to the single-nonce reference; all error/partial
   paths fall back to CPU).
5. **Profile-transition (v4→bmx4c) verdict:** SOUND. Single shared `>=` selector
   across seed/verify/dim; no off-by-one; no cross-profile replay.
6. **Confidence:** W-1 root cause and rejection outcome — **high** (proven by code
   reading + structural SHA-256 simulation; the only assumption is that
   `ContextualCheckBlockHeader` runs for BMX4C heights on an enforcing net, which
   it does). Verify+fallback and profile-transition verdicts — **high**. W-2/W-4
   — argued, low stakes.

---

## Resolution status (post-review)

- **W-1 (HIGH) — FIXED.** `SetDeterministicMatMulSeeds` no longer pins the
  ENC-BMX4C header seed fields via `DeriveOperandSeedBMX4C`. Both encoding
  profiles now pin `seed_a/seed_b` via the self-reference-free
  `DeterministicMatMulSeedV3` (whose preimage excludes `seed_a/seed_b`), so the
  `bad-matmul-seeds` recompute-and-compare is idempotent and accepts honestly-
  mined BMX4C blocks. The operand-B derivation (`DeriveOperandSeedBMX4C`, full
  header hash incl. the now-V3-pinned nonce-fresh seed fields) remains the
  digest/verify-time step, unchanged. Regression test added:
  `pow_tests/MatMulBMX4CSeed_field_pinning_is_v3_and_idempotent` asserts the
  pinned fields equal the V3 seeds AND that a recompute on the already-pinned
  header (exactly what `bad-matmul-seeds` does) is a fixed point.
- **W-2 (LOW) — OPEN (tracked).** `AssertBMX4CConstructionInvariants` is still
  wired only into the testnet + regtest/opts constructors. Harmless while
  mainnet/testnet4 leave `nMatMulBMX4CHeight == INT32_MAX` (inert); to be wired
  into every constructor when a BMX4C activation height is actually assigned on
  those networks (a one-line guard at fork-planning time).
- **W-3 / W-4 (INFO) — no action** (closed / argued sound above).
