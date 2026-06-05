# C-002 / R5 activation & legacy-note migration safety (v0.31)

Fund-safety analysis for the shielded paradigm shift at height 123000. Goal: NO
honest funds lost, stuck, or unspendable across the activation.

## 1. Legacy NOTE safety — GOOD (no data migration needed)

C-002 is a SPEND-PROOF gate, not a note migration. Note commitments on-chain are
untouched. A holder spends an old note by re-proving under v3 from data they
already have (amount, opening randomness, spend key).

- **Honest legacy notes are all v3-spendable.** The honest wallet always created
  amounts via `EncodeAmountToSmileAmountPoly` (canonical base-4, 0 ≤ a) and
  consensus caps value at MAX_MONEY = 21e6·COIN ≈ 2^50.9 < 4^26. R5 requires
  digits ∈{0,1,2,3} and high slots [26,32)=0 (value < 4^26). So every value
  ≤ MAX_MONEY satisfies R5 ⇒ every honest legacy note can produce a valid v3
  spend proof. **No honest funds become unspendable.**
- **Only NON-canonical / out-of-range notes become unspendable** under v3 — these
  can only exist via the pre-fix x1c/range exploit (minted-from-nothing value).
  Trapping them is INTENDED (don't let stolen/forged value out). No honest path
  produces them.

ACTION: the wallet must auto-build v3 for ALL notes incl. legacy ones, with zero
user action, and must surface a CLEAR error (never silent loss) if a note cannot
be upgraded (would only happen for a non-canonical exploit note).

## 2. ACTIVATION MECHANICS — FIXED (dual-format implemented)

UPDATE: the staged dual-format is now IMPLEMENTED and verified. The prover emits
v2 (legacy, NO balance_w/Γ/w_sn/range slots — v0.30-wire-compatible) before the
activation height and v3 (full C-002/R5) at/after it; the verifier, serializer,
and decoder all branch on the wire version (~20 coordinated gating sites keyed on
`is_v3`). The wallet/builder threads the real target block height
(`CreateSmileProof → TryProveCT`), so legacy notes spend in the correct format with
NO user action. `SmileCTProof::C002_ACTIVATION_HEIGHT` (=123000) is the single
source of truth shared by prover, verifier (verify_dispatch), and serialization.

VERIFIED (btx-work forge harness + btxd build): v3 honest accepts, v3 forges
(balance/Γ/range) reject, AND a v2 (pre-activation) proof builds, verifies, and
round-trips through serialize/decode (`rtx1_12`). btxd builds clean with the
production dual-format (no forge hooks / debug).

Original analysis (now resolved) retained below for reference:

## (historical) ACTIVATION MECHANICS — the bug that was fixed

The verifier gate (ValidateSmile2Proof) correctly requires v3 only at/after
height 123000. BUT the PROVER and WIRE FORMAT are NOT height-gated:

- `UsePostforkTupleHardening(bind_anonset_context) == bind_anonset_context`, and
  the prover (ct_proof.cpp ~2511) emits `WIRE_VERSION_C002_HARDENED` (v3)
  whenever bind_anonset_context — **regardless of height**.
- C-002 fields `w_sn`, `balance_w`, `balance_carry` (and the range-bit aux slots)
  are serialized UNCONDITIONALLY (serialize.cpp 924/942/945), not gated on v3.

CONSEQUENCE — pre-activation window breakage. If v0.31 is deployed before height
123000 (normal staged upgrade), a v0.31 node building a shielded spend pre-H:
  (a) emits v3, but its OWN verifier expects v2 pre-H ⇒ self-reject; and
  (b) emits C-002 fields that OLD v0.30 nodes cannot parse ⇒ they reject it.
=> shielded spends fail in [deploy, 123000). Funds effectively stuck until H.

### Required fix (height-gate the prover FORMAT, mirror the verifier)
1. Thread the target block height (tip+1) from the wallet spend-builder
   (v2_send/CreateSmileProof — both already have `validation_height`) into
   `TryProveCT`.
2. Prover wire_version: `height >= C002_ACTIVATION_HEIGHT ? v3 : (postfork ? v2 : legacy)`.
3. Serialize/deserialize `w_sn`, `balance_w`, `balance_carry` ONLY for v3 (mirror
   the seed_z gating). For v2/legacy, emit the OLD format (no C-002 fields) so
   v0.31 nodes remain wire-compatible with v0.30 nodes pre-H.
4. Verifier: skip C-002 balance/range/w3-1/seed_z relations for v2 (old regime);
   require them for v3. (Pre-H is the legacy vulnerable regime, accepted until H —
   that's the point of a flag-day cutover.)
5. SerializedSize: C-002 field sizes only for v3.

### Alternative (simpler, riskier): flag-day deploy == activate
Set the activation height so that deployment and activation coincide and ALL
nodes upgrade before H. Avoids the dual-format prover but is operationally
fragile (any laggard node or pre-H spend breaks). NOT recommended for value-
bearing consensus.

## 3. Migration invariants to TEST before mainnet (regtest, activation height lowered)
- [ ] pre-H: v0.31 honest shielded spend (old format) ACCEPTS; interop with a
      v0.30 node.
- [ ] at/after H: v2 spend REJECTS (`bad-smile2-proof-wire-version`); v3 ACCEPTS.
- [ ] legacy note created pre-H, spent post-H: wallet auto-builds v3, ACCEPTS,
      correct value, change note spendable.
- [ ] honest note of value == MAX_MONEY spends under v3 (R5 high-slot boundary).
- [ ] non-canonical/exploit note: v3 proof FAILS (intended), wallet shows clear
      error, no crash / no silent loss.
- [ ] reorg across H; tx in mempool across H (mempool re-eval picks correct format).
- [ ] no funds-stuck: every honest balance present pre-H is spendable post-H.

## 3b. Remaining: make activation a consensus param + E2E regtest (#10)

The activation height is currently the compile-time constant
`SmileCTProof::C002_ACTIVATION_HEIGHT = 123000`. To follow the existing pattern
(`nShielded*ActivationHeight` in `consensus/params.h`, set per network in
chainparams) AND to make the cross-activation E2E runnable in regtest without
mining 122,500 blocks, lift it to a consensus param:

1. `consensus/params.h`: add `int32_t nShieldedC002ActivationHeight{123000};`.
2. `kernel/chainparams.cpp`: mainnet=123000; testnet=<tbd>; **regtest=<low, e.g.
   100, or -con-overridable>** so functional tests can cross it cheaply.
3. Thread the activation height (default `SmileCTProof::C002_ACTIVATION_HEIGHT`) as
   one extra param alongside the already-threaded `validation_height`:
   - prover: `TryProveCT/ProveCT/CreateSmileProof` → `is_v3 = use_postfork &&
     validation_height >= activation_height`. Wallet/builder passes
     `consensus.nShieldedC002ActivationHeight`.
   - verifier: `ValidateSmile2Proof/VerifySmile2CTFromBytes` → `require_c002 =
     validation_height >= activation_height`. `validation.cpp` passes
     `consensus.nShieldedC002ActivationHeight`.
   (Defaults keep current behaviour; only consensus/wallet callers pass the param.)

### E2E regtest script (#10) — runnable once step 3 lands with regtest activation low
```
# regtest with nShieldedC002ActivationHeight = 100
generatetoaddress 105 <addr>          # mature coinbase, still pre-activation (<100? set 110)
z_shieldfunds <amt> <zaddr>           # create a shielded note PRE-activation (v2 era)
generate to just before activation
# spend the legacy note BEFORE activation -> wallet emits v2, accepted
z_sendmany <zaddr> [...]              # v2 spend pre-H accepts
# cross activation
generatetoaddress <past activation> <addr>
# spend a legacy note AFTER activation -> wallet auto-emits v3 (no user action)
z_sendmany <zaddr> [...]              # v3 spend post-H accepts; funds NOT lost/stuck
# negatives: a hand-crafted v2 proof post-H is rejected (bad-smile2-proof-wire-version)
```
Assert: legacy note created pre-H is spendable both pre-H (v2) and post-H (v3);
balances conserve; no funds stuck. The unit-level pieces are already verified:
`rtx1_12` (v2 proof builds/verifies/round-trips), `c002_activation_gate_v2_v3`
(verifier accepts matching / rejects mismatched version per height), and the
wallet height-threading (emits the correct version per target height).

## 4. Status
- Verifier-side all-path gate (V2_SEND + V2_INGRESS_BATCH): DONE + btxd-verified.
- Prover/verifier/serialize/decode dual-format (section 2): DONE + verified
  (forge harness rtx1_12 + btxd build).
- Wallet height-threading (legacy notes auto-upgrade, no user action): DONE.
- Section 1 (honest notes always spendable): holds.
- REMAINING: regtest test vectors at height >=123000 (v2-reject / v3-accept
  end-to-end) and an E2E legacy-note-spend-across-activation regtest; user/dev
  release docs.
