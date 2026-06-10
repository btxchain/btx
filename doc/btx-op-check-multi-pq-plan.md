# OP_CHECK_MULTI_PQ — research findings & deterministic execution plan

Tracking issue: **btxchain/btx-node#248**. Status: research complete; recommendation below.

> **Headline:** BTX almost certainly needs **no new consensus opcode**. A k-of-n ML-DSA-44 (or
> SLH-DSA) covenant is **already expressible today** via the existing `OP_CHECKSIGADD_MLDSA` /
> `OP_CHECKSIGADD_SLHDSA` P2MR opcodes — first-class, builder-backed (`BuildP2MRMultisigScript`),
> policy-validated, and unit-tested. EVX's `OP_CHECK_MULTI_PQ` (its `script.rs` opcode `0x02`) is an
> EVX-side placeholder; the resolution is to have EVX **emit the existing BTX pattern**, not to add a
> BTX opcode. A real BTX consensus change is warranted **only** in one narrow case — an **ML-DSA**
> committee with **n > 8** members — and even that is avoidable by EVX's own key-type/size choices.

---

## 1. The decision, in one tree

The binding BTX consensus limit is `MAX_P2MR_SCRIPT_SIZE = 11000` bytes (`src/script/script.h:93`),
which bounds the leaf script that holds the n committee **public keys**. Signatures live in the
witness, bounded by `MAX_P2MR_STACK_BYTES = 1_000_000` and the per-input validation-weight budget
(which *scales with witness size*, so large sigs self-fund their verification) — so the witness is
not the constraint; the **leaf (pubkeys)** is.

| Covenant committee | Per-key in leaf | Max n in 11 KB leaf | BTX change needed? |
|---|---|---|---|
| **ML-DSA-44** keys (1312 B pk) | ~1315 B (PUSHDATA2) | **≈ 8** | **None for n ≤ 8.** |
| **SLH-DSA-128s** keys (32 B pk) | ~34 B | **≈ 300** | **None** (any realistic n). |
| **ML-DSA-44**, **n > 8** (e.g. Babylon-typical 6-of-9) | ~1315 B | exceeds 11 KB | Yes → Path B, *or* switch committee keys to SLH-DSA (no BTX change). |

**Deciding inputs (EVX's call):** (a) committee key algorithm, (b) committee size n. Babylon's
reference deployment is `covenant_quorum: 6` (≈ 6-of-9). EVX's `MAX_COVENANT_MEMBERS` cap is 16.

**Recommendation, in order of preference:**
1. **Path A — zero BTX consensus change (STRONGLY PREFERRED).** Have EVX build the covenant leaf
   with the existing `OP_CHECKSIGADD_MLDSA`/`_SLHDSA` pattern. Keep ML-DSA committees at **n ≤ 8**,
   *or* use **SLH-DSA-128s committee keys** (32-byte pubkeys) for any n up to 16. Neither needs a BTX
   fork. This is neutral, already tested, and keeps BTX requiring nothing EVX-specific.
2. **Path B — fork-gated `OP_CHECK_MULTI_PQ` (CONTINGENCY).** Only if an **ML-DSA committee with
   n > 8** is a hard requirement. The value is *not* a new verification primitive (CHECKSIGADD
   already verifies k independent sigs correctly) — it is **witness/leaf compression**: move the n
   pubkeys out of the 11 KB leaf into a committed **Merkle root** (à la BIP-360 P2QRH / BTX's own
   P2MR), with the witness supplying only the k used keys + membership proofs. Full spec in §6.

---

## 2. Why this is the answer — research synthesis

Three independent research streams (full reports in issue #248 history); load-bearing facts:

**Multisig opcode design (BIP342).** Bitcoin *deliberately disabled* `OP_CHECKMULTISIG` in Tapscript
and replaced it with the tiny accumulator `OP_CHECKSIGADD`, because CHECKMULTISIG accreted: the
un-inspected dummy element (NULLDUMMY/BIP147 hack), a brittle same-order sig↔key rule, O(n·m)
trial-matching, a coarse flat sigops count, and batch-incompatibility. The accepted k-of-n pattern is
`<pk1> CHECKSIG <pk2> CHECKSIGADD … <pkn> CHECKSIGADD <k> NUMEQUAL`, one witness item per key (a sig or
an empty vector). Lesson: prefer the accumulator + script loop; a monolithic threshold opcode is
justified **only** to exploit a witness-compression win unique to large keys — and even then must
replicate CHECKSIGADD's discipline (1:1 pairing, empty-skip, NULLFAIL-on-non-empty-invalid, canonical
encoding, minimal counter, per-input CPU budget). Refs: BIP342, BIP387, BIP146/147, Optech.

**ML-DSA-44 + Babylon.** ML-DSA-44: pk **1312 B**, sig **2420 B**; verification is *cheap* (≈ Ed25519)
— **size is the cost, not CPU** — and there is **no batch verification or aggregation** (lattice
Fiat–Shamir, unlike Schnorr/BLS). True threshold Dilithium is research-grade (TOPCOAT/TALUS/Quorus)
with no on-chain size win, so **k independent signatures, each verified separately, is the correct
model** — exactly what CHECKSIGADD does. **Malleability:** the FIPS 204 *hint-unpacking* flaw means
non-canonical hint ordering yields a different *valid* signature (third-party witness malleability);
verification MUST enforce strict canonical decoding (ascending/unique hints, range/length checks) —
the PQ analogue of low-S/NULLFAIL. Babylon's covenant is a k-of-n committee co-sign across three spend
paths (timelock-unbond / unbonding / slashing-to-burn) with EOTS making equivocation self-slashing;
the **covenant quorum maps directly to the BTX k-of-n opcode/script**. BIP-360 P2QRH is the closest
precedent and endorses BTX's approach: commit to pubkey *hashes*, reveal at spend (which BTX's P2MR
already does), and gate new verify behavior behind an OP_SUCCESS-style soft fork.

**BTX P2MR internals (decisive).** `OP_CHECKSIGADD_MLDSA` (`interpreter.cpp:1229-1284`) and
`_SLHDSA` already implement the accumulator with the exact semantics k-of-n needs: stack
`(sig n pubkey -- n')`; empty sig → counter unchanged, **no weight charged, no NULLFAIL**; non-empty
valid → n+1 and weight debited; non-empty invalid → hard `SCRIPT_ERR_SIG_*` (NULLFAIL/strong
unforgeability); strict pubkey-size check; canonical verify in `CheckPQSignature`
(`interpreter.cpp:2047-2067`). `BuildP2MRMultisigScript` (`src/script/pqm.cpp:203-237`) already emits
`<pk0> OP_CHECKSIG_MLDSA <pk1> OP_CHECKSIGADD_MLDSA … <k> OP_NUMEQUAL`, mixed ML-DSA/SLH-DSA supported,
validated by `pq_multisig_tests.cpp` and the policy parser (`policy.cpp:926-982`, which checks
`non_empty_signatures == threshold`). So **k-of-n PQ multisig is a shipped, tested BTX feature today.**

---

## 3. Path A — execute with ZERO BTX consensus change (preferred)

**What BTX provides today (no change):** `OP_CHECKSIG_MLDSA`/`_SLHDSA`,
`OP_CHECKSIGADD_MLDSA`/`_SLHDSA`, the `BuildP2MRMultisigScript` builder, P2MR descriptor + policy
support, and the validation-weight budget. The covenant spend path is:

```
<pk0> OP_CHECKSIG_MLDSA  <pk1> OP_CHECKSIGADD_MLDSA  …  <pk_{n-1}> OP_CHECKSIGADD_MLDSA  <k> OP_NUMEQUAL
```
witness: one element per key (a 2420-byte ML-DSA sig for a signer, an empty vector for a non-signer),
then the leaf script + control block (P2MR reveal). The full Babylon-style script combines this
covenant branch with the staker-key branch and the unbond-timelock branch under the P2MR MAST.

**Work items (all EVX-side, in `../evx`):**
- A1. Replace the placeholder `OP_CHECK_MULTI_PQ` (0x02) / `OP_CHECK_PQ_SIG` (0x01) encoding in
  `packages/btx-staking-scripts/src/script.rs` with BTX's canonical P2MR opcodes and leaf layout
  (mirror `BuildP2MRMultisigScript`); the builder must produce a leaf whose `script_hash()` matches
  what BTX's P2MR control-block reveal expects.
- A2. Constrain the covenant config: ML-DSA committee **n ≤ 8**, *or* SLH-DSA-128s committee keys for
  larger n. Encode the limit in `CovenantConfig::validate` so an over-size ML-DSA committee is
  rejected at build time (today it allows up to 16, which BTX consensus would reject for ML-DSA).
- A3. (Optional, BTX **policy-only**, no fork) If a >8-key **ML-DSA** committee must *relay* (not just
  be consensus-valid), relax `MAX_PQ_PUBKEYS_PER_MULTISIG` (`script.h:85`, standardness only,
  `policy.cpp:880,959`). Note this does **not** raise the 11 KB consensus leaf ceiling, so it only
  helps SLH-DSA committees — for ML-DSA n>8 you still need Path B.

**Path A test plan (deterministic — proves EVX covenants validate on BTX *today*):**
- T-A1 (BTX, new): a regtest unit test in `src/test/pq_multisig_tests.cpp` building the exact
  Babylon-shaped covenant leaf (staker-OR-(k-of-n covenant)-OR-unbond-timelock) with ML-DSA n=8/k=5
  and asserting: (a) a valid k-signer witness spends; (b) k-1 signers fails; (c) a duplicate-signer
  witness fails (distinct-key requirement, via positional pairing); (d) a non-canonical/garbage sig
  aborts (NULLFAIL); (e) the leaf is ≤ `MAX_P2MR_SCRIPT_SIZE`.
- T-A2 (BTX, new): the SLH-DSA-128s n=16/k=6 variant — proves large committees work today with the
  small-pubkey algorithm; assert leaf size and spend validity.
- T-A3 (BTX, new): negative — an ML-DSA n=9 leaf must be **rejected** as `> MAX_P2MR_SCRIPT_SIZE`
  (documents the exact boundary that triggers Path B).
- T-A4 (EVX, in `../evx`): a cross-language test that EVX's covenant builder output parses/validates
  via BTX's `pqm`/policy parser (mirror EVX's existing precompiles-btx known-answer tests).
- T-A5 (functional): a `test/functional/` regtest that creates a covenant UTXO and spends it via each
  path against a live `btxd`.

If Path A suffices (the expected outcome), **issue #248 closes with no BTX consensus change** — only
the EVX builder update + these tests.

---

## 4. Security requirements (apply to BOTH paths)

Consolidated pitfalls-to-avoid (the opcode/script and any verifier MUST enforce all of these — most
are already enforced by the existing P2MR opcodes; Path B must re-assert them):
1. **No un-inspected stack/witness element** (the CHECKMULTISIG dummy/NULLDUMMY lesson).
2. **1:1 positional sig↔key pairing**; no O(n·m) trial-matching.
3. **Empty vector = skip; non-empty invalid = abort** (NULLFAIL / strong unforgeability) —
   `interpreter.cpp:1220,1278`.
4. **Strict canonical signature decoding**, incl. ML-DSA **ascending/unique hint indices** and
   range/length checks (kills the FIPS 204 hint-malleability vector). Confirm `CheckPQSignature` /
   `CPQPubKey::Verify` already rejects non-canonical hints (the Dilithium reference impl does; add a
   targeted malleability test regardless).
5. **k distinct signers** — forbid one committee key counting twice (positional pairing gives this for
   the inline pattern; Path B's bitmap/Merkle proofs must enforce no duplicate index).
6. **Minimally-encoded threshold counter** (`fRequireMinimal=true`, `interpreter.cpp:1236`).
7. **Per-input validation-weight budget**, charged per non-empty verification (`500`/MLDSA-multisig,
   `5000`/SLHDSA-multisig WU; `script.h:78-82`), self-funded by witness size; never a flat sigops
   count. ML-DSA cannot be batched, so each of the k sigs is a full independent verify.
8. **Cap n and k** to bound worst-case bytes + verifications.
9. **Quantum-emergency kill switch** continues to apply (`SCRIPT_VERIFY_DISALLOW_MLDSA`,
   `nMLDSADisableHeight`).

---

## 5. Activation/forking facts (critical for Path B)

The existing PQ opcodes are **active from genesis** — there is **no** soft-fork activation height,
only a *disable* height `nMLDSADisableHeight` (`consensus/params.h:295`; applied
`validation.cpp:2768,6165`). The FIPS-205 behavior change is height-gated via
`nShieldedC002ActivationHeight=123000` (`params.h:275-277`; applied `validation.cpp:6175`). The opcode
bytes `0xc0–0xc2` are reserved as `OP_SUCCESSx` (Falcon) precisely so new verify behavior can
**soft-fork-activate** later (`script.h:249-253`); free bytes `0xc3–0xfe` remain.

**Therefore a bare new opcode (0xc3) added without gating is a HARD FORK.** Path B MUST: treat the new
opcode as `OP_SUCCESS` pre-activation, add an `nCheckMultiPQActivationHeight` to `Consensus::Params`
(mirroring `nShieldedC002ActivationHeight`), gate a new `SCRIPT_VERIFY_*` flag in `GetBlockScriptFlags`
(`validation.cpp:~6155-6177`) and the mempool path (`:2785`), and ship it as a coordinated, fleet-wide
soft fork — never hot-deployed.

---

## 6. Path B — `OP_CHECK_MULTI_PQ` (contingency: ML-DSA committee, n > 8)

Build this ONLY if EVX confirms it requires an **ML-DSA** committee larger than 8 and will not use
SLH-DSA committee keys. Design = a Merkle-committed pubkey set (so n pubkeys leave the 11 KB leaf):

**Leaf:** `<pubkey_merkle_root(32B)> <n> <k> OP_CHECK_MULTI_PQ` (root is a Merkle root over the n
sorted committee ML-DSA pubkeys, domain-separated).
**Witness (per spend):** for each of the k signers — its pubkey, its Merkle membership proof, its
2420-byte ML-DSA signature; plus a strictly-increasing index list (enforces distinctness + ordering).
**Opcode semantics:** verify k ≤ provided ≤ n; for each provided signer: (a) verify the Merkle proof
binds the pubkey to the committed root at a strictly-increasing index (no duplicates), (b) verify the
canonical ML-DSA signature over the P2MR sighash, charging `VALIDATION_WEIGHT_PER_MLDSA_MULTISIG_SIGOP`
each; (c) require the count of valid signatures == k (or ≥ k); else abort (NULLFAIL discipline). All §4
rules apply.

**Insertion map (file:line, from the codebase analysis):**
- `src/script/script.h:248` add `OP_CHECK_MULTI_PQ = 0xc3`; bump `MAX_OPCODE` (`:259`); `GetOpName`
  in `script.cpp`. New `SCRIPT_ERR_*` codes in `script_error.{h,cpp}`.
- `src/script/interpreter.cpp` new `case OP_CHECK_MULTI_PQ:` modeled on `1229-1284`; P2MR-only gate;
  `SCRIPT_VERIFY_DISALLOW_MLDSA` check; Merkle-proof verify; per-sig weight debit with
  `< 0 → SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT` (`:1268-1272`); verify via `CheckPQSignature`.
- `src/script/pqm.cpp` builder + `DecodeP2MRChecksigOpcode` sibling (`:110`) + a `P2MRLeafType`;
  `policy.cpp` parser branch (mirror `:926-982`); `descriptor.cpp:3097` + `miniscript.cpp:87`.
- Activation gate per §5: `consensus/params.h`, `chainparams.cpp` (all nets), `validation.cpp:2785,6155-6177`.

**Path B test matrix (deterministic):**
- Unit (`pq_multisig_tests.cpp` style): valid k-of-n; k-1 fails; duplicate index fails; out-of-order
  index fails; bad Merkle proof fails; non-canonical/malleated sig aborts; weight-exhaustion fails;
  n>8 ML-DSA now succeeds (the Path A boundary case).
- Consensus (`pq_consensus_tests.cpp`, `script_tests.json`): end-to-end script validity vectors,
  pre- vs post-activation (OP_SUCCESS before, enforced after).
- Activation (`validation_*`/`versionbits`-style): pre-activation block treats 0xc3 as OP_SUCCESS;
  post-activation enforces; a node split-safety check that un-upgraded nodes don't diverge before the
  height.
- Policy (`pq_policy_tests.cpp`), descriptors (`pq_descriptor_tests.cpp`), sigops/weight
  (`sigopcount_tests.cpp`), fuzz (`fuzz/pq_merkle.cpp`), functional (`test/functional/`).

---

## 7. Deterministic execution checklist

1. **Decision gate (EVX owner):** confirm covenant (a) key algorithm and (b) max n.
   - ML-DSA & n ≤ 8, **or** SLH-DSA & n ≤ 16 → **Path A**. ML-DSA & n > 8 (and SLH-DSA refused) → **Path B**.
2. **Path A:** EVX builder change (A1) + config constraint (A2) + tests T-A1…T-A5. Optional BTX
   policy relax (A3). Build (clang, rtX1-orig), run `pq_*`/script/functional suites. Close #248.
3. **Path B (only if gated in):** implement §6 behind `nCheckMultiPQActivationHeight` (OP_SUCCESS
   pre-activation), full test matrix, clang build + suites, security review, then a coordinated
   soft-fork activation proposal (NOT hot-deployed) — separate fork-gated PR.

**Neutrality invariant (applies throughout):** any BTX change is a *general* PQ-multisig primitive,
not EVX-specific, fork-gated, requiring no permissioned/centralized input — consistent with the
reverted EVX-anchored finality floor (#246/#247). BTX stays the neutral, permissionless floor.

## 8. Open question for the EVX team (the single decision that picks the path)
**What are the covenant committee's key algorithm and maximum size?** If ML-DSA with n ≤ 8 or SLH-DSA
at any realistic n, BTX needs **nothing** (Path A). Only a mandatory ML-DSA committee of n > 8 triggers
Path B's fork.
