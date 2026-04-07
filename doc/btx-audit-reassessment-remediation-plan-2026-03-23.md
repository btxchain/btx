# BTX Audit Reassessment Remediation Plan

**Date:** 2026-03-23  
**Branch:** `audit-reassessment-fixes-20260323`  
**Source audit docs:** `../_audit/20260323/btx-audit-master-status-2026-03-23.md`, `../_audit/20260323/btx-fix-compatibility-analysis-2026-03-23.md`  
**Source reassessment:** `../_audit/20260323/btx-audit-review-reassessment-2026-03-23.md`

## Objective

Resolve the issues that remain actionable after the reassessment, with these constraints:

1. Do not require a chain restart.
2. Prefer no-fork fixes.
3. Only add a soft fork if it materially improves security/privacy and can be done with the existing wire format.
4. Avoid a hard fork unless it is clearly necessary and explicitly approved.

This plan therefore splits the work into:

- baseline no-fork fixes to implement now
- optional soft-fork work to keep separate
- confirmed hard-fork items to defer unless specifically approved

Implementation status for the current branch:

- the baseline no-fork series is implemented
- `M-017` is implemented as a height-gated stricter rule over the existing `extension_digest` field
- `M-009` is implemented as a height-gated bridge-tag derivation upgrade
- `M-016` is implemented as canonical no-Rice proof emission plus a height-gated consensus rejection of legacy Rice-coded SMILE proof vectors
- the new `M-016` Rice-codec gate is set to activate at height `51350`
- the earlier `M-017` and `M-009` rules remain historical `51000` activations already present on `main`

## Reassessment-Based Scope

### In scope for the baseline remediation series

- `C-001` CT rejection sampling constant mismatch
- `H-002` biased/non-cryptographic ternary sampling
- `T3-006` scan-hint fast path not constant-time
- `C-004` unsafe public-data key-derivation helper still present
- `H-005` placeholder ring member code still present in non-test surfaces
- `RT-001` remaining ring-selection privacy weakness
- `M-012` secret polynomial lifetime / zeroization gap
- `M-013` narrower post-proof secret cleanup gap
- `M-008` ciphertext-size privacy can be improved without consensus change by padding inside the existing encrypted plaintext

### Explicitly not in the baseline series

- `C-002`
  - Closed from the active audit-remediation backlog as a documented deliberate protocol choice on the current launch surface.
  - Default decision: do not change consensus here without separate cryptographic sign-off for a redesign.
- `M-017`
  - The prior hard-fork claim was overstated.
  - A soft-fork path likely exists, but the reassessment does not support treating it as an emergency must-fix.
  - Default decision: keep this as an optional follow-on soft fork, not part of the baseline no-fork series.
- `M-009`
  - Reassessment still points to this as a real consensus-relevant privacy issue.
  - Default decision: defer unless the project explicitly approves a hard fork now.
- `BA-001`
  - Downgraded: total transaction byte size is mostly redundant with structural metadata already serialized in the public wire format.
  - Default decision: do not pursue a dedicated hard-fork redesign for this as part of audit remediation.

## Default Decisions

Based on the stated goal of avoiding a chain restart and the follow-up instruction to "implement everything" with an activation height if needed:

- Proceed now with all no-fork fixes listed in the baseline series.
- Implement `M-008` as a wallet/encryption compatibility upgrade, not as a wire-format change.
- Include `M-017` now as a height-gated stricter validity rule using the existing `extension_digest` field.
- Include `M-009` now as a height-gated bridge-tag upgrade to avoid a restart while still fixing the issue.
- Keep the current CT monomial-challenge surface unchanged unless later cryptographic work produces an explicit reason to redesign it.

Under this plan, the branch still avoids a chain restart, but it now contains:

- a height-gated stricter rule for `M-016`
- a height-gated stricter rule for `M-017`
- a height-gated hard fork for `M-009`

## Implemented Commit Series

The branch is split into the following reviewable commits:

| Order | Issue | Default fix class | Height gate | Implemented change |
|---|---|---|---|---|
| 1 | `C-001` | No fork | None | Align CT rejection sampling with the intended acceptance rule instead of the hardcoded `14.0` shortcut. Keep verifier behavior unchanged. |
| 2 | `H-002` | No fork | None | Replace `SampleTernary` xorshift64 sampling with CSPRNG-backed unbiased ternary sampling. |
| 3 | `T3-006` | No fork | None | Make the scan-hint fast path use `constant_time_scan=true` so the fast path and fallback do not leak via timing. |
| 4 | `C-004` / `H-005` | No fork | None | Remove public-data placeholder SMILE helpers from production surfaces and move the remaining placeholder helpers to test-only utilities. |
| 5 | `RT-001` | No fork | None | Fix the remaining privacy profile in ring selection: cap exclusion behavior for small trees and mix in explicit historical sampling so older-note spends are less identifiable. |
| 6 | `M-012` / `M-013` | No fork | None | Add secure destruction/cleansing for `SmilePoly`-backed secret temporaries and explicitly cleanse post-proof secret material once it is no longer needed. |
| 7 | `M-008` | No fork | None | Add padded note-plaintext encoding within the existing ciphertext field and dual-format decryption so upgraded wallets recognize both legacy and padded notes. |
| 8 | `M-016` | Height-gated soft fork | `51350` | Stop emitting the legacy Rice witness codec and reject Rice-coded SMILE proof vectors only after activation. |
| 9 | `M-017` | Height-gated soft fork | `51000` | Canonicalize and enforce the `V2_SEND` `extension_digest` only after activation. |
| 10 | `M-009` | Height-gated hard fork | `51000` | Upgrade ingress/egress/rebalance bridge tags to include the note commitment and preserve spend compatibility across historical and upgraded leaves. |

## Per-Issue Detail

This section is intended to stand on its own without the larger audit packet. For each issue included on this branch it records:

- the original audit claim
- the reassessment conclusion used for this branch
- the concrete implementation choice made here
- the deployment and historical-chain impact

### `C-001` CT rejection sampling constant mismatch

- Original audit claim:
  - The prover used a hardcoded `14.0` constant in the CT rejection-sampling acceptance rule instead of the intended `ln(M)` style term, biasing accepted `z` vectors and weakening zero-knowledge.
- Reassessment conclusion:
  - This is a real prover-side issue.
  - The original classification that it does not require a fork was correct.
- Implemented on this branch:
  - Replace the hardcoded constant with the explicit `log(3)` form of the acceptance rule.
- Deployment / historical impact:
  - No fork and no restart.
  - Previously mined proofs remain valid.
  - Any historical leakage from already-mined biased proofs remains permanent.

### `H-002` biased `SampleTernary` and xorshift64 sampling

- Original audit claim:
  - `SampleTernary` used weak and biased randomness generation, including xorshift64-based sampling and modulo bias.
- Reassessment conclusion:
  - This remains a real unfixed issue and is wallet/prover-side only.
- Implemented on this branch:
  - Add SHA256 counter-mode byte expansion and rejection sampling for unbiased ternary coefficients.
  - Use the stronger sampler for key generation and prover commitment randomness.
- Deployment / historical impact:
  - No fork and no restart.
  - Historical artifacts stay valid but keep their old randomness quality.
  - New proofs and new keys stop inheriting the weaker sampler.

### `T3-006` scan-hint fast path uses `constant_time_scan=false`

- Original audit claim:
  - The wallet fast path for scan-hint handling used non-constant-time note trial decryption, creating a timing side channel.
- Reassessment conclusion:
  - The issue remained real.
- Implemented on this branch:
  - The fast path now always uses `constant_time_scan=true`.
- Deployment / historical impact:
  - No fork and no restart.
  - Past chain data is unchanged.
  - The improvement only changes wallet-side runtime behavior going forward.

### `C-004` placeholder key derivation from public data

- Original audit claim:
  - A placeholder SMILE key-derivation path reconstructed spend-capable material from public note commitment data.
- Reassessment conclusion:
  - The helper is dangerous, but it did not appear to be on the live production spend path in the current tree.
- Implemented on this branch:
  - Remove the public-data `DeriveSmileKeyPair` helper from production headers and production implementation surfaces.
  - Preserve equivalent helpers only in test-only utilities.
- Deployment / historical impact:
  - No fork and no restart.
  - Historical outputs are unchanged.
  - The change removes a dangerous production surface rather than changing consensus.

### `H-005` placeholder ring members may be distinguishable

- Original audit claim:
  - Placeholder ring members could produce distinguishable anonymity sets if they were used in production.
- Reassessment conclusion:
  - In the current tree this did not appear to be a live production-path issue because active wallet and verifier flows require canonical public accounts and account-leaf commitments.
- Implemented on this branch:
  - Remove `BuildPlaceholderRingMember` from production surfaces.
  - Keep placeholder construction only in test-only utilities.
- Deployment / historical impact:
  - No fork and no restart.
  - No historical chain rewrite is needed.
  - The practical effect is to prevent accidental future production use of placeholder members.

### `RT-001` ring-selection privacy weakness

- Original audit claim:
  - Ring selection had a gamma-distribution calibration problem and a tip-exclusion window regression that could make the real spend more identifiable; the original report also claimed very small trees could deterministically fail proof construction.
- Reassessment conclusion:
  - The privacy issue is real.
  - The small-tree deterministic liveness-failure claim is not supported by the current selector code.
- Implemented on this branch:
  - Mix explicit historical decoys into the ring instead of only `ANY` region sampling.
  - Cap the tip exclusion window by the number of positions that are actually excludable.
- Deployment / historical impact:
  - No fork and no restart.
  - Past rings remain permanently visible on-chain with their original selection pattern.
  - The fix improves privacy quality for new spends only.

### `M-012` / `M-013` SMILE secret lifetime and cleanup

- Original audit claim:
  - `SmilePoly` lacked secure destruction and post-proof secret material could remain in memory longer than necessary.
  - The older `H-006` wording overstated this by implying there was no cleanup at all.
- Reassessment conclusion:
  - The issue should be restated narrowly as a runtime secret-lifetime problem, not a consensus problem.
- Implemented on this branch:
  - Add `SmilePoly::SecureClear()`.
  - Use secure clearing in `SmileSecretKey`.
  - Add destruction-time cleansing for CT input/output secret material such as coin openings and amounts.
- Deployment / historical impact:
  - No fork and no restart.
  - No on-chain effects.
  - The benefit is purely runtime memory hygiene.

### `M-008` ciphertext-size leak from memo-length-dependent note encryption

- Original audit claim:
  - Ciphertext size varied with memo length, and the compatibility analysis classified the fix as a hard fork because it assumed `EncryptedNotePayload` would need a wire-version bump.
- Reassessment conclusion:
  - The hard-fork conclusion was too strong.
  - The existing ciphertext field can already carry variable-sized encrypted plaintext, so the mitigation can live entirely inside the encrypted plaintext format.
- Implemented on this branch:
  - Introduce a padded bound-note plaintext format with magic `BNO2`.
  - Keep legacy compact bound-note support and legacy full-note decryption.
  - Mark notes that use the modern SMILE derivation path so upgraded wallets can derive the right openings and keys when those notes are later spent.
- Deployment / historical impact:
  - No consensus fork and no restart.
  - Old nodes continue to relay and mine the transactions because the on-chain ciphertext field remains valid.
- Old wallets may fail to recognize newly padded notes until upgraded.
- Historical ciphertext-size leakage remains permanently visible for previously mined transactions.

### `M-016` Rice decoder unbounded unary prefix

- Original audit claim:
  - The SMILE proof deserializer accepted a Rice-coded witness surface whose unary-prefix decoder could be forced into unnecessarily expensive work before later norm and semantic checks rejected the proof.
- Reassessment conclusion:
  - The issue is real and availability-relevant.
  - A local mitigation alone would not protect the network against block-level abuse, so the preferred end state is a soft-fork rejection rule.
- Implemented on this branch:
  - The canonical serializer no longer emits Rice-coded Gaussian witness vectors.
  - Legacy Rice decoding remains available before activation for compatibility with older proof bytes.
  - At and after height `51350`, consensus parsing rejects Rice-coded SMILE proof vectors with `bad-smile2-proof-rice-codec`.
- Deployment / historical impact:
  - Height-gated at `51350`.
  - Pre-activation blocks and transactions remain valid.
  - Historical Rice-coded proofs remain valid only in pre-activation history; upgraded nodes reject new post-activation Rice-coded proofs without requiring a chain restart.

### `M-017` missing semantic binding for `extension_digest`

- Original audit claim:
  - The Fiat-Shamir transcript did not include transaction identity, and the prior compatibility write-up classified any fix as a hard fork because old verifiers would recompute a different transcript.
- Reassessment conclusion:
  - The hard-fork classification was too strong.
  - The code already had an outer `statement_digest` over a stripped transaction and the txid already commits to the shielded bundle including proof bytes.
  - If an extra rule is still desired, the existing `extension_digest` field provides a plausible soft-fork path.
- Implemented on this branch:
  - Define a canonical `V2_SEND` extension digest over a stripped transaction with `proof_payload`, `statement_digest`, and `extension_digest` zeroed.
  - Populate that digest when building `V2_SEND` transactions.
  - Enforce it only at and after the activation height.
- Deployment / historical impact:
  - Height-gated at `51000`.
  - Pre-activation blocks and transactions remain valid.
  - Old peers may relay or mine post-activation transactions that upgraded nodes reject, but this is a normal soft-fork-style tightening and does not require a chain restart.

### `M-009` deterministic bridge tags enable cross-transaction linking

- Original audit claim:
  - Ingress, egress, and rebalance bridge tags were deterministic across transactions, allowing cross-transaction linking.
  - Because bridge tags feed account-leaf commitments and registry state, the original audit correctly identified this as hard-fork sensitive.
- Reassessment conclusion:
  - This is a real consensus-relevant privacy issue.
  - A chain restart is not technically required, but changing the commitment rule is a hard fork.
- Implemented on this branch:
  - Introduce upgraded bridge-tag derivations that incorporate the note commitment.
  - Thread the upgraded derivation through account-leaf construction, bundle leaf collection, wallet indexing, chainstate rebuilds, block connect/disconnect, and spend-side witness matching.
  - Preserve spend compatibility by accepting either the historical or upgraded leaf commitment when reconstructing witnesses for already-existing notes.
- Deployment / historical impact:
  - Height-gated at `51000`.
  - This is a hard fork because post-activation account-leaf commitments and registry state differ from what old nodes compute.
  - Historical bridge tags and historical leaves remain permanently linkable, but they remain recognized and spendable by upgraded nodes.
  - Old peers will reject post-activation blocks built under the new rule until they upgrade.

## Deferred Audit Items Not Implemented On This Branch

### `C-002`

- Original audit claim:
  - The CT proof path uses a monomial Fiat-Shamir challenge with only 256 possible challenge values, while membership uses a dense ternary challenge, so CT soundness may be materially weaker unless the protocol relies on M-SIS hardness rather than challenge entropy.
- Documentation basis found locally:
  - `src/shielded/smile2/ct_proof.h` documents that the launch CT path intentionally retains a monomial Fiat-Shamir challenge because the live wire surface is still tuned to small response-width parameters.
  - `src/shielded/smile2/params.h` documents the parameter rationale: with monomial `c = ±X^k`, `||c·r||∞ <= 1` for ternary `r`, permitting the current small `σ` and compact response encoding.
  - `src/shielded/smile2/ct_proof.cpp` repeats the same assumption directly next to the challenge constructor and rejection-sampling surface.
- Reassessment conclusion:
  - The implementation fact is real, but the branch reassessment did not support treating it as a confirmed practical exploit from code review alone.
  - The local code and protocol documentation are enough to show this is a deliberate launch-surface design choice, not an accidental implementation divergence.
  - That closes `C-002` as an active audit issue for current planning purposes.
- Status on this branch:
  - Intentionally unchanged.
  - Treat as a documented protocol choice for the current launch surface, not as an unresolved implementation bug.
- Future assurance checklist:
  - Map the live CT prover and verifier transcript, challenge, and rejection-sampling surfaces to the intended SMILE or BDLOP theorem assumptions.
  - Confirm whether soundness on this exact CT surface relies on M-SIS hardness, challenge entropy, parallel repetition, or a combination.
  - Produce a concrete security estimate using the live BTX parameters and current monomial challenge distribution.
  - Record the theorem-to-code mapping in a dedicated protocol note if a future external cryptographic review is commissioned.
  - If later review concludes the monomial CT challenge is insufficient, scope that as a separate height-gated hard-fork redesign rather than retroactively reopening the current remediation branch.

### `BA-001`

- Original audit claim:
  - Shielded transaction size reveals structure such as input/output count, and a real on-chain padding fix would require a format-level hard fork.
- Reassessment conclusion:
  - The observed size correlation is real, but it is mostly redundant with structural metadata already serialized in the public wire format.
  - `TransactionHeader` exposes family and shard/chunk counts, `SendPayload` exposes exact spend/output counts, batch payloads expose their leaf/spend/output counts, and `proof_payload` is length-prefixed.
  - In a public repo where anyone can run a parser or operate a node, raw outer transaction size adds little incremental leakage beyond what the format already reveals.
- Status on this branch:
  - Not implemented.
  - This branch keeps the existing transaction-family formats and does not attempt a broad count-hiding format redesign.
- Future-work note:
  - If the project later wants true count-hiding or template-hiding wire formats for defense in depth, that would still be a separate hard-fork design exercise.
  - It is not treated as a worthwhile audit-remediation item for the current public-parser deployment model.

## Height-Gated Consensus Work Included On This Branch

These items are implemented separately from the baseline no-fork fixes, but they are part of the current branch.

### Commit: `M-017`

- **Current status:** included
- **Fork class:** soft fork candidate
- **Reasoning:** the existing wire format already carries `extension_digest`, and old nodes already compare it as part of the proof envelope. The missing piece is semantic validation, not transport.
- **Planned mechanism if enabled:**
  - Define a consensus function for `V2_SEND` bundles that computes the required `extension_digest` from the transaction under a canonicalized view.
  - Recommended shape:
    - clone the transaction
    - clear `proof_payload`
    - clear `statement_digest`
    - clear `extension_digest`
    - hash the canonicalized transaction under a dedicated domain tag
  - After activation, require `header.proof_envelope.extension_digest` to equal that derived digest for non-empty `V2_SEND` spends.
- **Why this is a soft fork:**
  - no new fields
  - no new wire version
  - upgraded nodes add a stricter validity rule over existing bytes
- **Old blocks / old transactions:**
  - pre-activation blocks remain valid
  - pre-activation transactions remain recognized by upgraded nodes
  - upgraded wallets/nodes must continue to accept legacy zero/unspecified `extension_digest` before activation
- **Old peers after activation:**
  - old peers can still relay or mine transactions that upgraded nodes reject
  - once upgraded miners enforce the rule, old peers remain on the same chain if they follow the most-work chain, but they do not enforce the new restriction locally
- **Activation mechanism used on this branch:** direct consensus height gate
  - `Consensus::Params::nShieldedTxBindingActivationHeight`
  - set to `51000` in `src/kernel/chainparams.cpp`

### Commit: `M-009`

- **Current status:** included
- **Fork class:** hard fork
- **Reasoning:** bridge tags are part of account-leaf material that feeds consensus-validated registry commitments. Changing the derivation changes the leaf commitment and registry state.
- **Planned mechanism if enabled:**
  - change ingress/egress/rebalance bridge-tag derivation to incorporate a per-output secret/nonce so tags are not deterministic across transactions
  - update wallet construction, registry leaf creation, and verifier-side recomputation consistently
- **Why this is a hard fork:**
  - old nodes deterministically recompute the current bridge tags
  - post-change leaves would hash to different commitments and produce a different account-registry state
- **Old blocks / old transactions:**
  - all pre-fork registry leaves remain valid and remain linkable
  - upgraded nodes continue to recognize the historical chain and historical notes
- **Old peers after activation:**
  - old peers will reject post-fork blocks/transactions using the new bridge-tag rule
  - this is a normal consensus split until they upgrade
- **Activation mechanism used on this branch:** direct consensus height gate
  - `Consensus::Params::nShieldedBridgeTagActivationHeight`
  - set to `51000` in `src/kernel/chainparams.cpp`

## Compatibility Notes For The Baseline No-Fork Series

### `M-008`

This item should be treated as a wallet/encryption compatibility change, not a consensus change.

- New nodes:
  - relay and mine padded-note transactions normally because the on-chain payload remains a valid `EncryptedNotePayload`
  - upgraded wallets recognize both legacy and padded note plaintexts
- Old nodes:
  - unaffected at consensus and P2P levels
  - continue to relay and mine the transactions
- Old wallets:
  - may fail to recognize newly padded notes until upgraded
  - will still recognize historical legacy notes

This means `M-008` needs rollout awareness, but not chain coordination.

### `C-001`, `H-002`, `T3-006`, `C-004`, `H-005`, `RT-001`, `M-012`, `M-013`

All of these are local wallet/prover/runtime changes:

- previously mined blocks remain valid
- previously mined transactions remain valid
- old nodes stay on the same chain
- new nodes simply stop creating weaker artifacts going forward

## Height-Gated Values To Review In The PR

The current branch uses direct height gates with mixed historical and new activation heights.

Definitions:

- `src/consensus/params.h`
  - `nShieldedTxBindingActivationHeight`
  - `nShieldedBridgeTagActivationHeight`
  - `nShieldedSmileRiceCodecDisableHeight`

Current per-network values:

- `src/kernel/chainparams.cpp`
  - mainnet constructor
  - testnet constructor
  - testnet4 constructor
  - signet constructor
  - regtest constructor
  - shieldedv2dev constructor

If the review decides on a different activation height, these are the places to change.

## Review Order

1. Review the baseline no-fork commits first.
2. Review `M-017` next as the soft-fork-style tightening over existing proof-envelope bytes.
3. Review `M-009` last as the chain-splitting bridge-tag upgrade.

## Manual Decisions That Are Actually Required

No manual decision is required to begin the baseline remediation series.

The new `M-016` activation height for this branch is fixed at `51350`.
This branch should only be deployed in-place while the live chain is still below that height.

## Summary

The current implementation plan is:

- fix the confirmed no-fork issues without a chain restart
- improve `M-008` without touching consensus
- activate the `M-016` Rice-codec rejection rule at height `51350`
- activate the `M-017` stricter `extension_digest` rule at height `51000`
- activate the `M-009` bridge-tag upgrade at height `51000`

That path still avoids a chain restart, but only if every validating node upgrades before height `51350`.
