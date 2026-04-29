# Implementation Record

Date: 2026-04-24

## Purpose

This log records the concrete upstream implementation steps for the post-fork
spend-path recovery patch.

The goal is to keep a reviewable history of:

- what changed
- why it changed
- what was verified
- what remains intentionally disabled

## Current milestone

### Recovery family is now activation-gated

The upstream tree no longer hard-rejects `v2_spend_path_recovery`
unconditionally.

Instead, recovery admission is now controlled by a dedicated consensus gate:

- `nShieldedSpendPathRecoveryActivationHeight`

and helper:

- `IsShieldedSpendPathRecoveryActive(height)`

Default behavior is still non-accepting because the activation height defaults
to `max()`.

When inactive, recovery still rejects explicitly with:

- `bad-shielded-v2-spend-path-recovery-disabled`

When active, the recovery family now enters the normal shielded validation
path instead of failing at the first family check.

### Deterministic reproduction is in place

The upstream tree now has a synthetic regression that reproduces the
lost-spend-path failure mode without any live-wallet artifacts:

- a legacy shield-only note is accepted into chain state
- the wallet scans it and counts it as spendable
- the note still lacks a direct-send account leaf hint
- an ordinary `V2_SEND` build fails with `bad-shielded-v2-builder-input`

This regression lives in:

- `src/test/shielded_wallet_chunk_discovery_tests.cpp`

### Recovery outputs now have an explicit success-path scaffold

The next scaffold regression proves the intended post-migration wallet shape:

- a synthetic spend-path recovery bundle is built from a real direct-send build
  result
- the wallet scans the recovery output
- the scanned note is labeled with a direct-send account leaf hint
- the cached transaction view identifies the family as
  `v2_spend_path_recovery`
- the scanned output can be used as the input note for a later ordinary
  `V2_SEND` build in test fixtures

This test still does not prove consensus acceptance of the recovery family.
It proves that recovery outputs are being shaped like modern direct-send notes
on the wallet side, which is a required precondition for the full patch.

### Recovery proof surface now has a first accepting slice

The upstream tree now has a dedicated proof-layer scaffold for
`v2_spend_path_recovery`:

- a distinct verification domain,
- a recovery statement digest and descriptor,
- a recovery proof parse/bind/context path,
- explicit nullifier extraction support for the recovery context, and
- bundle-wire support for proof-bearing recovery scaffolds under generic wire
  encoding,
- direct ring reconstruction for recovery spends,
- direct SMILE ring reconstruction for recovery spends, and
- recovery-family proof verification helpers for both MatRiCT-style and
  SMILE-style direct witnesses.

This slice also wires recovery through the surrounding consensus surfaces that
would otherwise have blocked it even after activation:

- allowed-family checks in mempool and block validation,
- account-registry reference validation,
- shielded proof-check dispatch, and
- shielded pool value-balance accounting.

The intent is still narrow:

- keep the feature disabled by default,
- prove that an activated recovery family can make it through the validator
  path safely,
- keep the postfork-specific activation boundary honest and explicit.

The first accepting slice now covers both:

- a prefork direct-style activated recovery fixture, and
- the full postfork generic-wire activated recovery fixture.

The postfork gap that remained earlier was traced to fixture-shaping order:
the recovery statement digest was being computed before the derived output
chunks were refreshed, so the stored statement digest no longer matched the
final transaction shape. After fixing that ordering, the activated postfork
generic-wire validator path went green.

## Code changes recorded in this milestone

### Wallet family naming

The wallet-facing family description now reports:

- `v2_spend_path_recovery`

in:

- `src/wallet/shielded_wallet.cpp`
- `src/wallet/shielded_rpc.cpp`

### Wallet output scanning

The wallet now treats spend-path recovery outputs like direct-send outputs for
metadata purposes in:

- `src/wallet/shielded_wallet.cpp`

Specifically:

- block scan assigns a direct-send account leaf hint to recovery outputs
- mempool scan assigns the same hint to recovery outputs

This matches the bundle/account-registry layer, which already derives
direct-send account leaves for recovery outputs.

### Regression coverage

The main wallet regression file now covers both:

- legacy-note lost spend-path reproduction
- recovery-output ordinary-spend-shape scaffolding

in:

- `src/test/shielded_wallet_chunk_discovery_tests.cpp`

The proof and bundle regression surface now also covers:

- recovery statement digest stability under stripped-proof hashing
- recovery proof context parsing under the disabled scaffold
- recovery proof context rejection on statement mismatch
- recovery proof context rejection on missing proof payload
- recovery proof context rejection on malformed witness encoding
- recovery proof verification against a recovery-family context
- proof-bearing recovery bundle round-trip under the scaffold
- recovery bundle fee accounting through shielded state-value balance
- explicit proof-check rejection for proof-bearing recovery bundles that remain
  disabled
- activated prefork recovery proof acceptance
- activated postfork recovery proof acceptance
- activated prefork recovery activation-boundary enforcement
- activated postfork recovery activation-boundary enforcement
- activated prefork recovery nullifier-tamper rejection
- activated postfork recovery nullifier-tamper rejection
- mempool nullifier-conflict detection for recovery-family transactions
- mempool duplicate-nullifier detection within a recovery-family transaction

in:

- `src/test/shielded_v2_proof_tests.cpp`
- `src/test/shielded_v2_bundle_tests.cpp`
- `src/test/shielded_validation_checks_tests.cpp`
- `src/test/shielded_mempool_tests.cpp`

### Regtest activation plumbing

Regtest now has an explicit spend-path recovery activation override in:

- `src/chainparamsbase.cpp`
- `src/chainparams.cpp`
- `src/kernel/chainparams.h`
- `src/kernel/chainparams.cpp`

The new regtest-only switch is:

- `-regtestshieldedspendpathrecoveryactivationheight=<n>`

This keeps the feature disabled by default while giving the functional harness
an activation boundary it can turn on deliberately for mixed-version and
network-divergence coverage.

Focused regressions run in this slice:

- `shielded_v2_proof_tests/v2_send_context_parses_and_verifies`
- `shielded_v2_proof_tests/spend_path_recovery_statement_tracks_stripped_tx_digest`
- `shielded_v2_proof_tests/spend_path_recovery_context_parses_under_disabled_scaffold`
- `shielded_v2_proof_tests/spend_path_recovery_context_rejects_wrong_statement_digest`
- `shielded_v2_proof_tests/spend_path_recovery_context_rejects_missing_proof_payload`
- `shielded_v2_proof_tests/spend_path_recovery_context_rejects_malformed_witness_encoding`
- `shielded_v2_proof_tests/spend_path_recovery_smile_proof_verifies_against_recovery_context`
- `shielded_v2_bundle_tests/postfork_generic_spend_path_recovery_bundle_roundtrip_uses_opaque_payload_encoding`
- `shielded_v2_bundle_tests/spend_path_recovery_bundle_roundtrip_accepts_proof_payload_scaffold`
- `shielded_v2_bundle_tests/spend_path_recovery_bundle_uses_fee_as_state_value_balance`
- `shielded_validation_checks_tests/proof_check_rejects_prefork_spend_path_recovery_family_as_disabled`
- `shielded_validation_checks_tests/proof_check_rejects_postfork_spend_path_recovery_family_as_disabled`
- `shielded_validation_checks_tests/proof_check_rejects_postfork_spend_path_recovery_proof_surface_as_disabled`
- `shielded_validation_checks_tests/proof_check_accepts_prefork_spend_path_recovery_when_activated`
- `shielded_validation_checks_tests/proof_check_accepts_postfork_spend_path_recovery_when_activated`
- `shielded_validation_checks_tests/proof_check_prefork_spend_path_recovery_enforces_activation_boundary`
- `shielded_validation_checks_tests/proof_check_postfork_spend_path_recovery_enforces_activation_boundary`
- `shielded_validation_checks_tests/prefork_activated_spend_path_recovery_smile_proof_verifies_at_proof_layer`
- `shielded_validation_checks_tests/proof_check_rejects_prefork_activated_spend_path_recovery_with_tampered_nullifier`
- `shielded_validation_checks_tests/proof_check_rejects_postfork_activated_spend_path_recovery_with_tampered_nullifier`
- `shielded_validation_checks_tests/proof_check_rejects_postfork_legacy_v2_send_wire_family`
- `shielded_mempool_tests/shielded_v2_spend_path_recovery_nullifier_conflict_detected`
- `shielded_mempool_tests/shielded_v2_spend_path_recovery_duplicate_within_tx_detected`
- `validation_tests/regtest_shielded_spend_path_recovery_activation_height_override`
- `validation_tests/regtest_shielded_spend_path_recovery_activation_height_rejects_negative`
- `shielded_wallet_chunk_discovery_tests/owned_legacy_note_is_counted_as_spendable_but_cannot_build_ordinary_v2_send`
- `shielded_wallet_chunk_discovery_tests/scanned_spend_path_recovery_output_rehydrates_to_ordinary_spend_shape`

## State-aware injector and activation compatibility scaffold

This slice added the first deterministic end-to-end recovery fixture pipeline
that derives its ring members from real legacy notes instead of synthetic
in-memory witness state.

The new injector lives in:

- `src/test/shielded_spend_path_recovery_fixture_builder.h`
- `src/test/shielded_spend_path_recovery_fixture_builder.cpp`
- `src/test/shielded_spend_path_recovery_fixture_builder_tests.cpp`
- `src/test/generate_shielded_spend_path_recovery_fixture.cpp`

What it does:

- consumes a fixed set of transparent funding outpoints
- emits a deterministic sequence of chain-valid legacy shield-only funding
  transactions whose anchors track the evolving commitment tree
- emits a deterministic prefork MatRiCT recovery transaction over the resulting
  ring members
- rejects post-disable heights explicitly, because this state-aware injector is
  currently scoped to the prefork MatRiCT surface

This was then wired into a functional regtest scaffold in:

- `test/functional/test_framework/bridge_utils.py`
- `test/functional/feature_spend_path_recovery_activation_compat.py`

The functional scaffold now proves the following with the current binary:

- a node with `-regtestshieldedspendpathrecoveryactivationheight=1` accepts the
  deterministic recovery transaction in mempool

## Real-batch trusted-state validation

After the synthetic and functional coverage was in place, the patch was also
checked against a copied affected-wallet batch and a copied trusted
shielded-state snapshot.

That validation was intentionally kept outside the PR codepath, but its result
matters for confidence:

- a real affected batch could be exported
- a real recovery transaction could be regenerated from that export
- the generated transaction was accepted by the patched proof path against a
  trusted shielded-state snapshot
- when the original generated transaction became stale by anchor drift alone,
  the same exported private inputs could be regenerated under the current
  trusted anchor and accepted again

This narrowed the remaining practical concern from "is the recovery path valid"
to "how are oversized recovery transactions included operationally."

The sanitized summary of that evidence is recorded in:

- `doc/design/post-fork-spend-path-recovery/11-real-batch-evidence.md`
- a peer with the feature left at its default disabled state rejects the same
  transaction with `spend-path-recovery-disabled`
- once the upgraded node mines that recovery transaction, the feature-off peer
  falls behind on the recovery block

During this work the functional scaffold exposed a real missing consensus
integration in `src/validation.cpp`: the generic ring-position precheck did not
recognize `V2_SPEND_PATH_RECOVERY` and rejected it with
`precheck-ring-positions-unsupported-family`. That gate is now wired through
`shielded::v2::proof::ParseSpendPathRecoveryWitness(...)`, which moved the
recovery transaction past the generic contextual reject and into normal mempool
policy/activation behavior.

Focused regressions run in this slice:

- `shielded_spend_path_recovery_fixture_builder_tests/state_aware_fixture_builds_prefork_recovery_tx_that_validates_with_tree_snapshot`
- `shielded_spend_path_recovery_fixture_builder_tests/state_aware_fixture_rejects_incorrect_ring_input_count`
- `shielded_spend_path_recovery_fixture_builder_tests/state_aware_fixture_rejects_post_disable_validation_height`
- `shielded_validation_checks_tests/*spend_path_recovery*`
- `test/functional/feature_spend_path_recovery_activation_compat.py`

## Divergence and block-reconnect hardening

The functional coverage now includes both:

- same-binary activation-split coverage, and
- strict patched-binary vs baseline-binary coverage when local baseline binary
  paths are provided through `BTX_BASELINE_BITCOIND` and
  `BTX_BASELINE_BITCOINCLI`.

The strict local run matters because the observed baseline behavior is even
stronger than the feature-off same-binary case: the unpatched upstream daemon
does not merely reject the recovery transaction at policy or activation time,
it fails to decode the recovery family on the wire. The compatibility test now
accepts either:

- explicit `spend-path-recovery-disabled` rejection, or
- `TX decode failed` from the baseline binary,

depending on which incompatibility surface the older node exposes.

This slice also adds recovery block disconnect/reconnect coverage in:

- `test/functional/feature_spend_path_recovery_reorg.py`

That test now proves:

- a mined recovery block connects successfully,
- invalidating that block returns the recovery transaction to mempool, and
- reconsidering the same block reconnects it and removes the transaction from
  mempool again.

Focused regressions run in this slice:

- `test/functional/feature_spend_path_recovery_activation_compat.py`
- strict local `feature_spend_path_recovery_activation_compat.py` with
  `BTX_BASELINE_BITCOIND` and `BTX_BASELINE_BITCOINCLI`
- `test/functional/feature_spend_path_recovery_reorg.py`

## PR readiness

At this point the upstream branch has:

- disabled-by-default consensus plumbing,
- deterministic lost-spend-path reproduction,
- deterministic prefork recovery fixture generation,
- activated prefork and postfork validator coverage,
- wallet-shape coverage for migrated outputs,
- mempool conflict coverage,
- same-binary activation split coverage,
- strict local patched-vs-baseline binary divergence coverage, and
- recovery block disconnect/reconnect coverage.

That is enough to move this patch into reviewer-facing PR shape.

The remaining work is now primarily review, naming, and rollout discipline
rather than missing core consensus scaffolding.

## Safety note

This milestone is intentionally narrow.

It still preserves disabled-by-default network behavior, while adding a small
activation-gated acceptance slice and the regression surface needed to build on
it safely.
