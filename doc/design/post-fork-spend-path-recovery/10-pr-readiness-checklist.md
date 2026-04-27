# PR Readiness Checklist

Date: 2026-04-25

## Scope of this checklist

This checklist is for opening the upstream spend-path recovery patch as a
reviewable pull request.

It is not an activation checklist for mainnet rollout.

## Patch shape

- Feature is disabled by default on all networks.
- Recovery admission is controlled only by
  `nShieldedSpendPathRecoveryActivationHeight`.
- Regtest can opt in explicitly with
  `-regtestshieldedspendpathrecoveryactivationheight=<n>`.
- Ordinary `V2_SEND` and `V2_INGRESS_BATCH` rules are unchanged.

## Required reviewer checks

- Confirm the new family only activates when the dedicated consensus gate is
  enabled.
- Confirm unknown or disabled-family behavior remains explicit and stable.
- Confirm migrated outputs scan back in as ordinary direct-send-shaped notes.
- Confirm recovery spends participate in nullifier conflict checks and
  duplicate-nullifier checks.
- Confirm shielded state-value accounting uses the recovery fee path
  intentionally.
- Confirm regtest activation plumbing is isolated from non-regtest defaults.

## Required regression coverage

- Synthetic reproduction of the lost spend path:
  `owned_legacy_note_is_counted_as_spendable_but_cannot_build_ordinary_v2_send`
- Recovery-output wallet-shape regression:
  `scanned_spend_path_recovery_output_rehydrates_to_ordinary_spend_shape`
- Proof and validation coverage for activated prefork and postfork recovery
  fixtures
- Mempool conflict coverage for recovery nullifiers
- Deterministic fixture-builder coverage
- Functional activation split coverage
- Functional recovery-block disconnect/reconnect coverage

## Strict local compatibility pass

For local hardening, the activation compatibility test also supports a true
patched-binary vs baseline-binary run through:

- `BTX_BASELINE_BITCOIND`
- `BTX_BASELINE_BITCOINCLI`

Expected old-node behavior is one of:

- explicit mempool rejection with `spend-path-recovery-disabled`, or
- transaction decode failure because the baseline binary does not recognize the
  recovery family on the wire

Either result is acceptable for the local divergence pass, because both prove
that unpatched nodes do not follow the activated recovery branch.

## Manual pre-PR run list

Run these before opening the PR:

- focused `test_btx` spend-path-recovery suite
- `feature_spend_path_recovery_activation_compat.py`
- `feature_spend_path_recovery_reorg.py`
- strict local compatibility pass with baseline binaries, if available
- real-batch trusted-state replay, if local copied-wallet evidence is available

## Real-batch evidence position

The PR does not depend on local copied-wallet evidence for correctness, but the
current packaging includes a separate sanitized memo summarizing that stronger
local validation:

- [11-real-batch-evidence.md](11-real-batch-evidence.md)

That memo documents that a real affected batch was regenerated under current
trusted state and accepted by the patched proof and validation path.

## Explicit non-goals for this PR

- default-on activation on any public network
- automatic wallet-side recovery without explicit activation
- bridge or settlement-surface extensions beyond the recovery family itself
- unrelated wallet migration or historical data backfill schemes
