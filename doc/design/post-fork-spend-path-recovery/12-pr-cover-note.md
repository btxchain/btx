# PR Cover Note

## Title

Add activation-gated post-fork spend-path recovery for stranded shielded notes

## Summary

This PR introduces a narrow, activation-gated recovery path for shielded notes
that remain owned and balance-visible after a shielded-model transition but no
longer have an accepted ordinary spend path.

The patch adds a dedicated `v2_spend_path_recovery` transaction family that:

- remains disabled by default on all networks
- activates only when the dedicated consensus height is set
- consumes eligible stranded notes
- recreates ordinary modern spendable outputs
- scans those outputs back into the wallet as ordinary direct-send-shaped notes

The PR does not weaken ordinary `V2_SEND` or `V2_INGRESS_BATCH` rules and does
not attempt any global historical backfill scheme.

## Problem

Some wallets can still:

- decrypt affected shielded notes
- account for them in balance
- prove ownership of them

but cannot spend them through the ordinary modern shielded path because the
required registry or witness context no longer exists for those note classes.

That leaves custody intact while spendability is lost.

## What This PR Changes

- reserves and implements the `v2_spend_path_recovery` family
- adds activation-gated validation and proof plumbing
- adds replay and nullifier conflict handling for recovery spends
- adds wallet-side recovery-output scanning so migrated outputs come back as
  ordinary spendable notes
- adds deterministic fixture generation and functional activation tests

## What This PR Does Not Change

- no default-on activation on any public network
- no relaxation of ordinary modern spend rules
- no unrelated relay-policy widening
- no automatic wallet migration without explicit activation

## Evidence Included

This patch is supported by:

- synthetic unit and integration coverage
- mixed-version activation-split functional coverage
- recovery-block disconnect and reconnect coverage
- a real-batch trusted-state replay against copied affected-wallet data

The real-batch replay showed that a real affected batch can be regenerated
under current trusted state and accepted by the patched proof and validation
path when anchored to current state.

## Operational Note

Real recovery transactions can be very large.

Local testing showed that ordinary mempool admission can still reject them for
`tx-size`, even when proof validation succeeds. That means activation of this
consensus path should not assume generic network relay for oversized recovery
transactions. Direct miner or block-template inclusion may still be required.

## Review Guidance

Reviewers should focus on:

- activation boundaries and default-off behavior
- recovery-family proof and contextual validation
- nullifier and replay handling
- wallet-side output rehydration into ordinary spend shape
- mixed-version divergence behavior after activation

## Suggested Testing

- focused `test_btx` spend-path-recovery suite
- `feature_spend_path_recovery_activation_compat.py`
- `feature_spend_path_recovery_reorg.py`
- strict patched-vs-baseline compatibility run

## Rollout Position

This PR is suitable for review as a narrow recovery patch.

Activation, miner coordination, and any relay-policy discussion should remain
separate rollout decisions after code review.
