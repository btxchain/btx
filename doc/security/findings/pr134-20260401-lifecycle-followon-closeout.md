# PR134 April 2026 Lifecycle Follow-On Closeout

This note reconciles the later PR #134 follow-on review that flagged a
proofless lifecycle value path, a post-fork `V2_SEND` policy bypass, and
operator-note wallet accounting drift.

## Summary

Those findings described an intermediate branch state. On the reviewed branch
head, they are closed on the live post-`61000` path.

The fix was not to tune the earlier lifecycle path. The design was moved onto a
distinct post-fork `V2_LIFECYCLE` transaction family with zero shielded-state
mutation and explicit binding to the full transparent transaction skeleton.

## Finding Reconciliation

### 1. Proofless / Unbound Lifecycle Value Path

Original concern:

- lifecycle controls rode `V2_SEND`
- validation admitted a no-proof bundle with transparent inputs
- shielded accounting consumed a claimed `value_balance` without a visible
  binding to the hidden lifecycle payload

Current branch state:

- post-fork lifecycle controls no longer use `V2_SEND`
- wallet construction emits `TransactionFamily::V2_LIFECYCLE`
- lifecycle bundles are zero-shielded-state bundles rather than hidden-value
  send bundles
- validation requires the lifecycle transparent-binding digest to match the
  full transaction skeleton before the transaction is accepted
- mempool and block-connect both route lifecycle transactions through the live
  proof-check gate instead of relying only on standalone validation helpers

Primary code surfaces:

- `src/shielded/v2_bundle.cpp`
- `src/shielded/validation.cpp`
- `src/validation.cpp`
- `src/wallet/shielded_wallet.cpp`

Primary regressions:

- `src/test/shielded_validation_checks_tests.cpp`
- `src/test/txvalidation_tests.cpp`

Outcome:

- the old unbound `V2_SEND` lifecycle value lane is closed

### 2. Post-Fork Direct Public-Flow `V2_SEND` Bypass

Original concern:

- lifecycle controls bypassed the post-fork direct-public-flow `V2_SEND` ban
- wallet construction could still rely on transparent inputs / change through
  the old lifecycle carveout

Current branch state:

- lifecycle controls in post-fork `V2_SEND` are explicitly rejected
- post-fork lifecycle controls use the dedicated `V2_LIFECYCLE` family instead
- multi-output transparent skeletons, including change, are accepted only when
  the transparent-binding digest matches
- output mutation after signing is rejected across proof-check, mempool, and
  block paths

Primary regressions:

- `tx_mempool_accepts_context_bound_lifecycle_at_activation`
- `tx_mempool_accepts_lifecycle_with_multiple_transparent_outputs`
- `tx_mempool_rejects_tampered_lifecycle_binding`
- `tx_mempool_rejects_tampered_lifecycle_output_value`
- `block_rejects_tampered_lifecycle_output_value`
- `proof_check_rejects_postfork_send_lifecycle_control`

Outcome:

- the direct-public-flow `V2_SEND` rule is not bypassed by lifecycle controls

### 3. Operator Notes Counted As Wallet Funds

Original concern:

- operator-class notes could appear in balance / unspent surfaces while still
  being excluded from ordinary spending

Current branch state:

- wallet spendability is restricted to `NoteClass::USER`
- operator-class notes are filtered out of spendable balance and unspent note
  surfaces
- lifecycle transactions are covered by wallet/RPC regressions showing that
  rotate/revoke actions do not change spendable shielded balance or note count

Primary code surfaces:

- `src/wallet/shielded_wallet.cpp`
- `src/wallet/shielded_rpc.cpp`

Primary regressions:

- `src/test/shielded_wallet_chunk_discovery_tests.cpp`
- `test/functional/wallet_shielded_postfork_privacy.py`

Outcome:

- operator-class notes are not treated as spendable wallet funds on the
  reviewed path

## Residual Caveats

- This closeout does not change the separate `L12` PQ-128 parameter-set
  redesign item.
- This closeout also does not certify performance parity by itself. Performance
  status remains tracked in `doc/security/current-status.md` and
  `doc/btx-postlaunch-optimization-roadmap.md`.
