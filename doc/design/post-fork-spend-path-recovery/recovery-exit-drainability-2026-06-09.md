# Recovery Exit Drainability Notes

Date: 2026-06-09

## Problem

Post-sunset transparent recovery exits need to drain historical shielded notes
whose ordinary wallet witnesses may be missing after older wallet/key-history
transitions. The funds are still represented by wallet notes and chain
commitments, but the wallet could fail locally with a missing Merkle witness
before it could build the `V2_RECOVERY_EXIT` claim.

Live mainnet testing also showed that a naive one-note witness reconstruction
path was too slow for large wallet drains because it replayed the indexed tree
for each note. Candidate selection then spent most of each send deriving SMILE
nullifiers for every remaining note just to check local pending state.

## Fix Summary

- Recovery-exit candidate selection includes locally owned confirmed notes,
  including non-user historical note classes, without exposing them through
  ordinary public balance/listing paths.
- Post-sunset transparent-only `z_sendmany` uses `V2_RECOVERY_EXIT` only for
  exact one-note exits and fails cleanly instead of falling back to ordinary
  disabled shielded sends.
- Missing membership witnesses can be reconstructed from the retained
  commitment index and verified against the current shielded root.
- Bulk current-root witness reconstruction amortizes indexed tree reads across
  all requested note positions.
- Reconstructed recovery-exit witnesses are cached in memory, not persisted in
  the encrypted wallet state, so repeated sends do not bloat wallet writes.
- Recovery-exit candidate scans use the already-reserved wallet note nullifier
  as the local pending-spend guard. The recovery nullifier is still derived and
  checked during transaction construction and consensus/mempool validation.

## Live Verification

On the production datadir, patched v0.32.3 successfully built and relayed
multiple `shielded_v2` recovery exits from the `mining-reward` wallet into the
25 encrypted transparent receive wallets. The first exact-note exit proved that
missing witnesses were the immediate blocker. After hot-path fixes, the drain
runner repeatedly produced valid recovery exits at roughly 22-25 seconds per
note with zero observed send failures.

The unshield velocity-cap diagnostic showed the remaining wallet balance was
well below the active rolling-window capacity, so this wallet drain does not
require a consensus or hard-fork parameter change.

## Tests

Focused verification:

- `test_btx --run_test=shielded_merkle_tests/witness_at_reconstructs_historical_leaf`
- `test_btx --run_test=recovery_exit_tests/membership_accepts_valid_witness_rejects_wrong_inputs`
- `test/functional/wallet_shielded_c002_sunset_lifecycle.py --descriptors --timeout-factor=4`
