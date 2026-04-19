# Shielded Invalid Block Drift Hardening And Auto-Recovery

Date: 2026-04-15

## Summary

This note documents the shielded-state hardening and automatic recovery work
landed on `fix/shielded-state-drift-hardening` to address a production issue
where a node could locally mark a valid shielded block invalid until `btxd` was
restarted and the block was manually reconsidered.

The observed incidents were not limited to one machine. The same false-invalid
class was seen on multiple nodes for the same block, which strongly suggested a
deterministic or semi-deterministic local shielded-state drift problem rather
than a one-off timing accident.

This fix is intended to remove the manual operator workflow for the covered
cases:

- no isolated manual restart procedure
- no manual `reconsiderblock`
- no permanent invalid-cache poisoning for a block that becomes valid again
  once local shielded state is repaired

This is local state hardening and repair. It is not a consensus-rule change.

## Problem Class

The production symptom was:

- a valid shielded transaction or block was rejected locally as
  `bad-shielded-anchor` or a recoverable shielded proof failure
- the block could become marked invalid in the block index
- restarting the node and rebuilding shielded state made the same block validate
  successfully

Two concrete live variants were observed:

1. A false-invalid block caused by local shielded proof-state drift.
2. A false-invalid block caused by stale recent shielded anchor history even
   though the node's current tree root was otherwise consistent.

The second case was especially important because it showed that a node could
restore persisted shielded state with a correct current tree root and still have
an out-of-date recent-anchor window.

## Root Causes Addressed

### 1. Persisted recent anchor history could be stale

On startup, the persisted shielded state could restore a valid tree/root view
while the deque of recent shielded anchor roots was stale. That made a valid
transaction or block appear locally invalid with `bad-shielded-anchor`.

The fix now rebuilds recent shielded anchor history from the active chain during
persisted restore and persists the repaired history when needed.

### 2. Scratch rebuilds and validation snapshots needed stronger isolation

Shielded rebuild and validation logic depends on commitment lookups by position.
Scratch trees and copied validation snapshots needed to be isolated from the
configured shared commitment-index store so temporary rebuild or proof-check
state could not mutate or implicitly reattach to the live retained index.

The fix adds explicit memory-only detachment for scratch trees and uses that for
rebuild/history reconstruction paths.

### 3. Live shielded state needed publish-after-success ordering

The live shielded tree, anchor history, registry-derived maps, and nullifier
state should not be published until the replacement state has been assembled
successfully.

The fix reorders the rebuild/repair flow so the replacement state is built first
and only then swapped into the active chainstate view.

### 4. Recoverable local-state failures needed to be distinguishable

Some failures that surfaced as generic `bad-shielded-proof` were actually local
snapshot/index issues such as:

- missing ring-member commitment position
- missing SMILE public-account snapshot entry
- missing account-leaf snapshot entry
- shared-ring reconstruction mismatch

The fix adds more specific reject reasons so the node can trigger targeted local
repair for recoverable shielded-state drift without weakening rejection of
genuinely invalid proofs.

## What Changed

### 1. Startup restore now repairs shielded state before admitting it

`EnsureShieldedStateInitialized()` now does the following:

- restores persisted shielded state when possible
- rebuilds recent shielded anchor history from the active chain even when the
  retained commitment index is otherwise intact
- audits the restored state against chain-derived expectations
- falls back to a full shielded-state rebuild from the active chain when the
  retained commitment index, recent anchor history, registry history, or other
  shielded metadata do not converge

This directly fixes the stale-anchor restore case.

### 2. One-shot in-process auto-repair for `bad-shielded-anchor`

When mempool or block validation sees `bad-shielded-anchor`, the node now:

1. repairs recent shielded anchor history from the active chain
2. retries validation once
3. only returns the anchor failure if the anchor is still invalid afterward

This keeps a stale recent-anchor window from causing a valid block to become
durably failed without first attempting an in-process repair.

### 3. One-shot in-process rebuild for recoverable proof-state drift

When mempool or block validation hits a recoverable shielded proof rejection,
the node now:

1. rebuilds shielded state from the active chain
2. retries validation once under the rebuilt state
3. only returns the consensus-invalid result if validation still fails

The recoverable set includes:

- `bad-shielded-proof`
- `bad-shielded-ring-member-position`
- `bad-shielded-ring-tree-unavailable`
- `bad-smile2-ring-member-account`
- `bad-smile2-ring-member-public-account`
- `bad-smile2-ring-member-account-leaf`
- `bad-smile2-shared-ring`

### 4. Retry gating is per shielded-state generation

Automatic repair is bounded to once per shielded-state generation, keyed from
the current shielded state rather than only the active tip.

That means:

- the node does not loop forever retrying the same repair against unchanged
  shielded state
- log noise and redundant rebuild work are reduced during catch-up
- a new chain tip that does not change shielded state does not reset the retry
  budget

### 5. Automatic startup reconsider for false-invalid shielded blocks

If startup repair was required, the node now scans failed blocks with available
data whose parent is on the active chain, filters for blocks that actually carry
shielded data, clears their failure flags, and lets normal
`ActivateBestChain()` retry them.

This closes the final operational gap: after a repaired restart, the node no
longer needs a manual `reconsiderblock` for the covered false-invalid shielded
cases.

## Operational Behavior

The intended operational result is:

- a covered local shielded-state drift issue should either be prevented or
  repaired automatically
- a node restart should repair stale persisted shielded state and automatically
  reconsider previously false-invalid shielded blocks
- genuinely invalid proofs should still remain invalid after the bounded retry

Some log lines during catch-up are still expected. For example, a node may log a
one-shot anchor-history repair attempt for a relayed transaction whose anchor is
not yet available on the node's current active shielded history. If the anchor
is still absent after repair, the transaction is rejected at that moment and may
be accepted later once the node advances its chain view. That is expected and is
not the same as the earlier false-invalid block issue.

## Why The Runtime Overhead Is Bounded

The implementation intentionally avoids adding continuous heavy audits to the
normal steady-state path.

The main overhead characteristics are:

- recent-anchor history rebuild on persisted restore
- one-shot anchor-history repair when `bad-shielded-anchor` is encountered
- one-shot full shielded-state rebuild only for recoverable local-state proof
  rejects
- bounded retry gating per shielded-state generation

This keeps the common path light while still giving the node a practical way to
repair itself automatically when the covered drift class appears.

## Tests Added And Validation Performed

The fix adds targeted coverage for both prevention and automatic repair.

Covered behaviors include:

- scratch-tree detachment and isolation from the live commitment index
- persisted anchor-history repair on startup
- in-memory anchor-history repair for mempool accept
- in-memory anchor-history repair for block connect
- bounded once-per-generation auto-repair gating
- startup repair plus automatic reconsider of a previously failed shielded block
- successful block recovery does not leave failed-block status behind
- concurrent inbound shielded mempool requests serialize behind the repair path
  and do not trigger a second rebuild
- a genuinely invalid shielded proof still fails after the single automatic
  rebuild retry and does not loop

Validation run for this branch:

```bash
./build-btx/bin/test_btx --run_test=validation_chainstatemanager_tests --catch_system_errors=no
./build-btx/bin/test_btx --run_test=shielded_merkle_tests,shielded_v2_proof_tests,shielded_validation_checks_tests,nullifier_set_tests,shielded_audit_regression_tests --catch_system_errors=no
./build-btx/bin/test_btx --run_test=txvalidation_tests --catch_system_errors=no
```

`txvalidation_tests` required a separate fixture update so the full suite is now
green under the current shielded activation rules.

## Landed Commits

The main branch-local commits for this work are:

- `da100d38` `shielded: auto-repair drifted state and reconsider false invalids`
- `10dad9b8` `shielded: add bounded recovery coverage`
- `3e4bf7c7` `test: fix txvalidation shielded fixtures`

## Operator Expectation After Deploy

For the covered issue class, the expected recovery path is now:

1. the node detects stale or drifted local shielded state
2. the node repairs anchor history or rebuilds shielded state automatically
3. on restart, the node clears stale shielded failure flags when startup repair
   was required
4. normal chain activation revalidates and reconnects the previously
   false-invalid shielded block

If a node still requires a manual isolated restart or manual `reconsiderblock`
for a shielded false-invalid incident after this patchset, that should be
treated as a new bug and investigated as an uncovered drift class.
