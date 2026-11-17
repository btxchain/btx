# Migration, compatibility and rollback

## Preserve the reviewed baseline

The source target is PR #714 at `0afc505f3e063ff8919366464881b81d9e037638`. Later commits may already fix related issues. Use exact file hashes and inspect overlaps. Do not replace `helper.cpp` with an older pre-search-gossip copy or restore compiled-in discovery hubs.

## SQLite changes

Additive tables store preview acknowledgements, maker quote-policy bindings and expiring provider sequence history. Existing grants, reservations, nonces, operation bytes, audit history, commit completion receipts and negotiation rows are not migrated destructively. Preserve WAL and consistent backups.

Preview confirmation recovers from a missing completion acknowledgement by the original quote-derived swap ID. It must not create another funding transaction or reuse a grant for different parameters. Terminal budgets retain the original conservative no-recycling rule.

## Behavior changes

New installations start as observers. Persisted owner-selected modes can resume. Legacy `-swapnet=1` remains an explicit operator choice; `-swapnet=0` is recovery-only, not a recovery-kill switch. Update help, scripts and native functional tests accordingly. A mode change alone cannot create a mandate.

BTC autodiscovery no longer treats a signing wallet as its own descriptor watch wallet. Use `setupswapbitcoin` with owner consent, or a pre-existing separately loaded watch wallet. Ambiguity is refused, not resolved by picking the first loaded wallet.

New EVM agreements require finalized creation-code provenance and bounded finality lag. Constructing/loading an existing EVM driver must not depend on those new-trade checks, so previously authorized recovery continues during proof/RPC unavailability.

## Rollback

Stop admitting new trades. Inventory active obligations and export consistent encrypted SwapNet recovery plus the native wallet backup. A source rollback does not cancel contracts or rewind either chain. Keep a tested recovery-capable binary and its matched interpreter dependencies available until every obligation is final.

The additive tables may be ignored by older source, but older binaries do not understand the new admission modes, preview guards or deployment preflight. Do not call such a rollback security-equivalent. Never merge financial journals or run cloned EVM signing accounts on two live nodes.
