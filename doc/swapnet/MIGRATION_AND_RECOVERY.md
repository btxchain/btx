# Journal migration, modes and rollback

The extension adds public-offer, finite-slot, request, refusal and preview records to the maintained SQLite journal and advances `PRAGMA user_version` to **3**. Version 2 data is migrated additively. Unsupported versions fail closed. A pre-extension binary that accepts only 0/2 must refuse version 3 rather than ignoring financial capacity commitments. Do not reset the version flag manually.

Before upgrade, stop the node cleanly, export encrypted SwapNet recovery and a separate native-wallet backup, and preserve the old application binaries. Backups and chain data are not replaced by the shared catalog. Source rollback cannot undo contracts or authorize a second payment.

A new journal starts as taker so the build dogfoods SwapNet. A saved maker or observe choice persists unless `-swapnetmode=recovery` is set. `-swapnet=0` does not start the engine. `setswapmode` cannot clear a startup recovery lock. An explicit `-swapnet=0` still makes the SwapNet RPCs report disabled.

Mode changes prevent new quotes/commitments but do not reinterpret immutable funded terms. Saved previously authorized sessions retain the maintained coordinator's claim/refund/rebroadcast behavior, fee caps and finality rules. New EVM deployment-attestation and readiness rules are applied only at entry to new obligations, not as an extra gate in recovery of existing ones.

Unfunded public slots expire or are withdrawn without releasing an already transferred monetary reservation. Database updates transition a bound public allocation to a normal reservation atomically. A crash after a response was sent is resolved by the original RFQ/quote/session identity. A preview-confirm retry uses the same saved mandate and quote; it cannot create a second trade.

Use `contrib/swapnet/tools/restore_recovery.py` only with the node stopped, the correct locally verified genesis and an empty destination. Keep the passphrase out of command history. Restore the corresponding native wallet. Do not merge journals, reuse a restored EVM account in two active nodes, delete a live WAL file or overwrite corrupted financial data automatically.

Shared public caches are reconstructible and not signing authority. A corrupt/unreadable shared cache fails closed instead of silently accepting altered records. A signed local receipt and a saved audit head aid reconciliation but cannot override independent blockchain truth.

Windows owner-private ACL support protects the existing portable vault layout. No DPAPI-only ciphertext migration is performed, so the encrypted export remains portable. Native Windows ACL, crash-durability and cross-account restore tests remain separate gates.
