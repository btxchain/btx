# Candidate acceptance and evidence contract

Run only against disposable test funds until native/security qualification is complete. Every report identifies source/base SHA, touched-file hashes, exact commands and raw logs. PASS means the command was run successfully on this candidate; NOT_RUN is not PASS. Prior-source receipts remain historical evidence, not candidate receipts.

Required gate groups:

1. Actual patch applicability and reverse check on the exact pristine source. Verify complete changed-file bytes and absence of missing generated source.
2. Real maintained SwapNet pytest suite plus public capacity, handoff, persistence, schema, auth, mode, invitation and application-wire tests. Test fixtures must disclose simulated cryptography/chain behavior.
3. Standalone shared-core and real two-process broker tests, including wrong token, forbidden service/wallet operations, strict-PQ assertions, rate limits, cache corruption and restart.
4. Full candidate `btxd`, `btx-modeld`, native wallet targets and Atlas Rust/Tauri build, not just JS syntax or independent headers.
5. Native default discovery and >32-item offer pagination, old-peer compatibility, duplicate and equivocation attacks, route blackholes, helper restarts, mode switching, wallet unload and restricted principals.
6. Funded two-node BTX/BTC and BTX/ETH swaps both directions, finality, pull withdrawals, refunds, dropped responses, SIGKILL, restart, fee replacement, reorg before/after preimage, and mixed-version/schema refusal. Record txids and exact balance/fee reconciliation.
7. Atlas end-to-end native approval, cancellation, expired preview, wallet switch, secret clearing, inaccessible verifier, maker setup, signed public-offer browsing and invitation opening/inspection/connection.
8. Published archive tests: matched Python runtime, cryptography, recovery tools, platform libraries, permission/ACL handling, relocatable paths, checksums and signatures. Build artifacts from earlier commits are not current evidence.

The deliverable builder must emit blockers if any required gate is FAIL/NOT_RUN. It may still package a source candidate, but must not label that candidate complete, production-ready or independently audited. No code bypass may be introduced to make a test pass.
