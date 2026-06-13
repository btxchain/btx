BTX version 0.32.8 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.32.8>

This v0.32.8 point release rolls in the post-0.32.7 btx-node production fixes
for recovery-exit fee replacement, recovery-exit mempool liveness, mining
health, local reorg protection, and CUDA solver performance. It is intended for
nodes, miners, pools, exchanges, services, explorers, and wallet operators
running the 0.32.x block-125,000 shielded sunset series.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.32.8 release artifacts.

BTX 0.32.8 does not introduce a new protocol activation height. It keeps the
block-125,000 shielded sunset posture and the existing recovery-exit consensus
rules, while hardening local mempool, mining, wallet, and reorg policy around
those rules.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+.

# Notable changes

- Wallet shielded recovery exits now have a direct fee-replacement path.
  `z_sendmany` accepts `conflict_txid` for an in-mempool `v2_recovery_exit`
  transaction, resolves the same wallet note, and rebuilds the exit with a
  higher fee. This gives wallet operators an explicit unstick path for
  recovery-exit transactions without creating a second claim against the note.

- Recovery-exit replacement remains fee-market governed. Mempool policy allows
  same-note recovery-exit replacement under opt-in replacement policy, but the
  normal replacement checks still require higher feerate, higher total fees, and
  enough incremental relay fee.

- Shielded relay policy now accounts for recovery-exit verification cost.
  Recovery-exit bundles are charged policy verify units even though their
  consensus proof envelope is intentionally proofless, and shielded transactions
  continue to require the fixed shielded relay premium.

- Recovery-exit mempool cleanup is targeted after block connection. Nodes evict
  mempool entries that touch nullifiers or recovery-exit commitments retired by
  the connected block, while keeping full scans available as a safety fallback.
  This avoids repeated expensive full-mempool revalidation during recovery-exit
  waves.

- Block-template construction excludes stale or conflicting shielded exits using
  mempool-maintained nullifier and recovery-exit commitment reservations. This
  prevents known-invalid recovery-exit transactions from poisoning local mining
  templates.

- Local mining health guards have stronger defaults and richer RPC reporting.
  Mining RPC output now exposes peer agreement, near-tip quorum, stale-peer
  filtering, and guard recommendations so pools can pause local mining when a
  node is not safely aligned with the network tip.

- Local deep-reorg protection is now profile based and durable. The default
  emergency profile warns at shallow reorg depths, parks branches at the
  configured local finality boundary, persists parked branch roots across
  restart, skips parked branches during candidate selection, and requires
  explicit `reconsiderblock` action to unpark a branch.

- Reorg and mining-health state is exposed through RPC, including the active
  protection profile, warn depth, park depth, local-finality depth, finalized
  height, parked branch count, and recent rejected reorg telemetry.

- CUDA matmul solving has the btx-node nonce-seed pipeline optimizations,
  reducing repeated CPU setup work and improving solver throughput on CUDA
  deployments without changing consensus validation.

- The 0.32.7 shielded startup, fast-start, pruned snapshot, and v8 shielded
  snapshot diagnostics remain in place. Pruned nodes should continue to use a
  current v8 or newer BTX shielded snapshot, a non-pruned datadir, or a full
  redownload when older snapshot sections cannot rebuild recovery-exit
  commitments locally.

# Recovery-exit fee replacement

For a stuck wallet-created transparent recovery exit, create a replacement by
spending the same note with a higher fee:

```bash
btx-cli -rpcwallet=<wallet> z_sendmany \
  '[{"address":"<transparent-address>","amount":"<new-output-amount>"}]' \
  '<higher-fee>' '[]' null null '<stuck-txid>'
```

Because the same note value must fund both the transparent output and the new
fee, the replacement output amount normally decreases by the fee increase.

# Credits

Thanks to everyone who contributed code, testing, operational validation, and
release engineering to this release.
