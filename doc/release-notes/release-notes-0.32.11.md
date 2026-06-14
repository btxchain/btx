BTX version 0.32.11 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.32.11>

This v0.32.11 point release rolls in the latest btx-node production hardening
for shielded-exit velocity accounting, assumeutxo snapshot compatibility, and
the block-130,000 empty-block subsidy transition. It is intended for nodes,
miners, pools, exchanges, services, explorers, and wallet operators running the
0.32.x block-125,000 shielded sunset series.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.32.11 release artifacts.

BTX 0.32.11 keeps the block-125,000 shielded sunset posture, existing
recovery-exit consensus rules, the 0.32.10 MatMul v3 binding rule at height
130,500, and the shielded-exit velocity cap. It adds forward consensus behavior
at height 132,000. Nodes, miners, pools, and services should upgrade before
height 132,000.

Nodes using assumeutxo snapshots should use the v0.32.11 v9 snapshot or newer.
Older shielded snapshots do not carry the unshield-velocity state needed by this
release. Non-pruned archive datadirs can rebuild that state locally; pruned
nodes should use a v9+ snapshot or reindex/redownload from a non-pruned source.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+.

# Notable changes

- Shielded unshield-velocity state is now part of the persisted shielded state
  and v9 assumeutxo snapshot section. This lets snapshot-started nodes evaluate
  the trailing shielded-exit capacity window from the same state as archive
  nodes.

- Startup verifies or repairs persisted shielded unshield-velocity state. If a
  full node has the historical blocks needed for the recent window, it can
  rebuild the missing or stale velocity log and continue. If a pruned node cannot
  rebuild missing state, startup fails closed with a clear instruction to use a
  v9+ snapshot, a non-pruned datadir, or a reindex/redownload.

- The release tooling rejects shielded assumeutxo release reports below snapshot
  version 9. This prevents publishing a snapshot that would later strand pruned
  nodes without the velocity state needed for shielded-exit validation.

- At height 132,000, the shielded-exit velocity window gains a 10,000 BTX
  minimum capacity floor. The percentage cap remains active, but large legacy
  shielded holders are no longer bottlenecked by a shrinking pool balance once
  the recovery process has already reduced the pool.

- At height 132,000, the temporary empty-block subsidy penalty ends and
  coinbase-only blocks may again claim the normal scheduled subsidy. The
  v0.32.10 MatMul v3 parent-context binding and fork-choice hardening remain in
  effect.

- `getshieldedstateinfo` and related RPC output include the velocity minimum cap
  and remaining capacity fields so operators can see when the floor is active.

- Regtest-only options were added for the velocity minimum-cap height/value and
  empty-block penalty end height. These are test harness controls and do not
  alter mainnet activation heights.

# Security note

No node-local policy can make 1-confirmation proof-of-work settlement final
against a miner who can privately outwork the public chain. Services should use
settlement-safe wallet fields, raise confirmation requirements for deposits and
settlement, and freeze affected account state immediately when wallet RPCs show
removed, conflicted, below-policy confirmations, or an active reorg settlement
hold.

# Credits

Thanks to everyone who contributed code, testing, operational validation, and
release engineering to this release.
