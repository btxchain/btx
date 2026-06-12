BTX version 0.32.7 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.32.7>

This v0.32.7 point release fixes shielded-state startup and mining-template
liveness issues found after the 0.32.6 recovery-exit hardening release. It is
intended for nodes, miners, pools, exchanges, services, and explorers running
the 0.32.x block-125,000 shielded sunset series, especially pruned fast-start
mining nodes, large live datadirs, and operators with active recovery-exit
mempools.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.32.7 release artifacts.

BTX 0.32.7 does not introduce a new protocol activation height. It keeps the
block-125,000 shielded sunset posture and the block-128,000 cleanup boundary for
proofless transparent-funded `V2_SEND` public-flow shielding. Upgrade from
earlier 0.32.x builds for the shielded startup ordering, fast-start restart,
snapshot restore diagnostics, and recovery-exit mining-template liveness fixes.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+.

# Notable changes

- Block-template assembly now uses the shielded nullifier and recovery-exit
  commitment reservations already maintained by the mempool, plus a per-template
  cache, instead of deriving recovery-exit identifiers inside
  `getblocktemplate`. This prevents live mempools with repeated recovery-exit
  transactions from keeping template creation hot in expensive identifier
  derivation.

- Mining templates now track both shielded nullifiers and recovery-exit
  commitments already selected into the in-progress block. Stale, duplicate, or
  same-block-conflicting shielded exits are filtered before a candidate block is
  built. Recovery-exit transactions missing their expected mempool reservations
  are left out of templates instead of falling back to expensive derivation.

- Startup initializes and audits shielded state before the initial blockstore
  prune pass. Pruned nodes therefore do not delete historical blocks that may
  still be needed for shielded recovery-exit repair, audit, or snapshot
  convergence during startup.

- Fast shielded startup now skips the expensive recovery-exit cross-chain audit
  when the persisted nullifier accumulator verifies and the full shielded state
  pin verifies at the active tip. The same verified evidence lets startup
  preserve persisted settlement-anchor and netting-manifest metadata, avoiding
  multi-minute shielded replays on clean restarts of large live datadirs.

- Shielded snapshot-section loading now returns explicit failure messages. Older
  shielded snapshots that lack account-registry or recovery-exit commitment
  sections fail safely when the node no longer has the historical blocks needed
  to rebuild those sections locally.

- The mining-node snapshot runbook now calls out the post-recovery-exit
  snapshot requirement: pruned fast-start nodes should use a current BTX
  shielded snapshot appendix, currently version 8 or newer, or use a non-pruned
  datadir / full redownload when only older snapshot data is available.

- Mainnet fast-start metadata has been refreshed to snapshot height 128,605
  (`d95c8b565fefcda79efe47acad98648b0a24899f22facba9eedeb02c8bffd4d2`).
  The published v8 snapshot has txoutset hash
  `2cfa629907fbc18f3edc1dbb8b33fda651ad3655fb88a9dffe7a67ead580a102`,
  SHA256
  `28b49fc6b10fc1db69c39bfe78e1cccbb175c8e44055c3c95d6c814762f71335`,
  and a compiled shielded-state pin
  `827f8bf52ddf6de1e780a0917179dac715abeb428580744505dc30fbd6be5f9d`.
  Clean fast-start nodes can load this snapshot in the default fail-closed
  mode without `-allowunpinnedshieldedsnapshot`.

- The operational lesson from this release is that recovery-exit safety checks
  also need explicit liveness controls: reuse admission-time mempool
  reservations, cache per-template state, track the in-progress block state, and
  trust-skip startup audits only when persisted shielded-state evidence verifies
  at the active tip.

- Release automation, fast-start, bootstrap, and mining examples now point at
  the 0.32.7 artifacts.

# Credits

Thanks to everyone who contributed code, testing, operational validation, and
release engineering to this release.
