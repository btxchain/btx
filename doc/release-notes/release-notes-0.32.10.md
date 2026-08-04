BTX version 0.32.10 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.32.10>

This v0.32.10 point release rolls in the latest btx-node production hardening
for fork choice, MatMul mining context binding, block-template performance,
mining guard behavior, and operator telemetry. It is intended for nodes, miners,
pools, exchanges, services, explorers, and wallet operators running the 0.32.x
block-125,000 shielded sunset series.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.32.10 release artifacts.

BTX 0.32.10 keeps the block-125,000 shielded sunset posture and existing
recovery-exit consensus rules. It preserves the 0.32.9 empty-block subsidy rule
at height 130,000 and adds a MatMul seed derivation upgrade at height 130,500.
Nodes, miners, pools, and services should upgrade before height 130,500.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+.

# Notable changes

- Fork-choice hysteresis is enabled by default. A late branch that would rewrite
  one or more active-chain blocks must exceed the current active chain by an
  additional work margin before automatic activation. This reduces the advantage
  of tiny-work late private branch releases while still allowing a clearly
  stronger most-work chain to converge.

- Deep-reorg parking is now explicit local policy instead of default behavior.
  Operators that want automatic parking can set `-parkdeepreorg=1`; the default
  node follows most-work once the hysteresis work margin is satisfied. This
  avoids unattended stalls from turning a warning condition into a permanent
  local partition.

- Equal-work chain ties are randomized per node. Ties use local secret material
  and the candidate block hash instead of first-seen ordering, so a withheld
  depth-1 block does not receive a systematic first-seen advantage. This only
  applies when cumulative work is equal and never overrides strictly more work.

- MatMul seed derivation gains a v3 mode at height 130,500. The seed binds the
  parent hash, parent median-time-past, and mutable header fields. Miners must
  derive matrices from the actual parent context, which makes work tied to the
  parent it is intended to extend.

- The 0.32.9 empty-block subsidy rule is preserved. After height 130,000, the
  first coinbase-only block after a non-empty parent may claim at most 50% of
  scheduled subsidy, and the second and later consecutive coinbase-only blocks
  may claim at most 25%. There is no zero-subsidy cliff.

- Block template construction remains bounded for unattended mining. The default
  template transaction cap is 25, recovery-exit template policy work is capped,
  and candidate-package evaluation is bounded so CPU-heavy mempool contents do
  not make `getblocktemplate` unusable.

- Empty mempool-validation fallback templates are not cached. If a set of
  mempool transactions unexpectedly fails full block validation, the node can
  return a one-shot empty fallback as a safety valve, but it retries normal
  non-empty template construction on later requests.

- The mining chain guard remains enabled on mainnet. Peer-derived fork or lag
  signals are advisory; template creation pauses only when the local node has no
  initialized tip or local networking is disabled. Peer disagreement,
  partitions, header spam, or stale peers should not stop unattended miners.

- Mining RPCs expose chain-guard status, fork-health telemetry, template policy
  capacity, skipped template-policy candidates, and whether a template used the
  mempool-validation fallback path. These fields give pools and services
  machine-readable health signals without requiring manual intervention for
  normal mining to continue.

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
