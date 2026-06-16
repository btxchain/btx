BTX version 0.32.12 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.32.12>

This v0.32.12 point release improves shielded-exit throughput after the
recovery window, keeps block templates useful when recovery-exit transactions
are temporarily invalid under local policy, and tightens release auto-update
packaging.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.32.12 release artifacts.

BTX 0.32.12 ends the shielded unshield velocity quota at height 135,000. This
is a consensus-visible relaxation: miners and archive nodes should upgrade
before height 135,000 so blocks containing uncapped post-135,000 shielded exits
are accepted consistently.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+.

# Notable changes

- The shielded unshield velocity quota is active from height 125,000 through
  134,999. The v0.32.11 10,000 BTX minimum-cap floor remains active from
  132,000 while the quota is still in force, and at height 135,000 and later
  shielded exits are no longer rate-limited by the velocity quota. Historical
  quota state remains persisted through the configured reorg horizon so
  rollback validation of capped blocks remains deterministic.

- `getshieldedstateinfo` now reports `velocity_end_height` and
  `velocity_capacity_unlimited`, making it clear when the next block is outside
  the quota window.

- Block-template construction now retries without recovery-exit transactions
  when a mempool-selected recovery-exit set causes whole-block validation to
  fail. The retry keeps ordinary transparent and non-conflicting mempool
  transactions instead of immediately falling back to a coinbase-only template.
  It also pre-filters positive shielded-pool egress when the pending mempool
  egress would exceed the remaining velocity capacity, so transparent mempool
  transactions are not dropped just because over-cap shielded exits are present.

- Local mining chain guard no longer stops `getblocktemplate`, MatMul
  challenge, or local block-generation RPCs. It reports stale-tip and fork-risk
  states through mining RPCs and automatically requests extra outbound and
  block-relay peers, but unattended miners keep receiving work so honest nonce
  rate stays on the public network.

- Mining RPC `chain_guard` output now includes IBD/network state, worst peer
  tip, stale-peer filtering, and default peer-mesh refresh settings so pool
  operators can diagnose warnings without scraping raw peer logs.

- Mainnet peer discovery now ships all three public bootstrap DNS seeds
  (`node.btx.dev`, `node.btxchain.org`, and `node.btx.tools`). The live-mining
  supervisor also uses that DNS mesh for peer recovery by default, while still
  allowing controlled deployments to override or disable the built-in list.
  The new `getminingpeermesh`, `addminingpeermeshnode`,
  `removeminingpeermeshnode`, and `refreshminingpeermesh` RPCs expose runtime
  mesh inspection and control for mining automation. The supervisor temporarily
  disables stale or unreachable mesh members instead of retrying them forever,
  and daemon-only miners now periodically enroll the built-in mesh into the
  runtime addnode set when mining chain guard reports unhealthy peer consensus.
  Peers that deliver full blocks failing high-confidence shielded/recovery
  consensus checks are now discouraged and disconnected so repeated invalid
  recovery-exit or over-cap shielded branches are less likely to remain in the
  mining peer set.

- The default emergency reorg-protection profile now reports practical local
  finality at 72 confirmations. This is an operator safety signal, not a
  consensus finality rule. Explicit `-reorghysteresisdepth=0` now matches the
  documented behavior and protects every active-chain rewrite instead of
  disabling hysteresis. `-reorghysteresisworkmargin=0` remains the explicit way
  to disable the extra-work hysteresis requirement; the default margin stays
  enabled so long-lived competing branches must prove materially more work
  before automatic activation.

- Shielded wallet RPCs canonicalize explicit and automatic shielded fees before
  note selection and output adjustment. This keeps `z_sendmany`,
  `z_shieldfunds`, and `z_sweeptotransparent` from selecting notes against one
  fee and then proving or filtering against another canonical fee.

- `z_sweeptotransparent` remains the supported bulk drain path for legacy
  shielded notes. It emits independent one-note `V2_RECOVERY_EXIT`
  transactions, avoiding shielded change and shared-ring construction.
  Post-sunset zero-output `V2_SEND` exits remain disabled until their explicit
  consensus activation height, while the decoder now round-trips such payloads
  safely for future activation/testing.

- Release archives now require and package `btx-util` alongside `btxd` and
  `btx-cli`, so nodes using PQ-signed auto-update manifests have the verifier
  available for the next update cycle. Auto-update startup checks now use a
  short bounded jitter window, transient fetch/signature/script failures retry
  from a five-minute backoff, and default request metrics are aggregate-only
  (`version`, `platform`, `arch`, rollout cohort). Persistent client UUID
  telemetry is opt-in with `-autoupdatetelemetryclientid=1`.

# Credits

Thanks to everyone who contributed code, testing, operational validation, and
release engineering to this release.
