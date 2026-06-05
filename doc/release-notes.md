BTX version 0.31.0 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.31.0>

This release covers changes merged after BTX 0.30.2 was prepared on June 1,
2026. It includes a coordinated protocol activation, post-quantum networking and
release-signing work, self-service shielded unshielding, signed auto-update
tooling, wBTX bridge references, and refreshed fast-start metadata.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive security and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.31.0 release artifacts.

BTX 0.31.0 includes a mandatory network upgrade that activates at block 123,000.
Nodes, miners, pools, exchanges, services, and explorers should upgrade before
that height. Older releases remain compatible before activation, but will not
follow the upgraded network rules after activation.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+.

# Notable changes

- Self-service shielded-to-transparent unshielding is now available after the
  0.31.0 activation. Wallets can build the direct unshield statement and proof
  locally, without a bridge operator or verifier set in the spend path.

- BTX v2 transport now supports a hybrid X25519 plus ML-KEM-768 handshake for
  BIP324 peers. Operators can use `-v2pqonly` to require the hybrid
  post-quantum transport on every connection.

- Auto-update support now includes signed manifest verification, release
  signature helpers in `btx-util`, staged/canary rollout cohorts, signed
  platform-specific prebuilt binaries with source-build fallback, and
  health-probe rollback to the previous release when an update does not become
  RPC-healthy.

- The new `contrib/wbtx` toolkit publishes reference EVM contracts, a Python
  SDK, and integration documentation for wrapped BTX. Wallet RPCs
  `buildhtlcclaim` and `buildhtlcrefund` support the BTX leg of atomic-swap HTLC
  flows.

- Shielded rebuild and reindex workflows now expose live progress and ETA
  information. `getblockchaininfo` reports shielded rebuild progress, startup
  logging is more explicit, and `getwalletinfo` now includes `shielded_balance`.

- Mining and accelerator observability improved. The daemon surfaces the
  resolved mining backend, MatMul solve exhaustion logs include best
  digest-versus-target data, CUDA hardware probing is crash-safe, and Metal AUTO
  mode defaults to the legacy CPU-finalize transcript path.

- Pruned and assumeutxo-backed shielded nodes have additional reorg recovery
  coverage, including prune-retention locking and end-to-end regression tests for
  shielded-state recovery.

- Zero-downtime shielded restart is now the default. When a node restarts with
  persisted shielded state that exactly matches the active chain tip (frontier
  root/size, commitment-index digest, and anchor/registry windows all validated),
  it trusts that state and skips the full-chain settlement/netting drift sync and
  the cross-chain re-audit, which previously ran on every restart. If the local
  data is missing, out of date, on the wrong chain, or fails any of those checks,
  the node gracefully falls back to a full rebuild from chain as before. Two
  operator knobs control this: `-fastshieldedstartup` (default `1`; set `0` to
  force the thorough drift sync + audit on every restart) and
  `-shieldedstartupaudit` (default `1`; on the non-fast path, set `0` to keep the
  drift sync but skip the cross-chain audit). Per-block consensus validation is
  unchanged and always runs on newly connected blocks.

- Mainnet snapshot, checkpoint, `minimumchainwork`, and `assumevalid` metadata
  have been refreshed to height 120,900 for the 0.31.0 fast-start release.

# Credits

Thanks to everyone who contributed code, testing, operational validation,
release engineering, and post-quantum integration review to this release.
