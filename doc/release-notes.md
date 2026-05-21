BTX version 0.30.1 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.30.1>

This patch release covers changes merged after BTX 0.30.0 was prepared on May
20, 2026. It focuses on prune-safe fast-mining reorg handling and refreshed
snapshot fast-start metadata.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive security and update notifications, please subscribe to:

  <https://btx.dev/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.30.1 release artifacts.

Compatibility
=============

BTX is supported on Linux, macOS 13+, and Windows 10+.

Notable changes
===============

- Pruned and assumeutxo fast-start mining nodes now restore consumed shielded
  settlement-anchor metadata from block undo during disconnect. Normal shallow
  reorg handling no longer falls back to a full historical
  `SyncShieldedSettlementAnchorState()` rebuild that can fail when old block
  files have been pruned.

- Block undo serialization now carries an optional versioned settlement-anchor
  extension while preserving compatibility with legacy undo payloads.
  Disconnect will fail with an explicit repair/reindex message if older undo
  data lacks the metadata needed for prune-safe restoration.

- Mainnet snapshot, checkpoint, `minimumchainwork`, and `assumevalid` metadata
  have been refreshed to height 106,875 for the 0.30.1 fast-start release.

- Regression coverage now exercises the undo extension, legacy undo
  compatibility, and a shallow reorg that consumes and restores a matured
  settlement anchor with its original creation height.

## Credits

Thanks to everyone who contributed code, testing, operational validation, and
fast-mining reorg reports to this release.
