BTX version 0.29.7 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.29.7>

This patch release covers changes merged into `btx-node` after BTX 0.29.6 was
prepared in the public `btx` repository on April 19, 2026. It focuses on
shielded recovery safety, bridge operator recovery tooling, and Apple Silicon
live-mining stability.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive security and update notifications, please subscribe to:

  <https://btx.dev/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.29.7 release artifacts.

Compatibility
=============

BTX is supported on Linux, macOS 13+, and Windows 10+.

Notable changes
===============

- Spend-path recovery for stranded shielded notes is now available behind an
  explicit activation height of 88,000. This adds the
  `z_recoverstrandednote` RPC, recovery-only shielded balance reporting, and
  activation/reorg coverage for mixed-version and post-activation recovery
  paths.

- Bridge recovery is now more durable for operators. Pending bridge batches can
  be persisted and recovered across restarts, archive/prune RPCs are available
  for bridge recovery records, and follow-up fixes harden externally funded
  unshield submit, `btx-cli` bridge argument handling, rebalance-submit
  redaction, and pending journal recovery.

- Apple Silicon mining defaults have been tuned for recent hosts, including M4
  Max and 4-perf-core systems, live mining peer-topology recovery has been
  improved, and the Metal product-digest divergence seen on mainnet-shaped
  workloads has been fixed.

- Test and operator tooling were refreshed to support these changes, including
  regtest shielded activation-height overrides, shielded topology/relay fixture
  updates, block-capacity expectation refreshes, and full-suite regression
  cleanup.

Credits
=======

Thanks to everyone who contributed code, testing, and operational validation to
this release.
