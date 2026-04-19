BTX version 0.29.6 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.29.6>

This patch release brings the public `btx` repository up to date with the
current BTX node mainline, restores `rpcauth` JSON compatibility for external
operator tooling, and aligns the public GitHub release automation with the
`btxchain/btx` repository.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive security and update notifications, please subscribe to:

  <https://btx.dev/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.29.6 release artifacts.

Compatibility
=============

BTX is supported on Linux, macOS 13+, and Windows 10+.

Notable changes
===============

- The public `btx` repository is now synced with the current `btx-node` mainline
  snapshot that was prepared for PR12, including the latest node, wallet,
  mining, and operator-surface updates already validated in the BTX node repo.

- `rpcauth` JSON compatibility has been restored so generated authentication
  metadata remains interoperable with existing external tooling and operational
  scripts.

- The release/readiness workflow has been corrected to keep publishing artifacts
  from the public `btxchain/btx` repository, including the readiness artifact
  path fix that was merged in the sync branch.

- Operator-facing release examples have been updated so fast-start, mining,
  release automation, and Windows build documentation all point at the public
  `btx` repository instead of the older `btx-node` path.

Credits
=======

Thanks to everyone who contributed code, testing, and operational validation to
this release.
