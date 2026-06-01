BTX version 0.30.2 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.30.2>

This patch release covers changes merged after BTX 0.30.1 was prepared on May
20, 2026. It focuses on production-ready bridge view grant handling.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive security and update notifications, please subscribe to:

  <https://btx.dev/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.30.2 release artifacts.

Compatibility
=============

BTX is supported on Linux, macOS 13+, and Windows 10+.

Notable changes
===============

- Bridge view grant decrypt handling now accepts canonical objects or bare hex,
  verifies serialized hex and component fields match, rehydrates encrypted
  shielded keys before decrypt, and respects object format hints during
  automatic decoding.

- Operator view grants default to structured minimal disclosure after the
  shielded privacy redesign. Legacy audit grants now require explicit
  `allow_legacy_audit_view_grants=true`, including disclosure policies and
  batch planning.

- View grant encryption now uses fresh ML-KEM encapsulation and AEAD nonce
  randomness for every grant. Grant-enabled plans may differ in
  `view_grant_hex`, `ctv_hash`, and `plan_hex`, while decrypted payloads remain
  stable for equivalent requests.

- Equivalent operator view grant requests now canonicalize to the same
  normalized order after shorthand expansion, policy grants, and duplicate
  merging.

- Bridge view grant readiness coverage now includes focused unit, functional,
  Docker regtest, documentation, and CI-path-filter gates for the shielded
  bridge surfaces.

- Mainnet snapshot, checkpoint, `minimumchainwork`, and `assumevalid` metadata
  have been refreshed to height 118,225 for the 0.30.2 fast-start release.

## Credits

Thanks to everyone who contributed code, testing, operational validation, and
bridge view grant review to this release.
