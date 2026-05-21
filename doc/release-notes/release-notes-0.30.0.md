BTX version 0.30.0 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.30.0>

This release covers changes merged after BTX 0.29.7 was prepared on April 28,
2026. It focuses on snapshot fast-start reliability, CUDA mining and release
packaging, public audit hardening, and operator tooling.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive security and update notifications, please subscribe to:

  <https://btx.dev/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.30.0 release artifacts.

Compatibility
=============

BTX is supported on Linux, macOS 13+, and Windows 10+.

Notable changes
===============

- Snapshot fast-start is more reliable for shielded nodes. Mainnet snapshot
  metadata has been refreshed to height 105,550, shielded snapshot state can be
  restored without requiring pre-snapshot block files, failed snapshot section
  loads restore prior shielded state, and the snapshot documentation now covers
  mining-node bootstrap and restart validation.

- Linux release packaging now includes CPU-only and CUDA Guix archive flavors.
  CUDA 12.9.1 and CUDA 13.2.0 release builds pin redistributable toolkit
  components, statically link the CUDA runtime, and leave host NVIDIA driver
  libraries outside the archive. Release docs describe the archive selection
  matrix, supported GPU targets, and target-host driver requirements.

- CUDA MatMul mining can batch work across multiple supported GPUs. The CUDA
  backend now caches topology probes, reports device topology through
  `btx-matmul-backend-info`, supports weighted device scheduling and manual
  per-device overrides, keeps digest pools device-local, and preserves the
  original single-device fast path when only one CUDA GPU is selected.

- Fast-start and download-and-go tooling were hardened. The setup flow handles
  Darwin ad-hoc signing, flat or sibling snapshot manifests, release archive
  naming across CPU/CUDA variants, DNS-only bootstrap guidance, and additional
  installer tests.

- Release and packaging infrastructure was cleaned up for BTX-branded builds.
  CMake target naming, generated manpages, Qt/macOS packaging names, Guix
  archive refresh behavior, Darwin cross-build framework lookup, and SPHINCS+
  variant selection all received release-focused fixes.

- Shielded and wallet behavior received compatibility fixes. Spend-path
  recovery now has a first-class transaction-family enum, `walletpassphrase`
  honors `-autoshieldcoinbase=0`, and shielded test fixtures were aligned with
  fee-bearing rebalance and snapshot bridge-state behavior.

- Public audit and tooling work from `btxchain/btx` was ported back into this
  tree. The libbitcoinpqc fuzz harnesses now include structured parsing,
  determinism, signature-substitution, garbage-verification, and local/CI smoke
  coverage, along with wrapper and documentation hardening.

- Operator mining tooling now includes `contrib/mining/live-mining-loop.py`, a
  JSON-RPC keepalive variant for hosts where repeatedly spawning `btx-cli` has
  measurable overhead.

## Credits

Thanks to everyone who contributed code, testing, audit feedback, packaging
validation, and operational validation to this release.
