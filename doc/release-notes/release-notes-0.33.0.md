BTX version 0.33.0 is being prepared for release from:

  <https://github.com/btxchain/btx/releases>

This release prepares the node backend for the BTX v0.33 public surface. It
improves external-miner template consistency, stale shielded-exit mempool
handling, non-CUDA fallback builds, and the staged CUDA MatMul mining path. It
also refreshes mainnet hardening and fast-start snapshot metadata.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

After the official v0.33.0 release is published, shut down the previous node
cleanly, wait for it to exit, and replace its `btxd`, `btx-cli`, and related
binaries with the signed final release artifacts. Back up wallets and
configuration before upgrading. Do not install unpublished candidate assets.

Version 0.33.0 introduces no new mainnet consensus activation and does not
change the P2MR transaction wire format. Miners and pool operators should
upgrade for the corrected `getblocktemplate` context and diagnostics.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+. CUDA mining remains a
hardware-specific accelerated path with a CPU fallback.

# Notable Changes

## External mining template consistency

- `getblocktemplate` now binds candidate height, deterministic MatMul seeds,
  and reported context to the template's actual parent block.
- Template JSON exposes `template_context` and `matmul_seed_derivation`
  diagnostics so pool software can verify the parent, height, seed rule, and
  final candidate header fields it received.
- A template/context parent mismatch fails closed instead of returning
  internally inconsistent mining work.

## Shielded mempool and template cleanup

- Individually overdrawn shielded pool-exit transactions are removed after a
  shielded block changes the available pool balance.
- Package-invalid candidates are filtered before they exhaust the block
  template candidate-evaluation budget, preventing stale high-fee shielded
  entries from crowding valid transparent transactions out of templates.

## Staged CUDA MatMul path

- The CUDA series batches input and prehash generation, hydrates survivor
  records, finalizes product digests on device, releases nonce-scan scratch
  buffers, and exposes buffer-pool capacity through mining diagnostics.
- The production-shape `512/16/8` path can use stream-A row-block product
  digests. Operators can disable that path with
  `BTX_MATMUL_CUDA_STREAM_A_WORDS=0` while retaining the established fallback.
- CUDA performance and memory gains remain hardware- and driver-dependent.
  Repository research measurements were collected on an RTX 5060 and are not
  a portable guarantee. Promotion to the public `btx` release remains gated on
  multi-architecture NVIDIA validation and CPU/CUDA parity checks.
- CUDA-disabled builds now provide complete stubs for the new batch APIs, so
  ordinary CPU nodes link and fall back cleanly.

## Browser wallet backend boundary

- The separately deployed beta browser wallet creates and signs P2MR
  transactions locally, then submits raw transactions through a constrained
  gateway backed by `testmempoolaccept` and `sendrawtransaction`.
- Browser key custody, WebAssembly cryptography, document signing, explorer
  history, and the public HTTP gateway are website/explorer components, not
  `btx-node` artifacts.
- Never expose the node JSON-RPC port directly to the public internet or store
  node RPC credentials in a browser.

## Mainnet hardening and fast start

- Mainnet `nMinimumChainWork`, `defaultAssumeValid`, the checkpoint, and
  `chainTxData` are refreshed from operator-collected archive data at height
  155,700.
- Operators generated a version-9 fast-start snapshot online from a canonical
  archive node at height 155,700 and reported the archive services healthy.
  Three archive nodes independently returned base hash
  `b5ea1fb02d12e1cfa4bbc5ccc4946ca026ad4a5f270b99a0816aa95853306c3d`.
- Snapshot SHA-256:
  `e0fb6d34852a7f0ac649dfaa9e4a50a1fa5bcde7ba97475ef3bf62f4175fc69e`.
- The snapshot manifest pins its serialized UTXO hash, chain transaction
  count, base block, and shielded-state commitment in mainnet chain parameters.
- A disposable v0.33.0 staging node loaded all 64,096 snapshot coins and
  retained the activated chainstate across an offline restart. Public promotion
  must repeat and retain that receipt using a clean binary from the exact
  `btxchain/btx` release commit.

# Known Limitations

- CUDA changes require independent validation on the final Linux CUDA 12/13
  release binaries and representative NVIDIA architectures before promotion
  to the public release repository.
- The browser wallet and post-quantum document-signing suite remain beta
  website features and are versioned separately from node consensus.

# Credits

Thanks to the contributors and reviewers of the shielded mempool cleanup,
MatMul template-context hardening, CUDA mining research, archive operations,
wallet integration, and release engineering work that prepared v0.33.0.
