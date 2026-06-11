BTX version 0.32.5 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.32.5>

This v0.32.5 point release fixes the Apple Metal variable-base MatMul product
digest path used by post-`nMatMulNonceSeedHeight` mining. It is intended for
Apple Silicon miners and operators running the 0.32.x block-125,000 mining
path, especially M4 hosts using Metal GPU input generation.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.32.5 release artifacts.

BTX 0.32.5 does not introduce a new protocol activation height. Nodes, miners,
pools, exchanges, services, and explorers should upgrade from earlier 0.32.x
builds for the Metal mining digest fix and the additional nonce-seed boundary
coverage.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+.

# Notable changes

- The Metal variable-base product digest path now matches the CPU reference for
  the production 512x16x8 nonce-seed-v2 mining shape at height 125,000. The fix
  replaces the SIMD-group partial-sum reduction in the fused product/prefix
  compression kernels with a deterministic threadgroup-memory reduction, so the
  digest no longer depends on how Apple maps threadgroup indices onto SIMD
  groups.

- Product-committed variable-base digest batching now finalizes directly from
  the contiguous final-compression words for each candidate. This keeps the
  post-activation Metal mining path on GPU in release builds instead of relying
  on CPU recomputation or fallback to correct a bad digest.

- Metal regression coverage now checks the height-125,000 mainnet boundary with
  `nBits=0x1d0b8746`, including generated base matrices, perturbed matrices,
  final product words, and product-committed digests against the CPU reference.

- CUDA nonce-seed boundary coverage was extended to guard the same
  post-activation digest behavior on the CUDA path.

- Release automation, fast-start, bootstrap, and mining examples now point at
  the 0.32.5 artifacts.

# Credits

Thanks to everyone who contributed code, testing, operational validation, and
release engineering to this release.
