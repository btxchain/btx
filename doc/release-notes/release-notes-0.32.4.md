BTX version 0.32.4 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.32.4>

This v0.32.4 point release focuses on operator safety and mining readiness after
0.32.3. It includes wallet-backup passphrase-safety metadata and warnings,
live-mining supervisor hardening, strict Apple Metal mining defaults,
auto-update installer fallback improvements, shielded recovery-exit
drainability, and node-local reorg/mining hardening.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.32.4 release artifacts.

BTX 0.32.4 does not introduce a new protocol activation height. Nodes, miners,
pools, exchanges, services, and explorers should upgrade from earlier 0.32.x
builds for the wallet backup, live mining, auto-update, and node-policy
hardening fixes.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+.

# Notable changes

- Wallet bundle and encrypted archive backups now make passphrase handling
  explicit. `backupwalletbundle` and `backupwalletbundlearchive` report
  `wallet_encrypted`, `wallet_passphrase_included=false`, and
  `wallet_passphrase_required_to_spend`; encrypted-wallet exports warn that the
  wallet passphrase is not stored in the bundle or archive. Archive restores
  also warn that the archive passphrase only decrypts the container and does not
  replace the original wallet passphrase needed to spend.

- The mining wallet backup helper now prefers `backupwalletbundle` when the RPC
  is available, captures integrity and balance snapshots for legacy fallback
  exports, and keeps `--format=legacy` available for older nodes.

- Live-mining supervision is safer for process managers and workstation starts.
  `start-live-mining.sh --foreground` lets launchd, systemd, or tmux supervise
  the loop process directly, and detached starts now resolve a stable
  `--launch-cwd` so the supervisor does not inherit an unusable terminal or
  mount working directory.

- Apple Silicon live mining now defaults to a strict Metal posture:
  `BTX_MATMUL_BACKEND=metal`, `BTX_MATMUL_REQUIRE_BACKEND=metal`,
  `BTX_MATMUL_GPU_INPUTS=1`, non-daemonized supervised nodes, and zero allowed
  backend fallbacks. The loop fails closed if `getmininginfo` reports a missing
  Metal backend or any Metal digest / nonce-seed GPU-to-CPU fallback.

- The Metal mining defaults were promoted for production hosts. GPU-generated
  inputs auto-enable for the production 512x16x8 product/nonce-seed mining
  shape, Apple host-class auto-tuning was tightened, and
  `doc/btx-metal-mining-tuning.md` documents the current monitoring fields,
  override model, and benchmark commands.

- Auto-update installs now fall back to a source build when prebuilt archive
  verification fails instead of aborting the install. The auto-update request
  path also records opt-out telemetry fields for version/platform/arch and a
  persistent client UUID, and the installer received shell hardening for empty
  array handling.

- Shielded recovery exits are drainable across the post-sunset path. The wallet
  can continue spending eligible recovery-exit value through transparent
  outputs, and the shielded account-tree helpers preserve the needed state
  across lifecycle and restart coverage.

- Node-local reorg and mining hardening was added without a new fork activation.
  Deep reorgs now default to warning and alerting while still following the
  most-work chain, with hard refusal available via `-parkdeepreorg`; optional
  `-randomtiebreak` support improves same-work tie behavior. MatMul validation
  also gained DoS classification for malformed pre-hash/seed headers and a
  fail-closed Freivalds self-test for NEON-vs-scalar consistency.

- Mainnet fast-start snapshot, checkpoint, `minimumchainwork`, and
  `assumevalid` metadata have been refreshed to height 126,800.

- `z_sendmany` help now describes the C-002 transparent unshield boundary more
  clearly, and the OP_CHECK_MULTI_PQ research plan plus Path A demonstration
  test were added for future post-quantum multisig work.

- Release automation, fast-start, bootstrap, and mining examples now point at
  the 0.32.4 artifacts.

# Credits

Thanks to everyone who contributed code, testing, operational validation, and
release engineering to this release.
