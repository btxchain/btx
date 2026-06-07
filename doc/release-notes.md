BTX version 0.32.0 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.32.0>

This v0.32.0 release is the block-125,000 activation release. It includes the
shielded sunset, transparent recovery exits, MatMul nonce-seed v2, shielded
unshield velocity-cap enforcement, shielded restart improvements, updated
wallet coinbase shielding defaults, developer verification artifacts, and
release tooling updates.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.32.0 release artifacts.

BTX 0.32.0 is required ahead of block 125,000 for nodes, miners, pools,
exchanges, services, and explorers that follow the upgraded chain.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+.

# Notable changes

- Zero-downtime shielded restart is now the default. When a node restarts with
  persisted shielded state that exactly matches the active chain tip (frontier
  root/size, commitment-index digest, anchor/registry windows, and nullifier-set
  accumulator all validated), it trusts that state and skips the restart audit
  path. If the local data is missing, out of date, on the wrong chain, or fails
  any check, the node falls back to a full rebuild from chain as before. Operator
  knobs are `-fastshieldedstartup` (default `1`) and `-shieldedstartupaudit`
  (default `1`).

- Coinbase auto-shielding is now opt-in. Mined rewards remain transparent by
  default unless the wallet is started with `-autoshieldcoinbase=1`. Even when
  enabled, automatic coinbase shielding waits until the C-002 shielded-pool
  activation height by default (block 123,000 on mainnet, 0 on regtest). Test
  networks can override this floor with `-autoshieldcoinbaseminheight=<n>`.

- The shielded sunset activates at block 125,000. From that height, shielded
  activity is outflow-only: legacy shielded value can exit through V2_SEND
  unshield transactions, while private transfers, new shielded credits, bridge
  and control operations, rollover, and re-shielding flows are no longer valid
  on the upgraded chain.

- The release enforces `ShieldedUnshieldVelocity`, a shielded-pool unshield
  velocity-cap consensus rule. The configured window is 960 blocks with a 5000
  bps (50%) cap, and the activation height is 125,000 (aligned to the shielded
  sunset) on the configured networks. The
  running state is persisted with shielded state, restored exactly across reorgs,
  and covered by unit tests plus `wallet_shielded_velocity_cap.py`. See
  `doc/btx-unshield-velocity-cap.md` for the operator and integration details.

- `V2_RECOVERY_EXIT` transparent-claim recovery activates at the 125,000
  shielded sunset on production-like networks. It reveals the recovered note,
  verifies ownership and sunset-tree membership, pays only transparent outputs,
  and retires both the revealed commitment and the canonical normal-path
  nullifier. Validation uses the sunset tree root for membership checks.

- MatMul nonce-seed v2 activates at block 125,000. Consensus validation and the
  CPU, Metal, and CUDA mining paths derive matrix seeds from each candidate
  header/nonce. The CPU solver restores parallelism while preserving the
  candidate-specific seed derivation used by consensus and the accelerator
  mining paths.

- macOS source builds again precompile MatMul and oracle Metal kernels into
  build-tree `.metallib` artifacts by default, matching the v0.30 developer
  path. The runtime loads the precompiled libraries first and keeps embedded
  source compilation only as a fallback when precompilation is unavailable or
  explicitly disabled.

- A new `formal-verification/` suite documents the tiered shielded-pool proof
  plan and reproducible Z3 checks. Tier 1 covers accounting and velocity-cap
  invariants, Tier 2 covers verifier-relation algebra, and Tier 3 documents the
  Module-SIS reduction. Each tier includes a `PROOFS.md`, and
  `python3 formal-verification/run_all.py` runs the machine-checkable
  obligations.

- The auto-update installer cleanup handling was updated, and release automation
  examples now point at the 0.32.0 artifacts.

# Credits

Thanks to everyone who contributed code, testing, operational validation, and
release engineering to this release.
