BTX version 0.32.9 is now available from:

  <https://github.com/btxchain/btx/releases/tag/v0.32.9>

This v0.32.9 point release is an emergency hardening release for the fragmented
BTX network. It makes deep private-branch releases visible and locally parked by
default, adds an objective empty-block subsidy haircut, and adds wallet/service
RPC metadata for shallow-reorg settlement safety.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

If you are running an older version, shut it down. Wait until it has completely
shut down, then install the new binaries or replace the existing `btxd`,
`btx-cli`, and GUI binaries with the 0.32.9 release artifacts.

BTX 0.32.9 introduces an empty-block subsidy consensus rule at height 130,000.
It does not change MatMul consensus validation, seed derivation, product digest,
or matrix verification code.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+.

# Notable changes

- The default reorg profile is now `emergency`: warn on candidate reorgs deeper
  than 3 blocks, park candidate branches that would reorganize more than 12
  blocks, and report a 12-confirmation settlement-safety depth. Parking is local
  policy, not consensus finality.

- Operators that need automatic most-work convergence can explicitly select
  `-reorgprotectionprofile=standard` or `archive`. This trades away the default
  emergency parking protection against late private releases.

- Empty coinbase-only blocks after height 130,000 have an objective consecutive
  subsidy cap: the first empty block may claim at most 50% of the scheduled
  subsidy, and the second and later consecutive empty blocks may claim at most
  25%. Blocks claiming more are invalid. This rule is based only on committed
  block/chain data, not on local mempool contents or miner identity.

- Block template construction now defaults to a 25-transaction cap and disables
  legacy coin-age priority mining unless explicitly configured. This gives miners
  a fast non-empty template path during CPU-heavy mempool pressure instead of
  falling back to empty templates.

- Post-sunset shielded recovery has a new batch operator RPC,
  `z_sweeptotransparent`, which sends wallet-owned shielded notes to a
  transparent address as standard one-note `V2_RECOVERY_EXIT` transactions.
  `z_sendmany` also now attempts exact zero-change shielded-to-transparent
  multi-note exits after the sunset instead of falling into a shielded-change
  build path. This is wallet/RPC construction hardening only; it does not change
  shielded consensus validity rules.

- Mining RPC reorg telemetry now reports every observed active-chain reorg,
  including shallow 1-block rewrites, plus whether parking is active and whether
  the node will follow most-work automatically. This makes it harder to mistake
  a local parking profile for deterministic protection against a stronger
  private miner, and gives operators a machine-readable signal for selfish
  mining/private-branch behavior.

- Wallet RPCs now expose advisory settlement-safety metadata. `gettransaction`,
  `listtransactions`, and `listsinceblock` report `settlement_safe`,
  `settlement_status`, `settlement_confirmations_required`, and explicit wallet
  transaction state. `getbalances`, `getwalletinfo`, and `listunspent` report
  settlement-safe balances/outputs using `-walletreorgsafetydepth` (default 12).

- Wallets now automatically enter a reorg settlement hold after any block
  disconnect. While the hold is active, settlement-safe balances are reported as
  zero and confirmed transactions/outputs report `settlement_safe=false` with
  `settlement_status=reorg_hold`. The hold lasts until both
  `-walletreorgholdblocks` blocks (default 12) and `-walletreorgholdseconds`
  seconds (default 3600) have elapsed, and is persisted across wallet restart.
  The elapsed-time hold prevents a premined replacement branch from immediately
  burning down settlement-safe reporting before services can react. Set either
  value to 0 to disable that part of the policy.

- `listsinceblock` removed entries now include the stale block hash, height, and
  transaction index for transactions removed by a reorg, giving services enough
  data to freeze or reverse affected credits automatically.

- The mining chain guard remains enabled by default on mainnet and pauses local
  mining only when outbound peer view is unhealthy. It is a mining safety guard,
  not a consensus finality mechanism.

# Security note

No node-local policy can make 1-confirmation proof-of-work settlement safe
against a miner who can privately outwork the public chain. Services should use
the new settlement-safe fields, raise confirmation requirements for deposits and
settlement, and freeze affected account state immediately when wallet RPCs show
removed, conflicted, below-policy confirmations, or an active reorg settlement
hold.

# Credits

Thanks to everyone who contributed code, testing, operational validation, and
release engineering to this release.
