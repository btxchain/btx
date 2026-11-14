# Recovery and failure handling

## What is durable

`<network datadir>/swapnet/` contains `state.sqlite` (with SQLite WAL files while running), `foreign-vault.json`, `vault.key`, and optional encrypted `backups/*.snr`. The database stores authorization, immutable agreements, operation IDs/raw transactions, nonce reservations, observations and audit continuity. Files are local owner-private. Do not copy a live SQLite main file alone and assume it is a consistent backup.

`exportswaprecovery` makes a consistent SQLite snapshot, includes the foreign vault and wrapping key, encrypts the complete bundle with a separate passphrase-derived AES-GCM key, and returns its path and SHA-256. Use a long independent passphrase and a terminal/client that does not retain it in shell history. The minimum length is 20 characters; length alone is not an entropy guarantee. The backup result contains no plaintext private keys. The native BTX wallet must also be backed up separately.

## Restore

Stop the native node first, preserve the failed directory, and restore only into a new empty SwapNet directory. Do not merge financial journals or copy the same EVM account into two concurrently active nodes.

```sh
python3 tools/restore_recovery.py \
  --bundle /absolute/path/to/recovery.snr \
  --destination /absolute/path/to/network-datadir/swapnet \
  --genesis ACTUAL_CHAIN_GENESIS_HEX \
  --confirm-node-stopped
```

The command prompts for the passphrase. The genesis argument is the exact locally verified chain genesis, not a value obtained from a provider. Authentication, file allowlist, SQLite integrity, audit head, vault key and empty destination are checked before publication. Restore the corresponding native wallet backup, select/unlock it normally, bring both chain verifiers current, and restart the node. Inspect every funded swap before issuing new mandates.

## Failure decisions

| Event | Expected behavior |
|---|---|
| RPC/network response lost after broadcast | Query the recorded transaction ID; reuse identical prepared bytes. |
| Crash before funding acknowledgement | Restart from the journal; do not create a fresh funding transaction. |
| Counterparty never funds | Wait for the local refund deadline and broadcast the durable refund. |
| Claim reorganized out after revealing secret | Keep `secret_exposed=true`; reconcile and rebroadcast the authorized claim/recovery path. |
| Mandate revoked during a funded swap | Reject new commitments, preserve fixed-beneficiary claim/refund recovery. |
| Chain unavailable/stale/wrong genesis | Stop risky advancement; preserve state; reconnect the correct verifier. |
| Claim/refund fee too low | Use `bumpswapfee` within signed/local absolute caps; never change beneficiary. |
| EVM claim creates credit but no final payout | Continue the exact authorized pull withdrawal; do not report complete prematurely. |
| Datadir/audit corruption | Refuse silent repair; restore from a consistent authenticated backup and reconcile on-chain truth. |
| Source rollback | Preserve wallet/journal; rollback does not cancel contracts or rewind chains. |

Raw signed claims may contain the secret; do not print them to general logs or send them as diagnostics. Audit logs contain identifiers and state changes, not private witnesses. The hash chain detects modification relative to a trusted saved head; it is not tamper-proof against an attacker who can rewrite both the database and every external reference.

## Limits

Recovery still depends on retained keys, available chain data, deadlines, fees and chain liveness. No software can make a signed refund spend before its consensus timelock or undo a finalized counterparty payment. Offline/manual recovery and deep-reorg behavior must be qualified against actual chains before mainnet use. Source availability and component tests are not proof that every disaster scenario has been executed.
