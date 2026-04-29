# BTX Bridge Pending Recovery

Date: 2026-04-25

## Summary

This note documents the wallet-managed persistence, archive retention, and
recovery flow for bridge settlement batches.

The goal is to remove the earlier one-shot operational model where a funded
bridge batch could stall until an operator manually rebuilt settlement or
refund from retained `plan_hex` metadata.

This is wallet-local state and RPC behavior. It is not a consensus-rule change
and does not require a soft fork or hard fork.

## What Shipped

The wallet now keeps two wallet-local bridge journals keyed by the funded
bridge outpoint:

- an active pending journal for batches that are still unresolved or still
  inside the confirmation safety window
- an archive journal for batches whose settlement or refund has reached the
  configured confirmation depth

Both journals are persisted in the wallet DB and reloaded on restart.

Tracked records include:

- bridge plan and kind
- funding outpoint and amount
- refund destination and refund fee
- imported-vs-native tracking origin
- last attempt height and retry count
- last error string
- last known settlement txid
- last known refund txid

Archived records additionally keep:

- completion kind: settlement vs refund
- completion txid
- completion height
- archive height
- archive timestamp

The bridge submit RPCs now track batches by default:

- `bridge_submitshieldtx`
- `bridge_submitunshieldtx`

Both RPCs accept:

- `track_pending` default `true`
- `refund_destination`
- `refund_fee`

New operator RPCs were added:

- `bridge_importpending`
- `bridge_listpending`
- `bridge_listarchive`
- `bridge_recoverpending`
- `bridge_prunearchive`

New wallet policy:

- `-bridgependingconfirmdepth=<n>` controls how many confirmations settlement
  or refund must reach before the active pending record is archived
- the default is `20`

## Recovery Model

### Upgrading old nodes with pre-journal stuck batches

Historical stuck batches that were created before this recovery journal existed
do not become auto-recoverable just because a node is upgraded.

On upgrade:

- batches already tracked in the journal will be retried automatically
- historical batches from older nodes will not be discovered automatically
- those historical batches need a one-time `bridge_importpending` attach step
  before startup/block-connect auto-recovery can take over

After that one-time import, the batch participates in normal automatic
recovery.

### Automatic recovery and archive-reconciliation triggers

Recovery is attempted:

- after wallet startup
- after each connected block

Archive reconciliation is also attempted:

- after wallet startup
- after each connected block
- after each disconnected block

If an archived settlement or refund drops back below the configured
confirmation depth because of a re-org, the wallet moves that record from the
archive back into the active pending journal so normal recovery can resume.

The wallet examines every unresolved pending record and then:

1. archives the record if settlement or refund has reached the configured
   confirmation depth
2. waits if the tracked transaction is still in the mempool
3. waits in a confirming state if the tracked settlement or refund has
   confirmations but has not yet reached the archive threshold
4. marks the batch `spent_elsewhere` if the funded outpoint is no longer
   available on the active chain and no tracked settlement/refund remains
   active
5. retries settlement while the refund path is not yet eligible
6. switches to refund once `refund_lock_height` has been reached and a valid
   refund destination is recorded

Retries are normally limited to once per height. Operators can bypass that
guard with `bridge_recoverpending ... true`.

### Confirmation depth and archive lifecycle

The active pending journal and the refund timeout are separate policies:

- `refund_lock_height` is the absolute on-chain timeout after which the refund
  path becomes eligible
- `bridgependingconfirmdepth` is the local wallet policy for how much chain
  depth is required before the wallet stops treating a settlement/refund as
  reorg-sensitive

With the default `-bridgependingconfirmdepth=20`, a bridge settlement or
refund remains visible in `bridge_listpending` while it is:

- still in the mempool, or
- confirmed but below `20` confirmations

Once it reaches the threshold, the record moves to `bridge_listarchive`
instead of being forgotten. Archive rows remain until explicitly pruned.

### Status model

`bridge_listpending` returns active batches only. This includes both unresolved
entries and entries whose settlement/refund is still below the configured
confirmation depth.

`bridge_listarchive` returns completed batches whose settlement or refund has
reached the configured confirmation depth and has been retained for audit,
reorg resilience, and operator review.

Common statuses are:

- `pending_settlement`
- `settlement_in_mempool`
- `settlement_confirming`
- `awaiting_refund`
- `refund_in_mempool`
- `refund_confirming`
- `manual_action_required`
- `spent_elsewhere`

Archive rows report:

- `archived_settlement`
- `archived_refund`

`bridge_listpending` also reports:

- `required_confirmations`
- `settlement_confirmations`
- `refund_confirmations`

`manual_action_required` generally means the wallet cannot safely continue
without operator input, for example:

- no valid refund destination is recorded once refund becomes eligible
- the wallet cannot sign the recovered PSBT
- PSBT finalization failed

### Transient `bad-shielded-anchor`

For bridge-in settlement, a transient `bad-shielded-anchor` mempool reject is
treated as retryable wallet-local failure as long as the funded outpoint is
still available. The tracked batch remains pending and can be retried:

- automatically on the next connected block
- immediately with `bridge_recoverpending <txid> <vout> true`

## Preferred operator flow

Run recovery on the wallet node that owns the bridge signing keys. This is
normally the node that originally created the bridge plan.

If enough metadata still exists, the preferred recovery path is:

1. verify the funding outpoint and metadata
2. import or reattach the batch to the wallet journal
3. inspect unresolved state with `bridge_listpending`
4. trigger recovery if needed
5. let the wallet keep retrying on new blocks until settlement or refund
   confirms deeply enough to archive

For old stuck batches created on nodes that did not have this code yet, step 2
is required once. Without it, the upgraded wallet has nothing to auto-recover.

### Lowest-error path

The least error-prone path for a historical stuck batch is:

1. run the helper script in `contrib/bridge/`
2. let the wallet auto-generate a refund destination unless there is a reason
   to force a specific one
3. leave `recover_now=true` enabled so import and first recovery attempt happen
   together

Example:

```bash
bash contrib/bridge/recover-pending-batch.sh \
  --wallet <wallet> \
  --plan-hex "<plan_hex>" \
  --funding-txid "<funding_txid>" \
  --vout <vout> \
  --amount <amount>
```

That wrapper:

- checks `gettxout` first when possible
- imports the batch into the journal
- defaults to immediate recovery
- lets the wallet auto-generate a refund destination if omitted
- prints the resulting status and the current `bridge_listpending` view for the
  outpoint

If the imported batch has already moved to archive by the time you inspect it,
query `bridge_listarchive` for the funding outpoint or completion txid.

### Raw RPC path

Example:

```bash
export WALLET="<wallet>"
export PLAN_HEX="<plan_hex>"
export FUNDING_TXID="<funding_txid>"
export VOUT=<vout>
export AMOUNT="<amount>"
export REFUND_DEST="<refund_destination>"
export REFUND_FEE="0.00010000"

btx-cli -rpcwallet="$WALLET" bridge_importpending \
  "$PLAN_HEX" "$FUNDING_TXID" "$VOUT" "$AMOUNT" \
  "{\"refund_destination\":\"$REFUND_DEST\",\"refund_fee\":$REFUND_FEE,\"recover_now\":false}"

btx-cli -rpcwallet="$WALLET" bridge_listpending

btx-cli -rpcwallet="$WALLET" bridge_recoverpending \
  "$FUNDING_TXID" "$VOUT" true

btx-cli -rpcwallet="$WALLET" bridge_listarchive \
  "{\"funding_txid\":\"$FUNDING_TXID\",\"funding_vout\":$VOUT}"
```

For a one-step raw RPC path that is still relatively safe, omit
`refund_destination` and keep the default `recover_now=true` so the wallet
generates a refund destination and attempts recovery immediately:

```bash
btx-cli -rpcwallet="<wallet>" bridge_importpending \
  "<plan_hex>" "<funding_txid>" <vout> <amount> \
  '{"refund_fee":0.00010000,"recover_now":true}'
```

Record the returned `refund_destination` so refund recovery can be audited or
rebuilt later if needed.

To retry every unresolved batch in the journal:

```bash
btx-cli -rpcwallet="$WALLET" bridge_recoverpending
```

To review archived completions:

```bash
btx-cli -rpcwallet="$WALLET" bridge_listarchive
```

To dry-run prune a single archived completion by completion txid:

```bash
btx-cli -rpcwallet="$WALLET" bridge_prunearchive \
  '{"completion_txid":"<completion_txid>","dry_run":true}'
```

To prune archive rows up to a known safe archive height:

```bash
btx-cli -rpcwallet="$WALLET" bridge_prunearchive \
  '{"max_archive_height":123456,"force":true}'
```

Archive RPC selector notes:

- `bridge_listarchive` accepts optional filters:
  `funding_txid` plus `funding_vout`, `completion_txid`, and
  `max_archive_height`
- `bridge_prunearchive` requires exactly one selector:
  `all`, `max_archive_height`, `funding_txid` plus `funding_vout`, or
  `completion_txid`
- `bridge_prunearchive` requires `force=true` for `all` and
  `max_archive_height` deletion unless `dry_run=true`

If a batch was submitted through the current RPC surface with the default
`track_pending=true`, import is not needed. It is already in the journal.

## Metadata required for historical stuck batches

Historical batches can only be recovered if enough metadata still exists.

Required:

- `plan_hex`
- funding `txid`
- funding `vout`
- funding `amount`
- access to the wallet or keys that can sign the bridge path

Helpful but not strictly required:

- original `bridge_address`
- original `refund_lock_height`
- original intended payout or refund destination

If `plan_hex` is gone, the wallet cannot safely reconstruct an arbitrary old
batch from chain data alone.

## Preflight verification

Before importing a historical batch, verify as much of the following as
possible:

- the wallet is the wallet that owns the bridge signing keys
- `plan_hex`, `funding_txid`, `vout`, and `amount` match the same batch
- the funding outpoint still exists on the active chain if settlement/refund is
  expected to proceed immediately

The most useful quick check is:

```bash
btx-cli gettxout "<funding_txid>" <vout>
```

Interpretation:

- returns a JSON object: the funding outpoint is currently unspent on this node
- returns `null`: the outpoint is already spent or unknown on the active chain,
  so recovery may report `spent_elsewhere`

## Inspecting a funded bridge output

If only the funding transaction id is known, inspect the transaction to recover
`vout` and funded amount:

```bash
btx-cli -rpcwallet=<wallet> gettransaction "<funding_txid>"
```

If needed, decode the funding transaction directly:

```bash
btx-cli getrawtransaction "<funding_txid>" 1
```

## Verifying the outcome

After import or manual retry, use:

```bash
btx-cli -rpcwallet=<wallet> bridge_listpending
```

For the specific batch, the most important result states are:

- `pending_settlement`: tracked and waiting for settlement retry
- `settlement_in_mempool`: settlement is built and waiting to confirm
- `settlement_confirming`: settlement is confirmed but below the archive depth
- `awaiting_refund`: settlement has not completed and refund is now eligible
- `refund_in_mempool`: refund has been built and is waiting to confirm
- `refund_confirming`: refund is confirmed but below the archive depth
- `manual_action_required`: operator input is still needed
- `spent_elsewhere`: the funded outpoint is no longer available on the active
  chain

If the batch no longer appears in `bridge_listpending`, check:

```bash
btx-cli -rpcwallet=<wallet> bridge_listarchive \
  '{"funding_txid":"<funding_txid>","funding_vout":<vout>}'
```

Interpretation:

- `archived_settlement`: the settlement reached the configured confirmation
  depth and the record was retained in the archive
- `archived_refund`: the refund reached the configured confirmation depth and
  the record was retained in the archive
- no row in pending or archive: the batch was never imported successfully, the
  archive was pruned, or the operator is looking at the wrong wallet

Check the immediate RPC result from `bridge_importpending` or
`bridge_recoverpending` as well. Those RPCs can return a `current` object that
already shows the archived state.

## Manual low-level recovery runbook

Use these commands when the journal-based path is not usable or when an
operator wants to rebuild settlement or refund directly from retained
metadata.

Run them on the wallet node that owns the bridge signing keys. Once a fully
signed raw transaction hex exists, final broadcast can happen from any node.

### Bridge-in retry

Use this when a transparent-funded bridge output was supposed to settle into
the shielded pool.

Fast path:

```bash
btx-cli -rpcwallet=<wallet> bridge_submitshieldtx \
  "<plan_hex>" "<funding_txid>" <vout> <amount>
```

Manual PSBT path:

```bash
PSBT=$(btx-cli -rpcwallet=<wallet> bridge_buildshieldtx \
  "<plan_hex>" "<funding_txid>" <vout> <amount> | jq -r '.psbt')

SIGNED_PSBT=$(btx-cli -rpcwallet=<wallet> walletprocesspsbt \
  "$PSBT" true "ALL" true true | jq -r '.psbt')

HEX=$(btx-cli finalizepsbt "$SIGNED_PSBT" | jq -r '.hex')

btx-cli sendrawtransaction "$HEX"
```

If the submit fails with a transient `bad-shielded-anchor` reject, wait for the
next block and rerun the same command. With a tracked batch, the wallet will
also retry automatically on the next connected block.

### Bridge-out retry

Use this when a bridge-funded output was supposed to settle back to a
transparent address.

Fast path:

```bash
btx-cli -rpcwallet=<wallet> bridge_submitunshieldtx \
  "<plan_hex>" "<funding_txid>" <vout> <amount>
```

Manual PSBT path:

```bash
PSBT=$(btx-cli -rpcwallet=<wallet> bridge_buildunshieldtx \
  "<plan_hex>" "<funding_txid>" <vout> <amount> | jq -r '.psbt')

SIGNED_PSBT=$(btx-cli -rpcwallet=<wallet> walletprocesspsbt \
  "$PSBT" true "ALL" true true | jq -r '.psbt')

HEX=$(btx-cli finalizepsbt "$SIGNED_PSBT" | jq -r '.hex')

btx-cli sendrawtransaction "$HEX"
```

### Refund after timeout

Use this once `refund_lock_height` has been reached and settlement is no longer
the intended path.

```bash
PSBT=$(btx-cli -rpcwallet=<wallet> bridge_buildrefund \
  "<plan_hex>" "<funding_txid>" <vout> <amount> "<refund_destination>" 0.00010000 true | jq -r '.psbt')

SIGNED_PSBT=$(btx-cli -rpcwallet=<wallet> walletprocesspsbt \
  "$PSBT" true "ALL" true true | jq -r '.psbt')

HEX=$(btx-cli finalizepsbt "$SIGNED_PSBT" | jq -r '.hex')

btx-cli sendrawtransaction "$HEX"
```

## Operational notes

- The active pending journal and archive do not change what makes a bridge
  transaction valid. They only persist enough metadata for the wallet to retry,
  refund, audit, and survive shallow chain re-orgs without losing track of a
  valid batch.
- Nodes that do not have this wallet-side recovery logic may still fail to
  recover their own stuck batches, but they do not need a consensus upgrade to
  accept blocks containing valid recovered settlement or refund transactions.
- Journal and archive state are wallet-scoped. Recovery and archive pruning
  have to happen on a wallet that can sign or already owns the relevant bridge
  metadata.
- `bridge_prunearchive` never touches active pending rows. Height-based and
  prune-all archive deletion require `force=true` unless `dry_run=true`.

## Validation coverage

Targeted coverage for this work is in:

- `wallet_bridge_pending_recovery.py`
- `wallet_bridge_refund_timeout.py`
- `bridge_wallet_tests`
- `rpc_tests`

The recovery flow was also rechecked against the existing postfork coinbase
auto-shield path to confirm that this wallet-local bridge work does not reopen
the earlier post-`61000` coinbase compatibility problem.
