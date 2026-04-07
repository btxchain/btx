# BTX Shielded Sweep Best Practices

This guide covers the supported transparent-to-shielded sweep flows in BTX,
with a focus on wallet UX, gateway/app integration, and recovery when a
shielding attempt is rejected or otherwise gets stuck.

After the post-`61000` privacy fork, the wallet-side sweep RPCs are limited to
mature coinbase compatibility flows. General transparent deposits should use the
bridge-ingress surface instead.

This guide is specifically about:

- `z_planshieldfunds`
- `z_shieldfunds`
- `abandontransaction`

## Why This Exists

BTX's shielded wallet already had strong note-side optimizations:

- persisted shielded Merkle state
- local MatRiCT proof generation
- shielded note selection and merge support
- shielded fee-floor estimation

But supported wallet-side compatible sweeps could still be too greedy. A single
`z_shieldfunds` call could attempt one very large shielding transaction, which
is fragile when the wallet has a large transparent UTXO set.

The current BTX wallet fixes that by:

- planning shielding chunks with a daemon-local safety policy
- exposing the same policy and chunk plan over RPC
- auto-abandoning rejected chunk candidates before retrying smaller batches

## Core RPCs

### `z_planshieldfunds`

Use this first when you care about UX, rate limits, or predictable fees.

Example:

```bash
btx-cli -rpcwallet=mywallet z_planshieldfunds 25.0 "btxs1..."
```

Optional override example:

```bash
btx-cli -rpcwallet=mywallet z_planshieldfunds 25.0 "btxs1..." 0.0001 '{"max_inputs_per_chunk":16}'
```

Key response fields:

- `requested_amount`
- `spendable_amount`
- `spendable_utxos`
- `estimated_total_shielded`
- `estimated_total_fee`
- `estimated_chunk_count`
- `policy`
- `chunks`

The `policy` object exposes the daemon's local chunking policy:

- `selection_strategy`: currently `largest-first`
- `recommended_max_inputs_per_chunk`
- `applied_max_inputs_per_chunk`
- `min_inputs_per_chunk`
- `soft_target_tx_weight`
- `max_standard_tx_weight`
- `relay_fee_floor_per_kb`
- `mempool_fee_floor_per_kb`
- `shielded_fee_premium`

### `z_shieldfunds`

This now executes a shielding sweep using the same policy-aware planner.
After `61000`, it is limited to mature coinbase compatibility inputs.

Example:

```bash
btx-cli -rpcwallet=mywallet z_shieldfunds 25.0 "btxs1..."
```

Optional override example:

```bash
btx-cli -rpcwallet=mywallet z_shieldfunds 25.0 "btxs1..." 0.0001 '{"max_inputs_per_chunk":16}'
```

Key response fields:

- `txid`: first chunk txid, preserved for older clients
- `txids`: all committed chunk txids
- `amount`: total shielded amount across all chunks
- `transparent_inputs`: total transparent inputs consumed
- `chunk_count`
- `chunks`
- `policy`

## How Chunking Works

BTX now uses the following supported sweep policy:

1. Collect spendable compatible transparent UTXOs.
2. Sort them `largest-first`.
3. Build a shielding candidate up to the current `max_inputs_per_chunk`.
4. Reprice the candidate against the live relay/mempool floor.
5. If the candidate violates the daemon's soft tx-size target, shrink the
   chunk and rebuild.
6. Broadcast the chunk.
7. If broadcast/mempool admission rejects the chunk candidate, auto-abandon it,
   shrink the chunk size, and retry.

That retry loop stops once it reaches `min_inputs_per_chunk`. At that point,
the RPC returns an error instead of silently leaving the wallet in a dirty
partially-selected state.

## Fee And Amount Math

Per chunk:

```text
gross_amount   = sum(selected transparent inputs)
shielded_amount = gross_amount - fee
```

Across the full sweep:

```text
estimated_total_fee      = sum(chunk.fee)
estimated_total_shielded = sum(chunk.amount)
```

Important consequence:

- lowering `max_inputs_per_chunk` usually increases `chunk_count`
- increasing `chunk_count` increases total fees
- if you are sweeping almost all transparent value, a very low chunk size can
  make a previously-possible request impossible because fees are paid once per
  chunk

## Practical Batch Sizing Guidance

Use the daemon default unless you have a good reason not to.

Recommended approach:

1. Call `z_planshieldfunds`.
2. Check `estimated_chunk_count`, `estimated_total_fee`, and `policy`.
3. Only override `max_inputs_per_chunk` if your wallet app has a specific UX or
   operational reason.

Good use cases for a lower override:

- mobile wallet wants shorter per-RPC latency
- gateway wants smaller mempool units
- operator wants very conservative batches during congestion

Good use cases for the default:

- standard desktop wallet UX
- large vault maintenance sweeps
- exchange/operator batch shielding where throughput matters

## Recovery For Rejected Or Stuck Shielding Transactions

### Automatic recovery

For chunk candidates that are created locally but rejected from mempool/policy
admission, BTX now:

- abandons the rejected candidate in wallet state
- shrinks the chunk size
- retries automatically

This is the main fix that prevents a failed oversized shielding attempt from
leaving the wallet in a bad local selection state.

### Manual recovery

If a transaction was already committed to the wallet and later becomes stuck,
the standard wallet recovery path remains:

```bash
btx-cli -rpcwallet=mywallet gettransaction "<txid>"
btx-cli -rpcwallet=mywallet abandontransaction "<txid>"
```

After abandoning a stuck transparent-ingress shielding tx:

1. re-run `z_planshieldfunds`
2. verify the new plan
3. retry `z_shieldfunds`

### What counts as "stuck"

Typical indicators:

- not in mempool
- depth `<= 0`
- no confirmations after a reasonable interval
- local wallet still shows it as pending

If a tx is already mined, do not abandon it.

## Application Integration Pattern

Wallet apps, services, and coordinators should use this pattern:

1. `z_planshieldfunds`
2. present chunk count + total fee to the user or policy engine
3. optionally override `max_inputs_per_chunk`
4. call `z_shieldfunds`
5. store every txid from `txids`, not just `txid`

Do not assume one shielding request equals one tx.

## Example Decision Matrix

| Situation | Recommended action |
|---|---|
| Normal wallet sweep | Use `z_planshieldfunds`, then `z_shieldfunds` with default policy |
| Huge UTXO set, latency-sensitive app | Preview plan, consider lowering `max_inputs_per_chunk` |
| Need lowest possible total fee | Prefer default or a higher chunk cap, then re-plan |
| RPC failed after mempool rejection | Re-run `z_planshieldfunds`; rejected candidates are auto-abandoned |
| Old pending tx looks stuck | Inspect with `gettransaction`, then `abandontransaction`, then retry |

## What This Does Not Change

This work improves the supported wallet-side shielding compatibility flow. It
does not:

- change the shielded note model itself
- change MatRiCT proof semantics
- reopen general post-`61000` public-flow transparent deposits on `V2_SEND`
- replace `z_mergenotes` for shielded-note consolidation

Once funds are shielded, later `z -> z` transfers remain the preferred path for
private movement inside the pool.
