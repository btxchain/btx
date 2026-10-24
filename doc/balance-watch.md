# Balance watch

Balance watch reports whether this wallet's balances are proven through the chain tip. Until the watch is ready, an amount asked from it is not known. Unknown is not the same as zero.

The Qt overview page shows one line under the balance: `Balances proven through block N` when the watch is ready, or `Balances not ready, N blocks behind` when it is not. That line does not replace the balance amount.

## getbalancewatch

`getbalancewatch` returns the status of this wallet's watch. It does not return an amount. A false `ready` does not imply a balance.

`ready` is true only when the chain has a tip height, the wallet has processed that height, and the wallet is not scanning. The status also includes `chain_height`, `wallet_height`, `blocks_behind`, `scanning`, `descriptors`, and `fetched`. `blocks_behind` is how many blocks the wallet is behind the tip when both heights are known. When the chain is unavailable, `ready` is false and `blocks_behind` is 0.

`descriptors` are this wallet's own public descriptor strings. `fetched` lists descriptor lookups that were not already in that set, at most 32. A descriptor this wallet already has is not listed. `shielded_foreign_watch` is always false.

## getbalanceatheight

`getbalanceatheight height` uses only transactions already stored for this wallet. It does not walk the chain.

When the wallet is ready through that height, the result is:

```json
{ "height": <height>, "amount": <amount>, "ready": true }
```

The amount sums transparent outputs that belong to this wallet, are confirmed at or below `height`, are not immature coinbase at that height, and are not spent by another wallet transaction confirmed at or below `height`.

When `height` is negative, the wallet has not processed `height`, or a scan is running, the command fails and does not include an amount.

## getbalances

`getbalances` keeps the existing trusted, pending, immature, and watch-only amounts on the same formulas. It adds two fields:

- `watch_ready` (bool): whether the watch has reached the chain tip and the wallet is not scanning.
- `blocks_behind` (number): how many blocks the wallet is behind the chain tip. This is 0 when the chain is unavailable.

## BTX_BALANCE_NOT_READY

`BTX_BALANCE_NOT_READY` means the amount is not known yet. `getbalanceatheight` returns this error when it is not ready through the requested height, and the response does not include an amount. Do not substitute zero.

## Scope

Shielded notes this wallet cannot open are omitted. Another person's shielded balance is not watched. Balance watch does not sign and does not spend.

## Lightweight client

`btx-cli lightwatch` is a separate watch. It stores this wallet's public descriptors and the outputs those descriptors can see. It does not store the chain. The node it talks to must be started with `-blockfilterindex=1`.

`lightwatch sync` asks for each block's basic compact filter. A block is downloaded only when the filter matches a watched script. The filter header must chain from the previous header. A break stops the walk. A filter that has not been checked stays unknown.

`lightwatch balance` and `lightwatch balanceat <height>` print an amount only when the walk has reached that height and the saved block hash at that height matches the node’s active chain. Heights above the current tip and replaced blocks fail with `BTX_BALANCE_NOT_READY` and include no amount. An unavailable RPC node also fails without an amount. A historical height on the unchanged prefix remains queryable even while the watch is behind the tip. These checks use the configured RPC node; they are not independent consensus verification. `amount` is the spendable total. `immature` is coinbase that the walk has already seen and that is not yet spendable. `lightwatch status` reports ready, the cursor, blocks behind, the descriptors, and the blocks that were downloaded because a filter matched.

`lightwatch sync` rewinds a disconnected suffix before querying hashes on a shorter chain, then finds the common ancestor and scans the replacement branch. Saved state is checked again after a restart. `lightwatch status` reports `ready: false` when the cursor height matches the tip but its block hash has changed; `blocks_behind` can still be 0 in that case. Chain checks are observations at RPC time, not a guarantee against a subsequent reorg.

`lightwatch init` refuses a descriptor that contains a private key, and it refuses a descriptor that does not expand to any script without one. A public descriptor that still needs a seed is in that second group. Watch `addr(...)` or a public-key descriptor instead. `lightwatch sendraw <hex>` relays an already signed transaction through the node and does not sign. Shielded notes are omitted. Coins created before `start_height` are outside the watch, so a balance at a lower height is not ready. Ranged descriptors are expanded for the first 200 indexes.
