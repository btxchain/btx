# Native RPC reference — 33 methods

All calls take one optional named request object. Authentication/owner status comes from the native caller and never from these fields. Amounts are atomic-unit decimal strings. See `rpc-catalog.json` and `schemas/local_request.schema.json` for constraints.

A market is named from the taker's side. `sell_asset` is what the taker pays and `buy_asset` is what the taker receives. The maker pays `buy_asset`, so `createswapmandate` for that maker must use `buy_asset`, and the maker's inventory is denominated in `buy_asset`. `max_receive_network_fee_atoms` and the taker's `claim_fee_atoms` are atomic units of `buy_asset`. `refund_fee_atoms` is atomic units of the asset that party refunds.

## getswaptradepreview

Owner-only read of one stored trade preview: `{"preview_id":"<64 lowercase hex>"}`.
The authenticated principal and effective RPC wallet must exactly match the
preview. An explicitly selected wallet does not create a binding during this
lookup; a different already-bound wallet is refused.

Returns the preview and quote IDs, principal/wallet scope, provider, exact asset
IDs, input/gross-output amounts, maximum send, requested minimum receive, quoted
net receive floor, local/refund/claim/maker/receive-network fee limits, preview
deadline and quote expiry. Amounts are canonical strings in asset atoms.
Local/refund limits use input atoms; claim/maker/receive-network limits use output
atoms. Contradictory or malformed stored review terms are refused.

This read returns historical terms even after expiry and neither refreshes a
preview nor authorizes a trade. It makes no wallet/chain call, installs no
mandate, reserves no funds and changes no accounting. It omits private signing
material and the embedded mandate. `confirmswap` alone retains its existing
expiry, wallet, quote and mode checks, including recovery of an already-started
trade after an expired preview or lost reply.

`runtime_hash` in an EVM asset policy is the keccak256 of the deployed runtime bytecode. For the artifact in this tree the runtime hash, the creation-code hash, the CREATE2 salt, and the address anyone can deploy are in `OPERATIONS.md`. The same runtime can be returned by different init code, so the runtime hash alone does not prove the lock. The policy still names both the address and the runtime hash. An anvil node reports `finalized` as block 0 until it is started with `--slots-in-an-epoch 1`.

## getswapnetworkinfo

Scope: `read`.

No request fields.

## listswapassets

Scope: `read`.

No request fields.

## listswapproviders

Scope: `read`.

- `after` — optional; string.
- `buy` — optional; schema-defined.
- `limit` — optional; integer.
- `sell` — optional; schema-defined.

## searchswaps

Scope: `read`.

- `after` — optional; string.
- `buy` — optional; schema-defined.
- `limit` — optional; integer.
- `sell` — optional; schema-defined.

## requestswapquote

Scope: `quote`.

- `buy_asset` — required; string.
- `nonce` — optional; string.
- `sell_asset` — required; string.
- `sell_atoms` — required; string.

## getswapquotes

Scope: `read`.

- `request_id` — required; string.

## acceptswapquote

Scope: `trade`.

- `mandate_id` — required; string.
- `max_local_fee_atoms` — required; string.
- `quote_id` — required; string.
- `refund_fee_atoms` — optional; string.
- `claim_fee_atoms` — optional; string. Atomic units of `buy_asset` (the short leg the taker claims).

## listswaps

Scope: `read`.

- `limit` — optional; integer.

## getswap

Scope: `read`.

- `swap_id` — required; string.

## cancelswap

Scope: `trade`.

- `swap_id` — required; string.

## getswaptranscript

Scope: `audit`.

- `swap_id` — required; string.

## listswapmandates

Scope: `read`.

No request fields.

## createswapmandate

Scope: `owner`.

- `mandate` — required; object.

## revokeswapmandate

Scope: `owner`.

- `mandate_id` — required; string.

## getswapcapabilities

Scope: `read`.

No request fields.

## resumeswap

Scope: `trade`.

- `swap_id` — required; string.
- `failed_withdrawal_txid` — optional; owner-only opt-in to retry a canonical finalized native ETH withdrawal failure once. A repeat with the same failed transaction returns the recorded retry ID.

## refundswap

Scope: `trade`.

- `swap_id` — required; string.

## listswapoperations

Scope: `audit`.

- `swap_id` — required; string.

## getswaphealth

Scope: `read`.

No request fields.

## publishswapprovider

Scope: `maker`.

No request fields.

## withdrawswapprovider

Scope: `maker`.

No request fields.

## getswapbootstrapinfo

Scope: `read`.

No request fields.

## getswaprecoveryinfo

Scope: `read`.

- `swap_id` — required; string.

## setswapmarket

Scope: `owner`.

- `market` — required; object.
- `mandate_id` — required; string.
- `max_local_fee_atoms` — required; string.
- `refund_fee_atoms` — required; string.
- `claim_fee_atoms` — required; string.
- `enabled` — optional; boolean.

## listswapmarkets

Scope: `read`.

No request fields.

## getswapwalletinfo

Scope: `owner`. The result names the node's identity and foreign-chain accounts.

No request fields.

## setswapassetpolicy

Scope: `owner`.

- `policy` — required; object.

## listswapassetpolicies

Scope: `read`.

No request fields.

## getswaprouteinfo

Scope: `read`.

No request fields.

## exportswaprecovery

Scope: `owner`.

- `passphrase` — required; string.

## bumpswapfee

Scope: `trade`.

- `swap_id` — required; string.
- `kind` — required; schema-defined.
- `new_fee_atoms` — required; string.

## getswapevents

Scope: `audit`.

- `after` — optional; integer.
- `limit` — optional; integer.

## getswapvalidationinfo

Scope: `read`.

No request fields.

`client_version` in the result is the btxd build, the same string as `clientversion` in `getgeneralinfo`. `source_version` is the SwapNet source version and does not change with every release.

## Result and error handling

Native RPC results are returned directly; rejected requests use a normal JSON-RPC error whose message starts with a stable SwapNet error code. Protocol/privacy/safety constraints are also enforced inside the application, so schema validity does not grant authority. A timeout can be ambiguous once execution started: inspect the recorded swap/operation before retrying.

## Common codes

`OWNER_REQUIRED`, `AUTH`, `FORBIDDEN`, `WALLET_SCOPE`, `WALLET_SELECTION`, `WALLET_UNLOADED`, `GENESIS_MISMATCH`, `CONTRACT_CODE`, `FINALITY_LAG`, `ASSET_UNAVAILABLE`, `QUOTE_EXPIRED`, `QUOTE_ALREADY_ACCEPTED`, `BAD_SIGNATURE`, `FEE_CAP`, `REFUND_EARLY`, `INPUT_UNCONFIRMED`, `SCRIPT_MISMATCH`, `REVISION_CONFLICT`, `SECRET_ROLLBACK`, `AUDIT_CORRUPT`, `BACKUP_AUTHENTICATION`, `LEGACY_STATE`, `SESSION_LIMIT`, and `ACTIVE_LIMIT` indicate explicit rejected conditions rather than permission to bypass checks.
