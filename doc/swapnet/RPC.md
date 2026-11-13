# Native RPC reference — 33 methods

All calls take one optional named request object. Authentication/owner status comes from the native caller and never from these fields. Amounts are atomic-unit decimal strings. See `rpc-catalog.json` and `schemas/local_request.schema.json` for constraints.

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
- `claim_fee_atoms` — optional; string.

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

Scope: `read`.

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

## Result and error handling

Native RPC results are returned directly; rejected requests use a normal JSON-RPC error whose message starts with a stable SwapNet error code. Protocol/privacy/safety constraints are also enforced inside the application, so schema validity does not grant authority. A timeout can be ambiguous once execution started: inspect the recorded swap/operation before retrying.

## Common codes

`OWNER_REQUIRED`, `AUTH`, `FORBIDDEN`, `WALLET_SCOPE`, `WALLET_SELECTION`, `WALLET_UNLOADED`, `GENESIS_MISMATCH`, `CONTRACT_CODE`, `ASSET_UNAVAILABLE`, `QUOTE_EXPIRED`, `QUOTE_ALREADY_ACCEPTED`, `BAD_SIGNATURE`, `FEE_CAP`, `REFUND_EARLY`, `INPUT_UNCONFIRMED`, `SCRIPT_MISMATCH`, `REVISION_CONFLICT`, `SECRET_ROLLBACK`, `AUDIT_CORRUPT`, `BACKUP_AUTHENTICATION`, `LEGACY_STATE`, `SESSION_LIMIT`, and `ACTIVE_LIMIT` indicate explicit rejected conditions rather than permission to bypass checks.
