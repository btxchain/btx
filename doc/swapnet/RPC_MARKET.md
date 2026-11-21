# Market RPC request catalog

All native RPCs take **one request object** as their first argument. Amounts are decimal atom strings. Owner authority comes from native authentication, never request fields. Exact schemas are in `contrib/swapnet/schemas/`.

| Method | Object fields | Required |
|---|---|---|
| `getswapauthinfo` |  |  |
| `getswapmode` |  |  |
| `setswapmode` | `mode` | `mode` |
| `getswaphealth` |  |  |
| `getswapnetworkinfo` |  |  |
| `getswapcapabilities` |  |  |
| `getswapreadiness` |  |  |
| `listswappublicoffers` | `after`, `limit`, `sell_asset`, `buy_asset` |  |
| `publishswapoffer` | `sell_asset`, `buy_asset`, `sizes`, `kind`, `slots`, `ttl`, `offer_id` | `sell_asset`, `buy_asset`, `sizes` |
| `withdrawswapoffer` | `offer_id` | `offer_id` |
| `getswapmakercapacity` |  |  |
| `requestpublicswapquote` | `provider`, `offer_id`, `tier` | `provider`, `offer_id` |
| `acceptswapquote` | `quote_id`, `mandate_id`, `max_local_fee_atoms`, `refund_fee_atoms`, `claim_fee_atoms` | `quote_id`, `mandate_id`, `max_local_fee_atoms` |
| `setswapmarket` | `market`, `mandate_id`, `max_local_fee_atoms`, `refund_fee_atoms`, `claim_fee_atoms`, `enabled` | `market`, `mandate_id`, `max_local_fee_atoms`, `refund_fee_atoms`, `claim_fee_atoms` |
| `setswapmarkets` | `markets` | `markets` |
| `previewswap` | `quote_id`, `max_local_fee_atoms`, `refund_fee_atoms`, `claim_fee_atoms`, `min_receive_atoms` | `quote_id`, `max_local_fee_atoms` |
| `confirmswap` | `preview_id` | `preview_id` |
| `createswapinvite` | `endpoints`, `ttl`, `allow_private` | `endpoints` |
| `inspectswapinvite` | `uri`, `allow_private` | `uri` |
| `connectswapinvite` | `uri`, `endpoint_index`, `allow_private`, `allow_dns` | `uri` |
| `exportswapreceipt` | `swap_id` | `swap_id` |
| `verifyswapreceipt` | `receipt` | `receipt` |
| `listswaprefusals` | `request_id` | `request_id` |
| `setswapexecutionpolicy` | `policy` | `policy` |
| `getswapexecutionpolicy` |  |  |
| `setupswapbitcoin` | `policy` | `policy` |
| `getsharedp2pinfo` |  |  |

Native mutation methods require review in Atlas. Read privileges are separately enumerated in the Rust allowlist. Preview is not confirmation; inspection is not connection; advertised firm capacity is not on-chain collateral. See the implementation authority map for exact scopes.
