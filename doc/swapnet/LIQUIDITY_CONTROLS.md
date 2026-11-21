# Liquidity controls and new native API

New methods are added to the same authenticated `swapnet` RPC category. Every call takes the ordinary optional request object. Read scope is not owner scope; peer packets can never call these methods.

| Method | Scope | Purpose |
|---|---|---|
| getswapmode | read | Admission mode and preserved recovery status |
| setswapmode | owner | Persist observe/trade/maker/recovery mode |
| getswaponboarding | read | Honest local prerequisites without spending |
| getswapexecutionpolicy | read | Owner-configured execution guard document |
| setswapexecutionpolicy | owner | Install integer-only price/fee/reference limits |
| previewswapquote | trade | Bind an exact quote and caps without authorizing funds |
| confirmswapquote | trade | Explicit consent, mandate and idempotent acceptance |
| setswapmakerpolicy | owner | Min size, inventory floor/skew and requester limits |
| getswapmakerpolicies | owner | Inspect local strategies |
| getswapmarkethealth | owner | Bounded local outcome/concentration page |
| exportswapreceipt | audit | Opt-in public-term/tx-reference disclosure |
| getswappeercoreinfo | read | Shared core status, not liquidity or trust proof |
| setupswapbitcoin | owner | Plan or explicitly create a separate watch-only wallet |

`previewswapquote` requires `quote_id`, `max_local_fee_atoms`, and optionally `refund_fee_atoms`, `claim_fee_atoms`. Fee units remain asset-specific: outgoing/refund fees use the sold asset; the taker claim cap uses the bought asset. A preview cannot extend a quote's expiry.

`confirmswapquote` requires `preview_id` and literal `consent: true`, with either `mandate_id` or explicit `create_single_trade_mandate: true`. Only an actual owner can request the latter. The one-trade authorization interval is displayed in the preview. It is not an unlimited recurring budget.

`setupswapbitcoin` without consent returns a plan. With consent, it creates only a private-keys-disabled descriptor watch wallet if necessary and binds the local policy. It does not install Bitcoin, sync a blockchain, create funded inventory, import a seed or send a transaction. Multiple possible funding wallets require selection.

A missing EVM `deployment` manifest prevents new EVM trades, but not existing recovery. The manifest's `creation_hash` must be the pinned init code. For an existing approved deployment, add that manifest to the local asset policy after active obligations finish or use the reviewed migration workflow. Never point the driver at a different contract while obligations are active.

Distinct provider identities and configured reference names are not proof of economically independent owners. Price protection is opt-in owner policy, not consensus or an official exchange rate.
