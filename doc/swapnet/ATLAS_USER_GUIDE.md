# SwapNet in BTX Atlas

## What is and is not automatic

On an integrated node, SwapNet starts in **observe** mode by default. It discovers signed provider advertisements and public offers through existing BTX peer connections. It does not install a spending mandate, create a funded position, download a foreign-chain binary, select a remotely advertised RPC server, or create market liquidity. An empty market is reported as empty. Existing explicitly authorized obligations continue to be monitored and recovered.

Atlas is a native client of the node. A browser preview cannot connect to RPC or execute a trade. Native actions use Atlas's prepare/review/execute path. A valid signature establishes who authored terms, not that the price is attractive or that the provider's entire business is solvent.

## First launch

1. Start the integrated `btxd` using its ordinary network configuration and open BTX Atlas. Select the correct local node and network. Do not point a real wallet at an unqualified candidate build.
2. Open **SwapNet**. Read the network, mode, peers, public offers, wallet binding, and independent-chain readiness panels. Waiting for a compatible peer is not an installation error; no matching providers is not proof of a networking failure.
3. Select the wallet that is already loaded into this node. The native owner binds the SwapNet wallet; a wallet-restricted RPC user cannot elevate itself by selecting a different wallet in Atlas.
4. Browse public offers without enabling trading. Asset identifiers contain the chain genesis and, for EVM assets, the chain ID. Display names are conveniences, not security identifiers.

## Independent chain setup

For BTC, run and synchronize a Bitcoin Core instance you control. In **Verifier setup**, select its loopback RPC URL, cookie path and loaded funding wallet. The reviewed setup action creates or loads a separate descriptor watch-only wallet for contract observations. It does not import BTX keys into Bitcoin or export the native BTX signing keys.

For ETH, run an independently validated execution/consensus setup and expose only the local RPC endpoint needed by SwapNet. Supply the exact genesis, chain ID, HTLC contract address, runtime hash and owner-selected deployment manifest. New trades verify deployment creation provenance against the configured chain. A link or a public maker advertisement cannot change these settings.

Setup actions can create an external watch wallet even if a later local policy write fails. A retry reuses that wallet; the UI does not claim that a multi-process setup transaction can be rolled back atomically. Existing funded sessions prevent unsafe asset-driver reconfiguration.

## Buy or sell BTX

In **Markets**, select an offer and an exact quantity tier. Requesting a quote reveals that request to the selected maker and any necessary forwarding peers. It does not lock funds. A public indicative tier is a price indication. A public firm tier is a signed local-capacity commitment whose requester-bound quote still requires independent verification and bilateral settlement.

Use **Quotes** to compare the exact quantity, provider, gross output, maker fee, maximum receive-chain fee, minimum proceeds, outgoing fee cap and expiry. No official BTX market price is imposed. A wide spread can be declined without transferring custody.

Choose **Preview**. This creates a short-lived, owner/wallet-bound preview, but does not install its one-trade mandate or reserve funds. Review the exact asset IDs and net proceeds. **Confirm** installs the saved bounded mandate and starts exactly the saved signed quote. It cannot replace the price, destination or fee parameters. Retrying an ambiguous response resolves the same session rather than initiating a second trade.

The native confirmation is a separate deliberate step. A web page, invitation, provider advertisement or model-network record cannot press it on the owner's behalf. The preview is not a perpetual authorization.

## Provide liquidity

Enable **maker** mode only after configuring both independent chain drivers and choosing explicit funding limits. Create a maker mandate for the asset you will pay to the taker. Market orientation is always from the taker's view: `sell_asset` is what the taker supplies, and `buy_asset` is what the taker receives. Therefore a provider offering BTC for incoming BTX requires a BTC mandate.

Set minimum/maximum practical trade sizes, the integer price ratio and fee limits. Publish optional standard-size offers. To provide both directions, configure the inverse asset pair under a separate mandate covering the other output asset; the atomic two-policy RPC is available to automation. There is no requirement to split inventory equally or maintain an official price.

Firm offer slots reserve local capacity across public offers, private quotes and monetary reservations. They are not on-chain collateral. External spending by the wallet owner, a changed chain balance, a malicious modified maker, fees or outages can still prevent completion. A taker does not fund merely because an advertisement says “firm.”

Withdraw a public offer to publish a signed higher-sequence tombstone. Already allocated requester-specific quotes remain bounded by their original expiry and existing obligations retain recovery. An offer disappearing from a cached page is not evidence that a signed funded contract has been cancelled.

## Share and open a peer invitation

Use **Peer invitations → Create** to sign one or more externally reachable native BTX P2P endpoints. Copy the resulting `btx://swapnet/v1/...` URI. The URI contains public metadata and a signature, never keys, RPC credentials, a spending mandate or a foreign-chain verifier URL.

The recipient opens the URI in Atlas or pastes it into **Peer invitations**. The startup inbox is inert. **Inspect** checks syntax, network, signature and expiry locally, without dialing or resolving DNS. The recipient then chooses one endpoint and separately reviews a single native P2P connection attempt. Private-address and DNS exceptions require explicit consent. Loopback, link-local, unspecified and malformed destinations are rejected.

The URI does not create an inbound NAT mapping. The provider needs a reachable endpoint, an operator-configured port forward, or its existing Tor service. A valid link is not a guarantee that a node is online. TCP reachability does not prove that the peer has the maker's key; signed offers and agreements bind that identity independently.

A native connection request returns “requested,” not “established.” Inspect normal peer status and signed market records to observe the outcome. Invitation processing never silently subscribes to all of a provider's markets or authorizes a swap.

## Pause, recover and back up

`observe` permits discovery but no new local taker/maker commitments. `recovery` pauses new market activity while maintaining already authorized settlement recovery. Explicit `-swapnet=0` means recovery-only in this extension, not deletion of the journal or a complete stop of its worker. A startup recovery restriction cannot be overridden by a remote RPC; restart deliberately to change it.

The worker preserves fixed-beneficiary claim/refund authority and continues watching completed records for deep reorgs. A pause does not erase existing signatures or invalidate on-chain contracts. A wallet may need to be loaded/unlocked normally; recovery cannot bypass consensus timelocks or invent missing keys.

Export encrypted recovery with a long independent passphrase entered twice in password fields. Back up the native BTX wallet separately. Restore only with the node stopped and into an empty directory using the packaged restore tool. Do not run two recovered copies of the same EVM account concurrently. A shared discovery cache is not a financial backup.

## Inspect outcomes honestly

Receipts contain signed terms, relevant public chain references and the exporting node's signed observations. Verification re-reads the configured independent chains. A signed local assertion is not a consensus inclusion proof. For EVM pull payments, observing claimed HTLC credits is not sufficient to attribute every pooled-credit withdrawal to one swap; wallet reconciliation remains explicit.

A signed refusal proves that the signer issued that refusal. A timeout is only a local observation. Identity counts do not measure independently owned businesses. Public offer data is optional; private trade records are not automatically published.
