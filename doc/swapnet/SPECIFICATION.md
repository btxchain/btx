# SwapNet v2 protocol and implementation specification

## 1. Product and scope

A BTX node discovers providers, requests exact-size prices, selects independently verifiable terms, and settles directly with a counterparty through two chain-enforced SHA-256 HTLCs. The provider is an economic counterparty and liquidity operator, not a privileged validator, custodian or minting authority. Normal BTX networking carries discovery and negotiation; each side's independently configured full nodes determine on-chain truth.

The delivered runtime supports native BTX/BTC and native BTX/ETH. Every route has a native BTX leg. ERC-20 routes, arbitrary bridges, AMM reserve pricing, partial fills, routed economic multihop and wrapped claims are outside the enabled runtime. The Solidity contract's standard-token primitive is not an assertion of token-route qualification.

## 2. Process architecture

`btxd` starts a dedicated bounded worker that owns an isolated CPython interpreter. The trusted Python implementation is compiled into a C++ source table at build time. Peer input cannot load Python modules or choose wallet RPC methods. The interpreter ignores user-site packages, PYTHONPATH and the working-directory import path; required system interpreter libraries and `cryptography` remain deployment dependencies.

The worker hosts the catalog, quote service, maker policies, authority engine, journal, coordinator and chain drivers. It reaches native chain/wallet functionality through a C++ allowlisted callback and reaches configured foreign clients through loopback-only RPC. Private native PQ material remains in CWallet. There is no SwapNet child daemon, public RPC relay, new discovery port, or mandatory external bootstrap service.

## 3. Names, assets and arithmetic

An asset ID is `family:genesis:chain_id:token`. Families are `btx`, `btc`, and `evm`. Genesis is exact lowercase 32-byte hex. UTXO chain IDs are zero; EVM IDs bind the chain identifier as well as genesis. Native assets use `native`. Contract/token addresses never identify a chain by themselves.

Atomic monetary quantities are canonical decimal strings with a uint256 upper bound. No binary floating-point price calculation is used. Fixed rational prices use integer numerator/denominator and explicitly conservative rounding. Atomic units of BTX, BTC and wei are never interchangeable just because each amount is a decimal string. Quotes bind both asset IDs, exact input size, output size, maker fee, maximum receive-network fee, requester, provider, nonce, sequence, issue time and expiry.

## 4. Discovery and routing

The native transport exchanges a v2/genesis hello only after the ordinary peer handshake. Provider records retain their separately domain-separated v1 record schema and are signed by native wallet identities. Records expire within 600 seconds, contain at most 16 pairs, and are subject to bounded catalog/high-water replay state. A record advertises willingness to quote; it does not prove inventory or spending authority.

The seven native commands are `swhello`, `swget`, `swprov`, `swrfq`, `swquote`, `swterms`, and `swreceipt`. Economic packets use a signed v2 envelope containing exact network, sender, recipient, kind, swap ID, sequence, issue time, expiry and payload. Relays can forward but cannot modify it. Routing is bounded to four hops and eight-way fallback fanout; learned next-hop entries expire. A next-hop route is not economic multihop settlement.

Messages are deduplicated durably, signatures are checked before routing state changes, and acknowledgements are bound to the recipient. Transactions and preimages are not sent as peer negotiation payloads. Funding receipts are only transaction references; recipients verify the referenced chain themselves. Failure or censorship can delay discovery or settlement but cannot turn a peer into a wallet owner.

## 5. Authorization

The native RPC layer derives `Principal` and owner status from the authenticated JSONRPCRequest, not from request-object fields. The local cookie and local Qt console are owner contexts and use the principal `owner:cookie`. A named RPC user uses `rpc:<username>` and is an owner only when explicitly configured with `-swapnetowner`. An empty HTTP username, the literal `local-owner`, and any name beginning with `owner:` are rejected. A non-empty wallet restriction must name the same wallet as the call, and that caller is not treated as an owner. Other authenticated users can spend only under mandates issued to their exact principal. Normal BTX RPC allowlists still apply outside the SwapNet callback boundary.

A mandate binds principal, outgoing asset, cumulative cap, per-trade cap, fee cap, expiry and nonce. Reserving a quote atomically holds its required budget. An agreement-specific grant freezes contract terms and permissible signing roles. The coordinator rechecks current authority before new funding signatures/broadcast. Revocation prevents new obligations but does not prevent an already committed swap from claiming or refunding to its fixed beneficiary.

The local owner/OS/process is part of the trusted computing base. This is not a defense against root, a replaced node binary or a compromised embedded dependency. Native wallet encryption and filesystem protections remain relevant.

## 6. Bilateral agreement and funding sequence

The initiator first obtains a signed exact-size quote. Acceptance reserves the mandate budget, creates an independent random preimage, persists it encrypted, creates independent per-chain claim/refund keys, and proposes long/short deadlines. The maker checks its currently authorized market, inventory and own mandate, independently checks the proposed clocks, and signs a bilateral agreement. The initiator verifies counterparties, quote binding, exact keys, beneficiaries, amounts, commitments, deadlines and fee limits before signing. The commit packet delivers both signatures.

The initiator prepares the long-leg funding transaction and its recovery path before broadcasting. UTXO funding includes exactly one agreed HTLC output and only independently verified wallet-owned change. Inputs, amounts, output scripts, non-RBF intent and absolute fees are checked. Raw signed bytes, transaction ID and recovery material are durable before network submission. BTX refund signing merges the local PQ provider in CWallet; BTC uses independent secp256k1 HTLC keys and BIP143 witness signing.

The responder independently waits for acceptable long-leg funding depth and pre-signs its long-leg claim template without the secret before risking its own short-leg funds. It then prepares short-leg funding and refund recovery, persists both, and broadcasts. The initiator independently verifies short-leg exact terms and depth/finality before permanently marking secret exposure and broadcasting the short-leg claim. The responder extracts and verifies the revealed SHA-256 preimage from the actual chain and claims the long leg. No peer's assertion that a secret or payment exists is sufficient.

## 7. Timelocks and chain observations

The short leg must mature first, leaving a conservative long-leg claim window. UTXO contracts use block heights; EVM uses timestamps. The policy checks minimum confirmation depths, observation freshness, chain staleness, reveal margin and long/short separation. The driver estimates block-time bounds for planning. Those are conservative policy assumptions, not mathematical guarantees about block production. Extreme stalls, deep reorganizations and fee-market failures remain external-chain risks.

BTX defaults to 20 confirmations and Bitcoin to 6; EVM requires the configured full node's finalized block semantics. Explicit local chain policies may be stricter. EVM verification binds genesis, chain ID, contract address and exact runtime-code hash at current and relevant historical blocks. UTXO verification checks actual funding output amount/script and canonical transaction inclusion. Spent-output discovery uses mempool references plus bounded resumable block scanning and rechecks cached spending inclusion after reorg.

## 8. Journal and crash ordering

SQLite uses WAL with FULL synchronous durability, transactions, compare-and-swap revisions, unique quote claims, cumulative mandate holds, per-outpoint locks, monotone exposure state, and hash-chained audit events. Local financial records are distinct from the bounded wire canonical JSON format. The journal contains signed raw operations before broadcast. An ambiguous retry asks the chain about the same transaction ID and retransmits identical bytes rather than creating a new funding payment.

Incoming economic messages have a bounded durable replay cache; outgoing messages have bounded retries and expiry. The coordinator reconstructs live sessions after restart and re-locks still-reserved UTXOs. A maximum of 128 active and 4096 retained sessions prevents silent scheduling starvation and unbounded session admission. Active sessions have scheduling priority; completed/refunded sessions continue to be checked for deep reorg recovery without replenishing previously consumed budget.

A legacy observer database with session records is refused by the embedded host rather than silently treated as a migrated financial journal. Preserve and review old state offline.

## 9. Claim, refund and fee recovery

A UTXO refund is fully signed before funding can escape. An EVM refund is an immutable bounded intent, not a premature reserved nonce that would obstruct other transactions; it is signed when mature. Claims/refunds keep their exact contract input, branch and beneficiary. Explicit replacement can increase claim/refund fees only within the signed agreement and local grant. Funding transactions are never silently repriced or replaced.

The EVM contract uses pull credits. Reaching `Claimed` or `Refunded` is not sufficient for this coordinator to report economic completion: the appropriate recipient must withdraw the exact credited amount. Gas authorization reserves capacity for that withdrawal. Exact-amount withdrawals do not accidentally drain the credit accounting of another concurrent swap.

Cancellation before irreversible funding releases eligible holds. After funding, an RPC cancellation is not an on-chain reversal: recovery continues to a valid claim or mature refund. Secret exposure is monotone even after a claim is reorganized out. Terminal budget is not automatically recycled after a refund, preventing a deep reorg from resurrecting already reused authority.

## 10. User and agent API

All 33 RPCs take one optional named request object. Readiness, discovery, asset availability, quotes, mandates, markets, operations, health and recovery are distinct states. `listswapassets` does not label a missing signer/full node as ready. Quotes report minimum receive amounts after disclosed maker and receive-network fee allowances. `acceptswapquote` accepts a specific quote ID and mandate ID, not an unbounded market order.

Generic status/transcript/event RPCs redact private keys, preimages, signed raw claim transactions and private key handles. Encrypted recovery export is an owner-only action; its RPC result contains a file path/hash, not plaintext keys. The full method catalog and machine-readable schemas accompany this specification.

## 11. Release evidence

Executed deterministic-ledger and embedded-runtime tests establish the behavior they actually exercise. They do not establish BTX consensus acceptance, Solidity compilation, successful transactions on external chains, economic liveness under all failures, or an independent audit. The supplied qualification runners and acceptance matrix are required before release. No economic success receipt or provider liquidity is fabricated to fill those gaps.
