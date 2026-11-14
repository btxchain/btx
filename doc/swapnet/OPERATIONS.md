# Operations and first-run guide

## First launch

Install the qualified binary with its matched Python runtime/standard library and `cryptography`. Launch BTX normally. `-swapnet` stays off unless it is set. With `-swapnet=1`, existing peer connections discover compatible nodes; no new port, seed list, domain name, hosted service, or external identity registration is required. If that explicit start fails, the node does not finish starting.

Run `getswapnetworkinfo`, `getswapbootstrapinfo`, `listswapassets` and `getswapwalletinfo`. An empty provider list or `awaiting_compatible_peer` is an accurate state, not an error to hide. Discovery alone never spends.

Load exactly one native wallet or select one with `-swapnetwallet=<name>`. The binding is persisted and cannot be switched by an unprivileged caller. `createwallet` does not load that wallet on the next start; `loadwallet` is required, and `getswapnetworkinfo` reports `wallet_loaded` and `wallet_warning` until it is loaded. Unlock the native wallet through its normal owner workflow when an authorized operation requires it. Wallet-unloaded, locked, read-only or ambiguous-wallet conditions fail rather than choosing somebody else's funds.

Deadline planning uses a fixed spacing for each chain: 90 seconds for BTX and 600 seconds for Bitcoin, with a fast bound of half that spacing and a slow bound of twice that spacing. A recent stall or a one-second sample does not change the lock. A hello that arrives before the peer's SwapNet runtime is up is retried until that peer admits. Rejected packets increment `packet_errors` and the last few codes are in `recent_packet_errors`.

A maker can cancel an unfunded quote. After the taker has funded the long leg, cancellation does not release that contract; the funds stay locked until the agreed refund height or timestamp. Configure Python 3.11 or newer and the `cryptography` package before building. Both are required by the in-process worker.

## External-chain prerequisites

For Bitcoin swaps, set `wallet` to the loaded funding wallet and `watch_wallet` to a separate loaded descriptor wallet with private keys disabled. Both use the same verified Bitcoin RPC endpoint. Public HTLC descriptors are imported into the watch wallet. Funding, change and signing stay with the funding wallet.

The host attempts to discover an already-running same-network Bitcoin node using standard local cookie locations. It requires an appropriate loaded wallet and chain verification. Automatic discovery does not download a blockchain, install a daemon, or create funded liquidity. A configured Bitcoin policy can specify its loopback URL, local cookie path, wallet, fee rate and confirmations with `setswapassetpolicy`.

EVM requires a deliberately configured loopback full-node endpoint and a locally approved contract: exact genesis, chain ID, deployed address and runtime hash. `getswapwalletinfo` exposes the separately generated public EVM account address. The owner must provision that account with test ETH/gas before test trading. No BTX key is converted into an Ethereum key. Unknown tokens are disabled.

Use independently operated chain clients with suitable historical transaction/block availability. `txindex=1` is recommended for qualification. Pruned or stale clients may lack evidence needed for a spend or recovery; the node must not guess.

## Agent access and budgets

Create ordinary authenticated BTX RPC users and restrict their allowed RPCs. Owner policy is separate from application input. A mandate's `principal` must equal the namespaced authenticated identity: `rpc:<username>` for a named RPC user, or `owner:cookie` for the local cookie and the local Qt console. A wallet-restricted RPC user is not a SwapNet owner and can act only on the wallet named by that restriction. Owner-only methods include mandate creation/revocation, market/policy changes and recovery export. Granting `-swapnetowner` gives broad policy authority, not merely permission to read prices.

All amounts are strings in the specified asset's atomic units. Set cumulative, per-trade, fee and expiry limits before trading. The maker's market policy includes an exact asset pair, rational price, size cap, fee terms, expiry and its outgoing mandate. Market configuration is owner intent; it is not taken from advertisements or incoming RFQs.

## Trading workflow

Read `listswapproviders`/`searchswaps`, call `requestswapquote` with exact sell asset, buy asset and atomic input size, then poll `getswapquotes` for that request. Compare minimum receive amounts rather than unadjusted headline prices. Accept a specific quote using `acceptswapquote`, an existing mandate ID and explicit local fee authorization. Monitor `getswap` and `listswapoperations`; `getswapevents` supports bounded event polling.

The node's worker continues already authorized execution/recovery while RPC callers disconnect. A timed-out RPC does not imply that no action occurred. Query the durable swap/operation IDs before issuing a new order. Do not repeat a commercial trade under a fresh quote merely because the first HTTP request timed out.

## Routine monitoring

`getswaphealth` checks audit continuity and reports worker errors/backlog. `getswaprouteinfo` distinguishes network reachability from price availability. `getswaprecoveryinfo` confirms whether durable refund material exists without returning it. Low gas, stale chain state, missing wallets, malformed contracts and insufficient inventory must be resolved locally; they are not reasons to bypass safety checks.

Preserve disk capacity and private datadir permissions. Keep the process and both chain verifiers online during obligations. Back up the native wallet and export the encrypted SwapNet recovery bundle after important state changes. A backup taken before funding cannot be assumed to contain later operations.

## Shutdown and disable behavior

Normal shutdown joins the embedded worker before native wallet teardown. Stop new market activity and revoke unused mandates before planned maintenance. Do not use `-swapnet=0` as a cancellation command: it disables the recovery worker too, while HTLC deadlines keep progressing on the chains. Pending funded swaps require continued operation or an independently tested recovery path.

## Distribution

Linux compilation is the initial local integration path. macOS and Windows require a packaged matched interpreter/development ABI, standard library and cryptography dependency plus native wallet/Qt regression tests. Existing Qt functionality is preserved; RPC console access is supplied, not an invented new graphical trading panel. No cross-platform binary qualification is claimed by the source archive.
