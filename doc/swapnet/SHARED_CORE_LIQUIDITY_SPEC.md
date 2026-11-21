# Shared P2P and decentralized liquidity specification

## 1. Objective and threat model

BTX should have a native, permissionless way to enter and exit its monetary ecosystem without making a custodian, exclusive dealer, hosted registry, or exchange-issued token mandatory. The design treats alleged intermediary extraction as a conditional threat model, not an established allegation against a particular firm.

The system protects custody, authorization, authentic terms, independent chain verification and recovery. It does not guarantee demand, fiat value, competitive prices, available inventory, independent economic owners, or the absence of external market manipulation. Honest selling is not an attack on the currency. A counterparty delivering real value under a freely accepted quote is not automatically extracting value merely because its inventory changes.

## 2. Existing economic primitive

Retain bilateral, exact-size native BTX/BTC and BTX/ETH swaps. Every enabled route has a native BTX leg. The existing initiator-long/responder-short HTLC sequence, signed agreement, exact outputs, monotone preimage exposure, durable operation journal, immutable raw transactions and refund authority remain the sole financial engine.

There is no pool of gateway balances, wrapped claim, privileged mint, central clearing balance, implicit economic multihop, or automatic partial-fill strategy. A networking next hop is never an economic intermediary. New market controls decide whether a new agreement may be attempted; they do not replace chain observations with provider assertions.

## 3. Shared core, service boundaries and transports

One `shared_p2p::Core` instance is selected per exact chain genesis by `ForNetwork`. It contains bounded service registration, admitted peer handles, control-plane rate budgets, route alternatives, fair queue primitives and pagination cursors. Services register immutable local policies, not policies received from peers. At most 16 services and 16 network cores exist per process.

SwapNet and ModelNet adapters share this core. SwapNet admits an existing BTX peer only after its normal network handshake and compatible SwapNet hello; it learns a route only after service-level signature validation. ModelNet admits a session only after its existing strict PQ1 authentication and exact native-network verification. Its pinning, signed provider records and resource verification stay in the ModelNet service layer.

The core never loads a wallet, creates a key, verifies a block, dials a peer URL, runs a model, installs a policy or signs a transaction. A module cannot query or consume another module's route or queue namespace. A peer cannot set a local authenticated-session boolean by sending it in a JSON object.

This is a shared control plane with multiple authenticated transport adapters. Existing BTX packet framing and ModelNet PQ1 bulk data transport remain. Unifying those sockets by removing PQ1 would be a security regression, not a successful implementation.

### Resource policy

Service-specific maximum frame sizes are 64 KiB for SwapNet and 4 MiB for ModelNet control responses; queues have explicit byte/frame/peer bounds. Generic queues use weighted recovery/control/discovery/bulk scheduling with peer rotation. Modules classify priority only after validating semantics. Existing financial queues remain authoritative until a separately tested native replacement consumes the generic scheduler end to end.

Routing retains up to four candidate relays per identity and up to 8,192 identity routes. A later replay cannot displace a healthy primary hop or extend the lifetime of an identical proof. Retries rotate candidates and eventually use a bounded, rotating fallback fanout. Enqueue success is not treated as a remote ACK. Expiry is derived from verified signed lifetime and translated to monotonic native time.

Catalog requests use legacy-compatible signed provider frames with bounded, resumable page streaming and backpressure. Providers are not assumed fully enumerated simply because the first page arrived. Bounded streams can expire under partitions or congestion; this is visible rather than a fabricated complete market view. Provider sequence tombstones expire conservatively only after the maximum signed-record lifetime; active records retain replay protection.

## 4. Modes and spending authority

A new installation starts in `taker` so discovery and quote requests are dogfooded. Taker mode has no spending mandate. A returning installation retains a mode deliberately chosen by its owner. Explicit startup overrides are local operator authority, never a network field.

Modes:

| Mode | New taker agreement | New maker agreement | Existing recovery |
|---|---:|---:|---:|
| observe | No | No | Yes |
| trade | Yes, separately authorized | No | Yes |
| maker | Yes, separately authorized | Yes, separately authorized | Yes |
| recovery | No | No | Yes |

Changing mode commits the setting before reporting success. A rejected settings write must not change live admission. A mode is not a mandate. `-swapnet` defaults on. `-swapnet=0` stops the engine. `-swapnetmode=recovery` keeps the recovery worker and refuses a switch to maker or taker until restart.

Accepted existing sessions retain original authority and exact terms. Revocation and cancellation retain the existing coordinator's distinctions among uncommitted, prepared, funded and secret-exposed positions. Do not silently turn a mode transition into a refund request or create a new signature for a different agreement.

## 5. Taker price controls

All monetary arithmetic is integer or exact rational arithmetic. Canonical atomic strings reject floating point, exponents, signs, leading-zero ambiguity and values beyond uint256. Native BTX/BTC units must not be interchanged with wei.

A local execution policy may require a minimum net receive amount, bounded receive-fee share, a minimum count of distinct valid signing identities, exclusion of selected identities, and a maximum adverse deviation from an owner-selected reference. No default hosted oracle is embedded. Sources have exact pairs, rational rates, issuance/freshness limits, expiries and explicitly configured names. The median is computed exactly.

A count of signing identities is not proof of independent firms. A quorum of provider URLs is not a light client or proof of finality. The UI must make those limits visible. Price references constrain an owner's own behavior, not the market or consensus. There is no official BTX floor price.

A quote must still pass the original signature/network/requester/pair/size/expiry checks. Policy evaluation never manufactures another provider's quote, alters the signed rate, changes a beneficiary, or silently chooses a less favorable route.

## 6. Preview and confirmation

A preview binds the exact verified quote, local principal, selected wallet, fee caps, policy digest, creation time and short confirmation expiry. Its ID is a domain-separated digest with a random nonce. Previewing does not sign, reserve inventory, generate a funding transaction or authorize spending.

Confirmation requires explicit consent. It rechecks principal/wallet binding, expiry, policy revision, current admission mode and execution policy before calling the existing coordinator. The signed quote determines the stable swap ID. A crash between acceptance and saving the preview acknowledgement is reconciled against that same session; it must never mint a second payment.

A local owner may explicitly request a one-trade mandate. It covers only the exact outgoing amount plus the chosen fee cap, has an exact principal and outgoing asset, and expires after a bounded authorization interval. Named agents cannot create that authority unless they are explicitly configured as owners. Otherwise confirmation requires an existing owner-issued mandate.

A preview binds pricing and authorization, not a promise that negotiated HTLC deadlines already exist. Exact deadlines remain governed by the existing conservative timing checks and signed bilateral agreement. Show that distinction in UI and documentation.

## 7. Maker policies and admission

Makers can set fee-aware minimum sizes, an inventory floor, target inventory, a capped rational inventory skew/spread and per-requester outstanding quote limits. These are owner policies. No advertisements set them.

An inventory-heavy maker may pay more of its outgoing asset; an inventory-light maker may pay less. The signed quote freezes the resulting price. A later inventory observation does not retroactively reprice it. The issued-quote ledger and current strategy digest must validate a dynamic quote at acceptance. A changed owner strategy can refuse an old unfunded offer; already funded recovery remains unchanged.

Reservations are local risk controls, not proof of exclusive reserves. A provider may still withhold funding or disappear. Per-identity limits reduce cheap repeated requests but do not solve Sybil identity creation. No punitive on-chain bond is introduced without a separately reviewed two-chain protocol.

## 8. Chain readiness, EVM provenance and finality

Bitcoin setup discovers only an already-running, matching local node using the existing cookie rules. It refuses ambiguous funding wallets. Creating a distinct descriptor watch wallet with private keys disabled is an explicit owner-consented action. It never imports a BTX seed, derives a Bitcoin key from a PQ key, or sends funds.

EVM new-trade readiness requires the existing chain/genesis/runtime checks plus finalized creation provenance. The exact pinned init-code hash must match a canonical successful direct creation or the pinned deterministic proxy/salt profile. A matching runtime alone does not prove initial storage. No deployed address or public success receipt is invented.

Creation verification is a new-trade preflight, not a prerequisite for loading the driver or recovering an existing obligation. If the proof is missing or a historical RPC is unavailable after restart, recoverability must be retained while new trades fail closed.

The `latest` to `finalized` timestamp lag must be bounded at maker quote, taker acceptance and new maker acceptance. Running swaps continue to use the original reveal/refund rules; do not suspend recovery merely because a preflight would reject a new trade. No silent fallback from finalized to latest is allowed.

Per-session chain-RPC backoff adapts #749 to the rotating #805 scheduler. It does not let one failed endpoint monopolize every tick. Explicit resume remains immediate. Errors, pending IDs and ambiguous broadcasts remain durable; a timeout never proves that a transaction did not escape.

## 9. Local market quality and optional disclosure

Metrics are derived from actual local session outcomes, grouped by exact asset pair and unit. They report settled outgoing volume, refunds, pending/unknown positions and provider-identity concentration. A bounded page is labelled as a page; its concentration score is not global network concentration. Reorganized-out outcomes must stop counting as completed observations.

Receipt export is owner/principal scoped and explicitly opt-in. It includes public signed terms, agreement signatures, selected transaction identifiers and the locally observed outcome. It excludes private keys, preimages, raw signed transactions, private handles, credentials and arbitrary unvalidated session fields. It warns that publishing creates links among participants and chain transactions.

An outage or timeout is not an attribution of misconduct. Provider histories are not solvency certificates. A legal allegation or punishment must not be generated automatically from a local incomplete observation.

## 10. UX and packaging

Qt and CLI use the same native RPC methods. The dialog displays exact net proceeds, outgoing fee caps, local policy decisions, current mode and recovery status. Calls run off the UI thread. Closing the dialog does not stop the node's financial worker. Pause means stop new admissions, not abandon funds.

Use a single owner-consented setup action for the Bitcoin watch wallet. EVM readiness must display the unresolved verifier/gas/deployment prerequisite instead of substituting a public gateway or fake liquidity. No one can honestly make a fresh installation own external coins or an independently verified chain merely by removing a configuration dialog.

Package matched Python/cryptography dependencies, the restore tool and their exact provenance. The optional DPAPI helper remains inactive until tested with portable encrypted recovery. Full disk/account compromise remains in the trusted-computing-base risk model.

## 11. Qualification and rollout

Review source and generated patch separately from executing tests. Require focused component tests, full Python regression, native transport/runtime tests, all supported platform builds, Qt flows, clean-user packages, mixed-version interoperability and real funded regtest/Anvil lifecycle/fault tests.

Roll out default observation only after monetary-node startup/lifecycle regression tests pass. Enable small authorized trade budgets on test networks before production. A missing test is NOT_RUN. A passing simulation is not a chain receipt. Neither source presence nor a green packaging probe establishes mainnet safety.

## 12. Deliberately deferred protocol changes

AMMs, economic multihop, partial fills, generalized ERC-20 routes, chain light-client implementations and enforceable cross-chain penalty bonds need their own specifications, cryptographic/consensus review and acceptance matrices. They are not required to provide native noncustodial BTX/BTC and BTX/ETH exchange, and are not labelled implemented by this package.
