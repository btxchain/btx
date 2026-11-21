# Public signed offers, version 1

## Security objective

SwapNet is an independently settled native exchange path, not a custodian or a privileged matching venue. The threat model includes a financially conflicted intermediary. No named intermediary misconduct is assumed to have been publicly proven. Visible unfavorable prices remain lawful protocol inputs; users choose whether to accept. The protocol prevents hidden changes to agreed consideration and unnecessary custody, not voluntary transfers or concentration of holdings.

## Wire identity and signatures

An offer is `{body, signature}` signed by the native provider identity under `BTX/SWAPNET/PUBLIC-OFFER/1`. The body binds version, exact BTX network genesis, provider, random offer ID, monotonic sequence, issue/expiry times, kind, exact input/output asset identifiers, tiers and a withdrawal flag. Every amount is a canonical nonnegative decimal integer string in atoms. Floating point never participates in price comparison or authorization.

Each tier specifies exact taker input, gross output, maker fee, maximum receive-network fee and a finite slot count. The minimum net output is gross minus the two disclosed output-side deductions. Outgoing fees remain separately authorized in the paying asset. Public offers do not add an unbounded spend grant.

Limits in the implementation are authoritative: a record is at most 24 KiB, maximum offer TTL 300 seconds, at most eight tiers, at most 64 slots, 2,048 live records and a bounded persistent replay ledger. The parser rejects unknown fields, invalid signatures, noncanonical amounts, duplicate tiers, invalid chains, expired/future records and sequence equivocation.

## Indicative versus firm

An indicative offer reserves no financial capacity. It cannot be accepted directly; the user requests a fresh requester-bound signed quote.

A firm offer creates a durable local reservation for its finite slots before publication. Capacity accounting includes other public offers, current outstanding maker quotes, existing mandate-held and spent totals, per-trade and fee limits, and a fresh independently observed local balance. This is a local protocol promise, not proof of reserves or on-chain collateral. A modified maker can lie, and an owner can spend externally; the actual HTLC funding is the stronger counterparty evidence.

A requester chooses one offer revision and tier and signs the request. The maker atomically assigns one available slot to that exact RFQ. A repeated RFQ resolves the same allocation. Two distinct requesters cannot consume the same slot. The generated legacy quote is bound to the requester and original exact economics; a public bound quote cannot change its quantities during proposal handling.

## Capacity handoff

The public hold remains until it is represented by a requester-specific maker quote. At proposal acceptance, the maintained coordinator creates the reverse maker-debit quote. The Store reservation code credits public capacity only when the exact original signed quote, initiator, nonce, inverse assets and quantities match; a reused nonce is not enough. The hold-to-monetary-reservation transition occurs in the same SQLite transaction as the normal reservation update. All other public slots still count against the mandate.

Withdrawal releases unallocated slots and publishes a higher-sequence tombstone. Bound requester quotes remain available until their original expiry; signed agreements and durable operations are not revoked by deleting an advertisement. Expiry releases only uncommitted capacity. Restart reconstructs the same slot states from the financial journal.

## Discovery protocol

Legacy `swhello` version 2 remains unchanged. New peers exchange `swcap` only after normal SwapNet admission. `swoget` requests bounded keyset pages; `swopage` returns signed records and continuation state. `swoffer` relays one signed update. `sworeq` carries the signed directed request for a public tier. Unknown capability commands are ignored by old peers; only negotiated-capable peers carry extensions.

Pagination binds each reply to a pending random request token and checks ordering/cursor progress. Receivers verify signatures before accepting records or learning provider routes. Records can be relayed by anyone; no trusted market server controls admission. Bounded route alternatives and retries preserve delivery when one forwarding peer becomes unavailable.

A direct public-tier request is not broadcast to every node when a maker route is known. This reduces information exposure; it is not end-to-end encryption and does not establish anonymity. The private RFQ protocol remains available, with its existing disclosure properties.

## Failure records

A signed explicit refusal is retained with its signer and request binding. Silence is a local timeout, not proof of maker malice. No automatic collateral penalty or global reputation ban is imposed. A provider can charge a wide spread; the recipient can decline. No official oracle, price floor, affiliated token or market-maker whitelist is required.
