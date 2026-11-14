# Threat model and security review

## Trust boundaries

Untrusted: every peer, provider advertisement, quote, funding receipt, routing hop and counterparty. Conditionally trusted: independently operated local full-node RPCs with exact chain/contract pinning. Trusted computing base: native BTX process, OS/account, interpreter/system crypto installation, owner policy and local financial state. A compromised root or node binary can bypass software checks; no stronger hardware boundary is claimed.

## Enforced protections

Exact chain namespaces and domain-separated signatures prevent cross-network replay. Quotes and bilateral agreements bind size, price, fees, keys, beneficiaries and deadlines. External funding is independently verified; a provider's "funded" packet is not evidence. Mandates and agreement grants are separate from discovery identities. Peer data cannot become a `Principal`, select an RPC URL, call arbitrary wallet methods, change owner flags or install an asset policy.

Canonical wire JSON, exact fields, finite integer/byte/depth bounds, version/genesis admission, rate-limited native queues, bounded caches, routing fanout and replay tables constrain resource use. SQL uses parameters and single-transaction reservation changes. Stored signed transaction bytes are immutable; status outputs redact secrets. State revisions prevent accidental overwrite, and preimage exposure cannot roll back.

HTLC construction checks both branches and actual chain output commitments. UTXO funding permits one exact contract output plus owned change, verified input values and bounded fees. EVM operations bind nonce, chain, contract, calldata, value and fee budget; the runtime pins deployed code. Contract recipients and refund accounts are fixed. Pull payments and reentrancy guards isolate arbitrary recipient behavior. Unknown and transfer-tax/rebasing token routes are not enabled by the runtime.

## Residual risks and required qualification

Chain stalls and deep reorganizations can exceed planning assumptions. Fee caps can become too small to guarantee timely inclusion. Local node RPCs can be stale or missing historical data. Peer eclipsing can suppress discovery. A maker can lie about availability; quotes/reservations are not public proof of reserves. Public preimages create timing risk after exposure. Timeout recovery may need independent operator intervention when local hardware or both backups fail.

The embedded runtime is a substantial additional trusted dependency. Verify reproducible packaging, interpreter/crypto provenance, private filesystem permissions, native callback lifetime and shutdown ordering, wallet-key ownership, multiuser RPC boundaries, and platform ABI compatibility. A full-node build and adversarial tests are required; no static-source package is an independent audit.

Review data poisoning or forged chain responses at each adapter; nonce collisions and concurrent swaps; reorg after completion; partial writes; journal/backup rollback; exhausted disk; source installer interruption; source rollback with live obligations; and EVM credit withdrawal accounting. Never remove safeguards or silently downgrade confirmation requirements to make a demonstration succeed.

A fixed-rational maker policy does not certify fair market value. Owner-configured size, cumulative spend, fee and expiry limits constrain exposure, but a deliberately wrong price can still lose value within those limits. Inventory reservations are local controls, not transferable public proofs of exclusive reserves.
