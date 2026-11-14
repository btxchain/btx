# Source map

## Embedded Python

| Module | Responsibility |
|---|---|
| `__init__.py` | BTX SwapNet integration candidate. No consensus changes; no implicit spending. |
| `adapters.py` | BTX P2MR and Bitcoin client adapters, with chain identity and exact-lock checks. |
| `application.py` | Native-node application: signed discovery, bounded routing, RFQ, and execution. |
| `assets.py` | Chain-qualified asset identities. A symbol is never an asset identifier. |
| `authorization.py` | Authenticated owner/agent budgets enforced immediately before every signature. |
| `bitcoin.py` | Bitcoin-only P2WSH HTLCs, canonical wire encoding, BIP143 SIGHASH_ALL. |
| `client.py` | Typed local agent SDK, bounded quote polling and explicit threshold acceptance. |
| `canonical.py` | SwapNet canonical JSON profile: ASCII keys, printable ASCII strings, no floats. |
| `coordinator.py` | Two-party HTLC execution, including restart/reorg/timeout recovery. |
| `discovery.py` | Signed provider catalog over existing BTX peers; no invented seed endpoints. |
| `drivers.py` | Operational BTX/Bitcoin drivers used by the native in-process coordinator. |
| `embedded.py` | Entry points called only by the compiled, isolated CPython node host. |
| `errors.py` | Stable machine-readable errors. Do not expose secrets in exception text. |
| `evm.py` | Ethereum-specific Keccak, ABI and EIP-1559 codecs plus pinned-contract reader. |
| `evm_driver.py` | Native-ETH execution with nonce-safe recovery intents and finalized-state checks. |
| `fee_bump.py` | Explicit, bounded replacement of a claim or refund; never reprice principal. |
| `journal.py` | Durable v2 execution journal. Network messages are never signing authority. |
| `machine.py` | Pure swap decision engine. Only locally verified observations enter this API. |
| `marketmaker.py` | Maker-side fixed-rational quotes with durable inventory reservations. |
| `plans.py` | Strict signer-side transaction plans. Network code cannot invent an approval. |
| `policy.py` | Conservative timing and budget policy; estimated block time is not a guarantee. |
| `psbt.py` | Bounded BIP174 map editing, with no BTX transaction deserialization. |
| `quote.py` | Signed executable quote format and deterministic, oracle-free ranking. |
| `recovery.py` | Encrypted consistent recovery bundles. No plaintext keys enter an RPC result. |
| `rpcclient.py` | Local RPC clients with bounded responses, no proxy use, redirects or peer URLs. |
| `service.py` | Authenticated local coordinator RPCs. Peer inputs have NO owner capabilities. |
| `store.py` | Crash-consistent reservations, mandates, immutable operations and audit events. |
| `terms.py` | Frozen two-chain settlement agreement, separate from an indicative price quote. |
| `vault.py` | Independent encrypted foreign-chain keys. NEVER accepts or derives a BTX seed. |

## Native boundary

`src/swapnet/node.*`: lifecycle/auth/core callback; `wallet_bridge.*`: native-only private provider merge; `embed.*`: isolated interpreter and callbacks; `runtime.*`: worker and queue; `transport.*`: peer admission and bounded frames; `src/rpc/swapnet.cpp`: 33 methods; `cmake/SwapNet.cmake`: frozen-source build integration.

## Tools

The package installer, diff planner, manifest verifier, schema checker, linked-host tests, local qualification runner and offline recovery tool are in `tools/`. Native/real-chain qualification source is in `qualification/` and `overlay/test/functional/`. The exact performed tests are listed in `evidence/VALIDATION_REPORT.json`.
