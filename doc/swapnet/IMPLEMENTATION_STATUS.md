# Implementation and qualification status

The runtime implementation, native lifecycle/network/RPC adapters, wallet-only HTLC provider bridge, durable coordinator, external-chain transaction drivers, backup/restore, schemas and local integration tools are supplied as source. They replace the disconnected reference-only execution path in the earlier package.

Executed validation is documented in the package's `evidence/VALIDATION_REPORT.json`: Python component/application/ledger/recovery tests, standalone native transport, linked C++ worker/frozen Python runtime with mocked native chain calls, JSON schemas/RPC coverage and installer/rollback fixture tests.

**Not executed here:** full merged BTX checkout compilation; actual native wallet/P2P functional suite; actual BTX/BTC settlement/refund/restart; Solidity compilation/Foundry; actual BTX/ETH settlement and withdrawal; packaged macOS/Windows builds; independent audit. The package includes commands, test source and acceptance materials for those gates. No receipt or deployed address is invented.

Implemented scope is bilateral native BTX/BTC and BTX/ETH. ERC-20 runtime routing, AMM pools, wrapped balances, partial fills, economic multihop, a new graphical trading panel and public proof-of-reserves certification are not advertised as implemented. Existing Qt behavior is preserved and the RPC console shares the native API.
