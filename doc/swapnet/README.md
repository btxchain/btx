# SwapNet v2

SwapNet is the native discovery and bilateral exchange subsystem described in `SPECIFICATION.md`. It uses the node's existing peers and wallet context while maintaining separate external-chain authorities. It does not modify BTX consensus or custody everyone's assets in a gateway pool.

For operating a node, read `OPERATIONS.md`, `BOOTSTRAP_AND_UX.md`, `KEYS_AND_WALLETS.md`, and `RECOVERY.md`. For integration, read `SOURCE_MAP.md`, `RPC.md`, `rpc-catalog.json`, and `schemas/`. For review and release, read `THREAT_MODEL.md`, `TESTING_AND_RELEASE.md`, and `IMPLEMENTATION_STATUS.md`.

The package's source implements the runtime. Executed component/embedded-host tests are distinct from target BTX builds and real-chain qualification. Do not infer a mainnet audit from the presence of source code or a passing deterministic-ledger test.
