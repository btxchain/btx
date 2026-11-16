# Testing and release acceptance

## Executable layers

In `contrib/swapnet`, install the test extras with `python3 -m pip install -e '.[test]'` and run `python3 -m pytest tests -q` for the Python components and application. In a build configured with `-DBUILD_TESTS=ON`, `ctest --test-dir build -R swapnet` runs the native transport (`swapnet_transport`) and the linked frozen embedded runtime (`swapnet_embed`). These tests run locally and report their actual exit status. No test in this tree checks the JSON schemas or `rpc-catalog.json`, and there is no installer to test. Deterministic ledgers are explicitly labeled in the test source and cannot be called on-chain evidence.

Build the actual merged BTX checkout with `-DBUILD_TESTS=ON`, run CTest, and run `build/test/functional/test_runner.py feature_swapnet.py rpc_swapnet_principal.py p2p_swapnet_frames.py wallet_swapnet_relock.py` for native functional execution. `feature_swapnet.py` tests default discovery, native RPC coverage, restart persistence and the disable switch. Existing wallet/HTLC tests must remain green. Run the wider repository functional suite, including ModelNet and Qt behavior, before distribution.

No script in this tree runs a live settlement. Live evidence for `settlement`, `restart`, and `refund` uses independent funded BTX and Bitcoin nodes on regtest, sends real native RPCs, mines through local test-chain RPCs, and records real transaction receipts. A missing state, a duplicate funding operation, a wrong chain or a timeout is a failure. The receipts listed below are that evidence. No test-network endpoint or genesis is fabricated in this tree.

In `contrib/swapnet/contracts`, with Foundry and solc 0.8.24 already installed, run `forge test --offline`; `foundry.toml` pins the compiler, EVM version and optimizer. Without them the layer is NOT_RUN, not PASS. Compile the supplied contract, execute positive/negative/fuzz tests, and compare the deployed runtime to the exact locally approved artifact: `cast keccak $(forge inspect SwapNetHTLC deployedBytecode)` must match the runtime hash in `OPERATIONS.md`. EVM settlement is not complete until the recipient's exact pull withdrawal is finalized.

## Required release matrix

| Gate | Evidence needed |
|---|---|
| Combined baseline | Exact commit, ancestry/equivalence review and installed patch hash. |
| Native build | Configure/build logs, compiler/Python/crypto versions and binary hashes. |
| Existing functionality | BTX wallet, ModelNet, networking, consensus and Qt regressions. |
| Two-party BTX/BTC | Independent nodes, exact HTLC outputs, signatures, beneficiaries and final balances. |
| Restart | Stop at committed/prepared/broadcast/secret-exposed stages; no duplicate funding. |
| Refund | Missing short funding, withheld preimage, offline counterparty, exact maturity boundary. |
| Authorization | Non-owner policy refusal, cross-principal isolation, cumulative budgets, revocation. |
| Network hostility | Replay, reordered/duplicate/lost packets, forged signatures, stale ads, wrong network, queue exhaustion. |
| Chain hostility | Wrong genesis, stale tip, missing/pruned data, funding replacement, reorg before/after exposure. |
| Fees | Bounded claim/refund replacement, no principal/beneficiary change, EVM withdrawal reserve. |
| EVM contract | solc/Foundry tests, exact runtime pin, nonce persistence, actual lock/claim/refund/withdrawal. |
| Recovery | Offline encrypted restore plus native wallet restore; corrupted/password/network mismatch refusal. |
| Distribution | Clean-user installation and native lifecycle on each platform actually advertised. |
| Review | Independent security review appropriate to funds at risk and documented residual risks. |

## Receipt discipline

Keep exact commands, timestamps, exits and reproducible fixtures. Report SKIP/NOT_RUN distinctly from PASS. A local test report must identify whether chain calls were mocked or real. Successful compilation does not prove economic correctness; a completed happy-path swap does not prove hostile-case recovery. Do not call the source archive a mainnet-qualified release until the necessary external receipts exist.

Independent evidence for the two-party BTX/BTC, BTX/ETH, restart, refund, maturity-boundary, and EVM lock/claim/refund/withdrawal rows names the commit, the commands, and whether each call was a real `btxd`, `bitcoind`, or EVM RPC. Those receipts are not stored in this tree. A public-testnet receipt is the same kind of evidence and does not by itself qualify mainnet.

Two such reports are on pull request 714. One covers the v0.34.16 tag `074dac16` with real regtest calls to btxd, Bitcoin Core, and anvil, including BTX/BTC settlement, BTX/ETH settlement, a restart, refunds, and the maturity boundary. The other covers SwapNet recovery on `release-0.34.17` at `0cb6f63e`, with real regtest restarts and anvil refunds. Neither report is a mainnet qualification, and this tree does not repeat those runs.
