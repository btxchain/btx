# Testing and release acceptance

## Executable layers

In `contrib/swapnet`, install the test extras with `python3 -m pip install -e '.[test]'` and run `python3 -m pytest tests -q` for the Python components and application. In a build configured with `-DBUILD_TESTS=ON`, `ctest --test-dir build -R swapnet` runs the native transport (`swapnet_transport`) and the linked frozen embedded runtime (`swapnet_embed`). These tests run locally and report their actual exit status. No test in this tree checks the JSON schemas or `rpc-catalog.json`, and there is no installer to test. Deterministic ledgers are explicitly labeled in the test source and cannot be called on-chain evidence.

Build the actual merged BTX checkout with `-DBUILD_TESTS=ON`, run CTest, and run `build/test/functional/test_runner.py feature_swapnet.py rpc_swapnet_principal.py p2p_swapnet_frames.py wallet_swapnet_relock.py` for native functional execution. `feature_swapnet.py` tests default discovery, native RPC coverage, restart persistence and the disable switch. Existing wallet/HTLC tests must remain green. Run the wider repository functional suite, including ModelNet and Qt behavior, before distribution.

The [native market runner](../../contrib/swapnet/qualification/live_market.py) exercises settlement, pause and restart through real local RPCs. From the checkout root, run it with a prepared disposable lab configuration and native build evidence:

```sh
python3 contrib/swapnet/qualification/live_market.py --lab LAB.json --output RESULTS
```

On report completion, the runner exits 2 and writes a partial `NATIVE_LIFECYCLE_REPORT.json`. Read the individual results in that file. A passing case verifies settlement state and exactly one original funding operation per party. The runner marks refund, reorg, exact four-wallet balance reconciliation and cross-platform qualification as `NOT_RUN`.

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

Two such reports are on pull request 714. One covers the v0.34.16 tag `074dac16` with real regtest calls to btxd, Bitcoin Core, and anvil, including BTX/BTC settlement, BTX/ETH settlement, a restart, refunds, and the maturity boundary. The other covers SwapNet recovery on `release-0.34.17` at `0cb6f63e`, with real regtest restarts and anvil refunds. A later report on that pull request, measured on the same `0cb6f63e` tree, is a six-hour one-box regtest soak: 138 swaps, 89 completed, 49 refunded, and none left stuck. Its stops were clean RPC stops, and the SwapNetHTLC hashes were checked again at `1e2f8b5f`. None of these reports is a mainnet qualification, and this tree does not repeat those runs.

Two later reports on `a97af7b3` used separate native test controllers on macOS ARM64:

- [Public BTX/BTC](https://github.com/btxchain/btx/pull/714#issuecomment-6973496820): real `btxd` and Bitcoin Core 32.1 regtest RPCs. Settlement, funded restart and the original-payment refund passed. The shared control socket failed to start with the fixture's long paths.
- [Public BTX/ETH](https://github.com/btxchain/btx/pull/714#issuecomment-6975876573): real `btxd` regtest and Anvil RPCs. Settlement, finalized ETH withdrawal and terminal accounting passed. The funded restart occurred after BTX funding and before ETH funding. The run leaves post-ETH-funding interruption and ETH refund untested.

Both runs used a diagnostic serial CPU profile. Their receipts record the test settings, binary identities and limits.
