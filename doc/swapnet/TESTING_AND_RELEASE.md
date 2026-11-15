# Testing and release acceptance

## Executable layers

Run `tools/run_checks.sh` for Python components/application, native transport, linked frozen embedded runtime, schemas/RPC consistency and source installer tests. These tests run locally and report their actual exit status. Deterministic ledgers are explicitly labeled in the test source and cannot be called on-chain evidence.

Use `tools/qualify_local.sh` against the actual merged BTX checkout for build, CTest and native functional execution. `feature_swapnet.py` tests default discovery, native RPC coverage, restart persistence and the disable switch. Existing wallet/HTLC tests must remain green. Run the wider repository functional suite, including ModelNet and Qt behavior, before distribution.

Use `qualification/live_regtest.py` with independent funded BTX and Bitcoin nodes for `settlement`, `restart`, and `refund`. It requires an explicit test-funds flag, rejects non-regtest networks, sends real native RPCs, mines through configured local test-chain RPCs, and records real transaction receipts. It returns failure for missing states, duplicate funding operations, wrong chains or timeouts. No test-network endpoint or genesis is fabricated in the package.

`tools/test_contracts.sh` runs preinstalled Foundry/solc offline. Exit 77 means NOT_RUN, not PASS. Compile the supplied contract, execute positive/negative/fuzz tests, and compare the deployed runtime to the exact locally approved artifact. EVM settlement is not complete until the recipient's exact pull withdrawal is finalized.

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
