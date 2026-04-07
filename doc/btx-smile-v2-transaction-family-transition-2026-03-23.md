# BTX SMILE V2 Transaction-Family Transition

> Status note (2026-04-02): this document describes the pre-`61000`
> transaction-family transition baseline on `main`. It is not the final
> post-fork architecture summary. After the `61000` hardening fork, direct
> public-flow `v2_send` is no longer the live post-fork path and lifecycle
> controls have moved onto a dedicated `V2_LIFECYCLE` family. Use
> [doc/security/current-status.md](security/current-status.md) and
> [doc/security/hardfork-61000.md](security/hardfork-61000.md) for the live
> hardening-fork state.

Date: 2026-03-23

Status:
- merged on `main` via PR `#115`

## Goal

Move every live wallet-built shielded transaction family that still depended on
legacy mixed-bundle construction onto the reset-chain SMILE v2 surface, while
keeping the already-live bridge families on their dedicated v2 paths.

This pass is about live construction and validation surfaces. It does not
delete every historical MatRiCT parser, test vector, or benchmark harness from
the tree.

## Final Pre-`61000` Live Transaction Matrix

| User-visible flow | RPC / builder | Live family | Proof path |
| --- | --- | --- | --- |
| Transparent -> shielded deposit | pre-`61000`: `z_shieldfunds`, `z_shieldcoinbase`, transparent-fallback `z_sendmany`; post-`61000`: mature-coinbase `z_shieldcoinbase` / compatible sweeps only | `v2_send` | proofless `v2_send` |
| Shielded -> shielded direct send | `z_sendmany`, `z_sendtoaddress` | `v2_send` | `DIRECT_SMILE` |
| Shielded -> transparent unshield | `z_sendmany` with transparent recipient, `UnshieldFunds()` | `v2_send` | mixed `DIRECT_SMILE` |
| Shielded note merge | `z_mergenotes`, `MergeNotes()` | `v2_send` | `DIRECT_SMILE` |
| Bridge ingress | bridge RPC batch builders | `v2_ingress_batch` | shared-ring `BATCH_SMILE` |
| Bridge egress | bridge RPC batch builders | `v2_egress_batch` | v2 egress surface |
| Rebalance | rebalance builders | `v2_rebalance` | v2 rebalance surface |
| Settlement anchor | settlement builders | `v2_settlement_anchor` | v2 settlement surface |

Mining / validation relevance:

- wallet-originated transparent->shielded funding and mixed unshield now enter
  mempool and blocks through `v2_send`
- synthetic miner / consensus fixtures were updated to build shielded sends on
  the same v2 accounting path, so fee, anchor, and nullifier handling are
  exercised on the new surface

Residual in-tree non-launch code:

- `DIRECT_MATRICT`
- native MatRiCT ingress shards
- receipt-backed ingress

These remain for parsing compatibility, historical tooling, and adversarial /
regression tests. They are not part of the reset-chain wallet launch surface.

## Benchmark Snapshot

Measured from:

- `python3 build-btx/test/functional/wallet_smile_v2_benchmark.py`
- local transparent baseline probe on regtest with `-autoshieldcoinbase=0`
  measuring a canonical `1-in/2-out witness_v2_p2mr` send

Current pre-`61000` baseline results:

| Flow | Bytes | Weight | Sample prove time | 24 MB fit | TPS @ 90 s |
| --- | ---: | ---: | ---: | ---: | ---: |
| Deposit `v2_send` | `19,172` | `19,172` | `0.221 s` | `1,251` | `13.90` |
| Direct `1x2 v2_send` | `60,218` | `60,218` | `22.708 s` | `398` | `4.42` |
| Mixed unshield `v2_send` | `44,330` | `44,330` | `10.875 s` | `541` | `6.01` |

Sequential direct-send sample:

- average prove time: `28.338 s`
- average tx weight: `60,202.333`
- max direct-send txs per `24 MB` block: `398`
- theoretical direct-send TPS: `4.42`

Headline mixed-L1 throughput assumption:

- `24 MB` serialized block cap
- `90 s` target block time
- `50%` of block bytes reserved for direct `1x2 v2_send`
- `50%` of block bytes reserved for measured transparent
  `1-in/2-out witness_v2_p2mr`
- transparent baseline: `3,916` bytes
- direct wallet-produced `1x2 v2_send`: `60,218` bytes

Mixed result:

- `199` shielded direct sends + `3,064` transparent sends
- `3,263` total tx / block
- about `36.26 TPS`

Important outcome:

- the old live wallet unshield path previously measured around `689 KB`
  because it fell back to the legacy mixed proof stack
- the current live mixed unshield path is now `43.8 KB` and uses `v2_send`
- repeated 2-input CT proving and repeated wallet-level multi-input send /
  unshield loops are now part of the regression suite to catch prover retry
  crashes instead of only benchmarking the happy path

## Verification

Build:

- `cmake --build build-btx -j8 --target test_btx`
- `cmake --build build-btx -j8 --target bitcoin-tx bitcoin-util btx-genesis`

Unit tests:

- `test_btx --run_test=shielded_v2_send_tests`
- `test_btx --run_test=shielded_v2_proof_tests`
- `test_btx --run_test=shielded_v2_bundle_tests`
- `test_btx --run_test=shielded_validation_checks_tests`
- `test_btx --run_test=shielded_bridge_tests`
- `test_btx --run_test=smile2_ct_tests`
- `test_btx --run_test=miner_tests`
- `test_btx --run_test=pq_consensus_tests`
- `test_btx --run_test=txvalidation_tests`

Functional tests:

- `python3 build-btx/test/functional/wallet_shielded_rpc_surface.py`
- `python3 build-btx/test/functional/wallet_shielded_send_flow.py`
- `python3 build-btx/test/functional/wallet_smile_v2_full_lifecycle.py --descriptors`
- `python3 build-btx/test/functional/wallet_smile_v2_benchmark.py`

## Pre-`61000` Production Reading

For the current reset-chain launch surface on `main`:

- live wallet-built shielded families are on v2
- direct private spend remains `DIRECT_SMILE`
- mixed transparent-edge send / unshield is no longer stuck on the legacy
  mixed proof path
- remaining MatRiCT code in-tree should be read as compatibility / tooling /
  adversarial coverage, not as the active launch backend
