# BTX Miner & Pool Readiness

This guide adds BTX-specific miner/pool readiness artifacts for the M7 milestone.
It builds on `doc/btx-mining-ops.md` by validating the full
`getblocktemplate -> stratum job -> submitblock` path under BTX's MatMul rules.

This legacy M7 harness does not clear the proposed MatMul v4.7 Epoch-A gates.
Before an activation-height review, pool software must additionally exercise
Profile 1 ExactReplay, header-first/no-chainwork-before-verdict behavior,
bounded back-to-back and three-branch reorg handling, admission starvation
resistance, and portable retry after a deliberately faulted device result.
Profile 2 and succinct-proof authority remain later, separately activated
epochs. See [the transition roadmap](btx-matmul-v4.7-transition-roadmap.md).

## Goals

- Stand up a regtest node with `-test=matmulstrict` to mirror the stricter BTX
  testnet path.
- Capture a canonical stratum-ready job snapshot (nonce range, target, payout,
  mempool policy).
- Exercise the external miner path by using `generateblock submit=false` and
  pushing the solved block via `submitblock`.
- Persist the collected data as a shareable artifact for pool/miner operators.

## Running the Readiness Script

```bash
scripts/m7_miner_pool_e2e.py build-btx --artifact doc/mining/m7-regtest-stratum-job.json
```

The script:

1. Launches `btxd` on regtest with strict MatMul validation enabled.
2. If wallet RPC is available, it creates a fresh descriptor wallet (`m7_pool`),
   generates 110 blocks for coinbase maturity, and injects a mempool transaction
   to mimic a pool payout path.
3. If wallet RPC is unavailable, it falls back to a walletless coinbase-only
   path while still validating BTX MatMul template/submission behavior.
4. Queries `getblocktemplate` and ensures the BTX nonce range is exposed as
   `0000000000000000ffffffffffffffff`.
5. Uses `generateblock` with `submit=false` and then calls `submitblock` to prove
   the external submission path is healthy.
6. Emits a JSON artifact (see below) summarizing the template, mempool entry, and
   accepted block header metadata.

If `--artifact` is omitted the script still performs all checks and prints a
summary of the verified job/submission pair.

## Artifact Layout

`doc/mining/m7-regtest-stratum-job.json` contains:

- `stratum_job.*`: the canonical template fields (height, previous block hash,
  target, nonce range, coinbase value, witness commitment) captured just before
  mining.
- `mempool_entry.*`: weight/fee/bip125 metadata for the transaction the pool
  decided to include (or `null` in walletless mode).
- `wallet_transaction.*`: the wallet RPC view of that transaction for traceability.
  This field is `null` in walletless mode.
- `submission.*`: block hash, mixhash, nonce64, and transaction ids proving the
  generateblock/submitblock pipeline exercised the BTX-specific header fields.

Operators can regenerate the artifact at any time to diff assumptions or to
seed automated checks around their stratum layer.

## Regtest/Testnet Alignment

Regtest with `-test=matmulstrict` uses the MatMul nonce layout and strict
validation path used to qualify BTX pool integration
(`src/kernel/chainparams.cpp`). This makes the collected artifact suitable for
verifying the legacy template/submission mechanics. It is necessary but not
sufficient for MatMul v4.7 testnet or mainnet activation.
