# PR #129 tracking: shielded transfer builder

Status on branch `fix/z-finalizepsbt-crash`:

- `z_finalizepsbt` crash fix: complete
- live-chain sync hardening in `z_finalizepsbt`: complete
- authoritative `z_fundpsbt` fee quote fields: complete
- deterministic multisig-to-shielded transfer bundle tool: complete
- `lockunspent` awareness in transparent shielding input selection: complete
- regtest coverage for bundle planning, simulation, execution, and block packing: complete

## Scope added in this PR

The branch now includes a deterministic operator tool at:

- `contrib/shielded_transfer_builder.py`

The tool is intentionally thin. It does not replace wallet logic. It drives the RPCs already fixed in this PR:

- `z_planshieldfunds`
- `z_fundpsbt`
- `walletprocesspsbt`
- `z_finalizepsbt`
- `testmempoolaccept`

That keeps the authoritative planning, fee analysis, and mempool admission logic inside the daemon.

One important nuance from implementation:

- the tool prefers `z_planshieldfunds` when the source wallet can provide a preview directly
- if the source wallet's preview path requires shielded-key state or attempts full multisig signing prematurely, the tool falls back to the same deterministic `largest-first` transparent UTXO ordering used by the daemon and then relies on authoritative `z_fundpsbt` quotes for the real plan

## Safety model

The tool builds and preserves real unsigned PSBTs as the canonical plan object.

That means the plan preserves:

- selected transparent inputs
- change outputs and change addresses
- destination addresses
- destination amounts
- explicit fees chosen for each transaction
- deterministic transaction ordering
- deterministic block packing metadata

The flow is split into explicit phases:

1. `plan`
2. `simulate`
3. `execute`
4. `release` (optional unlock if execution is deferred or cancelled)

## Deterministic planning rules

- destination order is preserved exactly as provided on the command line
- each destination is chunked greedily using the daemon's planner
- each chunk is rebuilt with `z_fundpsbt` until `required_mempool_fee` converges
- planning fails closed if `fee_authoritative` is false
- selected inputs can be locked immediately so later wallet activity does not perturb the plan
- block grouping is computed deterministically from transaction order, weight budget, and sigop budget

## Fee handling model

The tool adjusts from preview fee to authoritative fee before the plan is written.

For each chunk:

1. call `z_planshieldfunds` when available, otherwise build a deterministic largest-first preview from unlocked transparent UTXOs
2. take the first chunk preview
3. build a real PSBT with `z_fundpsbt`
4. read `required_mempool_fee`
5. reduce the chunk amount if the authoritative fee is higher than the preview fee
6. rebuild until the amount and fee stabilize

That produces a plan which already reflects current-node mempool policy.

`simulate` then signs the exact PSBT set, finalizes with `broadcast=false`, and runs `testmempoolaccept` on every finalized transaction before execution is allowed.

## Intended operator flow

Example:

```bash
python3 contrib/shielded_transfer_builder.py plan \
  --datadir=/path/to/datadir \
  --chain=main \
  --rpcport=19334 \
  --rpcwallet=signer-1 \
  --signer-wallet=signer-1 \
  --signer-wallet=signer-2 \
  --signer-wallet=signer-3 \
  --destination=btxs1...=1000.00000000 \
  --destination=btxs1...=500.00000000 \
  --bundle=/tmp/transfer-bundle.json
```

```bash
python3 contrib/shielded_transfer_builder.py simulate \
  --datadir=/path/to/datadir \
  --chain=main \
  --rpcport=19334 \
  --bundle=/tmp/transfer-bundle.json \
  --simulation=/tmp/transfer-simulation.json
```

Inspect the bundle and simulation files, then execute:

```bash
python3 contrib/shielded_transfer_builder.py execute \
  --datadir=/path/to/datadir \
  --chain=main \
  --rpcport=19334 \
  --bundle=/tmp/transfer-bundle.json \
  --simulation=/tmp/transfer-simulation.json \
  --result=/tmp/transfer-execution.json
```

If the transfer is postponed and the planned inputs were locked, release them with:

```bash
python3 contrib/shielded_transfer_builder.py release \
  --datadir=/path/to/datadir \
  --chain=main \
  --rpcport=19334 \
  --bundle=/tmp/transfer-bundle.json
```

## Merge bar for this added scope

This scope has now met the merge bar on the branch:

- the new functional test passes on regtest
- the tool proves multi-destination planning and deterministic execution
- the simulation phase confirms every finalized transaction via `testmempoolaccept`
- the bundle file is preserved bit-for-bit between simulation and execution via digest checks
- the daemon-side transparent shielding selector now respects `lockunspent`, which the bundle planner depends on

## Follow-up hardening after the initial builder landing

The builder has since been hardened further with:

- `btx.conf` support in the same config lookup path as `bitcoin.conf`
- RPC auth resolution from config files in addition to cookie auth
- deterministic fallback planning from one sorted UTXO snapshot instead of repeated full-wallet resorting
- explicit exclusion of pre-existing locked inputs from fallback planning
- temporary lock semantics for `--no-lock-inputs`, so planning remains deterministic without leaving persistent locks behind
- focused regression coverage for pre-existing locked inputs in addition to the full end-to-end builder test

The operator-facing workflow is now documented in:

- [doc/shielded-transfer-builder.md](doc/shielded-transfer-builder.md)
