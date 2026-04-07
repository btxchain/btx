# Deterministic Shielded Transfer Builder

`contrib/shielded_transfer_builder.py` is an operator tool for building,
reviewing, simulating, and executing deterministic multisig-to-shielded
transfer bundles.

It is designed for large important transfers where the operator wants:

- a canonical on-disk plan object before signing and broadcast
- deterministic destination ordering and transaction ordering
- authoritative fee convergence through `z_fundpsbt`
- exact mempool preflight before execution
- optional persistent input locks while a bundle is pending review

After the post-`61000` privacy fork, `z_fundpsbt` remains suitable for
mature-coinbase compatibility deposits but not for arbitrary transparent
ingress; general transparent deposits should use the bridge-ingress surface.

The tool is intentionally thin. It drives existing wallet/node RPCs instead of
re-implementing transaction logic outside the daemon.

## Commands

The builder has four phases:

1. `plan`
2. `simulate`
3. `execute`
4. `release`

### `plan`

Builds a deterministic JSON bundle containing real unsigned PSBTs plus planning
metadata.

Planning rules:

- destination order is preserved exactly as supplied
- each destination is chunked greedily until the requested amount is covered
- each chunk is rebuilt until the `z_fundpsbt` fee quote converges
- planning fails closed if `fee_authoritative` is false
- selected inputs are protected from reuse during planning

The bundle file becomes the canonical plan artifact.

### `simulate`

Signs every PSBT in the bundle with the requested signer wallets, finalizes with
`broadcast=false`, and checks the finalized hex with `testmempoolaccept`.

Simulation refuses modified bundle files by verifying the bundle digest.

### `execute`

Re-signs and re-finalizes the exact simulated bundle, confirms the txid matches
simulation, then broadcasts deterministically.

Execution refuses modified bundle or simulation files by verifying both digests.

### `release`

Unlocks all bundle-referenced inputs without broadcasting anything.

Use this when a planned bundle is postponed or abandoned.

## RPC auth and config lookup

The tool resolves RPC connection settings in this order:

1. explicit `--rpcuser` / `--rpcpassword`
2. `rpcuser` / `rpcpassword` from `bitcoin.conf` or `btx.conf`
3. RPC cookie under the configured datadir

The RPC port resolves from:

1. explicit `--rpcport`
2. `rpcport` from `bitcoin.conf` or `btx.conf`
3. chain default

## Fee fields

The planner uses the daemon's authoritative fee path. The important fields are:

- `fee_authoritative`: whether the quote is authoritative for the current node policy
- `required_mempool_fee`: minimum fee needed for current local mempool acceptance
- `estimated_vsize`: estimated virtual size of the planned finalized transaction
- `estimated_sigop_cost`: estimated sigop cost of the planned finalized transaction

The planner adjusts the chunk amount until the authoritative fee converges.

This gives a current-node policy-valid plan, but `simulate` and `execute` still
perform exact finalized mempool checks because policy can change over time.

## Lock behavior

Default behavior:

- `plan` locks selected inputs in the wallet after bundle creation
- `execute` releases those bundle locks after successful broadcast
- `release` unlocks them manually without broadcast

`--no-lock-inputs` behavior:

- the planner still uses temporary wallet locks while constructing the bundle
- this preserves deterministic input selection across later chunks
- those temporary locks are released automatically after successful planning
- pre-existing wallet locks remain untouched

## Preview path and fallback path

The planner prefers the daemon preview RPC:

- `z_planshieldfunds`

If that preview path is unavailable for the source wallet shape, the tool falls
back to a deterministic largest-first transparent UTXO snapshot and continues
planning with authoritative `z_fundpsbt` quotes.

The fallback path:

- sorts the candidate UTXO set once
- excludes already locked inputs
- excludes inputs selected by earlier bundle chunks

This keeps large-wallet planning deterministic and scalable.

## Example workflow

Plan a bundle:

```bash
python3 contrib/shielded_transfer_builder.py plan \
  --datadir=/path/to/datadir \
  --chain=main \
  --rpcwallet=signer-1 \
  --signer-wallet=signer-1 \
  --signer-wallet=signer-2 \
  --signer-wallet=signer-3 \
  --destination=btxs1...=1000.00000000 \
  --destination=btxs1...=500.00000000 \
  --bundle=/tmp/transfer-bundle.json
```

Simulate the exact plan:

```bash
python3 contrib/shielded_transfer_builder.py simulate \
  --datadir=/path/to/datadir \
  --chain=main \
  --bundle=/tmp/transfer-bundle.json \
  --simulation=/tmp/transfer-simulation.json
```

Execute the exact simulated bundle:

```bash
python3 contrib/shielded_transfer_builder.py execute \
  --datadir=/path/to/datadir \
  --chain=main \
  --bundle=/tmp/transfer-bundle.json \
  --simulation=/tmp/transfer-simulation.json \
  --result=/tmp/transfer-execution.json
```

Release inputs without broadcasting:

```bash
python3 contrib/shielded_transfer_builder.py release \
  --datadir=/path/to/datadir \
  --chain=main \
  --bundle=/tmp/transfer-bundle.json
```

## Artifacts

The tool writes machine-readable JSON artifacts:

- bundle: canonical unsigned PSBT plan
- simulation: finalized txids and mempool-acceptance proof for the exact plan
- execution: the txids actually broadcast

Operators should retain these artifacts for auditability and recovery.
