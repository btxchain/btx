# BTX Mining Ops Readiness

This document tracks BTX mining/operator readiness for milestone M7.

## Current State

- BTX node supports MatMul PoW consensus and strict regtest verification via:
  - `-test=matmulstrict`
- `getblocktemplate` exposes BTX MatMul nonce range:
  - `noncerange = 0000000000000000ffffffffffffffff`
- Upstream miner source baseline is available at:
  - `../upstream/matmulminer`

## Operator Prerequisite (Key Ops)

Before any production mining rollout, operators must:

1. Create or select the multisig descriptor public keys used for reward custody.
2. Derive and verify the payout address (`btx1z...`) from that descriptor.
3. Store backups of descriptor/public key material offline.

Public seed nodes should remain walletless unless a specific mining role
requires wallet capabilities.

Service-admission operators who are pairing mining with API gating should use
the fast-start `service` preset plus
`listmatmulservicechallengeprofiles` / `issuematmulservicechallengeprofile` to
size challenge costs against current network conditions. The profile catalog
surfaces average-node pacing estimates so capacity planning stays anchored to
what the chain is actually seeing instead of only a hand-picked raw target.

## Validation Scripts

- `scripts/m7_mining_readiness.sh`: fast regression covering strict MatMul
  activation, wallet mining, and `getblocktemplate` nonce exposure.
- `scripts/m7_miner_pool_e2e.py`: full miner/pool pipeline check that exercises
  `generateblock submit=false` + `submitblock` and captures a BTX stratum job
  artifact (see [miner/pool readiness](btx-miner-pool-readiness.md)).
- `test/util/m7_parallel_readiness_test.sh`: anti-hang isolation test that runs
  `scripts/m7_mining_readiness.sh` and `scripts/m7_miner_pool_e2e.py`
  concurrently to verify there is no port-collision startup deadlock.

Run the original quick check via:

```bash
scripts/m7_mining_readiness.sh build-btx
```

`scripts/m7_miner_pool_e2e.py` emits `doc/mining/m7-regtest-stratum-job.json`
and prints a summary of the verified job/submission pair. See
`doc/btx-miner-pool-readiness.md` for the full workflow and artifact format.
If wallet RPC is unavailable in the current build, it automatically falls back
to a coinbase-only submission-path validation.

The shell readiness script verifies:

1. BTX regtest node boots with strict MatMul checks.
2. Wallet + local mining path is functional.
3. `getblocktemplate` includes required MatMul mining fields.
4. Upstream `matmulminer` source is present for fork/integration work.

Both M7 scripts now allocate dedicated RPC ports and run with `-listen=0` so
parallel validation jobs do not block each other.

## Apple Silicon Metal Path (M11)

- MatMul solve flow now supports a full Metal digest backend on Apple Silicon
  builds with `BTX_ENABLE_METAL=ON`.
- Node mining (`SolveMatMul`) and `btx-genesis` both route through the same
  backend-selected digest path.
- Backend selection tokens are `cpu`, `metal`/`mlx`, and `cuda`; CUDA remains
  scaffolded/disabled by default and falls back to CPU.
- `btx-genesis --metal` remains available as an optional nonce prefilter layer
  on top of backend-selected digest solving.
- Non-Apple or Metal-unavailable hosts transparently fall back to CPU.

Validation entrypoint:

```bash
scripts/m11_metal_mining_validation.sh --build-dir build-btx --rounds 3 --artifact /tmp/btx-m11-metal-validation.json
```

This validation runs both standard strict-regtest block mining and Metal-assisted
`btx-genesis` runs in each round, and emits a machine-readable artifact.

## MatMul Backend Capability Telemetry

- `btx-matmul-backend-info` reports requested backend, active backend, and
  capability reasons in JSON form.
- Supported backend request tokens are `cpu`, `metal`, `mlx`, and `cuda`.
- `mlx` currently aliases the Metal backend profile.
- CUDA backend scaffolding is intentionally compiled out by default via
  `BTX_ENABLE_CUDA_EXPERIMENTAL=OFF`.
- Runtime mining backend for node solve is selected via `BTX_MATMUL_BACKEND`.

Example:

```bash
build-btx/bin/btx-matmul-backend-info --backend metal
```

`scripts/m7_miner_pool_e2e.py` now captures this backend telemetry in its
artifact (`requested_backend` + `backend` object), so readiness runs can verify
which backend profile was requested and what actually activated.

## Next M7 Actions

1. Fork `matmulminer` into a BTX-branded miner repo.
2. Add BTX pool defaults and sample launch profiles.
3. Validate external miner submission against BTX regtest/testnet with a stratum path.
4. Publish operator runbooks for node + miner + pool bring-up.
