# M15 Full Lifecycle Runbook (macOS + CentOS + Bridge)

This runbook validates the complete lifecycle requested for final pass:

1. node startup
2. wallet creation
3. mining blocks and earning spendable rewards
4. verifying mined block contents/header fields
5. locked-wallet rejection and unlock workflow
6. send/receive between wallets
7. macOS host <-> CentOS container interoperability (bi-directional transfer)

## Prerequisites

- macOS host build exists at `build-btx` with `btxd` and `btx-cli` (legacy aliases `bitcoind` and `bitcoin-cli` are still accepted).
- CentOS build exists at `build-btx-centos` (or allow rebuild in matrix runner).
- Docker daemon is running.

## Single-Node Lifecycle (macOS Host)

Command:

```bash
scripts/m15_single_node_wallet_lifecycle.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-m15-mac-single.json \
  --node-label mac-host
```

Expected output:

- `M15 single-node lifecycle checks passed (mac-host):`
- `Startup/wallet creation/mining/send/receive/lock/unlock all validated`
- `Verified MatMul header fields and tx inclusion for mined blocks`

Expected artifact (`/tmp/btx-m15-mac-single.json`) highlights:

- `"overall_status": "pass"`
- `"skipped_steps": []`
- `"transactions.miner_to_alice.txid"` present
- `"transactions.alice_to_bob.txid"` present
- `"locking_checks.locked_send_rc"` is non-zero

## Single-Node Lifecycle (CentOS Container)

Command:

```bash
docker run --rm -v "$(pwd):/workspace" -w /workspace quay.io/centos/centos:stream10 \
  bash -lc 'dnf -y install libevent python3 >/tmp/m15-centos-runtime-dnf.log && \
    scripts/m15_single_node_wallet_lifecycle.sh \
      --build-dir /workspace/build-btx-centos \
      --artifact /workspace/.btx-validation/m15-centos-single.json \
      --node-label centos-container'
```

Expected output:

- `M15 single-node lifecycle checks passed (centos-container):`
- `Startup/wallet creation/mining/send/receive/lock/unlock all validated`

Expected artifact (`.btx-validation/m15-centos-single.json`) highlights:

- `"overall_status": "pass"`
- mined height and both txids present
- lock checks present and non-zero on locked-send attempts

## Bridge Lifecycle (macOS <-> CentOS)

Command:

```bash
scripts/m13_mac_centos_interop_readiness.sh \
  --mac-build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --artifact /tmp/btx-m13-bridge.json \
  --skip-centos-build
```

Expected output:

- `M13 macOS/CentOS interoperability checks passed:`
- `Bi-directional P2P sync verified at height ...`
- `Forward transfer ... and reverse transfer ... confirmed`

## Full Matrix (All Lifecycle Phases)

Command:

```bash
scripts/m15_full_lifecycle_matrix.sh \
  --build-dir build-btx \
  --centos-build-dir build-btx-centos \
  --artifact /tmp/btx-m15-full-matrix.json \
  --log-dir /tmp/btx-m15-full-matrix-logs \
  --timeout-seconds 900 \
  --skip-centos-build
```

Expected output:

- `[PASS] mac_host_lifecycle: ...`
- `[PASS] centos_container_lifecycle: ...`
- `[PASS] mac_centos_bridge_lifecycle: ...`
- `Overall status: pass`

Expected artifact (`/tmp/btx-m15-full-matrix.json`) highlights:

- `"overall_status": "pass"`
- `"skipped_phases": []`
- all three checks have `"status": "pass"`
- `"phase_coverage"` includes:
  - `"mac_host_lifecycle": "pass"`
  - `"centos_container_lifecycle": "pass"`
  - `"mac_centos_bridge_lifecycle": "pass"`
- per-check logs are listed under `"checks[*].log"`

## Failure Triage

- Open per-check log from matrix artifact (`checks[*].log`).
- For wallet lock failures, confirm locked send returns RPC `-13` and mentions `walletpassphrase`.
- For bridge failures, inspect `mac-centos-bridge-artifact.json` and both node logs for connection/sync divergence.
