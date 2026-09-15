# Executable CLI examples (B0 DOC-01)

These commands are the in-tree examples. Run
`contrib/modelnet/validate-doc-examples.sh` against `build-gcc13/bin`
(or `BIN_DIR=...`) to prove they still execute. Packaged
`planning/acceptance-matrix.csv` is the bar.

GUI / `btx-qt` examples are out of scope.

## Qualify (no execution)

```bash
build-gcc13/bin/btx-modelcheck /path/to/model.safetensors
```

A `STRUCTURE_VERIFIED` line is not a claim that the model is useful.

## Preview a URI (no wallet)

```bash
build-gcc13/bin/btx-open 'btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25'
```

Expect `action=preview-only` and `wallet=not-opened`. Extra arguments are refused.

## Helper (loopback)

```bash
build-gcc13/bin/btx-modeld \
  -modeldir=./modelnet-data \
  -modelstorage=80GiB \
  -modelbind=127.0.0.1:29447 \
  -modelhost
```

Unix RPC is one JSON line. Packaged default storage is **auto**. `-modelstorage=0`
is the explicit no-payload setting.

## Search / feed / economy

```bash
contrib/modelnet/e2e-economy-search.sh
contrib/modelnet/e2e-network-feed.sh
contrib/modelnet/e2e-economy-three-host.sh
```

Desktop Models page: Latest / Nearly Funded / Releases without a terminal.

## Two-helper retrieve

```bash
contrib/modelnet/e2e-two-helper-pq1.sh
contrib/modelnet/e2e-all.sh
contrib/modelnet/e2e-regtest-two-host.sh
```

WAN (non-production seeder only):

```bash
BTX_WAN_E2E=1 SEEDER=127.0.0.1:39447 contrib/modelnet/e2e-wan-two-helper.sh
```

## Monetary-only tree (no second cmake)

```bash
contrib/modelnet/check-with-modelnet-off.sh
```
