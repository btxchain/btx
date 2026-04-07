# BTX Public Node Bootstrap (Archival)

This runbook is the canonical mainnet bootstrap path for operators who only
have this repository and public Internet access.

For the current precompiled-binary and fast-start service workflow, use
[btx-download-and-go.md](btx-download-and-go.md) and
[../contrib/faststart/README.md](../contrib/faststart/README.md). This
archival guide remains useful for full public-node bring-up, but it is no
longer the shortest path for binary users or service-gating operators.

## 1. Key Ops Prerequisite (Before Node Bring-Up)

If the node will mine, decide the payout target first:

- create/select the multisig descriptor and public keys that will receive mined
  rewards,
- generate the destination address (`btx1z...`) from that descriptor,
- back up descriptor/public key material offline.

This is a **hard prerequisite** for node provisioning. Do not start host bring-up
until you have both:

- a finalized payout address (`btx1z...`), and
- the corresponding public descriptor text used to derive it.

Do **not** put private keys on public seed nodes unless absolutely required.
Public archival seeds are normally run walletless.

## 2. Mainnet Config

Create `~/.btx/btx.conf` (BTX runtime canonical config path):

```ini
server=1
listen=1
port=19335

rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=19334

# Keep archival history for deterministic bootstrap service
prune=0

# Bootstrap guardrails
minimumchainwork=0
dnsseed=1
fixedseeds=1
addnode=node.btx.tools:19335
addnode=146.190.179.86:19335
addnode=164.90.246.229:19335
```

Notes:

- `19335` is the BTX mainnet P2P port.
- `19334` is the BTX mainnet default RPC port.
- `addnode=` seeds initial peers while preserving broader peer discovery.
- the current public bootstrap set is `node.btx.tools`, `146.190.179.86`,
  and `164.90.246.229`
- `getblocktemplate` enforces an outbound peer floor on mainnet by default
  (`-miningminoutboundpeers=2`) to reduce isolated-mining orphan risk.
  Set `-miningminoutboundpeers=0` only for intentional isolated lab mining.
- `getblocktemplate` also enforces that at least one outbound peer is actually
  near tip on mainnet by default
  (`-miningminsyncedoutboundpeers=1`, `-miningmaxpeersyncheightlag=2`).
  This reduces stale/forked mining when outbound peers are connected but lagging.
  Set `-miningminsyncedoutboundpeers=0` only for intentional isolated lab mining.
- `getblocktemplate` also enforces a validated-tip/header-lag bound on mainnet
  by default (`-miningmaxheaderlag=8`) so miners do not work from templates that
  are materially behind known headers. Set `-miningmaxheaderlag=0` only for
  intentional isolated lab workflows.
- Longpoll template requests re-check these guards on wakeup, so miners do not
  continue receiving work after a connectivity or validation-lag regression.
- This runbook is archival-only (`prune=0`).
- For newcomer/miner-first mode use `./contrib/devtools/gen-btx-node-conf.sh fast` (default `prune=4096`, scalable bootstrap).
- For canonical/seed operators use `./contrib/devtools/gen-btx-node-conf.sh archival` (default `prune=0`, scalable bootstrap).
- Use strict deterministic troubleshooting mode only when needed:
  `./contrib/devtools/gen-btx-node-conf.sh archival strict-connect`.
- If you control the managed archival fleet (`local` / `fra` / `nyc` / `sfo`),
  use direct managed peers instead of the public bootstrap set:
  `./contrib/devtools/gen-btx-node-conf.sh archival managed-direct <local|fra|nyc|sfo>`.

## 3. Start and Verify

```bash
./build/bin/btxd -conf="$HOME/.btx/btx.conf" -allowignoredconf=1 -daemon
./build/bin/btx-cli -conf="$HOME/.btx/btx.conf" getnetworkinfo
./build/bin/btx-cli -conf="$HOME/.btx/btx.conf" getpeerinfo
./build/bin/btx-cli -conf="$HOME/.btx/btx.conf" getblockchaininfo
```

Expected:

- peers connected on `:19335`,
- `networkactive: true`,
- `pruned: false` in `getblockchaininfo`.
- continuous progress in `blocks` and `headers` (no long-lived stall).

If you previously used strict deterministic mode (`connect=`), switch back to
`addnode=` + discovery for better mesh resilience and lower stale/orphan risk.

If you are operating the managed archival fleet, do not use the public
`node.btx.*` hostnames as fixed manual peers. They are acceptable public
bootstrap seeds, but the managed fleet should use `managed-direct` so each node
pins the canonical direct archival peers instead of whatever the public DNS
records currently resolve to.

Troubleshooting:

- If the node stalls near `blocks=16` and `headers=4000` with repeated
  `MatMul per-peer verification budget exhausted` disconnects in `debug.log`,
  you are likely running an older `btxd` binary.
- Rebuild from current source, then restart:

```bash
cmake --build build -j$(nproc)
./build/bin/btx-cli -conf="$HOME/.btx/btx.conf" stop
./build/bin/btxd -conf="$HOME/.btx/btx.conf" -allowignoredconf=1 -daemon
```

- If Tor logs contain `.onion ... resolve failed ... No more HSDir available to query`,
  treat that as a Tor connectivity problem (HSDir/bootstrap reachability), not a
  chain-consensus failure. For public clearnet bootstrap, set `onion=0` unless
  onion transport is explicitly required.

## 4. Archival Check (Historical Block Body)

```bash
H=$(./build/bin/btx-cli -conf="$HOME/.btx/btx.conf" getblockhash 1)
./build/bin/btx-cli -conf="$HOME/.btx/btx.conf" getblock "$H" 0 > /dev/null
```

If this succeeds (and `pruned: false`), the node has historical block body
access and is operating as archival.

## 5. Mining Payout Guardrail

For built-in test mining, always pass your chosen payout address explicitly:

```bash
./build/bin/btx-cli -conf="$HOME/.btx/btx.conf" generatetoaddress 1 "btx1z..."
```

Recommended public-only host artifacts (create these during provisioning):

```bash
sudo install -d -m 755 /opt/btx-runtime/artifacts
echo "btx1z..." | sudo tee /opt/btx-runtime/artifacts/mainnet_payout_address.txt >/dev/null
echo "mr(sortedmulti_pq(...))#...." | sudo tee /opt/btx-runtime/artifacts/mainnet_multisig_descriptor.txt >/dev/null
```

Optional watch-only wallet import (public descriptor only, no private keys):

```bash
./build/bin/btx-cli -conf="$HOME/.btx/btx.conf" -named createwallet \
  wallet_name=main_msig_watch \
  disable_private_keys=true blank=true descriptors=true load_on_startup=true

DESC="$(cat /opt/btx-runtime/artifacts/mainnet_multisig_descriptor.txt)"
REQ="$(jq -nc --arg d "$DESC" '[{desc:$d, timestamp:"now", active:false}]')"
./build/bin/btx-cli -conf="$HOME/.btx/btx.conf" -rpcwallet=main_msig_watch importdescriptors "$REQ"
```

For external/mainnet mining (`getblocktemplate` + `submitblock`), configure the
miner/pool coinbase destination to the same multisig-derived payout address.
