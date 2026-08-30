# BTX Public Node Bootstrap (Archival)

> **MatMul v4.7 note:** this bootstrap procedure does not opt a node into an
> consensus epoch beyond the compiled chain parameters: Epoch A remains a
> mainnet release candidate pending exact-final evidence, ratification, and a
> live activation height; all other transition heights remain disabled.
> Epochs A/B require Profile 1
> ExactReplay for every claimed block, so future validating-node release notes
> must state accelerator requirements and IBD/checkpoint assumptions. Profile 2
> is not an Epoch-A validator requirement. See
> [`btx-matmul-v4.7-transition-roadmap.md`](btx-matmul-v4.7-transition-roadmap.md).

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
# 0.34: these DNS names should run -matmulvalidation=relay (ADDR only).
# They are not chain oracles and must not be GPU attestors. IBD comes from
# archives/miners the relay introduces. See doc/design/0.34-discovery-relay.md.
addnode=node.btx.dev:19335
addnode=node.btxchain.org:19335
addnode=node.btx.tools:19335
addnode=146.190.179.86:19335
addnode=164.90.246.229:19335

# Published mainnet ExactReplay attestors (public keys only).
# Same set GPU attestors and following archives return from
# getmatmultrustedstatus / getfinalityinfo. P2P seeds do not push keys.
matmultrustedpubkey=03d90c148db37da28ce47ce15bade88a177728d663da4bc9ba765943b7d4e4f0aa
matmultrustedpubkey=0224e80df33697385b54b3c69bae1f097f533c0c43e93c29f73ee97319d4a5e04c
matmultrustedthreshold=1
```

Notes:

- `19335` is the BTX mainnet P2P port.
- `19334` is the BTX mainnet default RPC port.
- After `btxd` is up, `btx-cli getmatmultrustedstatus` must show
  `configured=true` and the two pubkeys above. That is the mining/archive
  bootstrap pin (same RPC GPU attestors and following archives serve).
- `addnode=` introduces peers while preserving broader discovery. In 0.34
  those hosts are discovery relays (`-matmulvalidation=relay`), not MatMul
  authority. Do not treat `getbestblockhash` on a public seed as the chain.
  GPU attestors stay off DNS/`addnode`.
- the current public DNS bootstrap set is `node.btx.dev`,
  `node.btxchain.org`, and `node.btx.tools`; direct IP addnodes are optional
  archive-node hints for controlled troubleshooting
- Mining diagnostics report advisory mainnet thresholds of three outbound
  peers, two synced outbound peers, one block of peer sync-height lag, and
  three blocks of validated-tip/header lag. The corresponding options are
  `-miningminoutboundpeers`, `-miningminsyncedoutboundpeers`,
  `-miningmaxpeersyncheightlag`, and `-miningmaxheaderlag`.
- These thresholds do not block `getblocktemplate`, including after a longpoll
  wakeup. That is intentional: remote peer churn or header spam must not be
  able to stop an unattended honest miner. A deficient diagnostic still means
  increased stale/orphan risk and should trigger peer recovery and operator
  alerting.
- This runbook is archival-only (`prune=0`).
- For newcomer/miner-first mode use `./contrib/devtools/gen-btx-node-conf.sh fast` (default `prune=4096`, scalable bootstrap).
- For canonical/seed operators use `./contrib/devtools/gen-btx-node-conf.sh archival` (default `prune=0`, scalable bootstrap).
- Use strict deterministic troubleshooting mode only when needed:
  `./contrib/devtools/gen-btx-node-conf.sh archival strict-connect`.
- If you operate a private archival set, pin those peers instead of the public
  bootstrap set. `./contrib/devtools/gen-btx-node-conf.sh archival managed-direct`
  emits RFC 5737 example addresses (`local` / `fra` / `nyc` / `sfo` are slot
  names); substitute your own.

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

If you operate a private archival set, do not use the public `node.btx.*`
hostnames as the only fixed manual peers. They are acceptable public bootstrap
seeds. Use `managed-direct` (with your own addresses substituted for the RFC
5737 examples) so each node pins the peers you actually control.

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

A mining/submit node must also:

- run `-blocksonly=0` (otherwise winning blocks often never reach the signer);
- set `-matmultrustedpubkey=<signer>` and `-matmultrustedthreshold` even in
  `-matmulvalidation=consensus` so `getmatmulattestedtip` is populated
  (ExactReplay is unchanged);
- build templates on that attested tip and never stack unattested candidates.

See [`btx-matmul-v4.7-gpu-operator-runbook.md`](btx-matmul-v4.7-gpu-operator-runbook.md)
section "Mining on the attested chain". Canonical rate is gated by the signer's
ExactReplay/attestation throughput, not by hashrate. 1-of-1 is a single point
of failure.
