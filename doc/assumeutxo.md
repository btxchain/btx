# Assumeutxo Usage

Assumeutxo is a feature that allows fast bootstrapping of a validating btxd
instance.

For notes on the design of Assumeutxo, please refer to [the design doc](/doc/design/assumeutxo.md).

## Loading a snapshot

BTX release snapshots are published as a small bundle:

- `snapshot.dat`: the UTXO snapshot to load
- `snapshot.manifest.json`: a compact, machine-readable summary with the
  snapshot height, base block hash, transaction-count metadata, and the
  snapshot file version and SHA256
- `SHA256SUMS` and `SHA256SUMS.asc`: checksum and signing artifacts for the
  release payloads
- optional signer-qualified Guix attestation assets published alongside the
  release bundle for build provenance

The manifest is a convenience receipt for fast-start workflows; treat the
checksum and signature files as the source of truth for file integrity.
For normal node setup, use the latest snapshot bundle published with the BTX
release you are installing. The snapshot file version is recorded in the
manifest for troubleshooting, but operators do not need to choose a format path
or pass a version to `loadtxoutset`.

If there is no published snapshot source for the version you need, you can
generate one yourself using `dumptxoutset` on another node that is already
synced (see [Generating a snapshot](#generating-a-snapshot)).

Once you've obtained the release bundle, verify the checksum and then use the
RPC command `loadtxoutset` to load the snapshot.

```
$ btx-cli -rpcclienttimeout=0 loadtxoutset /path/to/input
```

After the snapshot has loaded, the syncing process of both the snapshot chain
and the background IBD chain can be monitored with the `getchainstates` RPC.

### BTX fast-start workflow

BTX uses assumeutxo to support a "download the binary and go" workflow for:

- self-custody wallet balance access
- immediate RPC/API access (`getbalances`, shielded RPCs, MatMul service RPCs)
- self-custody mining setup without waiting for a full historical sync

The intended user flow is:

1. download the BTX release binary
2. download the latest matching `snapshot.dat` and `snapshot.manifest.json`
   published for that release
3. verify `SHA256SUMS` and `SHA256SUMS.asc`
4. confirm the manifest's `snapshot_sha256` matches the snapshot file, and
   keep the manifest's `snapshot_file_version` as the troubleshooting record
5. write a mining or service `btx.conf`
6. start `btxd`
7. wait until the manifest's `blockhash` is known in the local header chain
8. run `btx-cli -rpcclienttimeout=0 loadtxoutset /path/to/snapshot.dat`
9. monitor the snapshot and background validation chainstates with
   `getchainstates`

`loadtxoutset` requires the snapshot base block header to be known locally, but
it does not require the full snapshot base block to be downloaded. For fresh
nodes, use the `blockhash` from `snapshot.manifest.json` and poll the header
chain with the non-verbose form:

```bash
SNAPSHOT_BLOCKHASH="$(jq -r .blockhash /path/to/snapshot.manifest.json)"
btx-cli getblockheader "$SNAPSHOT_BLOCKHASH" false
```

If that RPC returns "Block not found", keep the daemon connected to peers and
try again after headers advance. Do not treat a low local block tip as a
snapshot problem; fresh snapshot nodes commonly have headers far ahead of
downloaded blocks during bootstrap. Seeing the manifest height at or below
`getblockchaininfo.headers` is a useful signal, but the `getblockheader` call
above is the definitive readiness check for loading the snapshot.

For a shorter operator-facing version of the same workflow, see
[BTX Download-and-Go Guide](/doc/btx-download-and-go.md).
For a detailed from-scratch miner procedure using generic `/var/btx/` paths,
see [BTX Mining Node Snapshot Runbook](/doc/btx-mining-node-snapshot-runbook.md).

If you want that workflow to install the right precompiled archive first,
`contrib/faststart/btx-agent-setup.py` consumes the published
`btx-release-manifest.json` and can immediately chain into the same snapshot
bootstrap flow with the `miner` or `service` preset.

Each release binary hardcodes the accepted snapshot metadata in
`src/kernel/chainparams.cpp`. Use the latest snapshot bundle published for the
same release as the binary; do not mix a newer snapshot with an older binary or
an arbitrary locally generated snapshot unless that snapshot's assumeutxo
metadata has been compiled into the binary. `main` and default-consensus
`regtest` have assumeutxo coverage in this tree. `testnet`, `testnet4`, and
`signet` do not yet have compiled assumeutxo entries, so new public-chain
reports must be generated and applied before fast-start bootstrap is supported
there.

### Miner fast-start `btx.conf`

For a new mining node that should become useful quickly while still validating
the chain, start with this posture:

```ini
server=1
listen=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# Peer discovery plus DNS-only public bootstrap hints.
dnsseed=1
fixedseeds=1
addnode=node.btx.dev:19335
addnode=node.btxchain.org:19335
addnode=node.btx.tools:19335

# Compact mining fast-start posture.
prune=4096
blockfilterindex=1
coinstatsindex=1
retainshieldedcommitmentindex=1
miningminoutboundpeers=2
miningminsyncedoutboundpeers=1
miningmaxheaderlag=8
```

Use all three DNS names rather than hard-coded peer IP addresses in operator
documentation and templates. Bootstrap IPs can change or become unavailable,
while DNS names can be updated without requiring miners to rewrite configs.
Avoid `connect=`-only topologies for production mining because they reduce peer
diversity and increase stale/orphan risk. The mining guard reports risk and
requests peer recovery while continuing to serve current-tip work instead of
turning unattended miners off.

### BTX shielded-state appendix

BTX mainnet snapshots are not UTXO-only in the practical sense. Current release
snapshots append the BTX shielded state needed to make a pruned or
assumeutxo-synced node load the snapshot and restart cleanly without replaying
historical shielded blocks it does not have on disk yet. The current snapshot
section carries:

- shielded commitment count
- persisted nullifier count
- recent anchor-output counts used to rebuild the rolling anchor view
- shielded pool balance
- settlement-anchor metadata
- netting-manifest metadata
- account-registry entry count and serialized account-registry entries
- recent account-registry root history
- the serialized commitment list
- the persisted nullifier list

On startup, BTX restores that snapshot appendix into the shielded commitment and
nullifier stores, rebuilds derived account-registry views from the persisted
snapshot data, persists the resulting tip-linked state, and can then restart
from the snapshot chainstate without needing a historical block walk. When the
local node only has headers before the snapshot, BTX retains the persisted
recent shielded roots and bridge metadata from the snapshot instead of trying to
read pre-snapshot block files that are intentionally absent. This is the
BTX-specific behavior that makes "download the binary, load the snapshot,
restart later, and keep using wallet/mining/service RPCs" viable.

BTX also now defaults to `retainshieldedcommitmentindex=1`, which keeps the
shielded commitment-position index on disk across restart and snapshot
recovery. That retained index is what prevents later starts from paying a
second historical shielded-state rebuild tax just to answer commitment lookup
queries again. Operators who explicitly prefer the lower-retained externalized
posture can set `-retainshieldedcommitmentindex=0`, but should expect slower
restart recovery as the node rebuilds that index from chain data.

### Pruning

A pruned node can load a snapshot. To save space, it's possible to delete the
snapshot file as soon as `loadtxoutset` finishes.

The minimum `-prune` setting is 550 MiB, but this functionality ignores that
minimum and uses at least 1100 MiB.

As the background sync continues there will be temporarily two chainstate
directories, each multiple gigabytes in size (likely growing larger than the
downloaded snapshot).

### Indexes

Indexes work but don't take advantage of this feature. They always start building
from the genesis block and can only apply blocks in order. Once the background
validation reaches the snapshot block, indexes will continue to build all the
way to the tip.


For indexes that support pruning, note that these indexes only allow blocks that
were already indexed to be pruned. Blocks that are not indexed yet will also
not be pruned.

This means that, if the snapshot is old, then a lot of blocks after the snapshot
block will need to be downloaded, and these blocks can't be pruned until they
are indexed, so they could consume a lot of disk space until indexing catches up
to the snapshot block.

## Generating a snapshot

The RPC command `dumptxoutset` can be used to generate a snapshot for the
current tip (using type "latest") or a recent height (using type "rollback").
A generated snapshot from one node can then be loaded on any other node.
However, keep in mind that the snapshot hash needs to be listed in the
chainparams to make it usable. If there is no snapshot hash for the height you
have chosen already, you will need to change the code there and re-compile.
Release snapshots should be generated from the current release branch so the
snapshot file uses the latest supported format and the published manifest
records the corresponding `snapshot_file_version`.

Using the type parameter "rollback", `dumptxoutset` can also be used to verify the
hardcoded snapshot hash in the source code by regenerating the snapshot and
comparing the hash.

### BTX release automation

BTX includes a helper script for the release/update workflow:

```
$ python3 contrib/devtools/generate_assumeutxo.py \
    --btx-cli ./build-btx/bin/btx-cli \
    --chain main \
    --snapshot /tmp/mainnet-utxo-HEIGHT.dat \
    --snapshot-type rollback \
    --rollback HEIGHT \
    --rpc-arg=-datadir=/path/to/synced/node \
    --rpc-arg=-rpcport=19334 \
    --json-out /tmp/mainnet-utxo-HEIGHT.json
```

The script:

1. calls `dumptxoutset` against a trusted synced node
2. computes the snapshot file SHA256
3. emits a compact published manifest JSON for the snapshot asset, including
   `snapshot_file_version`
4. emits a machine-readable JSON report
5. prints a ready-to-paste `m_assumeutxo_data` C++ snippet

The resulting JSON should be reviewed, then applied with:

```bash
python3 scripts/apply_assumeutxo_report.py \
    --report /tmp/snapshot.report.json \
    --chainparams src/kernel/chainparams.cpp
```

That helper rewrites the target chain's `m_assumeutxo_data` block without
hand-editing the source file. The snapshot file should be published alongside
its manifest JSON and the release checksum/signature files. When the final
release bundle is assembled, `scripts/release/collect_release_assets.py` also
emits `btx-release-manifest.json` so `contrib/faststart/btx-agent-setup.py` can
pick the correct archive for each supported platform.

For BTX, the resulting `snapshot.dat` already includes the shielded appendix
described above because it is generated from the live `dumptxoutset` path in the
node itself. No extra packaging step is required beyond publishing the file and
its manifest and SHA256 artifacts.

Example usage:

```
$ btx-cli -rpcclienttimeout=0 dumptxoutset /path/to/output rollback
```

For most of the duration of `dumptxoutset` running the node is in a temporary
state that does not actually reflect reality, i.e. blocks are marked invalid
although we know they are not invalid. Because of this it is discouraged to
interact with the node in any other way during this time to avoid inconsistent
results and race conditions, particularly RPCs that interact with blockstorage.
This inconsistent state is also why network activity is temporarily disabled,
causing us to disconnect from all peers.

`dumptxoutset` takes some time to complete, independent of hardware and
what parameter is chosen. Because of that it is recommended to increase the RPC
client timeout value (use `-rpcclienttimeout=0` for no timeout).
