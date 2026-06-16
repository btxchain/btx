# BTX Mining Node Snapshot Runbook

This runbook sets up a new mainnet mining node from the latest snapshot
published with a BTX release. It assumes `btxd` and `btx-cli` already exist,
either from a local build or a pre-packaged release archive.

Example paths use `/var/btx/`:

- `/var/btx/bin/`: BTX binaries and bundled helper scripts
- `/var/btx/data/`: node datadir
- `/var/btx/snapshots/<release>/`: downloaded snapshot bundle
- `/var/btx/logs/`: operator logs

## 1. Preflight

Commands below assume a Linux host with `jq`, `sha256sum`, and `lsof`
available. Install those through the host package manager before starting.

Create a dedicated user and directories:

```bash
sudo useradd --system --home /var/btx --shell /usr/sbin/nologin btx || true
sudo install -d -o btx -g btx -m 0750 /var/btx/bin
sudo install -d -o btx -g btx -m 0750 /var/btx/data
sudo install -d -o btx -g btx -m 0750 /var/btx/logs
sudo install -d -o btx -g btx -m 0750 /var/btx/snapshots
```

Install or copy the already-built binaries:

```bash
sudo install -o root -g root -m 0755 /path/to/btxd /var/btx/bin/btxd
sudo install -o root -g root -m 0755 /path/to/btx-cli /var/btx/bin/btx-cli
```

Confirm the binaries are available:

```bash
/var/btx/bin/btxd -version
/var/btx/bin/btx-cli -version
```

Stop any old process using the target datadir before continuing:

```bash
/var/btx/bin/btx-cli -datadir=/var/btx/data stop || true
pgrep -af 'btxd.*-datadir=/var/btx/data' || true
lsof +D /var/btx/data | head
```

Do not run two daemons against the same datadir. If LevelDB reports a database
lock, find and stop the owning process instead of deleting lock files while a
daemon is running.

## 2. Stage And Verify The Snapshot

Place the release snapshot bundle under a release-specific directory:

```bash
export SNAPSHOT_DIR=/var/btx/snapshots/vX.Y.Z
sudo install -d -o btx -g btx -m 0750 "$SNAPSHOT_DIR"
```

Use the newest snapshot bundle published for the release you are installing.
Operators do not need to select a snapshot file version manually; the manifest
records it for troubleshooting and `loadtxoutset` reads the snapshot file
directly.

The directory should contain:

- `snapshot.dat`
- `snapshot.manifest.json`
- `SHA256SUMS`
- `SHA256SUMS.asc`

Verify the release checksums and the manifest hash:

```bash
cd "$SNAPSHOT_DIR"
grep 'snapshot.dat$' SHA256SUMS | sha256sum -c -

EXPECTED_SHA="$(jq -r '.snapshot_sha256 // .sha256' snapshot.manifest.json)"
ACTUAL_SHA="$(sha256sum snapshot.dat | awk '{print $1}')"
test "$EXPECTED_SHA" = "$ACTUAL_SHA"

SNAPSHOT_HEIGHT="$(jq -r .height snapshot.manifest.json)"
SNAPSHOT_BLOCKHASH="$(jq -r .blockhash snapshot.manifest.json)"
SNAPSHOT_FILE_VERSION="$(jq -r '.snapshot_file_version // "unknown"' snapshot.manifest.json)"
printf 'snapshot height=%s file_version=%s blockhash=%s\n' \
    "$SNAPSHOT_HEIGHT" "$SNAPSHOT_FILE_VERSION" "$SNAPSHOT_BLOCKHASH"
```

Also verify `SHA256SUMS.asc` using the release signing key for the release you
are installing. The checksum and signature artifacts are the integrity source
of truth; the JSON manifest is the machine-readable receipt used by fast-start
tooling.

## 3. Configure The Mining Node

Create `/var/btx/data/btx.conf`:

```ini
server=1
listen=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# Keep peer discovery enabled and use DNS-only bootstrap hints.
dnsseed=1
fixedseeds=1
addnode=node.btx.dev:19335
addnode=node.btxchain.org:19335
addnode=node.btx.tools:19335

# Miner fast-start posture.
prune=4096
blockfilterindex=1
coinstatsindex=1
retainshieldedcommitmentindex=1
miningminoutboundpeers=2
miningminsyncedoutboundpeers=1
miningmaxheaderlag=8
```

Use all three DNS bootstrap names rather than hard-coded peer IP addresses.
Peer IPs can change or become unavailable, while DNS bootstrap names can be
updated without requiring local config changes. The three names are intended to
resolve to distinct public bootstrap/archive nodes so honest miners can find
each other quickly.

Avoid `connect=`-only production mining topologies. Normal peer discovery plus
DNS bootstrap hints gives the node better peer diversity and lowers stale block
risk.

## 4. Start The Daemon

Start `btxd` and wait for RPC readiness:

```bash
sudo -u btx /var/btx/bin/btxd -datadir=/var/btx/data -daemonwait
sudo -u btx /var/btx/bin/btx-cli -datadir=/var/btx/data getblockchaininfo
```

The local block tip may still be near genesis. That is expected on a fresh
node. The snapshot can load once the snapshot base header is known; the full
base block does not need to be downloaded first.

## 5. Wait For The Snapshot Base Header

Poll the header chain for the manifest block hash. Use non-verbose
`getblockheader ... false`; the full block does not need to be on disk.

```bash
SNAPSHOT_BLOCKHASH="$(jq -r .blockhash "$SNAPSHOT_DIR/snapshot.manifest.json")"

until sudo -u btx /var/btx/bin/btx-cli \
    -datadir=/var/btx/data \
    getblockheader "$SNAPSHOT_BLOCKHASH" false >/dev/null 2>&1
do
    sudo -u btx /var/btx/bin/btx-cli -datadir=/var/btx/data getblockchaininfo \
        | jq '{blocks, headers, initialblockdownload}'
    sleep 5
done
```

If this does not advance, check outbound connectivity and DNS resolution for
the configured bootstrap name. Do not treat a low local block height as a
snapshot failure when headers are still syncing.

## 6. Load The Snapshot

Run `loadtxoutset` with an unlimited CLI timeout:

```bash
sudo -u btx /var/btx/bin/btx-cli \
    -datadir=/var/btx/data \
    -rpcclienttimeout=0 \
    loadtxoutset "$SNAPSHOT_DIR/snapshot.dat" \
    | tee "$SNAPSHOT_DIR/loadtxoutset.json"
```

Expected output includes:

- `coins_loaded`
- `tip_hash` equal to the manifest `blockhash`
- `base_height` equal to the manifest `height`
- `shielded_retention_profile`

After success, inspect the active chainstates:

```bash
sudo -u btx /var/btx/bin/btx-cli -datadir=/var/btx/data getchainstates
sudo -u btx /var/btx/bin/btx-cli -datadir=/var/btx/data getblockchaininfo
```

The snapshot chainstate should be active at or beyond the snapshot base height,
and background validation should continue from genesis until it validates the
snapshot base.

## 7. Verify Restart Safety

Before handing the node to mining automation, confirm the datadir can restart
from the snapshot state:

```bash
sudo -u btx /var/btx/bin/btx-cli -datadir=/var/btx/data stop

until ! pgrep -af 'btxd.*-datadir=/var/btx/data' >/dev/null; do
    sleep 1
done

sudo -u btx /var/btx/bin/btxd -datadir=/var/btx/data -daemonwait
sudo -u btx /var/btx/bin/btx-cli -datadir=/var/btx/data getblockchaininfo
```

The daemon should reopen the snapshot chainstate and continue syncing without
requiring historical pre-snapshot block files.

## 8. Mining Readiness

Check mining state:

```bash
sudo -u btx /var/btx/bin/btx-cli -datadir=/var/btx/data getmininginfo
```

The chain guard may report:

- `reason=initial_block_download`
- insufficient outbound peers
- no near-tip synced outbound peers

Those states are expected while the node catches up from the snapshot height to
the current tip. They are warnings and recovery triggers, not stop signals:
keep miners requesting work while the node catches up.

If using the bundled live-mining helper, point it at the same datadir, config,
and binaries. Adjust the helper path to match the extracted release layout:

```bash
/var/btx/bin/contrib/mining/start-live-mining.sh \
    --datadir=/var/btx/data \
    --conf=/var/btx/data/btx.conf \
    --chain=main \
    --cli=/var/btx/bin/btx-cli \
    --daemon=/var/btx/bin/btxd \
    --wallet=miner
```

If you mine through another supervisor or pool integration, use
`getmininginfo` and `getblocktemplate` as readiness gates. `getblocktemplate`
requires a BIP 9 template-request object; on mainnet, call it with the `segwit`
rule:

```bash
sudo -u btx /var/btx/bin/btx-cli \
    -datadir=/var/btx/data \
    getblocktemplate '{"rules":["segwit"]}'
```

On current nodes, `chain_guard.should_pause_mining` is retained only for
compatibility and should remain `false`. Use `chain_guard.healthy`, `reason`,
and `recommended_action` to drive peer remediation and alerts without taking
hashrate offline.

## 9. Cleanup

After `loadtxoutset` succeeds and restart has been verified, the snapshot file
is no longer needed by the node:

```bash
sudo rm -f "$SNAPSHOT_DIR/snapshot.dat"
```

Keep the manifest, checksum files, and `loadtxoutset.json` for auditability.

## Troubleshooting

`Unable to load UTXO snapshot: The base block header ... must appear in the headers chain`

The node has not seen the snapshot base header yet. Keep the daemon running,
verify peer connectivity, and rerun the non-verbose `getblockheader` poll.

`Assumeutxo height in snapshot metadata not recognized`

The binary does not contain compiled assumeutxo metadata for that snapshot
height/block hash. Use the matching release binary or rebuild from source that
contains the snapshot entry in `src/kernel/chainparams.cpp`.

`Unable to load UTXO snapshot: could not load BTX shielded snapshot section`

Use a current binary and a current BTX snapshot. Post-recovery-exit pruned
nodes need a restart-safe shielded appendix that includes recovery-exit
commitments, currently snapshot version 8 or newer. A UTXO-only snapshot or an
older shielded appendix can only be repaired by replaying historical blocks,
which `prune=600` nodes usually no longer have. In that case, use a current
snapshot asset, a non-pruned datadir, or redownload/reindex from peers.

Database lock errors

Another process is using the datadir. Stop it cleanly with `btx-cli stop`, then
check `pgrep` and `lsof`. Do not start a second daemon against the same datadir.

Mining guard remains unhealthy after the snapshot loads

This is normally expected until the node catches up and has enough useful
outbound peers. Keep miners running, then check `getmininginfo.chain_guard`,
`getpeerinfo`, `getblockchaininfo.blocks`, and `getblockchaininfo.headers` to
confirm the warnings clear.
