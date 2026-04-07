Mining Operator Helpers
-----------------------

This directory contains optional operator tooling for local solo-mining
workflows. These scripts are not required for `getblocktemplate` / external
miner setups, but they provide a safer starting point than ad-hoc shell loops
when driving `generatetoaddress` directly against a BTX node.

If you are standing up a service-admission or agent-gating node, start with
`contrib/faststart/README.md` and `doc/btx-download-and-go.md` instead of the
helpers in this directory. Those docs cover the profile-based challenge catalog
and the `issuematmulservicechallengeprofile` issuance path.

Included scripts:
- `start-live-mining.sh`: starts the health-aware local mining supervisor in the background after preflighting `jq`, and now auto-creates / loads the mining wallet plus address file when you do not pass `--address` or `--address-file`.
- `live-mining-loop.sh`: continuously mines to a configured address while watching `getmininginfo.chain_guard` and an optional local idleness gate.
- `stop-live-mining.sh`: stops the supervisor and any lingering `generatetoaddress` worker.
- `backup-wallet.sh`: wraps `backupwallet` and exports descriptors + wallet metadata with a checksum.
- `test-live-mining-loop-health.sh`: deterministic self-test for the supervisor restart path.

Best practices:
- Mine only when the node is healthy and near tip. Watch `getmininginfo.chain_guard`.
- Avoid `connect=`-only islands for normal operation; prefer normal peer discovery plus optional `addnode=` hints.
- Keep the mining reward wallet backed up with descriptors, not just the SQLite wallet file.
- Prefer `btxd` / `btx-cli` in automation and service files.
- For production-scale mining, use `getblocktemplate` / `submitblock` and external workers. The scripts here are mainly for solo mining and operator automation.
- For first-run or fleet installs from a GitHub release, prefer
  `contrib/faststart/btx-agent-setup.py --preset miner` so the binary install,
  assumeutxo bootstrap, and mining-oriented config land together.
- The official per-platform release archives now already include the helpers in
  this directory, so a direct archive extraction still leaves the mining
  supervisor scripts available under `contrib/mining/`.
- For idle-time mining on workstations, pair the miner preset with the
  supervisor scripts here so the node can opportunistically mine while the GPU
  or host is otherwise unused, then stop cleanly when you need the machine
  back.
- Set `--should-mine-command='...'` or `BTX_MINING_SHOULD_MINE_COMMAND` to an
  operator-provided probe that exits `0` only when the machine is actually idle
  enough to mine. The loop will pause mining while that command returns
  non-zero.
- The supervisor now scopes forced restarts to its own node PID file instead of
  matching `btxd` globally, so multiple local nodes can coexist without one
  mining loop killing the others.
- `stop-live-mining.sh` now only stops the supervised loop PID recorded in the
  results directory, so shutting down one helper instance does not kill
  unrelated `btxd` or `btx-cli generatetoaddress` processes on the same host.
- `live-mining-loop.sh` now treats chain-guard reasons differently: it still
  pauses mining when consensus is weak or the node is behind tip, but it no
  longer thrashes the daemon just because peer consensus is temporarily weak or
  the node is still syncing. Instead it waits for sync progress, retries
  optional bootstrap peers, reuses the last healthy outbound peers it saw, and
  only restarts when the node has genuinely stalled.
- For service-gateway or agentic challenge workloads, use the fast-start
  service preset and inspect the profile's `operator_capacity` estimates when
  deciding whether one node, a shared registry, or a wider deployment is the
  right fit for the expected challenge volume. `getmatmulservicechallengeplan`
  is the quickest inverse planner when you know the target solves/hour or
  mean-seconds-between-solves you want to sustain.
- When a mining host also serves admission-control traffic, monitor
  `getdifficultyhealth.service_challenge_registry` so registry corruption or a
  shared-file lock problem is visible immediately instead of surfacing only as
  redeem failures.
- If your node was started from a generated fast-start config or a non-default
  RPC port, pass `--conf=...`, `--chain=...`, and `--rpcport=...` to the
  helpers so the supervisor talks to the same daemon instance that
  `btx-agent-setup.py` bootstrapped.

Quick start:

```bash
SETUP_JSON="$(python3 contrib/faststart/btx-agent-setup.py \
  --repo btxchain/btx-node \
  --release-tag v29.2-btx1 \
  --preset miner \
  --datadir="$HOME/.btx" \
  --json)"

BTX_CLI="$(printf '%s' "$SETUP_JSON" | jq -r '.btx_cli')"
BTXD="$(printf '%s' "$SETUP_JSON" | jq -r '.btxd')"
FASTSTART_CONF="$(printf '%s' "$SETUP_JSON" | jq -r '.faststart_conf')"

contrib/mining/start-live-mining.sh \
  --datadir="$HOME/.btx" \
  --conf="$FASTSTART_CONF" \
  --chain=main \
  --cli="$BTX_CLI" \
  --daemon="$BTXD" \
  --wallet=miner \
  --should-mine-command='/usr/local/bin/btx-should-mine-now'
```

If you omit `--address` / `--address-file`, `start-live-mining.sh` now loads or
creates the named wallet, writes a fresh payout address into
`$DATADIR/mining-ops/<wallet>-mining-address.txt`, and starts the supervised
loop with that address automatically. Auto-provisioned wallets are now added to
the node's load-on-startup list so the supervised loop can restart `btxd`
without losing the mining wallet, and `start-live-mining.sh` now fails fast if
the background loop dies during its initial startup check. In `--json` mode,
the installer keeps its progress on stderr so the command substitution above
receives only the JSON summary. The summary also includes
`start_live_mining_command` / `stop_live_mining_command` arrays when
`--preset miner` is used.

If you want the supervisor to actively re-seed peer discovery when
`getmininginfo.chain_guard.reason=insufficient_peer_consensus`, set
`BTX_MINING_BOOTSTRAP_PEERS` (or the legacy `BTX_MINING_BOOTSTRAP_ADDNODES`)
to a comma-separated host list such as
`node1.example:19335,node2.example:19335`. The loop will issue
`addnode ... onetry` refreshes after repeated weak-peer observations, while
`BTX_MINING_SYNC_STALL_RESTART_SECS` controls how long it waits for real sync
progress before restarting a stalled daemon. Once the node has been healthy,
the loop also caches its last healthy outbound peers in
`$RESULTS_DIR/live-peer-cache.txt` and retries those first during later
peer-consensus recovery.

For a first-run bootstrap before mining or service bring-up, see
[`contrib/faststart`](../faststart). Those entry points fetch the matching
snapshot, run `loadtxoutset`, and watch `getchainstates` until the bootstrap
chainstate clears.

Stop:

```bash
contrib/mining/stop-live-mining.sh --results-dir="$HOME/.btx/mining-ops"
```

Every helper in this directory also supports `--help` for quick flag discovery.
