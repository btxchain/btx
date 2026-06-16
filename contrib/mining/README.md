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
- `start-live-mining.sh`: starts the health-aware local mining supervisor in the background after preflighting `jq`, and now auto-creates / loads the mining wallet plus address file when you do not pass `--address` or `--address-file`. Use `--foreground` when a service manager such as launchd, systemd, or tmux should supervise the loop process directly.
- `live-mining-loop.sh`: continuously mines to a configured address while logging `getmininginfo.chain_guard` warnings and using those warnings to refresh peers instead of stopping nonce production. The optional local idleness gate can still be used when the operator explicitly wants workstation-idle mining only.
- `live-mining-loop.py`: a leaner RPC-keepalive variant of `live-mining-loop.sh`. A single long-running Python process holds one HTTP connection to the JSON-RPC endpoint instead of forking `btx-cli` once per iteration. Use this when the per-spawn cost of the shell loop is the dominant operational concern — for example, on macOS hosts where every fork triggers `syspolicyd` and `XprotectService` malware checks, which at one-second cadence can keep those system services warm continuously and induce thermal throttling. It does not include the supervisor's chain-guard reaction, peer remediation, or daemon restart logic, so it expects a separately-monitored healthy node.
- `stop-live-mining.sh`: stops the supervisor and any lingering `generatetoaddress` worker.
- `backup-wallet.sh`: wraps `backupwallet` and exports descriptors + wallet metadata with a checksum.
- `test-live-mining-loop-health.sh`: deterministic self-test for the supervisor restart path.

Best practices:
- Keep unattended miners asking for work whenever the local node can build valid templates. Watch `getmininginfo.chain_guard` and `getmininginfo.fork_health` for warnings, but do not turn peer disagreement or fork pressure into an automatic mining stop.
- On Apple Silicon mining hosts, the supervisor now defaults to the strict
  optimized Metal posture: `BTX_MATMUL_BACKEND=metal`,
  `BTX_MATMUL_REQUIRE_BACKEND=metal`, `BTX_MATMUL_GPU_INPUTS=1`,
  `--daemonize=0`, and `--max-backend-fallbacks=0`. The loop fails closed if
  `getmininginfo.backend_runtime.active_backend` is not `metal` or if Metal
  records any digest or nonce-seed pre-hash GPU-to-CPU fallback. Override those
  defaults only for controlled benchmarking or a host-specific workaround.
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
- Set `--should-mine-command='...'` or `BTX_MINING_SHOULD_MINE_COMMAND` only
  for workstation-idle mining. That operator-provided probe exits `0` when the
  machine is idle enough to mine; unlike chain-guard warnings, a non-zero probe
  result intentionally suppresses local mining because the operator asked for
  that local-resource policy.
- The supervisor now scopes forced restarts to its own node PID file instead of
  matching `btxd` globally, so multiple local nodes can coexist without one
  mining loop killing the others.
- `stop-live-mining.sh` now only stops the supervised loop PID recorded in the
  results directory, so shutting down one helper instance does not kill
  unrelated `btxd` or `btx-cli generatetoaddress` processes on the same host.
- When a process supervisor starts mining at boot or login, run
  `start-live-mining.sh --foreground` from a stable `WorkingDirectory` and let
  the supervisor restart that process. Detached mode is intended for interactive
  starts; it records its child PID and forces that child to start from
  `--launch-cwd` or the results directory so it does not inherit an unusable
  working directory from a stale terminal, mount, or macOS privacy boundary.
- `live-mining-loop.sh` keeps mining through chain-guard warnings, including
  IBD, local-behind-peer-median, local-ahead observations, insufficient
  near-tip quorum, disabled networking, or deferred reorg candidates. Peer
  disagreement and fork pressure are logged and may trigger peer refreshes; the
  supervisor only restarts for real RPC/node stalls, not for guard warnings.
- Daemon-only mining nodes also get peer recovery now. When
  `getblocktemplate`, MatMul challenge, or the background mining watcher sees
  an unhealthy chain guard, `btxd` periodically enrolls
  the built-in public mesh (`node.btx.dev`, `node.btxchain.org`,
  `node.btx.tools`) in the runtime addnode set in addition to requesting extra
  automatic outbound and block-relay peers. Use
  `-miningchainguarddefaultmesh=0` only for controlled deployments with an
  explicit peer policy, or adjust
  `-miningchainguardmeshrefreshseconds` to change the default 60-second
  throttle.
- Reorg hysteresis is still the first line of defense against long-lived
  competing branches. The default emergency profile protects every active-chain
  rewrite (`reorghysteresisdepth=0`) and requires the candidate branch to exceed
  the old tip by the configured extra-work margin
  (`reorghysteresisworkmargin=2`) before automatic activation. Setting
  `reorghysteresisworkmargin=0` disables that extra-work requirement and should
  only be used for controlled recovery. Valid competing headers are not treated
  as malicious by themselves, because banning every peer that has seen a
  work-bearing fork can partition honest nodes. The supervisor instead refreshes
  toward the public mesh and away from stale/unreachable peers while the daemon
  discourages peers that deliver full blocks failing high-confidence
  shielded/recovery consensus checks.
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
  --repo btxchain/btx \
  --release-tag v0.32.7 \
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

The supervisor actively re-seeds peer discovery when
`getmininginfo.chain_guard.reason=insufficient_peer_consensus` or the healthy
peer mix drops too low. By default it uses the public BTX bootstrap mesh
`node.btx.dev:19335,node.btxchain.org:19335,node.btx.tools:19335`. Override that
with `BTX_MINING_BOOTSTRAP_PEERS` (or the legacy
`BTX_MINING_BOOTSTRAP_ADDNODES`) or the `--bootstrap-peers=` option. Set
`BTX_MINING_USE_DEFAULT_BOOTSTRAP_PEERS=0` or pass
`--no-default-bootstrap-peers` only for controlled lab deployments. The loop
will issue `disconnectnode` calls for obviously stale manual peers followed by
`addnode ... onetry` refreshes after repeated weak-peer observations while
continuing to mine if templates remain available. If the node still does not
make tip progress for `BTX_MINING_SYNC_STALL_RESTART_SECS`, the supervisor
escalates to a daemon restart so startup recovery can rebuild local state
instead of sitting on a stuck process. Once the node has been healthy, the loop
caches its last healthy outbound peers in
`$RESULTS_DIR/live-peer-cache.txt`, ranks public/full-relay low-latency peers
ahead of private/manual ones, and retries those first during later
peer-consensus recovery. Healthy runs also re-top-off the peer set when the
public/full-relay mix drops too low, so a temporary private/manual peer island
does not quietly become the miner's steady-state topology.

Stale manual mesh peers are cooled off automatically instead of being retried
forever. The shell supervisor records temporary disables in
`$RESULTS_DIR/disabled-peer-mesh.txt`; tune the cooldown with
`BTX_MINING_PEER_MESH_DISABLE_SECS` or set
`BTX_MINING_PEER_MESH_DISABLED_FILE` to share state across supervisor
instances. Daemon-side runtime controls are also available for pool and fleet
automation:

```bash
btx-cli getminingpeermesh
btx-cli addminingpeermeshnode node.btx.tools:19335 true true
btx-cli removeminingpeermeshnode node.btx.tools:19335 true
btx-cli refreshminingpeermesh true true
```

These RPCs manage the current process' runtime mesh. Use `addnode=` in
`btx.conf` or the supervisor's `--bootstrap-peers=` option for restart-persistent
operator policy.

For a first-run bootstrap before mining or service bring-up, see
[`contrib/faststart`](../faststart). Those entry points fetch the matching
snapshot, run `loadtxoutset`, and watch `getchainstates` until the bootstrap
chainstate clears.

Stop:

```bash
contrib/mining/stop-live-mining.sh --results-dir="$HOME/.btx/mining-ops"
```

Every helper in this directory also supports `--help` for quick flag discovery.
