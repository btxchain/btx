# BTX Download-and-Go Guide

This guide is the shortest path from a precompiled BTX binary to:

- wallet balance access
- shielded-wallet usage
- self-custody mining setup
- MatMul service-RPC usage for anti-spam, rate limiting, and admission control

Throughout this guide, the intended operator surface is a
fast-start validating node: a normal validating BTX node that boots from a
published rollback snapshot instead of waiting for a full historical sync
before becoming useful.

## 1. Fast-sync with Assumeutxo

For agentic or unattended installs, the shortest end-to-end flow is:

```bash
export GH_TOKEN="$(<github.key)"  # only needed for private GitHub releases

python3 contrib/faststart/btx-agent-setup.py \
  --repo btxchain/btx \
  --release-tag v0.29.6 \
  --preset miner \
  --datadir="$HOME/.btx"
```

That one command installs the correct platform archive from the published
`btx-release-manifest.json`, verifies the manifest/archive/snapshot-manifest
against `SHA256SUMS` and `SHA256SUMS.asc` for remote releases, downloads the
matching snapshot manifest, and invokes the fast-start bootstrap wrapper. The
installer keeps its temporary download cache in a sibling
`<install-dir>-agent-setup-cache` directory unless you override `--cache-dir`.
For private GitHub releases, set `BTX_GITHUB_TOKEN`, `GITHUB_TOKEN`, or
`GH_TOKEN` before running the installer so it can authenticate the manifest and
archive fetches through the GitHub release asset API. The same token env vars
are also honored by `contrib/faststart/btx-faststart.py` when a snapshot
manifest or snapshot URL points at a private GitHub release asset.

If an agent needs the installed binary paths or the generated fast-start config
for follow-on automation, add `--json`. The installer now keeps bootstrap
progress on stderr and prints a clean JSON summary on stdout:

```bash
SETUP_JSON="$(python3 contrib/faststart/btx-agent-setup.py \
  --repo btxchain/btx \
  --release-tag v0.29.6 \
  --preset miner \
  --datadir="$HOME/.btx" \
  --json)"

BTX_CLI="$(printf '%s' "$SETUP_JSON" | jq -r '.btx_cli')"
BTXD="$(printf '%s' "$SETUP_JSON" | jq -r '.btxd')"
FASTSTART_CONF="$(printf '%s' "$SETUP_JSON" | jq -r '.faststart_conf')"
```

When `--preset miner` is used, that summary also includes
`start_live_mining_command`, `stop_live_mining_command`, and
`mining_results_dir` so an unattended installer can immediately hand off to the
local mining supervisor without guessing paths.

If you prefer to run the bootstrap steps yourself:

1. Download the BTX binary release.
2. Download the matching `snapshot.dat`, `snapshot.manifest.json`, and
   `btx-release-manifest.json`.
3. Verify `SHA256SUMS` and `SHA256SUMS.asc`.
4. Check that the manifest's `snapshot_sha256`, height, and base block hash
   match the release notes or `m_assumeutxo_data`.
5. Start the daemon.
6. Load the snapshot:

```bash
btx-cli -rpcclienttimeout=0 loadtxoutset /path/to/snapshot.dat
```

7. Monitor background validation:

```bash
btx-cli getchainstates
```

Once the snapshot chainstate is active, wallet and mining RPCs become usable
without waiting for a full historical sync.

If you prefer a one-command bootstrap flow, the scripts under
`contrib/faststart/` can consume the same published bundle directly.
The wrapper tolerates the case where a reachable peer advances the active
chainstate past the snapshot before `loadtxoutset` runs, and it mirrors
daemon-side RPC connection overrides such as `-rpcport` into its own bootstrap
RPC calls.

BTX snapshot files generated from current releases also include the shielded
state appendix needed for restart-safe snapshot operation. That means a pruned
or assumeutxo-synced node can stop and start again without needing a full
historical shielded-block replay before wallet/service RPCs become usable.

## 2. Wallet access

Transparent and combined balances:

```bash
btx-cli getbalances
btx-cli z_gettotalbalance
```

Shielding mature coinbase rewards or prefork-compatible transparent ingress safely:

```bash
btx-cli -rpcwallet=mywallet z_planshieldfunds 25.0 "btxs1..."
btx-cli -rpcwallet=mywallet z_shieldfunds 25.0 "btxs1..."
```

See [btx-shielded-sweep-best-practices.md](btx-shielded-sweep-best-practices.md)
for chunking, fees, and stuck-transaction recovery. After `61000`, those RPCs
are limited to mature coinbase compatibility sweeps; use bridge ingress for
general transparent deposits.

## 3. Self-custody mining and useful-work APIs

For idle-time solo mining after a `--preset miner` install, hand the installed
binary paths and generated config directly into the helper scripts instead of
assuming `btxd` / `btx-cli` are already on `PATH`:

```bash
contrib/mining/start-live-mining.sh \
  --datadir="$HOME/.btx" \
  --conf="$FASTSTART_CONF" \
  --chain=main \
  --cli="$BTX_CLI" \
  --daemon="$BTXD" \
  --wallet=miner \
  --should-mine-command='/usr/local/bin/btx-should-mine-now'
```

If you omit `--address` / `--address-file`, the helper now loads or creates the
named wallet, writes a payout address under `$HOME/.btx/mining-ops/`, and then
starts the supervised mining loop. Auto-provisioned wallets are added to the
node's load-on-startup list so the supervisor can restart the daemon without
losing the mining wallet, and the launcher now reports an error if the
background loop dies during its initial startup verification. Stop it with:

```bash
contrib/mining/stop-live-mining.sh --results-dir="$HOME/.btx/mining-ops"
```

All three mining helper scripts now support `--help`, which is especially
useful for agentic installers and service managers that need to discover the
available flags dynamically.

Current challenge and service profile:

```bash
btx-cli getmatmulchallenge
btx-cli getmatmulchallengeprofile 1 0.25 0.75 2 35
btx-cli listmatmulservicechallengeprofiles 0.25 0.75 0.25 6 1 adaptive_window 24 4 35
btx-cli getmatmulservicechallengeprofile balanced 0.25 0.75 0.25 6 1 adaptive_window 24 4 35
btx-cli getmatmulservicechallengeplan solves_per_hour 600 0.25 0.75 adaptive_window 24 0.25 6 4 35
```

Profile-based application challenge / verification flow:

```bash
btx-cli issuematmulservicechallengeprofile \
  rate_limit \
  "signup:/v1/messages" \
  "user:alice@example.com" \
  normal \
  300 \
  0.25 \
  0.75 \
  0.25 \
  6 \
  1 \
  adaptive_window \
  24 \
  4 \
  35
btx-cli solvematmulservicechallenge '{...}' 250000
btx-cli redeemmatmulserviceproof '{...}'
```

Raw target-based application challenge / verification flow:

```bash
btx-cli getmatmulservicechallenge \
  rate_limit \
  "signup:/v1/messages" \
  "user:alice@example.com" \
  1.0 \
  300 \
  0.25 \
  0.75 \
  adaptive_window \
  24 \
  0.5 \
  3.0 \
  4 \
  35
btx-cli solvematmulservicechallenge '{...}' 250000 1500 2
btx-cli verifymatmulserviceproof '{...}'
btx-cli redeemmatmulserviceproof '{...}'
```

Batch verification / redemption:

```bash
btx-cli verifymatmulserviceproofs '[{...},{...}]'
btx-cli redeemmatmulserviceproofs '[{...},{...}]'
```

These RPCs are intended for:

- comment / signup anti-spam
- API rate limiting
- abuse-priced access to AI or compute services
- low-latency challenge issuance with cheap verification
- operator-facing capacity planning through the profile response's
  `operator_capacity` estimates
- inverse challenge planning through `getmatmulservicechallengeplan`, which
  returns both a direct issuance plan and the closest built-in profile matches

Operational note:
- issued service challenges are tracked in a persistent file-backed registry
- `redeemmatmulserviceproof` is still the correct anti-replay path for real
  admission control, and issued challenges survive normal daemon restarts
- a single-node setup uses the default per-datadir registry automatically
- a multi-node service tier can share redemption state by pointing every node
  at the same `-matmulservicechallengefile=/shared/path/...` value
- `getdifficultyhealth.service_challenge_registry` reports the registry's
  current `status`, `healthy` flag, `path`, entry count, and any
  `quarantine_path` / `error` details after a load or persist failure
- unreadable or unsupported registry files are quarantined on load so a bad
  shared state file is preserved for inspection instead of being silently reused
- `listmatmulservicechallengeprofiles` returns the built-in `easy`, `normal`,
  `hard`, and `idle` service tiers together with average-node solve-time and
  throughput estimates for the current chain, plus operator-capacity guidance
  for idle-time and service-gateway planning
- `getmatmulservicechallengeplan` is the easiest operator-facing inverse
  planner when you know the solve cadence you need instead of the raw
  solve-time target you want to issue
- `solver_parallelism` and `solver_duty_cycle_pct` let agents ask “what can a
  4-worker gateway at 35% duty cycle sustain?” without inventing their own
  difficulty math
- `issuematmulservicechallengeprofile` is the quickest operator path when you
  want network-relative difficulty without hand-picking a raw target
- both the profile and planner RPCs now return `issue_defaults` /
  `profile_issue_defaults`, which are intended to be consumed directly by
  agentic clients rather than copied into hand-maintained config
- `difficulty_policy=adaptive_window` lets issuers anchor service difficulty to
  recent chain timing, while `min_solve_time_s` / `max_solve_time_s` clamp the
  user-visible solve target into an acceptable UX envelope
- `solvematmulservicechallenge` is useful for local automation, smoke tests,
  and agent-controlled clients that want the node to solve a challenge directly
- local solvers can now pass `time_budget_ms` and `solver_threads` to keep
  challenge work inside an idle-time or background-execution budget
- `verifymatmulserviceproof` and `verifymatmulserviceproofs` accept an optional
  final boolean, `include_local_registry_status`; set it to `false` for
  stateless high-volume verification when you do not need local
  issued/redeemed/redeemable flags

## 4. What release maintainers need to publish

To keep this workflow usable for binary users, every release should ship:

- the BTX archives for every supported platform
- the matching `snapshot.dat`
- a compact `snapshot.manifest.json`
- `btx-release-manifest.json` with `platform_assets` entries for the supported
  Linux, macOS, and Windows archives
- `SHA256SUMS` and `SHA256SUMS.asc` covering both release assets
- updated `m_assumeutxo_data` in `src/kernel/chainparams.cpp`
- a release build that has passed the BTX assumeutxo functional coverage
- the snapshot SHA256 in the manifest and/or release notes

`contrib/faststart/btx-agent-setup.py` relies on the release manifest to select
the correct archive automatically, so the bundle contract matters just as much
as the snapshot itself.

The release-generation helper is:

```bash
python3 contrib/devtools/generate_assumeutxo.py --help
```
