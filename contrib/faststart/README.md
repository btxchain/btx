# BTX Fast-Start Validating Nodes

This directory contains the first-run bootstrap wrapper for operators who want
to:

1. fetch the matching snapshot for a chain,
2. load it with `loadtxoutset`,
3. keep an eye on background validation with `getchainstates`.

The scripts are intentionally small and composable. They do not try to invent a
canonical snapshot distribution system for BTX. Instead, they support either:

- a direct `--snapshot-url` plus `--snapshot-sha256`, or
- a JSON manifest that maps each chain name to the published snapshot metadata, or
- the compact per-release `snapshot.manifest.json` emitted by
  `contrib/devtools/generate_assumeutxo.py`.

Entry points

- `btx-agent-setup.py` installs the right published binary archive for the
  current platform from a GitHub release bundle and can immediately hand off to
  the fast-start bootstrap flow.
- `miner-faststart.sh` starts the bootstrap flow with the miner-oriented preset.
- `service-faststart.sh` starts the bootstrap flow with the service-oriented preset.
- `btx-faststart.py` is the shared orchestrator and can be called directly.

Presets

- `miner` keeps the node in a compact, mining-friendly state:
  `prune=4096`, `blockfilterindex=1`, `coinstatsindex=1`,
  `retainshieldedcommitmentindex=1`, and conservative outbound-peer floors for
  mining.
- `service` keeps the node in a service-oriented state:
  `prune=0`, `txindex=1`, `blockfilterindex=1`, `coinstatsindex=1`, and
  `retainshieldedcommitmentindex=1`.

For horizontally scaled service gateways, add
`--matmul-service-challenge-file=/shared/path/matmul_service_challenges.dat`
so every issuer/redeemer node points at the same shared challenge registry.

The wrapper writes its generated config and downloaded snapshot under
`<datadir>/faststart/`, so the workflow is isolated from an operator's existing
`btx.conf`.

By default `btx-agent-setup.py` keeps its download cache in a sibling
`<install-dir>-agent-setup-cache` directory so the extracted install tree stays
clean. Pass `--cache-dir` if you want that cache somewhere else.

Published release bundles should also include `btx-release-manifest.json`.
That manifest advertises `platform_assets`, which map the release archives for
Linux/macOS/Windows to stable platform ids such as `linux-x86_64` and
`macos-arm64`. `btx-agent-setup.py` consumes that manifest so binary users can
install the right archive without hard-coding filenames. For remote release
URLs, the installer now treats `SHA256SUMS` as the source of truth for the
manifest, archive, and snapshot-manifest hashes, and it verifies
`SHA256SUMS.asc` when the release advertises one. Use
`--allow-unsigned-release` only for intentionally unsigned test bundles.
If the GitHub repository or release is private, export `BTX_GITHUB_TOKEN`,
`GITHUB_TOKEN`, or `GH_TOKEN` before running the installer so it can
authenticate the manifest and archive downloads through the GitHub release
asset API. `btx-faststart.py` honors the same env vars for private snapshot
manifest and snapshot asset URLs.
The canonical platform archives also now include the helper scripts in this
directory, the mining helpers under `contrib/mining/`, and
`doc/btx-download-and-go.md`, so a direct archive extraction still gives the
operator the documented fast-start entry points without needing a second repo
checkout.
Release bundles may also publish signer-qualified Guix attestation assets under
the manifest's `attestation_assets` list. The installer ignores those
provenance files, but they are part of the intended operator-facing release
contract for reproducible major-architecture builds.

One-shot install + bootstrap

```bash
python3 contrib/faststart/btx-agent-setup.py \
  --repo btxchain/btx-node \
  --release-tag v29.2-btx1 \
  --preset service \
  --datadir="$HOME/.btx-service"
```

That flow:

1. downloads `btx-release-manifest.json`,
2. verifies the manifest against `SHA256SUMS` and `SHA256SUMS.asc` for remote releases,
3. selects the matching binary archive for the current platform,
4. verifies the archive and `snapshot.manifest.json`,
5. extracts `btxd` / `btx-cli` plus the bundled helper scripts/docs,
6. runs `btx-faststart.py` with the chosen preset.

Machine-readable install summary

`btx-agent-setup.py --json` now keeps bootstrap chatter on stderr and prints a
clean JSON summary to stdout. That makes it safe for agentic installers to
capture the installed binary paths and the generated fast-start config before
handing off to mining or service automation:

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

When `--preset miner` is used, the JSON summary also includes
`start_live_mining_command` and `stop_live_mining_command` arrays for direct
handoff into unattended mining supervisors.

Manifest shape

```json
{
  "main": {
    "url": "https://.../main-snapshot.dat",
    "sha256": "..."
  },
  "testnet4": {
    "url": "https://.../testnet4-snapshot.dat",
    "sha256": "..."
  }
}
```

You can keep a local copy as `contrib/faststart/snapshot-manifest.json`, or
pass `--snapshot-manifest=/path/to/manifest.json` or
`--snapshot-url=https://...` directly. If those URLs point at a private GitHub
release, `btx-faststart.py` also honors `BTX_GITHUB_TOKEN`, `GITHUB_TOKEN`, or
`GH_TOKEN` for the manifest and snapshot asset downloads.

Example

```bash
contrib/faststart/miner-faststart.sh \
  --datadir="$HOME/.btx" \
  --chain=main \
  --snapshot-manifest="$HOME/btx-snapshot-manifest.json"
```

The wrapper will stop only after `loadtxoutset` succeeds and the chainstate
poller sees the snapshot chain disappear, unless `--follow` is set. If the
daemon reaches a better active chainstate before `loadtxoutset` runs, the
wrapper now treats the snapshot as superseded and continues instead of failing.
Daemon-side RPC connection overrides such as `--daemon-arg=-rpcport=...` are
also mirrored into the wrapper's internal `btx-cli` calls automatically.

Service-gateway example with a shared redeem registry:

```bash
contrib/faststart/service-faststart.sh \
  --datadir="$HOME/.btx-service-a" \
  --chain=main \
  --snapshot-manifest="$HOME/btx-snapshot-manifest.json" \
  --matmul-service-challenge-file=/srv/btx-shared/matmul_service_challenges.dat
```

Adaptive service-challenge example:

```bash
btx-cli listmatmulservicechallengeprofiles 0.25 0.75 0.25 6 1 adaptive_window 24 4 35
btx-cli getmatmulservicechallengeprofile balanced 0.25 0.75 0.25 6 1 adaptive_window 24 4 35
btx-cli getmatmulservicechallengeplan solves_per_hour 600 0.25 0.75 adaptive_window 24 0.25 6 4 35
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
```

Real admission control should still use `redeemmatmulserviceproof`; the local
`solvematmulservicechallenge` RPC is mainly for integration testing and
agent-controlled clients. The profile-based issuance path is the recommended
operator default because it maps directly onto the built-in `easy`, `normal`,
`hard`, and `idle` tiers, returns average-node pacing estimates, and now
includes operator-capacity guidance for planning how much challenge volume a
node can sustain during idle-time or service-gateway workloads.
`getmatmulservicechallengeplan` adds the inverse planner for “I need N
solves/hour with this worker budget”; it returns the direct issuance defaults
plus the closest built-in profile matches for the current network state.

For agentic clients that do solve locally, `solvematmulservicechallenge` now
accepts optional `time_budget_ms` and `solver_threads` arguments so a client
can cap how long or how wide the local solver runs in the background.
High-volume verification services can keep proof checking stateless by passing
`false` as the final argument to `verifymatmulserviceproof` or
`verifymatmulserviceproofs`, which skips the local/shared issued-challenge
registry lookup and omits the local issuance/redeem fields from the result.

Operators can watch `getdifficultyhealth` for
`service_challenge_registry.status`, `healthy`, `path`, and `quarantine_path`.
If a shared registry file is unreadable or on an unsupported version, the node
now quarantines that file instead of silently reusing it.

For the miner preset, `contrib/mining/start-live-mining.sh` now understands the
fast-start-generated `--conf`, `--chain`, and custom `--rpcport` settings, and
it auto-provisions the named mining wallet plus an address file when you do not
pass `--address` / `--address-file`. The mining helpers now also support
`--help`, which is useful when an installed binary bundle is being driven by an
agent instead of a hand-maintained shell profile. Auto-provisioned mining
wallets are added to the node's load-on-startup list so supervised daemon
restarts keep mining working, and the launcher now fails early if the
background loop dies before its initial startup check completes.
