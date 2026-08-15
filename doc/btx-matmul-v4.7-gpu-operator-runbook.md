# MatMul v4.7 GPU validator operator runbook

Status: Epoch A is a mainnet release candidate with a finite compiled candidate
height (`185000`) and true source ratification flags. Those values are
technically live if this source is merged unchanged, but they are not a release
approval. Testnet and signet remain disabled. Operators must not advertise
production readiness until the exact-final combined-tree golden, schema-4
ASERT, trusted-mirror rehearsal, full-suite, operational-evidence, and
live-tip-runway gates close.

Canonical transition and activation policy:
[`btx-matmul-v4.7-transition-roadmap.md`](btx-matmul-v4.7-transition-roadmap.md).

## Roles and policy

Production Profile 1 mining requires a qualified device for both candidate
work and winner reseal. It never falls back to a CPU episode.

Validation has three explicit local policies:

- `-matmulrcexecution=strict-device`: production validator mode; requires a
  production-eligible provider and forbids CPU GEMM fallback.
- `-matmulrcexecution=auto-fallback`: pre-activation/test mode; a failed device
  contraction may use the portable oracle. It is the default only while the
  public RC epoch is disabled.
- `-matmulrcexecution=cpu-diagnostic`: explicit offline diagnostic/dispute
  mode.

The default asymmetry is deliberate. A miner cannot publish a production
Profile 1 winner without strict reseal, while a pre-activation validator can
still exercise consensus mechanics on a CPU-only test machine. An active
public RC validator must use strict-device and satisfy every readiness gate.

## CUDA / cuBLASLt stack (sm_120)

Self-qualification and the production canary on Blackwell sm_120 are bound to
the **runtime stack**, not only the silicon:

| Stack | Observed result |
|---|---|
| CUDA **13.2** + cuBLASLt **13.4** | Canary / ExactReplay pass on RTX 5090 / RTX PRO 6000 |
| CUDA 13.0 + cuBLASLt 13.1 | `episode_digest_mismatch_backend_vs_cpu` — fails closed |

Ada (4090), Hopper (H100), and B200/B300 are outside the sealed golden
manifest and cannot self-qualify. Archive / consensus operators on sm_120
should pin the 13.2 / 13.4 combo before expecting `NODE_MATMUL_CONSENSUS`.

## Competing-branch / “zombie” ExactReplay

If headers for a better-work chain arrive while the node still holds a local
stub tip, async ExactReplay of that competing branch must not run at
`SpeculativeValidation` priority (it was preempted → `ExactReplay: cancelled`
and the branch never connected). 0.33.3 maps competing-branch verify work to
`TipValidation`. Until upgraded, operators can recover with:

```text
matmulrcexecution=strict-device
# then invalidateblock <local stub tip> and/or feed blocks via submitblock
```

## Public block-data peers (post-activation)

Public archival seeds are enough for functional participation. Do **not**
require a direct signer `addnode`. After the 0.33.3 network-stability work,
those archives persist tip-child bodies before quorum, `getdata`-serve them
to the signer, cache-and-forward `MMATTEST`, and answer `GETMMATTEST` from
that cache. Keep `blocksonly=0` so the seeds actually see your blocks.

Seed list: [`btx-public-node-bootstrap.md`](btx-public-node-bootstrap.md).

## Mining on the attested chain

Canonical blocks are those the configured signer set attests. A heavier
unattested fork is an orphan once the signer stays on the other branch. Hashrate
wins races; it does not raise the canonical block rate above the signer's
ExactReplay + attestation throughput (today often ~1 block / 1–2 minutes with a
single signer). 1-of-1 is a single point of failure; M-of-N is the production
shape when independent signers exist.

### Submit/mining node config (none of these is optional)

```text
blocksonly=0
matmulvalidation=consensus
matmultrustedpubkey=<signer compressed pubkey>
matmultrustedthreshold=1
```

- `-blocksonly=0`: a mining/submit node must relay aggressively. With
  `-blocksonly=1` winning blocks often never reach the signer (signer tip stuck
  at yours minus one) and every win orphans.
- `-matmultrustedpubkey` + `-matmultrustedthreshold`: a plain consensus node
  reports `getmatmultrustedstatus.configured=false` and stores zero
  attestations, so tooling cannot see the attested tip. Adding the signer key
  does **not** skip ExactReplay; it only lets the node track `MMATTEST` and
  follow/recover onto the attested chain. A self-run bridge/archive signing
  key as the only `-matmultrustedpubkey` follows that key's chain. An
  unusually high local win rate (near-consecutive blocks) is a mining-alone
  symptom: check `getmininginfo.chain_guard.island_suspect` and
  `getfinalityinfo.warnings`.
- Pool: build only on `getmatmulattestedtip` (or
  `getmatmultrustedstatus.attested_tip`). If `on_active_chain` is false, the
  node is on a competing unattested fork and will auto-reorg; do not stack
  unattested candidates. Win → wait for attestation; lose → abandon.
- Public archival `addnode` seeds are enough for participation. Do **not**
  require a direct signer peer: archives persist tip-child bodies before
  quorum, `getdata`-serve them to the signer, cache-and-forward `MMATTEST`,
  and answer `GETMMATTEST` from that cache. Keep `blocksonly=0` so those
  seeds actually see your blocks.
- `NODE_MATMUL_ATTESTATION_ARCHIVE` is not a signer locator. Competing-tree
  nodes advertise that bit too. Follow `getmatmulattestedtip` with
  `on_active_chain=true`, not a peer's service flags.
- `loadtxoutsetattested`: the snapshot base header must be known. A competing
  most-work headers-only tree (the 1883xx flood) does **not** block the load
  and is not a reason to `invalidateblock` or `connect=`-restrict. Do not
  `preciousblock` that tree.
- `-matmulvalidation=trusted` only connects past the snapshot when archives
  can answer `GETMMATTEST` for the canonical suffix. Until the public seed
  fleet is on this head, use `consensus` (ExactReplay) for that climb;
  `trusted` after the seeds are upgraded.

`getmatmulattestedtip` is the continuous attested-tip surface. On a quiet
linear chain the signer typically attests ~1 behind the active tip, so `hash`
may lag `getbestblockhash` by one block. `hash` / `on_active_chain` only see
HAVE_DATA on **this** chain: a stranded fork still reports
`on_active_chain=true` there. Use `getblockchaininfo.matmul_signed_frontier`
(`blocks_behind`, `on_active_chain`) — also on `getmatmulattestedtip.signed_frontier`
and every `UpdateTip` line as `signed_frontier=` / `behind=`. A large
`blocks_behind` with `on_active_chain=false` is a fork, not a paused signer.
`getmatmulattestations <hash>` still only lists retained signatures for that
hash.

Until upgraded, a node already on a heavier unattested fork needed
`invalidateblock` of the first divergent block (deep invalidate deadlocked
before `3d7a6600`; after that commit a stuck RPC can still freeze activation
until restart). Current heads auto-abandon that fork when a unique competing
attested `HAVE_DATA` chain is known.

Public archival `addnode` seeds:
[`btx-public-node-bootstrap.md`](btx-public-node-bootstrap.md).

## Monitoring

Inspect:

```text
getmininginfo.backend_runtime.rc_exact_replay
getmininginfo.backend_runtime.rc_accelerator_scheduler
```

Required healthy state includes:

- selected provider is self-qualified and production eligible;
- strict-device policy is active;
- provider is not quarantined;
- an unconfirmed mismatch reports `no-independent-provider` rather than
  quarantining the sole healthy device;
- the last validation is fully accelerated with zero CPU calls/fallbacks;
- scheduler release-invariant violations are zero;
- scheduler queue/capacity rejections and deadlines are understood; the
  conservative request/reservation high-water remains within declared usable
  capacity; provider-measured current/high-water values are treated as actual
  allocation evidence only when `workspace_telemetry_samples` is nonzero;
- candidate, winner-reseal, relay, and tip-validation lifecycle components
  have all been measured;
- complete lifecycle tail latency, not one replay, fits the calibrated target.

`complete_lifecycle_readiness.within_target_spacing` is an uncorrelated
latest-component screen, not a measurement of one block. The stronger
`operationally_ready` additionally requires one block-correlated end-to-end
record, which the launch candidate does not manufacture from unrelated lane
samples, so it remains false even if static hardware gates are later enabled.
Neither field is an activation vote or a substitute for sustained correlated
p99 evidence.

The daemon's relay sample measures the monotonic interval from a newly accepted
direct-tip header announcement to arrival of its complete body. It is published
only if that body subsequently passes ordinary acceptance with local
ExactReplay provenance. It intentionally excludes verification execution time,
which is reported by the tip-validation scheduler lane, and it does not accept
trusted-mirror authority as hardware lifecycle evidence.

## Device mismatch or provider failure

A first strict device digest mismatch is classified
`LocalAcceleratorFailure` / `unconfirmed-digest-mismatch`. The node does not
produce a consensus-invalid verdict, punish the peer, cache a negative result,
or quarantine the provider merely because it disagreed with an untrusted
header commitment.

If a different, independently canaried backend execution identity computes the
same non-header digest, the header is `InvalidConsensus` and both healthy
providers remain available. If the alternate reproduces the header, only the
faulty provider is quarantined. If no independent provider exists, the block
remains retryable in an explicit degraded state and the sole provider continues
serving other headers.

Recovery:

1. Preserve the block as pending/retryable.
2. Pause local mining and inspect the accelerator/driver.
3. Repair or reset the device.
4. Retry on an independently canaried provider/device when registered. A
   process restart by itself is not independent mismatch evidence.
5. Restart only after repair/reset if the failed provider must be restored.
6. Wait for qualification/canary completion and confirm clean telemetry before
   resuming service advertisement.

Do not use automatic CPU replay as an inline remedy. CPU diagnostic replay is
an operator-initiated dispute tool only. The bounded registry and deterministic
adjudication are present, but production alternates are not registered until
each independently addressable device/provider has its own exact production
canary, opaque process capability, and resolver-bound physical-device execution
identity. Until that binding exists, production independence returns false;
free-form labels or thin callback wrappers cannot confirm a peer-invalid
verdict.

## Daemon lifecycle

RC accelerator initialization occurs after Unix daemonization and before
network service publication. `-daemon` and `-daemonwait` abort if resolver or
canary state exists before `fork()`. Before deployment, run the opt-in real-CUDA
functional lifecycle test in foreground, `-daemon`, and `-daemonwait` modes;
the final activation evidence must additionally mine through the RC boundary
and validate on a separately daemonized strict GPU node.

## Calibration and testing boundary

Block-time and ASERT calibration must include winning candidate execution,
winner reseal, the bounded local authority handoff (or any fallback local
replay), relay, receiving-node validation, and every scheduler wait.
Measure two-node p50/p95/p99/max under simultaneous mining, tip validation,
speculation, IBD, and reorgs.

Unit tests repeat deterministic contention, cancellation, priority handoff,
and release-integrity scenarios at CI scale. They do not constitute a GPU
thermal, driver-reset, multi-daemon, or long-duration soak. Those hardware
campaigns remain mandatory activation evidence.
