# MatMul v4.7 GPU execution and activation gates

Date: 2026-07-31

Status: implementation-only; public activation disabled

Canonical transition and activation policy:
[`btx-matmul-v4.7-transition-roadmap.md`](btx-matmul-v4.7-transition-roadmap.md).

## Boundary

Profile 1 validity remains backend-neutral. A validator derives the same exact
episode digest regardless of its local provider. GPU availability, provider
health, queueing, and execution policy are local liveness concerns and are not
additional consensus inputs.

Production operation is nevertheless GPU-dependent at the frozen Profile 1
shape. CPU ExactReplay remains useful as an explicit diagnostic/dispute oracle,
but it is not a viable automatic mining reseal, validator fallback, device
mismatch retry, or shutdown path.

## Implemented execution controls

The PR97 implementation has the following local controls:

- Profile 1 candidate mining and winner reseal use strict, self-qualified
  device execution and require complete device MAC coverage with zero CPU GEMM
  calls or fallbacks.
- `-matmulrcexecution=strict-device` requires the strict verifier path.
  `auto-fallback` is retained for pre-activation testing, and
  `cpu-diagnostic` is an explicit portable-oracle mode.
- ExactReplay reports `Valid`, `InvalidConsensus`,
  `LocalAcceleratorFailure`, or `Cancelled`. Only a completed authoritative
  disagreement or over-target digest is consensus-invalid.
- Strict validation never starts the automatic portable replay after a device
  digest mismatch. The provider failure is local and the block remains
  retryable. A provider that returns a mismatching digest or fails after device
  submissions begin is quarantined for the rest of the process lifetime.
  Further strict work on that provider fails locally before submission.
- One process-wide accelerator owner schedules authenticated-tip validation,
  winner reseal, candidate mining, and speculative validation in that priority
  order. Higher-priority work can request cancellation of a lower-priority
  owner.
- Resolver and scheduler readiness, queue, cancellation, and timing state is
  exposed under `getmininginfo` backend-runtime telemetry.
- Scheduler telemetry is split into candidate-mining, winner-reseal,
  authenticated-tip-validation, and speculative-validation lanes. The
  `complete_lifecycle_readiness` object sums the latest candidate, reseal,
  authenticated relay, tip validation, and queue-wait components against the
  configured target spacing. Missing even one component is fail-closed; a
  single replay can never report lifecycle readiness.
  The ordinary daemon does not yet produce a defensibly correlated
  authenticated-relay sample, so that component remains missing outside the
  controlled two-node evidence harness and readiness stays false.
- The RC admission budgets, retained-address/netgroup accounting, pending-work
  reservation, same-hash sidecar hardening, and equal-priority handoff rules
  apply before scarce accelerator work starts. Local failure and cancellation
  release delivery and reservation state without caching a consensus verdict.

While RC is disabled, the existing v3 `NODE_MATMUL_CONSENSUS` advertisement is
unchanged. Once an RC epoch is configured, the bit is withheld unless strict
device execution and the production readiness gates are satisfied.

The configuration defaults are intentionally asymmetric while public RC is
disabled: production-shape mining is always strict-device, but validation
defaults to `auto-fallback` so pre-activation and diagnostic nodes remain
usable. Operators preparing for an activated RC epoch must explicitly select
`-matmulrcexecution=strict-device`. At an active RC height,
`auto-fallback` cannot advertise full MatMul consensus readiness.

## Local accelerator failure runbook

`getmininginfo.backend_runtime.rc_exact_replay.provider_health` reports the
quarantined provider, reason, event count, and recovery action. A quarantined
provider is a local availability problem:

1. Leave the candidate pending/retryable. Do not invalidate it, reduce its
   authenticated chainwork, or punish its announcing peer.
2. Stop mining on the affected device and inspect the provider, driver,
   allocation, temperature, and device-reset logs.
3. Repair or reset the accelerator, then restart `btxd` so startup
   qualification runs again. Alternatively restart with another independently
   qualified provider/device selected.
4. Confirm `provider_health.quarantined=false`, strict-device policy,
   production qualification, zero CPU fallbacks, and a successful canary
   before advertising validator readiness.
5. Use `cpu-diagnostic` only for an explicit offline dispute. It is not an
   inline recovery path and its result must not silently clear a device
   quarantine.

The current resolver selects one qualified provider per process. Automatic
same-process failover is therefore not claimed. Selecting a second provider
requires an operator-controlled restart; adding hot multi-provider failover
requires a separate device registry and scheduler ownership review.

## Lifecycle calibration

ASERT and target-spacing review must use:

```text
candidate execution
+ candidate queue wait
+ winner reseal
+ reseal queue wait
+ authenticated relay
+ receiving tip validation
+ validation queue wait
```

The RPC calculation is operational telemetry only. Latest-component values
are useful for diagnosis but are not a statistically coherent percentile
campaign. Activation still requires a sustained two-node campaign reporting
p50/p95/p99/max for the complete lifecycle under mining, IBD, competing-tip,
and reorg contention. CI exercises deterministic repeated priority handoffs
and exact release/cancellation accounting; it is not represented as a
hardware soak.

## Evidence gates that remain false

Correctness self-qualification and automatic-provider eligibility are distinct
from activation readiness. The source therefore keeps all of these public
activation records false:

- `BTX_MATMUL_NO_INVERSION_GATE_RATIFIED`;
- `BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED`;
- `kRCProfile1ProductionGoldensAvailable`; and
- `kRCProfile1StartupCanaryPassed`.

The repository contains useful M4 Max production evidence, but it is not an
independently reproduced CPU-oracle corpus for every supported provider.
No missing production golden or canary value is invented by this change.

The 2026-07-31 GPU audit additionally reported an RTX 5060 three-episode mean
of approximately 21.38 seconds and a production mining run that remained in
CPU winner reseal for more than 38 minutes. Those external artifacts were not
present in this workspace and are not treated here as independently verified
activation evidence.

## Required activation review

The separate activation-height change must still provide:

1. Complete production-shape CPU-oracle goldens with header inputs,
   intermediate checkpoints, provenance, and independent reproduction.
2. A startup/epoch production canary keyed by binary revision, provider,
   device architecture, driver/runtime, and epoch parameters.
3. Strict zero-fallback two-node mining, winner-reseal, relay, and validation
   evidence on every supported provider family.
4. Missing-device, allocation/kernel/driver failure, mismatch quarantine,
   recovery/alternate-provider retry, cancellation, restart, IBD, and reorg
   campaigns showing that local failures never punish peers or poison verdict
   caches.
5. Sustained contention and tail-latency results, including simultaneous
   mining, tip validation, and speculative work.
6. ASERT and target-spacing calibration against the complete
   candidate-to-authenticated-tip lifecycle rather than one replay in
   isolation.

Until that review deliberately flips both public activation gates and installs
finite activation heights, mainnet remains on MatMul v3.
