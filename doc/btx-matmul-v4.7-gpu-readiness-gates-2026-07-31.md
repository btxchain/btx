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
  digest mismatch. A first mismatch is a block-scoped ambiguity, not evidence
  that the provider failed: the block remains retryable and the provider stays
  in service. A bounded registry can retry only on another opaque,
  production-canary-authorized backend execution identity. Agreement on the
  same non-header digest produces
  `InvalidConsensus`; reproduction of the header quarantines only the faulty
  provider. With no independent provider, the result is explicitly degraded
  and retryable. Execution/coverage failures remain local and may quarantine
  the provider that actually failed.
- One process-wide accelerator owner schedules authenticated-tip validation,
  winner reseal, candidate mining, and speculative validation in that priority
  order. Direct/internal ExactReplay callers enter the same owner unless their
  current worker thread already holds its lease. Higher-priority work can
  request cancellation of a lower-priority owner. The owner has fixed global
  and per-lane waiter bounds, a queue deadline, exact release ownership, and
  observable workspace request/capacity/high-water accounting. Every mining,
  reseal, worker, and direct replay lease carries the canonical nonzero
  workspace estimate; strict readiness requires the post-daemon device probe
  to report enough usable capacity. Request/reservation fields are explicitly
  estimates. Actual-use fields remain zero with a zero sample count unless the
  provider publishes a measured allocation value. The current generic backend
  ABI does not yet publish that measurement, so actual-use fields remain
  explicitly unavailable instead of echoing the admission estimate.
- A completed strict Profile 1 winner reseal may publish one bounded,
  expiring, exact-final-header and height-bound authority record. Local block
  acceptance consumes it once to skip only the duplicate ExactReplay. Ordinary
  block-body, transaction, script, chain-context, and connection checks still
  run, and a pool share that misses the real block target cannot publish it.
- Accelerator resolution, self-qualification, provider/runtime identity,
  production canary execution, and readiness-dependent service bits run only
  in the final daemon process. A pre-fork invariant aborts daemonization if an
  RC resolver or canary was entered early.
- Resolver and scheduler readiness, queue, cancellation, and timing state is
  exposed under `getmininginfo` backend-runtime telemetry.
- Scheduler telemetry is split into candidate-mining, winner-reseal,
  authenticated-tip-validation, and speculative-validation lanes. The
  `complete_lifecycle_readiness` object sums the latest candidate, reseal,
  authenticated relay, tip validation, and queue-wait components against the
  configured target spacing. Missing even one component is fail-closed; a
  single replay can never report lifecycle readiness.
  The production P2P path now stages an announcement-to-complete-body relay
  observation for a new direct child of the authenticated tip. The bounded
  observation is committed only after ordinary block acceptance records local
  ExactReplay provenance; forged headers, malformed bodies, trusted-mirror
  attestations, duplicates, and incomplete observations cannot create a
  sample. This supplies the live transport component, but the latest-component
  summary is still not a correlated percentile campaign and readiness remains
  false until the hardware evidence gates pass.
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

`getmininginfo.backend_runtime.rc_exact_replay.last_validation` distinguishes
execution failure from an unconfirmed digest mismatch and reports adjudication,
attempt counts, and the participating providers. `provider_health` reports a
provider proven faulty, its event count, and the recovery action. A quarantined
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

The bounded same-process registry and independent-adjudication state machine are
implemented, but the launch candidate deliberately registers no production
alternate by default. Registration requires an opaque capability issued by a
successful current-process production canary and bound to the runtime/device,
exact backend callbacks, transcript, MatMul dimension, and episode epoch.
Moreover, production independence is fail-closed until the resolver binds each
capability to a distinct physical-device execution identity; labels and thin
callback wrappers are not sufficient. Per-device enumeration/binding and
canary evidence must be completed for each supported multi-device deployment.
Until then, a sole GPU remains available after an unconfirmed mismatch and the
affected header remains retryable; restart alone is not independent evidence.

## Lifecycle calibration

ASERT and target-spacing review must use:

```text
candidate execution
+ candidate queue wait
+ winner reseal
+ reseal queue wait
+ one-shot local winner-authority handoff
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
from activation readiness. The source therefore keeps both public
ratification records false:

- `BTX_MATMUL_NO_INVERSION_GATE_RATIFIED`;
- `BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED`.

Production-golden availability and startup-canary success are derived runtime
states rather than manually flipped constants. Both remain false because the
committed production manifest is empty and no matching canary can run.

The startup/epoch canary mechanism itself is implemented. It binds a strict
production replay to provider family, public device architecture class,
driver/runtime ABI, activation height, profile, transcript, the consensus
MatMul dimension carried by the canonical canary header, and complete episode
parameters. CUDA binds its public compute-capability class and numeric
driver/runtime API versions. Metal binds its public GPU architecture class and
the OS build/release that distributes the Metal driver and runtime; it never
records a device name, serial, hostname, or account identifier. The committed
production-golden manifest is intentionally empty, so an identity-complete
CUDA or Metal provider reports `missing_golden` and cannot become
production-eligible. Provider families whose common resolver does not yet
expose a stable public driver/runtime fingerprint report
`provider_identity_unavailable`. What remains is reviewed evidence, any
additional provider-family identity probes, and completed provider passes—not
invention of another canary mechanism.

The repository contains useful 100-run M4 Max and sanitized Blackwell-class
CUDA production evidence, but neither is an independently reproduced
CPU-oracle corpus for every supported provider. The CUDA artifact's recorded
source fingerprint also predates the current PR head, so the exact final binary
still needs a corrected 100-run rerun. No missing production golden, canary,
or final-binary qualification value is invented by this change.

The 2026-07-31 GPU audit additionally reported a Blackwell-class 16 GiB discrete
GPU three-episode mean of approximately 21.38 seconds and a production mining
run that remained in CPU winner reseal for more than 38 minutes (that reseal
path has since been replaced by strict-device reseal). Those external artifacts
were not present in this workspace and are not treated here as independently
verified activation evidence.

## Required activation review

The separate activation-height change must still provide:

1. Complete production-shape CPU-oracle goldens with header inputs,
   intermediate checkpoints, provenance, and independent reproduction.
2. Reviewed manifest entries containing independently reproduced production
   goldens, followed by successful startup/epoch canary passes on the exact
   final binary for each provider/device architecture/driver/runtime and epoch
   tuple.
3. Strict zero-fallback two-node mining, winner-reseal, relay, and validation
   evidence on every supported provider family.
4. Foreground, `-daemon`, and `-daemonwait` CUDA lifecycle campaigns on the
   exact final binary, including a two-daemon strict RC-boundary cycle.
5. Missing-device, allocation/kernel/driver failure, independent mismatch
   adjudication, degraded sole-provider operation, alternate-provider retry,
   cancellation, restart, IBD, and reorg campaigns showing that local failures
   never punish peers or poison verdict caches.
6. Sustained contention and tail-latency results, including simultaneous
   mining, tip validation, and speculative work.
7. ASERT and target-spacing calibration against the complete
   candidate-to-authenticated-tip lifecycle rather than one replay in
   isolation.

Until that review deliberately flips both public activation gates and installs
finite activation heights, mainnet remains on MatMul v3.
