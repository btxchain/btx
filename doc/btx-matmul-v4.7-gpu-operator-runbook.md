# MatMul v4.7 GPU validator operator runbook

Status: pre-activation; public RC activation remains disabled

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
- the last validation is fully accelerated with zero CPU calls/fallbacks;
- scheduler release-invariant violations are zero;
- candidate, winner-reseal, relay, and tip-validation lifecycle components
  have all been measured;
- complete lifecycle tail latency, not one replay, fits the calibrated target.

`complete_lifecycle_readiness.within_target_spacing` is an uncorrelated
latest-component screen, not a measurement of one block. The stronger
`operationally_ready` field also requires the production-golden and startup
canary gates; it therefore remains false in this PR. Neither field is an
activation vote or a substitute for sustained correlated p99 evidence.

## Device mismatch or provider failure

A strict device digest mismatch is classified
`LocalAcceleratorFailure`. The node does not produce a consensus-invalid
verdict, punish the peer, or cache a negative result. The provider is
quarantined and further strict submissions to that provider are refused.

Recovery:

1. Preserve the block as pending/retryable.
2. Pause local mining and inspect the accelerator/driver.
3. Repair or reset the device.
4. Restart `btxd`, or restart with another qualified provider.
5. Wait for qualification/canary completion and confirm clean telemetry before
   resuming service advertisement.

Do not use automatic CPU replay as an inline remedy. CPU diagnostic replay is
an operator-initiated dispute tool only. The current implementation does not
claim same-process hot failover because the resolver owns one selected
provider; a future multi-provider registry must preserve scheduler exclusivity,
health isolation, and deterministic retry semantics.

## Calibration and testing boundary

Block-time and ASERT calibration must include winning candidate execution,
winner reseal, relay, receiving-node validation, and every scheduler wait.
Measure two-node p50/p95/p99/max under simultaneous mining, tip validation,
speculation, IBD, and reorgs.

Unit tests repeat deterministic contention, cancellation, priority handoff,
and release-integrity scenarios at CI scale. They do not constitute a GPU
thermal, driver-reset, multi-daemon, or long-duration soak. Those hardware
campaigns remain mandatory activation evidence.
