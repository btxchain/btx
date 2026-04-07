# L12: Shielded PQ-128 Parameter Upgrade

Tracker reference:

- [../../btx-security-fixes-20260328-tracker.md](../../btx-security-fixes-20260328-tracker.md)

## Status

- `open`
- severity in the current tracker: `Low`
- category: architectural / future proof-system upgrade

## What This Means

BTX already has post-quantum signature support on the P2MR side, but the
shielded proof parameter sets do not yet reach the desired full PQ-128 margin.

This is not currently tracked as a live practical break of existing shielded
transactions. It is a long-term security-margin and future-quantum readiness
gap.

## Why It Is Not Already Landed

A real PQ-128 shielded upgrade is expected to increase:

- proof size
- prover time
- verifier time

So it should ship as an explicit measured upgrade, not as an unmeasured quiet
change hidden inside the `61000` hardening fork.

## Enablement Already Present In This Branch

- dedicated consensus field: `nShieldedPQ128UpgradeHeight`
- dedicated regtest override: `-regtestshieldedpq128upgradeheight`

This means the future upgrade can be activated cleanly without reopening the
basic fork-plumbing work.

## Required Future Work

1. choose the replacement parameter set / proof version
2. benchmark proof size and runtime against the live post-`61000` surface
3. add full activation-boundary tests for the PQ-128 fork
4. document wallet/operator migration expectations for any affected shielded
   funds or tooling
