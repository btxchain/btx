# BTX Security Roadmap

This roadmap tracks the remaining security work that should outlive the
`61000` hardening fork and continue as stable project documentation.

## Completed By The `61000` Hardening Program

- shielded proof/wire-family hardening
- RPC disclosure reduction
- Dandelion++ hardening
- post-fork wallet privacy redesign
- state durability/restart hardening on the reviewed launch path
- SMILE tuple-opening hardening (`M4`)

Detailed closeout is recorded in
[findings/audit-20260328-closeout.md](findings/audit-20260328-closeout.md) and
the detailed issue matrix in
[../btx-security-fixes-20260328-tracker.md](../btx-security-fixes-20260328-tracker.md).

## Open Security-Margin Work

### 1. PQ-128 Shielded Parameter Upgrade (`L12`)

Status:

- still open
- future consensus upgrade, not a live mapped critical implementation bug

What is already enabled in-tree:

- dedicated consensus parameter: `nShieldedPQ128UpgradeHeight`
- regtest override: `-regtestshieldedpq128upgradeheight`
- future fork plumbing can be exercised without reopening chain-parameter work

Primary next deliverables:

1. new parameter set and proof-size/runtime measurement report
2. upgraded prover/verifier codec and versioning plan
3. `60999` / `61000`-style boundary coverage for the eventual PQ-128 fork
4. migration guidance for funds and tooling

See [findings/l12-pq128-parameter-upgrade.md](findings/l12-pq128-parameter-upgrade.md).

## Production Merge Gating Still Separate From Security Closure

The hardening program and the performance/launch-signoff program are related
but not the same:

- security closure says the mapped live bugs are addressed
- production merge readiness still requires acceptable size/TPS/runtime results
  on the post-fork launch surface

Use the stable optimization roadmap at
[../btx-postlaunch-optimization-roadmap.md](../btx-postlaunch-optimization-roadmap.md)
for those follow-on throughput and proof-size tasks.

## Lifecycle Guidance

- add new active security items as stable files under `doc/security/findings/`
- keep this roadmap limited to items still open or intentionally staged
- move implementation scratch notes out of the repo instead of adding new
  `tmp-*` trackers
