# BTX Security Current Status

This file is the stable branch-level summary for the shielded hardening program
that activates at block `61000`.

## Current State

- The hardening branch closes the mapped live implementation findings from the
  2026-03-28 source audit on the reviewed node path, and the later
  lifecycle-control follow-on is now also closed by a dedicated post-fork
  transaction family instead of the earlier proofless `V2_SEND` lane.
- The original source-audit row that remains open is `L12`, the future PQ-128
  shielded parameter-set redesign.
- There is no currently mapped unresolved `Critical` finding from the original
  2026-03-28 tracker, and there is no remaining live branch-local lifecycle
  security follow-on on the reviewed node path.
- The lifecycle closeout now includes explicit regression coverage showing
  that a legitimate multi-output transparent skeleton is accepted only when
  the binding matches, any post-signature transparent output mutation is
  rejected across proof-check, mempool, and block-connect paths, and lifecycle
  transactions do not create spendable shielded value or operator-note wallet
  balance.
- The later PR #134 lifecycle/operator-note follow-on review is reconciled in
  [findings/pr134-20260401-lifecycle-followon-closeout.md](findings/pr134-20260401-lifecycle-followon-closeout.md).

## What The `61000` Fork Preserves

- Existing pre-`61000` blocks remain valid.
- Existing pre-`61000` wallet funds remain spendable under the historical
  rules, then transition onto the post-fork rules when new spends are created.
- Persisted shielded state, registry data, nullifiers, settlement anchors, and
  bridge metadata are recovered through the reviewed restart/rebuild paths
  instead of requiring a chain rewrite.

## What The `61000` Fork Tightens

- retired MatRiCT envelopes and legacy post-fork SMILE wire families are
  rejected
- post-fork V2 bundle wire families collapse to the generic post-fork surface
- direct public-flow `V2_SEND` is disabled after the fork, with a narrow
  mature-coinbase compatibility lane retained for miner shielding flows
- post-fork lifecycle controls move onto a distinct zero-shielded-state
  `V2_LIFECYCLE` bundle bound to the transparent transaction skeleton, while
  legacy send-lifecycle controls are rejected
- default RPC disclosure is reduced and raw viewing-key export/import is gated
- Dandelion++ routing and shielded state journaling are hardened
- post-fork SMILE tuple construction uses the hardened proof path

## Remaining Security Work

- `L12`: stronger shielded PQ-128 parameter sets and the corresponding proof
  size / runtime tradeoff

The activation plumbing for that future upgrade already exists:

- `nShieldedPQ128UpgradeHeight`
- `-regtestshieldedpq128upgradeheight`

See [roadmap.md](roadmap.md) and
[findings/l12-pq128-parameter-upgrade.md](findings/l12-pq128-parameter-upgrade.md).

## Readiness Caveat

Security hardening and functional transition coverage are in place. The
remaining non-security caveat is no longer a broad post-fork regression.
The live `61000` readiness surface is now measured explicitly by validation
surface:

- postfork direct `1x2` runtime report:
  `62,105` bytes, `386 tx/block`, `6.84 s` build sample, `264 ms` proof check
- postfork egress `32x32` runtime report:
  `468,653` bytes, `51 tx/block`, recovered size/block-fit envelope, `20.54 ms`
  proof check on the latest host-local sample
- prefork proofless deposit compatibility report:
  `29,407` bytes, `816 tx/block`, `162.80 ms` build sample, `0.77 ms` proof
  check

The important distinction is that the old wallet `mixed unshield v2_send`
benchmark is a prefork compatibility number, not a post-`61000` merge-readiness
signal. Postfork direct mixed unshield is intentionally disabled in favor of
bridge/egress settlement, so those prefork numbers are no longer used to judge
the hardening fork.

So the honest remaining merge-readiness question is not a live security gap and
not a postfork size/capacity regression. It is limited to operator-path
benchmark/documentation polish around wallet cold-start variance, with the
current branch numbers documented in
[../btx-postlaunch-optimization-roadmap.md](../btx-postlaunch-optimization-roadmap.md).
