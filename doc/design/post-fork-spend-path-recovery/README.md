# Post-Fork Spend-Path Recovery Bundle

Date: 2026-04-23

## Purpose

This bundle is a generalized recovery design package for any BTX wallet that:

- still owns shielded notes
- can still decrypt and account for them
- but no longer has an accepted spend path after a hard-fork or shielded-model transition

This is intended as an engineering and operations package for restoring a
 consensus-valid spend path. It is not a wallet-only workaround package.

## Intended audience

- protocol engineers
- validation / wallet engineers
- miner and node operators
- release coordinators

## What problem this bundle addresses

Some post-fork shielded notes can become trapped in a state where:

- custody is intact
- visibility is intact
- ordinary spendability is gone

This bundle treats that as a spend-path restoration problem, not a simple
 wallet repair problem.

## Bundle contents

- [01-problem-statement.md](01-problem-statement.md)
- [02-consensus-design-memo.md](02-consensus-design-memo.md)
- [03-implementation-rfc.md](03-implementation-rfc.md)
- [04-rollout-and-activation-plan.md](04-rollout-and-activation-plan.md)
- [05-operator-runbook.md](05-operator-runbook.md)
- [06-test-and-verification-plan.md](06-test-and-verification-plan.md)
- [07-upstream-port-context.md](07-upstream-port-context.md)
- [08-initial-upstream-touchpoints.md](08-initial-upstream-touchpoints.md)
- [09-implementation-record.md](09-implementation-record.md)
- [10-pr-readiness-checklist.md](10-pr-readiness-checklist.md)
- [11-real-batch-evidence.md](11-real-batch-evidence.md)
- [12-pr-cover-note.md](12-pr-cover-note.md)

## Recommended design direction

The recommended direction in this bundle is:

- do not weaken ordinary modern spend rules
- do not fake missing registry or witness state
- add a narrow consensus-backed migration or recovery path that converts owned
  stranded legacy notes into ordinary modern spendable outputs

## Bundle status

This bundle is a design-and-implementation package.

It now includes an activation-gated upstream implementation plus deterministic
regression coverage, a real-batch trusted-state validation memo, and a PR-ready
cover note, but rollout still depends on review and coordinated activation
planning.
