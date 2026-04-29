# Rollout And Activation Plan

Date: 2026-04-23

## Goal

Roll out a consensus-backed spend-path restoration patch without creating an
 uncontrolled chain split or unsafe operator behavior.

## Recommended rollout model

Use a coordinated upgrade with explicit activation.

Preferred sequence:

1. finish implementation
2. pass fixture and functional tests
3. ship binaries to validators and miners
4. coordinate upgrade window
5. activate at a future height
6. begin pilot migration batches after activation

## Why explicit activation matters

If the patch changes which blocks are valid, then old nodes and upgraded nodes
 can disagree. That is effectively a fork boundary, even if the change is
 framed as a bug fix.

An explicit activation height gives operators:

- time to upgrade
- a clean communication target
- less ambiguity during cutover

## Upgrade targets

The following participants must be upgraded before activation:

- mining nodes
- block-validating full nodes
- wallet or recovery nodes that will construct migration transactions
- any recovery helper nodes used for auxiliary mining or validation

## Pre-activation checklist

- migration family or wire encoding finalized
- all family/context validation paths reviewed
- replay and double-claim tests passing
- activation height selected
- release notes written
- operator runbook reviewed
- pilot destination wallets chosen

## Pilot rollout

Do not start with the full stranded inventory.

Pilot sequence:

1. migrate one small stranded note or one small batch
2. confirm the block is accepted on the active chain
3. confirm the destination outputs are ordinary modern spendable notes
4. perform one ordinary spend from the recovered outputs
5. only then move to larger batches

## Rollback posture

Before pilot activation:

- preserve wallet snapshots
- preserve chainstate and shielded-state rollback points
- capture deterministic recovery plan and build artifacts

After activation:

- if the patch proves invalid in production, stop migration operations first
- do not keep forcing failed recovery blocks
- evaluate rollback only with clear network coordination

## Communication package

Operators need a short, plain statement:

- some owned shielded notes became stranded after a fork-model transition
- the patch introduces a narrow migration path
- ordinary modern spend rules are unchanged
- pilot recovery should happen in bounded batches only

## Success criteria

Rollout is successful when:

- upgraded nodes agree on migration-block validity
- pilot migration transactions confirm on the active chain
- recovered outputs are ordinarily spendable
- no replay or duplicate-claim issues appear
