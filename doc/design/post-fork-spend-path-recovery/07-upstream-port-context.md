# Upstream Port Context

Date: 2026-04-23

## Purpose

This note keeps the clean upstream port effort tied to the live recovery
evidence and tooling that still exist only in the parallel recovery branch.

The goal is to let engineers work on a clean upstream base without
losing the hard-won incident knowledge, replay artifacts, and wallet-specific
diagnostics gathered during the active recovery effort.

## Branch roles

The clean upstream branch is the implementation track.

The parallel recovery branch remains the source of:

- captured rejected tx and block behavior
- custom recovery RPCs and wallet builders
- live recovery operations knowledge
- local test fixtures already written against the custom branch

## Important guardrails

- Do not replace the live recovery daemon with the upstream daemon while the
  port is in progress.
- Do not discard the current recovery branch. It contains the only working
  reproduction path for several recovery-specific failures.

## Current findings to preserve

### Wallet state

- Affected wallets can still own, decrypt, and account for the stranded notes.
- Ordinary spendability is gone because the notes do not have the modern
  account-registry spend witness and hint material required by normal post-fork
  `V2_SEND` and `V2_INGRESS_BATCH` flow.
- Wallet recreation, unlock changes, and local metadata backfill did not
  restore ordinary spendability.

### Ruled-out no-fork paths

- Reviving the old non-V2 `legacy_direct` spend family does not work after
  activation; the current fixture probe rejects it at block level with
  `bad-shielded-matrict-disabled`.
- Rebuilding ordinary spend metadata from wallet state alone did not work,
  because the required account-registry witness path is missing on-chain for
  the stranded inputs.
- Transparent re-shielding is not relevant to the stuck notes and is disabled
  post-fork in the current wallet flow.

### Recovery-family lessons

- The custom recovery branch has already exposed at least one validator
  integration gap where a solved recovery block hit a generic
  `bad-shielded-v2-contextual` reject.
- The recovery family currently appears on the wire as its own transaction
  family in the custom branch, which raises network-compatibility risk if the
  final migration patch depends on a distinct family id.
- The clean upstream port should explicitly evaluate whether the migration
  semantics need their own wire family or can be carried inside an already
  accepted one.

## Local evidence and tooling still worth reusing

### Source tree and tests

- recovery branch source tree
- recovery branch consensus and wallet tests
- recovery branch wallet recovery tests

### Incident artifacts

- recovery capture sets
- live node debug logs
- generalized operator and design bundle

### Existing high-value replay material

- captured rejected recovery block and tx behavior from the live node
- fixture-level `legacy_direct` rejection tests in the custom branch
- recovery wallet planner/build artifacts from prior investigation

## Recommended upstream-port workstreams

1. Add precise failure diagnostics so contextual rejects identify the exact
   recovery gate being hit.
2. Design the migration path as a narrow spend-path restoration mechanism for
   stranded legacy-owned notes without weakening ordinary post-fork rules.
3. Prefer replayable fixtures and regtest coverage before any live-network
   rollout assumptions.
4. Maintain mixed-version tests so the team knows exactly when upgraded and
   non-upgraded nodes diverge.
5. Keep the local recovery branch available for regression replay until the
   upstream implementation can reproduce the same wallet state and failure
   surfaces on its own.

## Immediate next steps in this branch

- build the upstream daemon, CLI, and test binary on this clean branch
- map the migration design onto upstream consensus and wallet touchpoints
- add dedicated regtest and mixed-version tests for spend-path restoration
- use the preserved live artifacts only as replay input and validation evidence
