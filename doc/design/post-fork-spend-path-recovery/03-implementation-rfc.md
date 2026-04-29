# Implementation RFC: Post-Fork Spend-Path Restoration Patch

Date: 2026-04-23

## Scope

This RFC describes the recommended patch shape for a generalized consensus
 escape hatch that restores spendability to owned stranded shielded notes.

## Patch objective

Implement a migration path that:

- accepts owned stranded note inputs
- proves ownership under the old note model
- consumes those inputs exactly once
- emits ordinary modern direct-spend style outputs
- leaves ordinary modern wallet flow unchanged for unaffected notes

## Functional model

### Inputs

The new migration path must accept:

- shielded inputs from the stranded note class
- proof of spend authority under the historical note model
- ring, tree, and nullifier semantics required for safe consumption

The new migration path must not require:

- pre-existing modern account-registry spend witnesses for the stranded inputs

### Outputs

The migration path must emit:

- modern shielded outputs
- output note structure compatible with ordinary post-fork spend flow
- output account-registry leaves or equivalent modern spend metadata

Post-recovery outputs should be spendable via ordinary `V2_SEND` without any
 special-case wallet behavior.

### Transaction rules

Required rules:

- no transparent inputs
- no transparent outputs
- canonical fee treatment
- exact amount conservation minus explicit fee
- replay-safe nullifier handling
- deterministic ownership proof rules

## Preferred patch shape

### Semantic design

Use a narrow migration semantic family dedicated to:

- stranded-note input consumption
- modern direct-send style output creation

If a distinct wire family continues to create network-integration risk, the
 same semantics may instead be encoded inside an already-accepted wire family.

That choice should be made explicitly rather than accidentally through default
 behavior.

### Validation design

Validation must be explicit in all of these layers:

- tx-level family/context checks
- block-level family/context checks
- proof-envelope checks
- proof-statement construction
- amount and fee checks
- output account-state creation checks
- replay / duplicate nullifier rejection

Any place that currently collapses failures into a generic contextual reject
 should be instrumented with family-specific reject strings for recovery
 development.

### Wallet design

Wallet code should:

- continue to classify stranded notes as non-ordinary spend candidates
- keep them out of ordinary note selection
- expose a narrow planning and build flow
- capture deterministic batch artifacts for replay and audit

## Candidate code areas

Consensus and serialization:

- [v2_bundle.h](../../../src/shielded/v2_bundle.h)
- [v2_bundle.cpp](../../../src/shielded/v2_bundle.cpp)
- [bundle.cpp](../../../src/shielded/bundle.cpp)
- [validation.cpp](../../../src/shielded/validation.cpp)
- [validation.cpp](../../../src/validation.cpp)

Wallet and RPC:

- [shielded_wallet.cpp](../../../src/wallet/shielded_wallet.cpp)
- [shielded_rpc.cpp](../../../src/wallet/shielded_rpc.cpp)
- [shielded_coins.cpp](../../../src/wallet/shielded_coins.cpp)

State derivation:

- [account_registry.h](../../../src/shielded/account_registry.h)
- [account_registry.cpp](../../../src/shielded/account_registry.cpp)

Tests:

- [src/test](../../../src/test)
- [src/wallet/test](../../../src/wallet/test)

## Required engineering work

### WP1: Family and wire semantics

- define final migration semantic model
- decide whether wire family is distinct or reused
- make family handling explicit in every switch and contextual gate

### WP2: Proof semantics

- define proof statement for stranded-note ownership
- ensure proof-envelope rules remain valid post-fork
- confirm the family does not accidentally inherit disabled legacy proof rules

### WP3: Output modernization

- create direct-send style modern outputs
- create modern account-leaf commitments for those outputs
- ensure resulting outputs are discoverable by ordinary wallet rebuild logic

### WP4: Replay safety

- reject duplicate nullifier reuse
- reject duplicate migration attempts
- reject mixed or malformed migration payloads

### WP5: Diagnostics

- replace generic contextual rejects with more precise failure codes during
  development
- add replay tooling for captured rejected blocks or txs

## Open architectural question

The main remaining design choice is:

- distinct migration wire family
- or migration semantics carried inside an already-accepted wire family

Decision criteria:

- smaller rollout risk
- cleaner validation rules
- lower chance of partial integration bugs
- easier interoperability with the wider node population

## Deliverable

The patch is complete only when:

- a stranded input fixture migrates successfully under consensus
- the resulting output becomes ordinary modern spendable
- replay fails safely
- the activation and rollout plan is ready for operators
