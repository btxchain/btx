# Consensus Design Memo: Spend-Path Restoration Escape Hatch

Date: 2026-04-23

## Purpose

This memo evaluates consensus-level options for restoring spendability to
 shielded notes that remain owned but stranded after a post-fork transition.

The goal is to restore a valid spend path, not merely improve wallet
 visibility.

## Current problem

Affected notes remain:

- owned
- decryptable
- visible in balance

But they no longer have a working accepted spend path.

There are typically two failed paths:

1. Ordinary post-fork spend
   Ordinary modern builders require account-registry or related witness state
   that the stranded notes never created.

2. First-generation custom recovery path
   A custom migration family may exist locally, but if blocks carrying it are
   rejected, it is not yet a valid network escape hatch.

## Design constraints

Any consensus design must:

- preserve amount conservation
- preserve replay and double-spend safety
- keep ordinary modern spend rules intact
- avoid fake registry or witness material
- produce outputs that ordinary wallet code can spend afterward

## Options considered

### Option A: One-step migration transaction

Introduce a narrow consensus-backed migration path that:

1. proves ownership of legacy or stranded notes
2. consumes those notes
3. creates ordinary modern spendable outputs
4. creates the modern account state required by those outputs

Pros:

- simplest operator story
- easiest audit story
- smallest long-term operational complexity

Cons:

- requires explicit consensus support
- must be integrated cleanly across tx validation, block validation, and wallet
  tooling

### Option B: Two-step registry-bootstrap path

Step 1 proves ownership of a stranded note and creates missing modern spend
 metadata.

Step 2 later spends that now-modernized note through ordinary flow.

Pros:

- conceptually matches "restore spend path first, spend later"

Cons:

- introduces an intermediate state
- increases replay and partial-migration edge cases
- complicates operator flow

### Option C: Relax ordinary modern spend rules

Make ordinary post-fork spend accept stranded notes directly.

Pros:

- looks simple superficially

Cons:

- weakens normal validation semantics
- contaminates the ordinary spend path with special cases
- broadens protocol risk

This should not be chosen.

### Option D: Global deterministic rebuild of missing state from history

Attempt to reconstruct modern registry or witness state for all stranded notes
 directly from chain history.

Pros:

- no explicit migration tx for operators

Cons:

- likely impossible or unsafe if history lacks enough information
- difficult to reason about globally
- large consensus surface

This is not preferred.

## Recommended design

Choose **Option A: one-step migration transaction**.

That means:

- keep ordinary modern spend rules unchanged
- keep stranded notes excluded from ordinary spend selection
- add a narrow consensus-backed migration mechanism that consumes stranded
  notes and emits ordinary modern direct-spend style outputs

## Why this is the best escape hatch

This design is best because it:

- isolates the exception to the affected note class
- avoids weakening ordinary modern spend logic
- makes post-recovery outputs normal and boring
- is the easiest design to test end to end
- is the easiest design to explain to operators and reviewers

## Important implementation nuance

The migration path may be implemented either as:

- a dedicated semantic and wire family, or
- the same migration semantics encoded under an already-accepted wire family

The objective is the same either way:

> prove ownership of stranded notes without relying on missing modern witness
> state, then emit modern outputs that ordinary wallet code can spend

The second variant is the main fallback if a distinct wire family would be too
 disruptive to roll out safely.

## What the patch must not do

The patch must not:

- treat stranded notes as ordinary modern spends
- fabricate missing account-registry witnesses
- rely on wallet-only metadata to simulate consensus validity
- expose unrestricted migration logic to unrelated note classes

## Bottom line

Yes, a consensus patch can restore spendability.

The best version of that patch is not "make ordinary spends accept these
 notes." The best version is:

> add a narrow migration rule that converts owned stranded notes into ordinary
> modern spendable outputs while preserving the normal post-fork spend model
