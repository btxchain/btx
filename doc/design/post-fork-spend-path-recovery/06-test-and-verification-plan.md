# Test And Verification Plan

Date: 2026-04-23

## Goal

Prove the spend-path restoration patch works before and during rollout.

## Test philosophy

The patch is not done when a transaction can be built.

The patch is only done when:

- the migration transaction validates
- a block carrying it validates
- the resulting outputs become ordinary spendable notes
- replay attempts fail safely

## Minimum fixture matrix

### Affected-note fixture

Create a fixture with:

- owned stranded shielded notes
- ordinary spend path intentionally unavailable
- deterministic output commitments and note inventory

Expected result:

- wallet identifies the notes as recovery candidates
- ordinary `V2_SEND` still fails

### Migration success fixture

Build one migration transaction from the fixture.

Expected result:

- tx validates at tx level
- tx validates inside a block
- block connects successfully

### Post-migration spend fixture

Take the migration outputs and run ordinary spend flow.

Expected result:

- outputs appear in ordinary spendable note selection
- ordinary `V2_SEND` succeeds

## Required consensus tests

- family-context acceptance
- proof-envelope acceptance
- proof verification success
- block-level acceptance
- duplicate nullifier rejection
- replay rejection
- malformed payload rejection
- amount-conservation checks
- fee-bucket checks
- activation-boundary checks

## Required wallet tests

- affected notes remain excluded from ordinary selection pre-migration
- migration planner chooses deterministic bounded batches
- migration outputs become ordinary spendable notes
- operator diagnostics are truthful and precise

## Required network tests

- upgraded miner and validator agree on migration-block validity
- old node versus new node behavior around activation is documented
- reorg handling is tested
- stale-block handling is tested

## Required observability

Add or preserve:

- explicit reject codes for each contextual recovery failure path
- txid and block-hash logging for migration attempts
- artifact capture for dry-run and built transactions
- runtime metrics for accepted, rejected, replayed, and confirmed migration
  attempts

## Pilot acceptance checklist

Before live pilot:

- unit and fixture tests pass
- one block-connect test passes
- one post-migration ordinary spend test passes
- activation build is tagged and reproducible

After live pilot:

- tx confirmed
- destination output ordinary-spendable
- one ordinary post-recovery spend confirmed

## Failure handling

If pilot fails:

- stop additional migration batches
- capture tx hex, block data, reject reason, and node logs
- replay the failure locally with instrumented reject sites
- do not continue with larger batches until the failure is understood
