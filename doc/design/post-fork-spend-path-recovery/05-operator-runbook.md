# Operator Runbook: Spend-Path Recovery For Stranded Shielded Notes

Date: 2026-04-23

## Purpose

This runbook is for operators handling wallets that still own shielded notes
 but cannot spend them through ordinary post-fork flow.

## Identify affected wallets

An affected wallet generally has all or most of these properties:

- shielded balance still visible
- spending keys still loaded
- note ownership still provable
- ordinary send or merge path unavailable
- wallet diagnostics indicate recovery is required or ordinary spend metadata is
  missing

## Immediate operator rules

- freeze ordinary merge or sweep automation for affected wallets
- do not keep retrying normal sends
- do not rely on wallet recreation as a fix
- preserve wallet files, balance snapshots, and recovery artifacts

## Before any live recovery attempt

Capture:

- current balance snapshot
- note counts
- wallet integrity output
- list of affected commitments or recovery candidates
- node version and build id
- current chain height

## Safe recovery order

1. confirm the node is upgraded to the activation-ready recovery build
2. confirm the network or mining cohort is also upgraded
3. select a fresh controlled destination
4. build a dry-run migration artifact
5. execute one small pilot batch only
6. confirm resulting outputs are ordinary spendable
7. only then continue with bounded batches

## Destination guidance

The first recovery destination should be:

- a fresh controlled recovery destination, or
- another wallet whose receive path is already known-good

Avoid mixing pilot recovery output with unrelated large wallet workflows until
 ordinary spendability is confirmed.

## What to verify after a pilot batch

- tx accepted by mempool and block validation
- tx confirmed on the active chain
- recovered output appears in destination wallet
- recovered output is visible in ordinary spendable note selection
- a small ordinary post-recovery spend succeeds

## What not to do

- do not migrate the full inventory first
- do not mix recovery with unrelated consolidation jobs
- do not keep mining rejected payloads blindly
- do not change ordinary spend rules locally and assume the network agrees

## Completion condition

An affected wallet is no longer in recovery mode only when:

- stranded-note inventory is cleared, or reduced to known residuals under a
  planned later batch
- recovered outputs are confirmed
- recovered outputs are ordinary spendable
- normal wallet automation can resume safely
