# Problem Statement: Post-Fork Spend-Path Loss For Owned Shielded Notes

Date: 2026-04-23

## Summary

This document describes a class of failure where shielded notes remain fully
 owned by a wallet but become non-spendable through the ordinary post-fork
 transaction flow.

The problem is not "funds disappeared."

The problem is:

> the spend path disappeared while custody remained intact

## Symptoms

An affected wallet typically shows all or most of the following:

- the wallet still reports a shielded balance
- the wallet still holds the spending keys
- note decryption still works
- the wallet can identify concrete note commitments and nullifiers
- ordinary merge, sweep, or send RPCs fail
- rescans may restore truthful visibility but not spendability

## Root cause pattern

The most likely root-cause pattern is:

1. Notes were created under an earlier shielded transaction model.
2. A later protocol transition moved ordinary spending to a newer spend model.
3. The older notes never created the modern witness or registry state now
   required by ordinary spend builders.
4. The wallet still owns those notes, but ordinary spend selection excludes
   them or cannot build a valid spend from them.

This can happen even if:

- the wallet is unlocked
- the node is healthy
- the notes are not watch-only
- the balance is still visible

## Why ordinary fixes are not enough

The following are not sufficient:

- wallet recreation
- rescanning
- local index rebuilding
- unlocking again
- retrying ordinary shielded sends
- loosening wallet-side spend filters only

These actions may improve visibility or diagnostics, but they do not create a
 new accepted spend path.

## Problem framing

The right framing is:

- custody: intact
- visibility: intact
- ordinary spend path: lost
- network-accepted recovery path: not yet available

## Recovery objective

A correct solution must:

1. prove ownership of stranded notes safely
2. convert them into ordinary modern spendable outputs
3. preserve amount accounting and auditability
4. avoid weakening normal spend rules for unaffected notes

## Non-goals

This bundle does not attempt to:

- redefine ordinary modern note spending for everyone
- hide the problem with wallet-only tricks
- invent fake witness material
- justify operator shortcuts without consensus validity
