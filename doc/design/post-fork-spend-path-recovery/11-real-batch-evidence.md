# Real-Batch Evidence Summary

Date: 2026-04-27

## Purpose

This memo records the highest-signal local evidence gathered against a copied
affected wallet and a copied trusted shielded-state snapshot.

It is intentionally sanitized:

- no wallet names
- no private key material
- no machine-specific operational details

The goal is to answer one question:

> Does the spend-path recovery patch validate a real affected batch under
> trustworthy shielded state, or only synthetic fixtures?

## Scope

The local validation flow used:

- a copied affected wallet
- a copied trusted shielded-state snapshot
- a real exported recovery batch derived from that copied wallet
- an offline generator for the recovery transaction
- a direct trusted-state replay harness

Nothing in this evidence path broadcast a transaction or modified live wallet
files.

## What Was Proved

### 1. A real affected batch can be exported

The copied wallet exported a real recovery batch using the dedicated local-only
export surface. That export included:

- the selected legacy note commitments
- the destination output contract
- the spend anchor
- ring positions
- ring members
- encrypted output payloads
- private spend material needed for offline regeneration

This proved that the recovery path can be grounded in real affected wallet
state, not only synthetic fixtures.

### 2. A recovery transaction can be regenerated from that export

The exported batch was consumed by the offline generator and produced a real
`v2_spend_path_recovery` transaction.

This proved that the patch’s witness and proof surface is sufficient to
represent a real affected batch end-to-end.

### 3. Proof validation succeeds against a copied trusted shielded-state snapshot

The first replay of the real generated transaction against a copied trusted
shielded-state snapshot showed:

- proof validation accepted
- nullifiers were still unspent
- commitment-index digests matched the persisted state

The only failure on that first replay was anchor freshness: the original
transaction anchor had fallen out of the trusted anchor window.

This was important because it separated proof validity from anchor drift.

### 4. The same real batch validates cleanly after anchor refresh

Using the same exported private spend inputs, the transaction was regenerated
with:

- the current trusted shielded tree root as its spend anchor
- the current tip-derived next validation height

The refreshed replay then showed:

- the refreshed anchor was present in trusted state
- nullifiers were still unspent
- proof validation accepted
- no mutation marker or other replay inconsistency was present

This is the strongest local evidence gathered so far:

> a real affected batch can be regenerated under current trusted state and
> accepted by the patched recovery validation path.

## Remaining Caveat

The real recovery transaction remains very large.

In local testing, ordinary mempool admission still hit:

- `tx-size`

That is a relay and admission policy concern, not a proof-validity concern.

The practical implication is that rollout should assume:

- consensus recovery patch in the PR
- no broad default relay-policy widening unless reviewed separately
- operator/miner block inclusion may still be needed for oversized recovery
  transactions

## Conclusion

The patch is no longer supported only by synthetic tests.

It now has:

- synthetic regression coverage
- mixed-version activation-split coverage
- reorg coverage
- and a real-batch trusted-state acceptance replay

That is strong enough to support a public PR for a narrowly scoped recovery
patch, with explicit documentation that oversized real recovery transactions
may still require direct miner inclusion.
