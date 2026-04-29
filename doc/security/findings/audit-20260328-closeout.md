# 2026-03-28 Audit Closeout Summary

Source audit:

- `/Users/admin/Documents/btxchain/docs/btx-security-fixes-20260328.rtf`

Detailed tracker:

- [../../btx-security-fixes-20260328-tracker.md](../../btx-security-fixes-20260328-tracker.md)

## Summary

The `61000` shielded hardening program closes the mapped live implementation
issues from the source audit on the reviewed node path, while preserving
historical chain validity and existing funds. The later branch-local
lifecycle-control follow-on is also closed: post-fork lifecycle controls no
longer use the earlier proofless `V2_SEND` / operator-note lane and instead
ride a dedicated lifecycle family bound to the transparent transaction they
authorize. The separate April 2026 follow-on reconciliation is recorded in
[pr134-20260401-lifecycle-followon-closeout.md](pr134-20260401-lifecycle-followon-closeout.md).
Launch-readiness performance follow-on work is tracked separately in
[../../btx-postlaunch-optimization-roadmap.md](../../btx-postlaunch-optimization-roadmap.md)
and is no longer carrying an open security-tracker row. The runtime/report
surface now also distinguishes prefork compatibility measurements from live
postfork measurements, so the historical wallet mixed-unshield benchmark is no
longer treated as a `61000` readiness signal.

## Main Mitigation Buckets

### Consensus / Proof Hardening

- MatRiCT retired on the live post-fork shielded path
- post-fork generic V2 wire family and opaque payload carriage
- post-fork proof/wire/version enforcement
- spend-authority transcript hardening
- settlement-anchor maturity and single-use enforcement
- tuple-opening hardening for post-fork SMILE proofs

### Wallet / RPC Privacy Hardening

- default RPC redaction for note/value/family-specific disclosure
- viewing-key export/import restricted after the fork
- direct public-flow `V2_SEND` removed from the post-fork path
- transparent-change leakage reduced by forcing explicit bridge/egress
  settlement paths
- shielded address lifecycle controls moved onto a dedicated post-fork
  `V2_LIFECYCLE` family bound to the transparent transaction skeleton, with
  legacy send-lifecycle controls rejected after activation and operator-class
  notes excluded from spendable wallet balance/unspent enumeration
- lifecycle closeout coverage now explicitly includes multi-output transparent
  skeleton acceptance, output-tamper rejection across proof-check/mempool/block
  boundaries, including the contextual mempool/block proof-check gates for the
  dedicated `V2_LIFECYCLE` family, and wallet/RPC checks that lifecycle
  transactions do not change shielded balance or note count

### State Durability / Recovery

- prepared transition journaling before reviewed cross-store shielded writes
- deterministic restart rebuild/restore paths
- registry payload externalization and orphaned-blob pruning

### Networking / Relay

- post-fork Dandelion++ activation and route-handling hardening
- bounded per-source relay pools
- improved relay/netgroup selection behavior

## Remaining Open Items

- `L12`: shielded PQ-128 parameter-set redesign

`L12` is documented separately in
[l12-pq128-parameter-upgrade.md](l12-pq128-parameter-upgrade.md).
