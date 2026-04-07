# Falcon Soft-Fork Readiness Analysis

Date: 2026-03-29

## Executive Summary

BTX should keep ML-DSA-44 as the active primary signature algorithm today and
keep SLH-DSA-SHAKE-128s as the independent hash-based backup, while preparing
now for a future Falcon-512 activation path.

The important consensus fact is that adding Falcon later is only a soft fork if
we reserve the script surface now. Adding a new P2MR checksig opcode later is
soft-fork-compatible if the slot is an `OP_SUCCESS` today. By contrast, adding
Falcon support to the existing `OP_CHECKSIGFROMSTACK` size-dispatch path later
would be a hard fork, because old nodes currently reject unknown PQ pubkey
sizes there. This branch addresses that by reserving Falcon-specific P2MR
soft-fork slots now, including a dedicated CSFS/oracle path.

## Why Falcon Matters

Falcon-512 is attractive for BTX because transparent transactions are
signature-dominated:

- ML-DSA-44 public key: 1312 bytes
- ML-DSA-44 signature: 2420 bytes
- Falcon-512 public key: about 897 bytes
- Falcon-512 signature: about 666 bytes in current planning material

That planning delta is large enough to materially improve transparent
throughput, bandwidth, and long-term block bloat pressure. Falcon is a natural
candidate once implementation maturity and side-channel hardening are good
enough for production.

## Current BTX Position

Active today:

- ML-DSA-44 for primary transparent signing
- SLH-DSA-SHAKE-128s for backup/recovery leaves
- ML-KEM-768 for shielded-pool encapsulation only

Current architectural strengths:

- P2MR Merkle-root addresses are algorithm-agnostic at the address layer.
- Wallet, signer, and policy code already carry a `PQAlgorithm` abstraction.
- Script size limits already leave room for large PQ multisig leaves.
- P2MR already supports `OP_SUCCESS`-style forward compatibility.

Current architectural gaps before this branch:

- Too many ML-DSA vs SLH-DSA decisions were hardcoded as two-way branches.
- P2MR parsing and policy logic repeated algorithm-specific size handling.
- Existing `OP_CHECKSIGFROMSTACK` only recognized ML-DSA and SLH-DSA by pubkey
  size, which would make future Falcon CSFS support a hard fork.
- No repository-level roadmap captured the migration from "not active" to
  "default when mature."

## Decisions In This Branch

This branch intentionally does **not** activate Falcon yet. Instead it prepares
the chain so later Falcon activation can be shipped cleanly.

Implemented now:

1. Reserve Falcon soft-fork opcode slots in P2MR:
   - `OP_CHECKSIG_FALCON`
   - `OP_CHECKSIGADD_FALCON`
   - `OP_CHECKSIGFROMSTACK_FALCON`
2. Leave those Falcon slots inside the P2MR `OP_SUCCESS` set today.
3. Keep relay policy rejecting Falcon leaf scripts as non-standard today.
4. Centralize active algorithm metadata and P2MR script push/opcode helpers.
5. Refactor policy, interpreter, and signer parsing away from scattered
   ML-DSA-vs-SLH-DSA size branches where practical.
6. Document the roadmap and the activation boundary explicitly.

Not implemented yet:

- Falcon key generation/sign/verify in `libbitcoinpqc`
- Falcon descriptors, wallet defaults, RPC surfaces, or signer support
- Falcon activation logic, deployment mechanism, or default flip

## Soft Fork vs Hard Fork Boundary

What this branch makes soft-fork-ready later:

- P2MR Falcon checksig leaves
- P2MR Falcon multisig leaves
- P2MR Falcon CSFS/oracle/delegation leaves

What would still require new code later, but can now be introduced as a soft
fork because the slots are reserved:

- Actual Falcon verification semantics
- Activation-height or version-bits deployment logic
- Wallet and descriptor exposure for `pk_falcon(...)`-style leaves

Why the dedicated Falcon CSFS slot matters:

- Reusing `OP_CHECKSIGFROMSTACK` for Falcon later would widen validity on an
  already-defined opcode and therefore be a hard fork.
- A reserved `OP_SUCCESS` slot lets BTX define Falcon CSFS semantics later as a
  restriction, which is soft-fork-compatible.

## Milestones

| Milestone | Status | Deliverables |
|---|---|---|
| M0. Analysis and repo docs | Done in this branch | This analysis doc, temporary tracker, README/spec updates |
| M1. Consensus/script reservation pass | Done in this branch | Reserved Falcon P2MR opcode slots, tests proving they stay `OP_SUCCESS` today, policy keeps them non-standard |
| M2. Refactor for algorithm extensibility | Done in this branch for core P2MR plumbing | Shared algorithm metadata, generic P2MR pubkey-push/opcode helpers, reduced two-algorithm branching in policy/interpreter/signing |
| M3. Falcon library evaluation | Future | Pick implementation(s), verify constant-time story, verify deterministic behavior on supported hardware, define signature-size contract |
| M4. Wallet/signer/testnet opt-in | Future | Descriptor syntax, PSBT/signer support, RPC help, devnet/testnet gating, fuzz/unit/functional coverage |
| M5. Soft-fork activation | Future | Deployment mechanism, activation rules, policy rollout, node upgrade guide |
| M6. Default flip | Future | Make Falcon the default primary leaf only after M5 is stable and operational evidence is strong |

## Activation Criteria For Future Falcon Work

BTX should not activate Falcon until all of the following are true:

- At least one mature implementation exists with a credible side-channel story.
- Signing behavior is validated on BTX target hardware classes.
- Signature size handling is settled for the chosen library/API surface.
- Unit, functional, fuzz, and cross-platform verification coverage are in
  place.
- External signer and wallet flows can generate, import, export, and sweep
  Falcon-backed P2MR outputs.
- Deployment and rollback procedures are documented.

## Recommended Future Rollout

1. Keep the current default descriptor as `mr(<mldsa-key>,pk_slh(<slhdsa-key>))`.
2. Land Falcon verification and signing support behind explicit activation and
   policy gates.
3. Expose Falcon as opt-in on devnet/testnet first.
4. Observe chain behavior, signer compatibility, and operational support.
5. Activate Falcon on mainnet as an additional accepted key type.
6. Only after long soak time, consider making Falcon the default primary leaf.

## Risks That Remain

- Falcon signing maturity remains the main blocker, not Falcon verification.
- The exact production signature-size contract depends on the implementation BTX
  ultimately standardizes around.
- Wallet and signer ecosystems will need their own readiness work even after
  consensus/script preparation is complete.

## Bottom Line

BTX should not switch to Falcon today, but it should reserve the Falcon path
today. This branch does that: it keeps the conservative ML-DSA-44 + SLH-DSA
posture for current production, while moving the later Falcon introduction from
"another hard fork" to "a planned soft fork with clear activation work."
