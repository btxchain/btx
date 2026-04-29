# Initial Upstream Touchpoints

Date: 2026-04-23

## Purpose

This note records the first-pass mapping from the generalized spend-path
recovery design onto the clean upstream tree.

It is meant to shorten the time between "the design is clear" and "the first
upstream patch set is scoped."

## Immediate structural observation

The clean upstream tree does not contain any recovery-specific surface such as:

- `V2_LEGACY_RECOVERY`
- `z_planlegacyrecovery`
- `z_buildlegacyrecovery`
- `legacyrecovery`

That means the upstream port starts from a simpler and cleaner baseline, but it
also means the current parallel recovery branch remains necessary for reproducing
incident-specific behavior until the new work is in place here.

## High-value upstream touchpoints

### Family and bundle surface

These files define or route the currently accepted shielded family surface:

- `src/shielded/v2_types.cpp`
- `src/shielded/bundle.cpp`
- `src/shielded/v2_send.cpp`
- `src/shielded/v2_send.h`

The first pass shows a family surface centered on:

- `V2_SEND`
- `V2_INGRESS_BATCH`

Any migration patch will need a deliberate answer to:

- whether to add a new semantic and wire family, or
- whether to encode migration semantics inside one of the already accepted
  upstream envelopes

### Ordinary spend witness requirements

The ordinary post-fork spend path in `src/wallet/shielded_wallet.cpp` still
hard-requires both:

- an account-leaf hint
- an account-registry witness

The first-pass grep landed on the relevant failure points in the existing
`CreateV2Send` flow where ordinary spending aborts on missing hint or missing
registry witness. That makes this file one of the main patch decision points:

- either the migration path bypasses these ordinary requirements by design
- or the patch creates a separate bootstrap path that produces modern outputs
  without pretending the stranded inputs already satisfy ordinary `V2_SEND`
  preconditions

### Account-registry coupling

The account-registry dependency is visible throughout:

- `src/shielded/account_registry.h`
- `src/shielded/account_registry.cpp`
- `src/shielded/v2_send.cpp`
- `src/wallet/shielded_wallet.cpp`

The clean upstream tree already has helper logic such as
`CollectAccountLeafCommitmentCandidatesFromNote(...)`, but that still assumes a
modern witness path exists for the spend input. The migration design should not
count on that assumption for stranded-note inputs.

## Patch-shaping implications

### What looks promising

- a narrow migration path that consumes stranded legacy-owned shielded notes and
  emits ordinary modern spendable outputs
- precise reject codes and replay tooling for any new migration validation path
- regtest and mixed-version tests before live-network assumptions

### What still looks risky

- weakening ordinary `V2_SEND` semantics
- trying to fake or infer missing account-registry spend witnesses from wallet
  state alone
- adding a distinct wire family unless the team is comfortable treating the
  result as a coordinated consensus rollout

## Suggested first upstream implementation steps

1. Add diagnostic plumbing so contextual recovery failures cannot collapse into
   a generic reject string.
2. Introduce a migration design stub in the shielded family plumbing and choose
   whether it is semantic-only or both semantic and wire-visible.
3. Add fixture coverage for:
   - stranded-input migration success
   - replay rejection
   - modern-output ordinary spend success after migration
4. Add a mixed-version test proving exactly how upgraded and non-upgraded nodes
   diverge once the migration rule is exercised.

## Relationship to the parallel recovery branch

This upstream branch is the clean implementation track.

The parallel recovery branch is still the right place to mine for:

- captured live rejects
- wallet-specific recovery planner artifacts
- historical test fixtures already written around the recovery incident

Use the upstream branch for patching and clean validation.
Use the parallel recovery branch for replay evidence and regression comparison.
