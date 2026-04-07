# Shielded Hardening Fork At Block 61000

This document summarizes the shielded hardening fork integrated on this branch.

## Activation Rule

- All reviewed post-launch shielded hardening rules activate at block `61000`.
- Heights below `61000` continue to validate historical transactions using the
  legacy rules for that era.
- Heights at or above `61000` enforce the hardened post-fork rules.

## Backwards Compatibility

The fork is backwards-compatible with existing chain history in the normal hard
fork sense:

- old blocks are not rewritten
- pre-fork transactions remain part of canonical history
- existing wallet funds are not invalidated
- post-fork consensus changes apply only to new blocks and new transactions at
  height `>= 61000`

## Main Post-Fork Effects

### Consensus / Proof Surface

- MatRiCT is disabled on the live post-fork shielded path.
- Post-fork V2 traffic uses the generic wire family and opaque payload surface.
- Legacy post-fork SMILE proof bytes and legacy post-fork V2 family ids are
  rejected.
- Settlement anchors are maturity-gated and single-use.
- Registry append limits, total-entry limits, canonical fee buckets, and
  post-fork proof/wire requirements are enforced in mempool and block
  validation.

### Wallet / RPC Surface

- Direct transparent public-flow `V2_SEND` is disabled after the fork, except
  for the wallet's mature-coinbase shielding compatibility lane used by
  `z_shieldcoinbase`, autoshield, and compatible coinbase-only sweep helpers.
- Mixed direct shielded-to-transparent sends are disabled in favor of explicit
  bridge/egress settlement.
- Default RPC responses redact sensitive note / value / family-disclosure
  fields unless the caller explicitly requests sensitive surfaces.
- Wallet-local lifecycle control for shielded addresses is available through
  rotation / revocation flows.

### State / Restart Safety

- Shielded state mutations persist prepared transition journals before
  cross-store writes.
- Restart restores the prepared target snapshot when possible, otherwise it
  deterministically rebuilds to chain-equivalent state.
- Externalized registry payload blobs are pruned during truncate/restore/restart.

## Operator Expectations

Before the fork:

- keep nodes/wallets upgraded before chain height `61000`
- avoid relying on retired MatRiCT or legacy post-fork wire assumptions in
  custom tooling

After the fork:

- expect stricter shielded validation on mempool and block admission
- use bridge/egress surfaces for explicit transparent settlement
- use the new security docs in this directory as the source of truth for
  branch-level hardening status
