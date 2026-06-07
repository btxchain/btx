# BTX Security Audit Report Reassessment

Date: 2026-06-06
Branch: `audit/v2-rebalance-pool-credit-probe`
Source report: `BTX-Security-Audit-Report.pdf`

This note maps the external report findings against the current audit branch after the
125,000 shielded-sunset work, `RECOVERY_EXIT` scaffolding, relay/mempool DoS hardening,
MatMul nonce-bound seed hardening, and the internal C-002 lattice-focused review in this
branch.

## Executive verdict

The branch renders the report's two shielded value-safety critical findings irrelevant for
new post-upgrade activity:

- C2-style forgeable hidden nullifiers are blocked for new spends at/after height 123,000 by
  mandatory C-002 wire-v3 proofs and serial-to-key binding.
- C3-style proofless transparent-to-shielded pool credits are blocked for new transactions
  at/after height 123,000 by the pool-credit disable gate, and then by the stricter
  outflow-only sunset at height 125,000.

The previous non-obsolete implementation items are now addressed in this branch:

- e1 is closed by the height-125,000 MatMul seed-v2 rule, which binds matrix seeds to
  mutable header fields including `nNonce64`, `nTime`, `nBits`, and the merkle root.
- a5 is covered by the uniform 125,000 activation policy plus boundary/regtest tests. This
  remains release-timing sensitive: a production release must land before mainnet height
  125,000.
- f3 / C-002 has received an internal lattice-focused code review. The live post-123,000
  verifier path requires C-002 wire v3 and enforces serial-to-key, transcript, and
  value-conservation bindings. This is not a substitute for independent third-party
  cryptographic sign-off.

The sunset remains a blast-radius reducer: after height 125,000 the shielded pool can only
drain via transparent exits, but proof-system soundness and historical state correctness
still matter for exit validation until all legacy shielded value has exited or all shielded
exit paths are retired.

## Finding status matrix

| Report item | Current branch status | Reason |
|---|---|---|
| C1 CT inflation carry forge | Refuted / not actionable | The report itself marks the claim refuted. No branch change is required for this item. |
| C2 shielded double spend via forgeable nullifier | Closed for new post-123,000 spends; historical only below 123,000 | `VerifySmile2ProofDispatch` requires C-002 wire v3 at/after height 123,000. v3 proof verification enforces `w_sn` serial-to-key binding, so the revealed nullifier must match the same spend key opened by the proof. Pre-123,000 history is not retroactively invalidated. |
| C3 proofless transparent-to-shielded mint | Closed for new post-123,000 credits and post-125,000 shielded activity | `RejectDisabledShieldedPoolCredit` rejects negative shielded state value balance at/after 123,000 and structurally disables rebalance/settlement credit machinery. `RejectShieldedSunsetViolation` then permits only pure transparent exits at/after 125,000: V2_SEND with `value_balance > fee` and zero shielded outputs, plus V2_RECOVERY_EXIT when active. Any hypothetical pre-123,000 bad note is not proven away by this branch, but its later impact is constrained by the frozen pool, transparent exit-only rule, and velocity cap. |
| e1 MatMul-PoW amortized mining | Closed at/after height 125,000 in this branch | `nMatMulNonceSeedHeight` activates at 125,000 on main/test/signet networks. `SetDeterministicMatMulSeeds` switches from legacy `H(prev || height || which)` to `BTX_MATMUL_SEED_V2 || prev || height || version || merkle || time || bits || nonce64 || dim || which`, and the post-activation solver derives fresh A/B per nonce instead of reusing a fixed instance. Mining RPC work profiles also advertise that fixed-instance reuse is no longer possible after activation. |
| a5 activation-boundary chain halt | Closed for the 125,000 stack; release-timing caveat remains | The branch now has one uniform 125,000 production boundary for the shielded sunset and MatMul nonce-seed activation, plus regtest override coverage and activation-boundary solver/validation tests. The remaining operational risk is shipping late: if mainnet reaches 125,000 before this code is broadly deployed, the activation height must be reassessed rather than merged as-is. |
| d3 shielded full-chain-rebuild DoS | Hardened in this branch for untrusted mempool input | Mempool shielded proof failure no longer triggers `TryAutoRebuildShieldedState`. Rebuild remains available on block connection/state recovery, but remote transaction candidates cannot force a full shielded-state rebuild before rejection. |
| dltx Dandelion shielded relay bypass | Hardened in this branch | Shielded `DLTX` payloads now apply `nMaxShieldedTxSize` and `ConsumeShieldedRelayBudget` before `ProcessTransaction(..., test_accept=true)`, matching the expensive-validation budget discipline used for `TX`/`SHIELDEDTX`. |
| vg-2 view-grant issue | Refuted / not actionable | The report marks this refuted. No branch change is required for this item. |
| f3 / C-002 lattice soundness | Internally reviewed; independent external assurance still recommended | The reviewed live path requires C-002 wire v3 at/after height 123,000 for anonset-bound SMILE2 proofs. v3 carries `w_sn`, `seed_z`, `balance_w`, and `balance_carry`; the verifier binds the revealed serial/nullifier to the same opened secret, requires the step-12 transcript binding, and checks value conservation. No remaining code-level C-002 bypass was found in the post-123,000 spend path reviewed here. This remains an internal review, not an external cryptographer sign-off. |

## Recovery-exit posture

`V2_RECOVERY_EXIT` is live at the 125,000 shielded sunset on production-like
networks. The branch derives and retires both the revealed commitment `cm` and
the canonical normal-path nullifier `normal_nf`, checks membership against a
hardcoded frozen root when present or the immutable live post-sunset tree root
otherwise, and reserves both identifiers in mempool/package validation.

The recovery path is still intentionally narrow: it reveals the note, pays only
transparent outputs, appends no shielded outputs, and counts as pool egress. It
has internal AI-assisted review and tests; independent external cryptographer
review remains recommended but unavailable for this emergency activation.

## Deployment interpretation

For v0.32.0 containment, the branch is correctly positioned as:

- no new shielded credits after 123,000;
- no shielded-to-shielded transfers, lifecycle, rebalance, bridge, or recovery-path reshielding after
  125,000;
- legacy shielded holders can still exit through pure transparent V2_SEND unshield, and stranded notes
  can exit through V2_RECOVERY_EXIT when the wallet has the needed witness/key material;
- the remaining shielded blast radius is bounded by the actual frozen pool and drains under the
  velocity cap; and
- MatMul fixed-instance economics are removed for blocks at/after height 125,000 by nonce-bound
  seed-v2.

As of the local mainnet node check on 2026-06-07, the chain was at height 122,920. That leaves
height 125,000 in the future, but the release window is short and should be treated as
consensus-critical.
