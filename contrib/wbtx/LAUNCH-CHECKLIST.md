# wBTX bridge + OTC escrow — pre-launch checklist (0.34.6)

Status of the money-movement tooling as of the 0.34.6 hardening pass. This tracks what is **done in-repo**
and what remains **before any real value flows**. It is the operational companion to `SECURITY.md`.

> The wBTX EVM contracts are UNAUDITED reference implementations. This checklist gets the code to
> "effectively launch-ready barring an external audit"; it does **not** substitute for that audit.

## 0. What this hardening pass closed (done ✅)

All defects from the community pre-ship review (2026-08-22) and four internal adversarial rounds, each
cursor-authored → `forge test`/selftest-gated → deepseek-audited → committed (PR #137):

- **Mint attestation binds BTX finality** (block hash/height/attested-frontier/deadline + bridgeId) and
  enforces depth ≥ `MIN_CONFIRMATIONS=100` + expiry. *(F1)*
- **Durable guardian veto**, **fail-closed breakers** (`limitsConfigured`, all-non-zero), **continuous
  token-bucket window** (no 2× boundary burst), budget consumed at execution. *(F2/F9/F11)*
- **In-contract timelocks** on verifier swap (7d) / signer rotation (7d) / veto-clear (48h) + guardian
  cancel; `guardianDelay` floor (6h). *(F4)*
- **Issuance bound to an immutable bridge**, allowance-gated burns (no confiscation), **compliance hook**
  excludes issuance + gas-capped try/catch + immediate clear; pause-independent `mintRefund`. *(F8/F13)*
- **Attested + reversible redeem fulfillment** (M-of-N + depth, `unfulfillRedeem`), **non-release-attested
  refund** routed through the supply cap, pause-independent. *(F3/F10/F12)*
- **HTLC claim-expiry** (disjoint claim/refund), **exact-amount custody**, corrected **Model-B flow** +
  `check_timeout_ordering`, `MIN_TIMEOUT` 30m→6h. *(F5/F6/F7)*
- **SDK** robust `to_sat` (Decimal), `find_deposits` minconf floor (100), ripemd160 portability. *(F14/F15)*
- **OTC escrow rounds 1–4:** locktime-domain, tier-A venue-key pinning (+ round-4 tier-downgrade fix),
  BIP68 masking, tier-A+ CTV verification + made buildable (`ctv_pk`), timeout-asymmetry helper + flow
  docs, 0-conf/RBF/dup-key/sub-floor guards.
- **P2MR script findings** (r1/r2/r7) verified: r1 already guarded (trailing-SIGHASH-byte rejection present
  at both checksig sites); r2/r7 by-design, addressed with SDK usage docs. **No consensus change.**
- **Solvency invariant fuzz suite** added (`test/WBTXInvariant.t.sol`).

Tests: `forge test` green; Python SDK selftests green.

## 1. MUST complete before real value (blocking)

- [ ] **External professional audit** of `WBTXBridge.sol` / `WBTX.sol` / `WBTXAtomicSwapHTLC.sol`. This is the
      top gate; the internal loop (cursor-write → deepseek-audit → review) is strong but not a substitute.
- [ ] **Address audit findings** and re-run the full suite + invariants.
- [ ] **Invariant-fuzz campaign at scale** — the new suite is the seed; run high `runs`/`depth` (and/or
      Echidna/Medusa) in CI and keep the solvency invariant (`circulating wBTX ≤ net attested backing`) green.
- [ ] **Signer-set independence** (the review's deepest point — worry about someone *becoming* the verifier):
      M-of-N with genuinely independent operators + custody (HSM/threshold), documented rotation. Security
      reduces to `min(signer honesty, dominant-producer honesty, governance-key security)`.
- [ ] **Governance = Timelock owned by a multisig** for the bridge admin, WBTX admin, and the verifier admin
      (three distinct signer sets where possible). The contracts *recommend* but cannot *enforce* this.
- [ ] **Deploy/wiring dry-run on testnet:** the immutable-bridge ↔ token construction order, role provisioning
      (GOVERNANCE/GUARDIAN/FEDERATION/PAUSER all granted — the constructor grants none), the attestation
      relayer, and `setLimits` with conservative non-zero breakers **before** the first mint.
- [ ] **Testnet burn-in** with the real signer topology across a reorg + a signer-stall event.

## 2. SHOULD complete (strongly recommended)

- [ ] **Re-derive `MIN_CONFIRMATIONS` and the timeout floors** against the chain's *actual* block-production
      concentration and observed reorg depth (SECURITY.md Addenda I/II) — `100` is grounded in
      `COINBASE_MATURITY`, but the honest bound depends on producer concentration; re-measure by payout
      address, not coinbase tag.
- [ ] **Off-chain liveness interlock:** relayer/attestor refuses to sign during a block/checkpoint stall;
      post-stall stabilization buffer before resuming mints.
- [ ] **Monitoring → automated pause:** watch role grants, verifier/signer proposals, large outflows,
      backing-invariant divergence; wire to an automated `mintPaused`, tested under weekend/holiday conditions.
- [ ] **Value-scaled caps** set from an attack-cost model (mintable-per-window < cost to rewrite that window).

## 3. Roadmap (not blocking 0.34.6, tracked for later)

- [ ] **SPV / light-client trustless-depth relay** (SECURITY.md Addendum II) to remove the federation from the
      depth claim — the path to L2BEAT Stage-1/2 trust-minimization.
- [ ] **Independently-coded verify/veto layer** (CCIP-RMN style) distinct from the bridge signer set.

## 4. Integrator / operator invariants (usage, documented in the SDKs)

- Sign every escrow/HTLC spend with **SIGHASH_ALL** (never NONE/SINGLE/ANYONECANPAY).
- Never reuse a **CSFS/oracle key** across contexts; prefer `htlc_tx()` over bare `csfs()`; bind CSFS
  messages to a unique per-contract context (terms hash / nonce / operation_id).
- Treat a deposit/bond as real only at **≥ 100 confirmations** and non-RBF; `check_timeout_ordering()` is
  necessary-but-not-sufficient — the preimage-holder must fund the long (BTX) leg and claim the short leg first.
- Tier-A/A+ escrow verification is fail-closed only if the buyer **pins** the expected venue / CTV template
  and runs verification against **their own** node.

---
*Companion to SECURITY.md and the 0.34.6 hardening PR #137.*
