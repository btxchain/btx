# wBTX contracts — security dossier

Consolidated from a survey of the wrapped-BTC landscape (WBTC, cbBTC, FBTC, Binance BTCB, kBTC, 21BTC,
tBTC v2, renBTC, sBTC, Liquid L-BTC, Nomic nBTC), the Circle FiatToken/USDC compliance design, the
major bridge/wrapped-token exploits, and OpenZeppelin v5.6 / Foundry best practice. This file records
the threat model, the defenses our contracts implement, the design decisions, and the residual risks
and audit plan. It is the rationale companion to `evm/WBTX.sol`, `evm/WBTXBridge.sol`,
`evm/WBTXAtomicSwapHTLC.sol` and `../../docs/wbtx-bridge-architecture.md`.

> These contracts are UNAUDITED references. An external audit + invariant-fuzz campaign is mandatory
> before any real value flows.

## 1. Incident corpus → root-cause classes (what we learned from)

| Incident | ~Loss | Root-cause class | Lesson baked into our design |
|---|---|---|---|
| Ronin | $624M | Validator key compromise (5/9, shared org/infra; stale delegation) | High M-of-N w/ independent custody; **mint rate-limit + circuit breaker**; outflow monitoring |
| Harmony Horizon | $100M | Threshold too low (2/5); plaintext keys on host | M ≥ ⅔N; HSM/threshold custody (operational) |
| Multichain | $125M | "MPC" was single-operator custody | Decentralized, independent signer operation; on-chain rotation |
| Wormhole | $326M | Signature-verification bypass (fake sysvar) | Verifier binds to authoritative signer set; **OZ ECDSA**; no attacker-supplied "already verified" |
| Nomad | $190M | Upgrade/init bug — "uninitialized == valid" (zero root proven) | **Non-upgradeable core**; replay guard sentinel can't collide with empty; no "default==valid" |
| Poly Network | $611M | Access-control / control-plane takeover (keeper set swap) | `setVerifier` gated by **Timelock GOVERNANCE_ROLE**; control plane ≠ data plane |
| Qubit | $80M | Deposit spoofing (`safeTransferFrom(address(0))` no-op) | **Balance-delta accounting** in HTLC; reject `address(0)` |
| Meter.io | $4.4M | Unverified deposit amount across divergent paths | Verify value actually moved (balance delta) |
| pNetwork | $12M | Event not bound to canonical emitter | Statement binds exact deposit outpoint; off-chain must bind emitter |
| BadgerDAO | $120M | Frontend/CDN compromise + unlimited approvals | Pause lever; steer integrators to finite approvals/permit; supply-chain hygiene |
| renBTC | (collapse) | Operational/financial centralization; no trustless refund | **Depositor-unilateral BTX refund leaf**; on-chain redeem refund path; transparent rotation |
| WBTC (depeg) | — | Custody concentration / confidence | Publish & monitor **backing invariant**; pausable redemption |

Root-cause classes: (1) key compromise, (2) signature-verification flaw, (3) replay/uniqueness, (4)
upgrade/init bug, (5) access-control/message-auth, (6) infinite-approval/frontend, (7) custody/depeg.

## 2. Defense checklist → where implemented

### Bridge (`WBTXBridge` + `ECDSAMultisigVerifier`)
- **EIP-712 typed attestation** with domain `{name,version,block.chainid,address(this)}` → cross-chain,
  cross-bridge, **post-fork** replay all prevented. (Fixes the latent bug in the v0 draft, which
  captured `chainid` at construction and would stay replayable on a forked chain.) *Class 2/3.*
- **Outpoint replay guard** `minted[depositKey(txid,vout)]`, set before mint (CEI); `depositKey` uses
  `abi.encode` (collision-safe). One mint per BTX deposit. *Class 3.*
- **OZ `ECDSA.recover`** in the verifier → rejects high-s malleability, bad `v`, and `ecrecover==0`;
  strictly-ascending recovered-signer order enforces distinctness; loop bounded by signer-set size.
  *Class 2.*
- **Real signer-set rotation** (`rotateSigners`) clears the prior set (no stale-signer accumulation),
  emits an event; gated by the verifier's `DEFAULT_ADMIN` (Timelock). *Class 1.*
- **Circuit breaker:** `windowMintCapSat` (rolling-window cap) + `maxSupplyWbtx` (hard ceiling). A
  compromised verifier/federation cannot mint unbounded or drain instantly. *Class 1 (Ronin/Harmony).*
- **Guardian veto / optimistic minting:** mints above `optimisticThresholdSat` are time-queued
  (`guardianDelay`); a `GUARDIAN_ROLE` can `cancelQueuedMint` within the window. Bounds a compromised
  threshold even with "valid" attestation. *Class 1/2 (tBTC pattern).*
- **Granular pause** (`PAUSER_ROLE`): independent `mintPaused` (the critical backing-safety lever) and
  `redeemPaused`, so halting minting doesn't trap redemptions and vice versa. **Role separation** via
  `AccessControlDefaultAdminRules` (2-step admin + enforced delay); `setVerifier`/`setLimits`/
  `refundRedeem` are `GOVERNANCE_ROLE` (**must be a Timelock owned by a multisig**). *Class 5 (Poly).*
- **Redeem safety:** `uint64` truncation guard; auditable `Redeem` records; `fulfillRedeem` (federation
  writes the BTX txid on-chain); `refundRedeem` (governance re-mints to the burner after
  `redeemRefundTimeout` if a redemption can't be honored) → no silently-lost funds. *renBTC/FBTC lesson.*
- **ReentrancyGuard** on `mint`/`executeQueuedMint`/`redeem`/`refundRedeem`. *Class (reentrancy).*

### Token (`WBTX`)
- **OZ `ERC20` + `ERC20Permit` (EIP-2612)** + **EIP-3009** (`transferWithAuthorization`,
  `receiveWithAuthorization`, `cancelAuthorization`) — gasless approvals AND gasless transfers /
  meta-transactions with random-nonce replay protection (Circle FiatToken pattern). `receiveWith-
  Authorization` is payee-gated (front-run safe).
- **Role separation** (`MINTER_ROLE`/`BURNER_ROLE` held by the bridge, `PAUSER`/`UNPAUSER` separate,
  `RESCUER`) via `AccessControlDefaultAdminRules` (2-step + delay). *Class 5.*
- **Issuance pause** (mint/burn) — the backing-safety lever — **without** freezing holder transfers
  (deliberate: no censorship lever; see Decisions).
- **Optional compliance hook** (`IComplianceHook`) — default **OFF** (`address(0)` = neutral); only the
  Timelock can install one. Captures the Circle/cbBTC blacklist *capability* as an explicit, opt-in,
  governance-gated module rather than an unconditional `blacklisted[]` — neutrality is the default.
- **`rescueERC20`** (SafeERC20) recovers *foreign* tokens mis-sent here; **cannot** touch wBTX. *Class 6.*

### HTLC (`WBTXAtomicSwapHTLC`)
- **SafeERC20 + balance-delta accounting** → non-standard (USDT), fee-on-transfer, rebasing tokens
  cannot break custody/insolvency. *Class 5 (Qubit/Meter).*
- **In-contract, sender-bound swap id** (`computeId`) → no `id`-squatting front-run. *(HTLC griefing.)*
- **ReentrancyGuard** + CEI; **timeout sanity bounds** (`MIN/MAX_TIMEOUT`).
- **Hash domain** `RIPEMD160(SHA256(preimage))` matches BTX `OP_HASH160` exactly (verified against a
  BTX node: preimage `0x42…42` → `8739f40ec4dbf569dcb38134c6e7310908566981`).

## 3. Design decisions (explicit, not by omission)

- **Decimals — DECIDED: 18 (EVM-native positioning).** The wrapped-BTC *norm* is 8 (WBTC, cbBTC, FBTC,
  tBTC, kBTC); the one major 18-dec precedent is Binance-Peg **BTCB**. wBTX deliberately follows the
  **BTCB model**: an EVM-native 18-decimal asset prioritizing uniform DeFi math and sub-satoshi
  granularity on the EVM side, with `1 sat == 1e10 units` (`SAT_SCALE`). Why this is safe and coherent:
  - **Mints are always whole-satoshi multiples** (`amountSat × 1e10`) — no sub-sat backing is ever
    created by the bridge. Sub-sat balances arise *only* from EVM-side division (DeFi splits/AMMs) and
    are backed in aggregate by whole locked sats.
  - **Redeem rounds DOWN and burns the full amount**, so the sub-sat remainder accrues to the bridge's
    backing **surplus** — the dust mechanism is *solvency-positive*, not a leak. The only one to ever
    lose <1 sat is a user who chooses to redeem a fractional-sat amount.
  - L1 redemption of sub-sat amounts requires consolidation to whole sats — a deliberate, federated
    (coordinated) secondary concern, not a soundness issue.
  Tradeoff accepted: non-idiomatic vs the BTC-wrapper norm (integrators must read `decimals()`, which
  competent ones do; WBTC at 8 dec also lives in all of DeFi). The choice is isolated to
  `WBTX.decimals()` (18) and `WBTXBridge.SAT_SCALE` (1e10).
- **Blocklist — NO (default).** No unconditional `blacklisted[]` in transfers (WBTC stance) → credibly
  neutral. If compliance ever requires it, add a *governance-gated, default-noop* compliance hook
  (swappable only by Timelock), never an unconditional check. (cbBTC/USDC have a blacklister; that is a
  centralization/honeypot tradeoff we decline by default.)
- **Transfer pause — NO.** We pause *issuance* (mint/burn), not holder transfers — issuance pause is
  the backing-safety lever; transfer-freeze is a censorship lever we omit.
- **Upgradeability.** Core token + bridge are **non-upgradeable** (avoids the entire Nomad/Parity
  uninitialized-impl class); the only swappable piece is the `IAttestationVerifier` (and limits/roles),
  behind Timelock governance. If a future bridge ever goes UUPS, it MUST `_disableInitializers()` in the
  implementation constructor, use ERC-7201 namespaced storage, and gate `_authorizeUpgrade` to the
  Timelock (with a path to renounce upgradeability once stable).
- **EVM-leg trust (v1).** `ECDSAMultisigVerifier` is *classical* M-of-N. The authoritative security is
  BTX's M-of-N **post-quantum** attestation; the BTX lock + refund leaf bound exposure. The verifier is
  swappable for a **zk-attestation** verifier (constant-gas SNARK proving M-of-N ML-DSA/SLH-DSA sigs;
  see architecture §8) to make the EVM leg PQ-secure without changing the lock format.

## 4. Residual risks (must be owned operationally)
- **No on-chain BTX SPV proof of the deposit.** Mint trusts the attestation (like renBTC), not an
  independent chain-state check. Mitigations: high M-of-N, circuit breaker, guardian veto, and the
  off-chain **backing-invariant watcher** that auto-pauses on divergence. The trust-minimized endgame is
  the zk/SPV verifier (architecture §C/§8).
- **Federation key custody** is the dominant real-world risk (Ronin/Harmony/Multichain were all key
  compromises, not contract bugs). Require independent operators, HSM/threshold custody, and monitoring.
- **HTLC cross-chain timeout asymmetry** cannot be enforced on-chain — the SDK/integrator MUST set the
  slower/first leg's timeout strictly longer than the faster/second leg (e.g. BTX 24–48h vs EVM 6–12h).
- **Frontend/supply-chain** (BadgerDAO) is out of contract scope — harden CDN/DNS and prefer finite
  approvals/permit.

## 5. Test & audit plan (before mainnet)
- **Foundry invariants:** `totalSupply ≤ lockedSat·SAT_SCALE`; `Σbalances == totalSupply`; no
  double-mint per outpoint; redeem conservation; dust monotonic non-decreasing; window cap never
  exceeded; supply ceiling never exceeded; queued-mint can't execute before delay or after cancel.
- **Unit/fuzz:** threshold exactly met / off-by-one; duplicate/out-of-order/non-member/high-s sigs;
  wrong chainid/bridge/recipient/amount attestation; post-fork replay; permit valid/expired/replayed;
  every privileged fn reverts for non-role; 2-step admin begin/accept/cancel/delay; rescue can't touch
  wBTX; SafeERC20 vs a no-return mock; HTLC fee-on-transfer token; id-squat attempt; timeout bounds.
- **Static:** Slither (fail high/med) + Mythril on the bridge/verifier core; OZ Upgrades storage check
  if ever upgradeable.
- **External audit** of the full set + the BTX-side lock/refund script and the zk verifier when added.

## 6. Building the contracts
These reference contracts target **OpenZeppelin Contracts v5.6.x**. With Foundry:
```
forge install OpenZeppelin/openzeppelin-contracts@v5.6.1
# remappings.txt: @openzeppelin/=lib/openzeppelin-contracts/
forge build && forge test
```
