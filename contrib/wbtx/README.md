# contrib/wbtx — BTX ↔ EVM wBTX bridging toolkit

Reference tooling for bridging BTX to a wrapped, EVM-native token (**wBTX**). It pairs the BTX node's
existing primitives (P2MR script trees, the federation bridge, HTLC/CSFS/CTV, PSBT) with EVM-side
reference contracts and a Python SDK. Architecture, trust models, and the security analysis live in
[`docs/wbtx-bridge-architecture.md`](../../docs/wbtx-bridge-architecture.md); the token unit model is
[`docs/wBTX.md`](../../docs/wBTX.md).

**These contracts and scripts are UNAUDITED references. Do not move real value before an external
security audit and an adversarial test campaign.**

## What's here
```
evm/WBTX.sol                 ERC-20 wBTX on OpenZeppelin v5.6 — ERC20 + Permit(EIP-2612) + EIP-3009
                             (gasless transfers) + AccessControlDefaultAdminRules roles + issuance-pause
                             + rescueERC20 + optional governance-gated compliance hook. 18 dec (DECIDED).
evm/WBTXBridge.sol           Model A: federation lock-and-mint, HARDENED — EIP-712 attestation, outpoint
                             replay guard, mint circuit-breaker + guardian veto, redeem refund lifecycle,
                             timelock governance; pluggable IAttestationVerifier (+ ECDSAMultisigVerifier
                             v1, upgradeable to a zk verifier).
evm/WBTXAtomicSwapHTLC.sol   Model B: trustless HTLC, hashlock = RIPEMD160(SHA256(preimage)) (BTX-compatible),
                             SafeERC20 + balance-delta, squat-proof swap id, reentrancy-guarded.
test/WBTX.t.sol              Foundry suite (21 tests: replay, EIP-712, threshold, circuit-breaker,
                             guardian veto, redeem/refund, granular pause, permit, EIP-3009, compliance
                             hook, backing-relation fuzz, HTLC) — all passing on OZ v5.6.1 / solc 0.8.24.
btx_wbtx.py                  Python SDK over the BTX node RPCs (descriptors + PSBT)
SECURITY.md                  Threat model, incident corpus → defenses, design decisions, audit/test plan.
```

**Docs:** [`docs/wbtx-contracts.md`](../../docs/wbtx-contracts.md) — how the contracts work, the design
decisions, deployment, and the **EVM-chain integration guide** (dApps, federation operators, atomic-swap
integrators, relayers). [`docs/wbtx-bridge-architecture.md`](../../docs/wbtx-bridge-architecture.md) —
models + trust analysis. [`docs/wBTX.md`](../../docs/wBTX.md) — token unit spec.

The contracts are hardened against the bridge-hack corpus (Ronin, Wormhole, Nomad, Poly, Qubit,
Multichain, renBTC) and follow OpenZeppelin/Circle best practice — see **`SECURITY.md`** for the full
mapping of each defense to the incident it prevents, and the open **decimals** decision (industry norm
is 8; we keep 18 per `wBTX.md`).

## Build & test
```
cd contrib/wbtx
forge install OpenZeppelin/openzeppelin-contracts@v5.6.1 foundry-rs/forge-std
forge test          # 21 passing
```

## Two models (both ship; see architecture §2)
- **A — federation lock-and-mint (the wBTX path).** Lock BTX to a federation-controlled P2MR address
  carrying your EVM recipient; the M-of-N attestor set attests the deposit; `WBTXBridge.mint()` mints
  `sat × 1e10` wBTX. Burn wBTX via `WBTXBridge.redeem()` → the federation releases BTX (round-down).
- **B — trustless atomic swap.** No custodian. Both legs lock under the **same 20-byte hashlock**;
  revealing the preimage to claim one leg exposes it for the other.

## The hashlock that makes Model B atomic
BTX's P2MR HTLC leaf uses `OP_HASH160 = RIPEMD160(SHA256(preimage))`. Both are EVM precompiles, so the
EVM contract hashes identically:
```solidity
bytes20 h = ripemd160(abi.encodePacked(sha256(preimage)));   // == BTX HASH160(preimage)
```
Use the **same 32-byte preimage** on both chains. The Python SDK's `btx_hash160(preimage)` produces the
identical 20-byte value for the BTX descriptor.

## BTX-side recipe (Model B)
1. **Lock address (descriptor):**
   ```
   mr(<internal_pk>, { htlc(<H160>, <claimer_pk>), refund(<locktime>, <sender_pk>) })
   ```
   - `<H160>` = `RIPEMD160(SHA256(preimage))` (hex, 20 bytes).
   - `<claimer_pk>` = the claimer's ML-DSA/SLH-DSA pubkey (the CSFS "oracle" key — here, the recipient
     themselves, so the claim needs *both* the preimage and the recipient's signature).
   - `<locktime>` = absolute block height/time after which `<sender_pk>` may refund.
   Add the checksum with `getdescriptorinfo`, derive with `deriveaddresses`, import with
   `importdescriptors`.
2. **Fund** the derived address (`sendtoaddress`).
3. **Claim (recipient)** — use the wallet RPC:
   ```
   buildhtlcclaim "<descriptor#cksum>" {"txid":"<txid>","vout":<n>} "<preimage_hex>" "<dest_address>" <fee_sat>
       -> {"hex":"<signed raw tx>", "complete":true}
   ```
   It assembles the HTLC leaf witness `<0x01> <csfs_sig> <preimage> <leaf_script> <control_block>`
   (the wallet produces `csfs_sig`, the recipient's PQ signature over `TaggedHash("CSFS/btx", preimage)`,
   and injects the `hash160` preimage + the P2MR CSFS message), signs, and returns the raw tx. Broadcast
   it with `sendrawtransaction` — the preimage is now on-chain, so the counterparty can claim the EVM leg.
4. **Refund (sender)** — after `<locktime>`, use the wallet RPC:
   ```
   buildhtlcrefund "<descriptor#cksum>" {"txid":"<txid>","vout":<n>} "<dest_address>" <locktime> <fee_sat>
       -> {"hex":"<signed raw tx>", "complete":true}
   ```
   It spends the refund leaf with the sender's PQ signature and sets `nLockTime`/sequence so the tx is
   only valid once the chain tip is at/after `<locktime>`. Broadcast with `sendrawtransaction`.

`btx_wbtx.py`'s `build_claim` / `build_refund` are thin wrappers over exactly these two RPCs (with a
graceful `NotImplementedError` on older nodes that lack them); it also automates the descriptor and
preimage extraction. See the module docstring for an end-to-end example.

## SECURITY notes (read before using)
- **Timeout ordering (Model B).** The party who can be left holding nothing must have the *longer*
  refund timeout. Standard rule: the BTX leg's refund `<locktime>` (the value passed to the descriptor's
  `refund(...)` leaf and to `buildhtlcrefund`) must be **strictly and safely longer** than the EVM leg's
  `open(..., timeout)`, so the secret-revealer never loses the race. Pick conservative deltas (account
  for BTX ~90s blocks and EVM finality); the node/SDK does not police the cross-chain gap — you must.
- **Hash-domain agreement.** Both chains MUST use `RIPEMD160(SHA256(preimage))`. A mismatch silently
  breaks atomicity. The contract and SDK enforce this; do not substitute keccak256/sha256-only.
- **Replay binding (Model A).** The mint statement binds `{evmChainId, bridgeId, btxTxid, vout, to,
  amountSat}`; an attestation cannot be replayed across chains/bridges/deposits/recipients/amounts.
- **EVM-leg trust (Model A v1).** `ECDSAMultisigVerifier` is *classical* M-of-N. The authoritative
  security is the PQ attestation on BTX; the BTX lock+refund bounds exposure. Upgrade the verifier to
  the zk-attestation path (architecture §8) to make the EVM leg post-quantum too.
- **Backing invariant.** circulating wBTX / 1e10 ≤ BTX locked, at all times, reorg-safe on the BTX
  side. Monitor it; halt mint on violation.
- **Audit.** Mandatory before mainnet value.

## Status / roadmap
- ✅ Architecture + decisions + EVM-attestation-verification analysis (`docs/wbtx-bridge-architecture.md`).
- ✅ EVM reference contracts (token, bridge + ECDSA v1 verifier, atomic-swap HTLC).
- ✅ BTX-side SDK for the Model-B swap leg (descriptors + PSBT).
- ✅ HTLC spend RPCs `buildhtlcclaim` / `buildhtlcrefund` (audited control-block + CSFS + preimage
  witness assembly and signing); covered by `test/functional/wallet_htlc_atomicswap.py`.
- ⏳ Remaining ergonomic node RPCs: `createwbtxlock`, `extractpreimage`, `scanwbtxdeposits` — thin
  wrappers over existing script-tree/PSBT machinery.
- ⏳ Indexer/relayer reference; zk-attestation verifier; adversarial campaign; external audit.
