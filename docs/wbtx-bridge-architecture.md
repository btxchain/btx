# wBTX ↔ BTX bridging — architecture, current state, and build plan

Status: design / planning. Companion to the canonical token spec [`wBTX.md`](wBTX.md).

This document inventories what BTX **already** provides for bridging BTX to a wrapped, EVM-native
representation (wBTX), defines the trust/security models, and lays out the work to make wBTX↔BTX
bridging robust, scalable, and secure — the BTX side, the EVM side, and the developer surface.

---

## 1. Executive summary

The BTX node is **already ~70% of the way to a production lock-and-mint bridge**, and has the full
primitive set for **trustless atomic swaps**. The expensive, security-critical consensus/script work
is done; the remaining work is mostly *off-chain* (EVM contracts, an SDK, indexer/relayer) plus a
small, well-scoped set of node RPCs for ergonomics and robustness.

What already exists on the BTX side:
- **P2MR script trees** (`src/script/pqm.*`, BIP341/Taproot-analogous, **post-quantum**): key-path +
  tapleaf-style script paths with control blocks and a Merkle commitment.
- **Bridge lock primitive** — `BridgeScriptTree` (`src/shielded/bridge.cpp`): a 2-leaf lock
  (`normal_leaf` claim + `refund_leaf` timeout) with control blocks; this *is* a bridge deposit
  address. It already binds an external **`destination_id`** (a 32-byte field — an EVM 20-byte
  address fits) so a lock carries its intended mint recipient.
- **Federation/attestor settlement** — verifier sets, batch receipts, proof receipts, settlement
  witnesses, with **FIPS-205 SLH-DSA** (or ML-DSA) attestor signatures (hardened in v0.31; height-
  gated at C-002/123000). RPCs: `bridge_buildverifierset`, `bridge_buildrefund`, `bridge_build*`.
- **Trustless-swap primitives** — `BuildP2MRHTLCLeaf` (hashlock + oracle CSFS), `BuildP2MRRefundLeaf`
  (CLTV timeout + PQ-sig), `BuildP2MRAtomicSwapLeaf` (CTV covenant + PQ-sig), `OP_CHECKSIGFROMSTACK`
  (`CSFS/btx` tagged hash), CTV. Descriptors express them: `mr(KEY,{htlc(H160,PK),refund(T,PK)})`.
- **PSBT** carries everything needed to *spend* these end-to-end: hash preimage fields
  (`hash160_preimages`/`sha256_preimages`), and P2MR fields (`m_p2mr_leaf_script`,
  `m_p2mr_control_block`, `m_p2mr_merkle_root`, `m_p2mr_csfs_msgs/sigs`, `m_p2mr_pq_sigs`). The
  descriptor-wallet `FillPSBT` path populates the script tree; `walletprocesspsbt`/`finalizepsbt`
  sign and assemble the witness.

What is **missing** (the build):
- **EVM contracts**: wBTX ERC-20, the bridge mint/burn contract, and an atomic-swap HTLC contract —
  none live in this repo (it is the node).
- **Hash-domain compatibility plumbing** between BTX HTLCs (`HASH160 = RIPEMD160(SHA256(x))`) and EVM.
- **Developer surface**: an SDK + a few node RPCs so integrators don't hand-assemble descriptors,
  control blocks, and PSBT preimage fields (a funds-loss footgun class).
- **Indexer/relayer reference**: watch BTX deposits → mint on EVM; watch EVM burns → release on BTX.

## 2. The two bridging models (and a third)

| Model | Trust | BTX-side status | Best for |
|---|---|---|---|
| **A. Federation lock-and-mint** | Trust the attestor set (M-of-N) | **Largely built** (BridgeScriptTree + attestors + settlement) | The canonical "wBTX" mint/redeem in `wBTX.md`; high throughput |
| **B. Trustless atomic swap (HTLC)** | Trustless (hashlock+timeout) | **Primitives present** (htlc/refund leaves, CSFS, PSBT) | P2P / DEX swaps BTX↔token; no custodian, needs counterparty liquidity |
| **C. Trust-minimized light client** | Cryptographic (header/proof verification) | Not built (would need EVM-side BTX light client and/or BTX-side EVM proof verification) | Maximum decentralization; largest effort |

`wBTX.md` defines wBTX as a **lock-and-mint** wrapped token (18 decimals, 10¹⁰ scaling, round-down on
redeem) — i.e. **Model A** is the primary "wBTX" path. **Model B** complements it for trustless
swaps and does not require the federation. **Model C** is a future hardening of A.

## 3. wBTX unit model (from `wBTX.md`)
- BTX is 8-decimal `int64` satoshis; wBTX is an **18-decimal** EVM token. Scaling factor **10¹⁰**.
- Mint locks N sat on BTX → mints `N × 10¹⁰` wBTX. Redeem burns wBTX, **rounds down** to whole sat,
  releases on BTX; the sub-satoshi remainder is non-redeemable dust. Backing invariant: locked-sat ≥
  redeemable-wBTX/10¹⁰ at all times.

## 4. Security & scalability requirements (non-negotiable for adoption)
- **No new value creation:** wBTX in circulation MUST be ≤ BTX locked (per-direction accounting,
  reorg-safe on the BTX side — BTX already makes settlement-anchor undo prune/reorg-safe).
- **Attestor security (Model A):** M-of-N PQ (FIPS-205/ML-DSA) signatures over a *replay-bound*
  statement (chain id, bridge id, nonce, destination, amount). Already the shape of BridgeBatch.
- **Refund safety:** every lock has a timeout refund leaf (present); a stuck mint never traps funds.
- **Hash/domain agreement (Model B):** EVM HTLC MUST hash with `ripemd160(sha256(preimage))` (both are
  EVM precompiles) to match BTX `HASH160`; mismatched domains silently break atomicity.
- **Scalability:** batch settlement (BridgeBatch already batches); deposits/withdrawals indexed, not
  rescanned; PQ signatures are large (ML-DSA ~2.4 KB, SLH-DSA ~7.8 KB) so prefer ML-DSA for hot-path
  attestors and batch to amortize.

## 5. Recommended build (phased)

**Phase 0 — foundation (no consensus risk):**
- This architecture doc; the canonical **HTLC/atomic-swap recipe** (descriptor, hash domains, witness
  layout, PSBT fields); EVM reference contracts; a BTX-side **SDK** over existing RPCs; a regtest E2E.

**Phase 1 — BTX-side DX/robustness RPCs (small, justified core additions):**
- `createwbtxlock` / `wbtxlockaddress` — build a lock address (BridgeScriptTree or HTLC) binding an
  EVM destination; returns address + descriptor + the redeem/refund metadata. Footgun-free deposits.
- `buildhtlcclaim` / `buildhtlcrefund` — build the spend PSBT for a chosen leaf (populates leaf
  script, control block, preimage / CSFS msg). Generalizes the proven `bridge_buildrefund`.
- `extractpreimage` — pull the revealed preimage from a confirmed claim tx (for the EVM relayer).
- `scanwbtxdeposits` — index deposits to a watched bridge/HTLC address (descriptor-scan, not rescan).
  Each is thin, reuses existing script-tree/PSBT machinery, and is independently testable.

**Phase 2 — EVM side (reference, audited separately):**
- `WBTX.sol` (ERC-20, 18 dec); `WBTXBridge.sol` (mint on M-of-N PQ attestation, burn→release request);
  `WBTXAtomicSwapHTLC.sol` (`ripemd160(sha256)` hashlock + timeout) for Model B.

**Phase 3 — robustness & scale:** indexer/relayer reference, monitoring of the backing invariant,
adversarial test campaign (double-mint, reorg, refund-race, hash-domain confusion), and an external
audit before mainnet value flows.

## 6. The minimal core additions, justified (not bloat)
The flows above are *spendable today* via descriptors + PSBT; the additions are **ergonomics and
safety**, not new capability — they encapsulate control-block derivation and preimage/PSBT-field
encoding that, done by hand, risk stuck or stealable funds. They reuse the existing
`BridgeScriptTree`/`GetP2MRSpendData`/PSBT code; none touch consensus or the script interpreter.
Anything that *would* touch consensus (e.g. Model C proof verification) is explicitly out of scope
until separately designed and audited.

## 7. Decisions (recorded)
- **Models:** ship **A (federation lock-and-mint)** as the canonical wBTX path **and B (trustless
  HTLC atomic swaps)** for P2P/DEX. C (light client) deferred.
- **Custody (Model A):** **M-of-N post-quantum federation** — minting is authorized by an M-of-N
  attestor set (the existing BTX verifier-set / BridgeBatch shape), over a replay-bound statement.

## 8. The hard problem: verifying BTX's M-of-N PQ attestation *on the EVM*

ML-DSA / SLH-DSA verification is **not feasible directly in EVM gas** (no precompile; ML-DSA verify is
thousands of field ops, SLH-DSA far more — millions of gas, likely > block limit). So "M-of-N PQ
federation, verified by the EVM contract" cannot mean naive on-chain PQ-sig checks. Three viable
realizations, in order of preference:

1. **zk-attested mint (recommended target).** Off-chain, verify the M-of-N PQ signatures over the
   mint statement and produce a succinct proof (Groth16/PLONK) of *"≥M valid attestor PQ-signatures
   over statement S, where S binds {chainid, bridgeId, nonce, evmRecipient, amount}"*. The EVM
   contract verifies the **SNARK** (a few hundred k gas) and mints. This is **constant-gas, scalable,
   and keeps the PQ security end-to-end.** BTX **already** has proof-receipt infrastructure
   (`BridgeProofReceipt`, `proof_system_id`, sp1/plonk references in `shielded_rpc.cpp`) — the same
   machinery extends to attestation proofs and an EVM verifier contract.
2. **ECDSA-mirrored federation (pragmatic v1).** The same M-of-N committee *also* holds secp256k1
   keys; the EVM contract verifies M-of-N ECDSA (cheap, native `ecrecover`). The **authoritative**
   security is the PQ attestation on the BTX side (consensus); the EVM leg mirrors it with classical
   multisig. Trade-off: the EVM leg is only classically secure (acceptable short-term — an EVM-side
   classical break lets a quorum mis-mint, but the BTX lock/refund still bounds exposure), and it
   ships now. Designed to swap the verifier to (1) without changing the lock format.
3. **Optimistic + fraud proofs.** Mint optimistically against a posted attestation; a challenge
   window lets anyone submit a fraud proof. Lowest crypto cost, adds latency + a watchtower role.

**Plan:** ship **(2) ECDSA-mirrored** for v1 to unblock liquidity, with the lock/statement format and
contracts structured so the verifier upgrades to **(1) zk-attested** without a lock migration. Model B
(HTLC) has **no** such problem — it is pure hashlock/timelock and ships fully trustless immediately.

> This is the single most important security design point. It is called out here so the EVM-side
> verifier is never mistaken for "real on-chain PQ verification" until (1) lands.
