# BTX Custody Profile 1 (BCP/1)

Contract name: **`BTX_EXCHANGE_PROFILE_V1`**.

**Release state.** This contract describes the tree at **0.34.8rc3** (`CLIENT_VERSION_RC=3`, `CLIENT_VERSION_IS_RELEASE=false`). It has not been frozen by a shipping tag; the last shipping tag is **0.34.7**. Treat the surface below as a release-candidate contract under review, not a published standard.

**Scope.** BCP/1 is a **major monetary-wallet addition**: it adds the wallet RPCs and the external-digest signing lifecycle described here, and it also changes existing signing RPCs and wallet lifecycle behavior. It is larger than an integration wrapper and should be reviewed at wallet level.

BCP/1 is the monetary custody surface for exchanges and external signers. It is independent of HCP. Wallet monetary RPCs may spend; they must not invent `automatic_spend_atoms`.

This document is the profile contract. Index: [README.md](README.md). First-page FAQ: [exchange-custody.md](exchange-custody.md). Signer lifecycle: [external-sign.md](external-sign.md). Key-Link / raw-signing: [key-link.md](key-link.md). Incident/recovery: [incident-recovery.md](incident-recovery.md). Network constants: [../../contrib/bcp1/network-manifest.json](../../contrib/bcp1/network-manifest.json).

Venue names are examples of adapters (Key-Link, PKCS#11, HTTPS). They are not consensus and not evidence of vendor support: the PKCS#11, KMIP, and HTTPS adapters are **fail-closed stubs** with no client library linked ([external-sign.md](external-sign.md)).

---

## Required vs not required

### Required processes / capabilities

| Piece | Role |
|---|---|
| `btxd` | Monetary full node: P2P, mempool, validation, index, broadcast |
| JSON-RPC | Stable wallet + raw-tx subset below |
| ZMQ and/or wallet notify | Mempool, block connect/disconnect, deposit state |
| Descriptor watch-only wallet | `WALLET_FLAG_DISABLE_PRIVATE_KEYS` (+ descriptors) |
| External signing | `SignerProvider` / `-signer` / BTXPSBT digest flow |
| P2MR / ML-DSA-44 construction | Unsigned package, canonical digest, signature import |
| Block and transaction indexing | Resolve `txid`+`vout` after restart |

`-exchange-watchonly` (already in `src/wallet/init.cpp`) refuses in-process private signing. Wallets must be descriptor + `disable_private_keys` (external signer or imported deposit pool). Do not combine with `-disablewallet`.

### Explicitly not required

| Piece | Why it is out of profile |
|---|---|
| `btx-modeld` | Model Network helper |
| HCP | Hosted control plane |
| Model discovery / inference | Not money |
| Mining / MatMul templates | Custody nodes do not mine |
| Cognitive Reserve | Not money |
| GUI (`btx-qt`) | Headless RPC is enough |
| CUDA / GPU | Not required to accept or send money |
| Shielded pool | BCP/1 withdrawals are transparent P2MR |

Build a monetary-only binary with **`-DWITH_MODELNET=OFF`**. ZMQ is compiled in by default (`-DWITH_ZMQ=ON`); enable the pub sockets at runtime (`-zmqpubsequence`, `-zmqpubhashblock`, `-zmqpubhashtx`, …). See [../zmq.md](../zmq.md).

---

## RPC list

Wallet RPCs fail closed if they would use in-process private keys under `-exchange-watchonly` / `WALLET_FLAG_DISABLE_PRIVATE_KEYS`. Results contain no seed and no private keys. `finalizeexternalsign` does **not** broadcast.

### BCP/1 wallet RPCs

| RPC | Purpose |
|---|---|
| `getexchangereadiness` | Profile health: chain, wallet flags, signer, ZMQ, indexes |
| `deriveexchangeaddress` | Address at `branch`/`index` from pool or signer pubkeys — never a fake xpub |
| `importdepositpool` | Import pre-generated P2MR pubkeys / addresses for watch-only |
| `prepareexternalsign` | Wrap a PSBT / funded tx as BTXPSBT JSON (no secrets) |
| `getsigningdigests` | Canonical per-input P2MR digests |
| `finalizeexternalsign` | Insert signatures; return hex; do not send |
| `getdepositstatus` | `txid`,`vout` → state + confirmations + block identity |
| `listdepositutxos` | Watch-only spendable / immature deposit coins |
| `planconsolidation` | Coin-selection plan (min value, max inputs, fee ceiling, …) |
| `createconsolidationtx` | Unsigned consolidation (sweep) package |
| `estimateconsolidationfee` | Fee / weight for a consolidation plan |
| `createexchangebatch` | One tx, N withdrawal outputs, change, digests |

### Reused (already in tree)

| RPC | Purpose |
|---|---|
| `createpsbt` | Unsigned BIP174 PSBT (inputs/outputs) |
| `walletcreatefundedpsbt` | Fund + unsigned PSBT (watch-only) |
| `walletprocesspsbt` | Existing PSBT path; BCP/1 prefers digest lifecycle |
| `sendmany` | Multi-output send when the wallet may sign |
| `sweeptoself` | Existing sweep primitive |
| `testmempoolaccept` | Policy/consensus check before broadcast |
| `sendrawtransaction` | Broadcast |
| `createwallet` | `disable_private_keys`, `blank`, `passphrase`, `avoid_reuse`, `descriptors`, `load_on_startup`, `external_signer` |
| `importdescriptors` | Watch-only descriptors (fingerprint form cannot derive PQ children) |
| `enumeratesigners` / `walletdisplayaddress` | Existing `-signer` command |
| `getrawtransaction`, `getblock`, `getblockchaininfo` | Chain queries |
| `decoderawtransaction`, `decodepsbt` | Inspect P2MR fields |

Every BCP/1 result is safe to log from a watch-only coordinator: no wallet seed, no ML-DSA secret.

---

## Events

BCP/1 event names (JSON). `-walletdepositnotify=<cmd>` runs a command on deposit transitions (`%e` event name, `%j` JSON, `%s` txid). Chain-level names still map onto existing ZMQ sockets (do not add new topic strings).

| BCP/1 name | Meaning | Existing ZMQ / RPC |
|---|---|---|
| `block.connected` | Block added to the active chain | `sequence` body `\<32-byte hash\>C`; tip also on `hashblock` / `rawblock` |
| `block.disconnected` | Block removed from the active chain | `sequence` body `\<32-byte hash\>D` |
| `transaction.mempool` | Tx accepted to mempool | `sequence` `A`; `hashtx` / `rawtx`; `hashwallettx-mempool` |
| `transaction.confirmed` | Tx included in a **connected** block (depth ≥ 1) | `hashtx` / `rawtx` on block; `hashwallettx-block`; confirm with RPC |
| `transaction.reorged` | Confirming block disconnected; tx may return to mempool | `sequence` `D` then wallet status `REORGED` |
| `deposit.detected` | Watch-only wallet first sees a matching output | `-walletdepositnotify` (`%e`, `%j`) + `getdepositstatus` |
| `deposit.confirmations_changed` | Depth or block identity changed | `-walletdepositnotify` + poll `getdepositstatus` |
| `deposit.finalized` | **Policy alias only**: confirmations ≥ the venue's configured depth. **Not** chain finality |
| `utxo.created` | New spendable (or immature) output in the wallet | wallet |
| `utxo.spent` | Output consumed | wallet / `getdepositstatus` → `SPENT` |

`hashblock` / `rawblock` fire on **tip** update only. A reorg may emit only the new tip there; subscribers must walk from the last known block. `sequence` is the complete connect/disconnect feed. Hashes on ZMQ are **little-endian**; RPC hashes are display (byte-reversed) hex. See [../zmq.md](../zmq.md).

Stable event identifiers:

```json
{
  "chain": "BTX",
  "network": "main",
  "txid": "…",
  "vout": 1,
  "address": "btx1z…",
  "amount_atoms": 125000000,
  "block_hash": "…",
  "block_height": 253184,
  "confirmations": 7
}
```

`amount_atoms` is the integer amount in the smallest unit (`COIN = 100000000`). Node C++ still names that unit `sat` (`CURRENCY_ATOM`); BCP/1 JSON uses `amount_atoms`.

---

## Confirmation and reorg

### What is 1 confirmation?

**Included in a block that is connected to the active chain tip, at depth 1.** Mempool is 0. The coinbase maturity rule (`COINBASE_MATURITY = 100`) is separate: a coinbase output is not wallet-spendable until 100 additional blocks, even if `confirmations` is already large.

### What if the confirming block disappears?

The node disconnects that block (`sequence` `D`). `getdepositstatus` becomes `REORGED` (typically back in the mempool) or `CONFLICTED` if a double-spend won. Listeners must un-credit or hold per venue policy. Restart-only recovery is a failure: the watch-only wallet must reconcile from disk + RPC without a bounce.

### Can a `txid` change? Can the transaction be malleated?

Verified in `src/primitives/transaction.cpp`:

- **`txid`** = SHA256d of `TX_NO_WITNESS_WITH_SHIELDED` (witness **excluded**, shielded bundle **included** if present).
- **`wtxid`** = SHA256d of `TX_WITH_WITNESS` (full serialization). If there is no witness and no shielded bundle, `wtxid == txid`.

P2MR signatures live in the **witness**. Attaching or replacing an ML-DSA-44 / SLH-DSA-128s signature therefore:

- does **not** change `txid` (outpoints stay stable — this is the sense in which P2MR `txid` is wtxid-stable);
- **does** change `wtxid`.

BCP/1 deposit keys are **`txid` + `vout`**, not `wtxid`. Native P2MR spends use an empty `scriptSig`, so classic scriptSig malleation of the txid does not apply on the P2MR path. BCP/1 does not claim ML-DSA signatures are unique; `wtxid` may differ across two valid witnesses for the same txid. If a transaction carries a shielded bundle, both hashes commit to that bundle. BCP/1 monetary withdrawals should not include one.

### When is a deposit “irreversible”?

**BCP/1 never claims irreversible.** PoW plus local reorg policy is not economic finality.

Facts the node *does* expose:

- Confirmation **depth** and **block hash/height** via `getdepositstatus` and wallet transaction metadata.
- Disconnects (`sequence` `D`, `block.disconnected`) and status transitions to `REORGED` / `CONFLICTED`.
- Wallet **reorg hold** flags (service policy, not consensus): after a block disconnect the wallet can report `settlement_safe=false` and zero settlement-safe balances until hold clears — `-walletreorgsafetydepth` (minimum confirmations for settlement-safe reporting), `-walletreorgholdblocks`, and `-walletreorgholdseconds` (`src/wallet/init.cpp`). Use these together with `getdepositstatus` so crediting pauses after a reorg without requiring a node restart.
- Local reorg **protection** (not a BCP/1 finality gadget): optional PARK/warn profiles via `-parkdeepreorg` / `-maxreorgdepthpark`; `getreorgprotectionstatus` reports the active profile. This affects how the **local** node treats deep competing chains; it does not make any confirmation depth irreversible for deposits.

### How deep a reorg has BTX historically experienced?

**BCP/1 does not publish a normative maximum historical reorg depth** for listing or credit policy. Past depth on any network is an empirical question; integrators must not hard-code a magic number from documentation.

Implement policy with:

1. **`getdepositstatus(txid, vout)`** on every connect/disconnect and on a timer — states `MEMPOOL`, `CONFIRMED`, `REORGED`, `CONFLICTED`, `SPENT`, `UNKNOWN` plus `confirmations`, `block_hash`, `block_height`.
2. **Wallet reorg hold** (`-walletreorgsafetydepth`, `-walletreorgholdblocks`, `-walletreorgholdseconds`) so internal settlement reporting stays conservative after `sequence` `D`.
3. **ZMQ `sequence`** (and wallet notify) so disconnects are not missed while polling.

A venue chooses its own confirmation threshold; BCP/1 only exposes the signals above.

### Does ASERT change confirmation counting?

**No.** ASERT (`nMatMulAsertHeight = 50000` on mainnet, half-life 3600s then 14400s after the pow-limit upgrade) retargets MatMul difficulty. It does not rewrite `confirmations`, txids, or deposit state. An ASERT retarget may change block times; depth is still “how many active-chain blocks are on top of this one.”

### Chain-finality assumptions beyond PoW?

None in BCP/1. No BFT gadget, no checkpoint-as-finality for deposits. Assumeutxo / `defaultAssumeValid` are sync accelerators, not a credit policy.

### `getdepositstatus(txid, vout)`

| Status | Meaning |
|---|---|
| `MEMPOOL` | In mempool, 0 confirmations |
| `CONFIRMED` | In a connected block; `confirmations >= 1` |
| `REORGED` | Previously confirmed; confirming block(s) disconnected |
| `CONFLICTED` | Another tx spending the same prevout is in the active chain or mempool |
| `SPENT` | This output has been spent |
| `UNKNOWN` | Not in wallet / not indexed |

Also: `confirmations`, `block_hash`, `block_height`. Depth 1 = included in a connected block.

---

## Address and script types (monetary)

- Encoding: **Bech32m**, witness **version 2**, program **32 bytes** (`WITNESS_V2_P2MR_SIZE`).
- Mainnet HRP `btx`; addresses start `btx1z…` (version 2 encodes as `z`).
- Parser: `DecodeDestination` in `src/key_io.cpp`. Rejects v2 programs whose length is not 32.
- Default `-addresstype` / `DEFAULT_ADDRESS_TYPE`: `p2mr`.
- Supported spend algorithms on P2MR leaves: **ML-DSA-44**, **SLH-DSA-128s**.

Derivation honesty is in [exchange-custody.md](exchange-custody.md). Watch-only cannot BIP32-derive public ML-DSA children.

---

## Fees, size, dust (policy, not a credit rule)

From `src/policy/policy.h` and `src/consensus/consensus.h` / `src/consensus/amount.h`:

| Item | Value |
|---|---|
| Decimals | 8 (`COIN = 100000000`) |
| `MAX_MONEY` / `nMaxMoney` | 21_000_000 BTX (sanity / subsidy cap) |
| Initial subsidy | 20 BTX; halving interval 525_000 |
| Coinbase maturity | 100 blocks |
| Default min relay | 1000 atoms/kvB |
| Default dust relay | 3000 atoms/kvB (`DUST_RELAY_TX_FEE`) |
| Standard tx weight cap | 1_200_000 (`MAX_STANDARD_TX_WEIGHT`) |
| Block weight / serialized size | 24_000_000 |
| Witness scale factor | **1** (weight = size) |

Dust for a standard P2MR output is `GetDustThreshold`: serialized `CTxOut` plus a 148-byte input addend (because `WITNESS_SCALE_FACTOR == 1`). At the default dust relay rate that is **573 atoms** for a 34-byte P2MR `scriptPubKey`. Dust is **relay policy**, not consensus.

Fee rates in RPC are BTX/kvB or sat/vB (`FeeEstimateMode`). BCP/1 packages should also report integer `fee_atoms` and weight.

---

## Readiness

`getexchangereadiness` reports profile, chain/network/tip/IBD, wallet flags, ZMQ/`txindex`, signer fields, and deposit-pool facts. Read the aggregate `ready` flag as the conjunction of those prerequisites:

- `ready` is true only when the wallet is a descriptor wallet with `disable_private_keys`, the node is not in IBD, **and** a deposit pool or a healthy `-signer` exists (`ready_capabilities` lists each bit).
- An empty descriptor watch-only wallet reports `ready=false`. Signer health and deposit material are also returned separately so callers can see *why*.
- `walletprocesspsbt(sign=true)` on `WALLET_FLAG_EXTERNAL_SIGNER` delegates to FillPSBT / `-signer`. `signrawtransactionwithwallet` and `dumpprivkey` still refuse in-process private keys.

Do not describe `ready` as a venue certification.

---

## Related

- FAQ: [exchange-custody.md](exchange-custody.md)
- External-sign lifecycle, BTXPSBT, `SignerProvider`: [external-sign.md](external-sign.md)
- Key-Link / raw-signing stages (Stage 1 digest vs Stage 2 native asset): [key-link.md](key-link.md)
- Incident / recovery runbook: [incident-recovery.md](incident-recovery.md)
- Existing `-signer` command protocol: [../external-signer.md](../external-signer.md)
- Machine-readable network parameters: [../../contrib/bcp1/network-manifest.json](../../contrib/bcp1/network-manifest.json)
- Certification harness overview: [../../contrib/bcp1/README.md](../../contrib/bcp1/README.md)
