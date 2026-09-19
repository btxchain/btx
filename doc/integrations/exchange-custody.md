# BTX Custody Profile 1 — Exchange / Custody FAQ

This page is an integration guide for custody and exchange engineering teams. It is **not** a listing announcement, and it does not claim that any exchange, custodian, or venue has listed, integrated, or approved BTX. "Listing" below means a reader's operational use case, not a commitment by BTX or by any venue.

**Release state.** This tree is **0.34.8rc3** (`CLIENT_VERSION_RC=3`, `CLIENT_VERSION_IS_RELEASE=false`). That is a release-candidate stamp, not a shipping tag. The last shipping tag is **0.34.7**. Do not treat any interface on this page as frozen, published, or independently certified.

**Scope.** BCP/1 is a **major monetary-wallet addition**, not a cosmetic helper. It adds a custody RPC surface and an external-digest signing lifecycle, and it also changes existing signing RPCs and wallet lifecycle behavior. Review it as a wallet change, not only as an integration document.

Public name: **BTX Custody Profile 1 (BCP/1)**, also called **BTX Exchange Profile v1** (`BTX_EXCHANGE_PROFILE_V1`). It is a small, deterministic **monetary** custody surface. It is independent of HCP and of the Model Network.

Vendor-neutral. Venue, HSM, and Key-Link product names appear only as examples of how an adapter might attach. They are not consensus, not a listing requirement, and not a BCP/1 PASS. There is no vendor-support claim: PKCS#11, KMIP, and loopback HTTPS adapters exist only as **fail-closed stubs** with no client library linked ([external-sign.md](external-sign.md)).

Related:

- Integration docs index: [README.md](README.md)
- Profile contract, RPC list, events, confirmation/reorg semantics: [bcp1.md](bcp1.md)
- External-sign lifecycle, BTXPSBT, `SignerProvider`: [external-sign.md](external-sign.md)
- Key-Link / raw-signing attachment: [key-link.md](key-link.md)
- Incident / reorg / crash recovery: [incident-recovery.md](incident-recovery.md)
- Existing `-signer` command protocol: [../external-signer.md](../external-signer.md)
- Watch-only / descriptor operating model: [../btx-key-management-guide.md](../btx-key-management-guide.md)
- Machine-readable network parameters: [../../contrib/bcp1/network-manifest.json](../../contrib/bcp1/network-manifest.json)
- Certification harness overview: [../../contrib/bcp1/README.md](../../contrib/bcp1/README.md)

---

## FAQ

### Is BTX UTXO or account based?

**UTXO.** Spends consume previous outputs (`txid` + `vout`) and create new outputs. There is no account nonce, no global balance object, and no EVM-style chain ID. Internal ledgers at a venue are the venue's own book; the chain tracks coins as UTXOs.

### Can custody be completely external?

**Yes.** `btxd` can construct, track, and broadcast without possessing private keys. Keys stay in an external signer (software mock on regtest, or `-signer` command wrapping an HSM/Key-Link process). PKCS#11, KMIP, and loopback HTTPS classes exist as **fail-closed stubs** (no client library is linked) and are not wired to wallet RPC. Consensus does not contain venue-specific code.

### Does `btxd` require the private key?

**No.** Create the coordinator wallet with `disable_private_keys=true` (and usually `external_signer=true` or an imported deposit pool). `-exchange-watchonly` refuses in-process private signing. Signing is `SignDigest` on the provider, then `finalizeexternalsign`.

### Can an exchange run watch-only?

**Yes.** That is the intended BCP/1 topology:

1. External signer holds ML-DSA-44 (and any SLH-DSA-128s policy keys).
2. Exchange coordinator runs a watch-only descriptor wallet: import addresses / pubkeys, track UTXOs, build unsigned withdrawals, estimate fees, emit deposit/reorg events, export signing requests.
3. `btxd` validates and relays. It never needs the seed.

### What signature scheme does a normal BTX withdrawal use?

**ML-DSA-44** spending a **witness v2 P2MR** output (`WITNESS_V2_P2MR`, 32-byte program). Leaves may also use **SLH-DSA-128s**. Mainnet consensus sets `fEnforceP2MROnlyOutputs = true`; the default wallet address type is `p2mr`. BCP/1 monetary withdrawals are transparent P2MR. They do not require a shielded bundle.

### Can one wallet generate many deposit addresses?

**Yes, with an honest derivation limit.**

Canonical path on the **signer**, from the **master seed** (HKDF, not BIP32 CKD):

```text
m/87h / coin_typeh / accounth / branch / index
```

- `87h` is the BTX PQ purpose tag (`src/pq/pq_keyderivation.cpp`: salt `BTX-PQ-BIP87-HKDF-V1`, info `m/87h`).
- `coin_typeh`: **0h** on mainnet, **1h** on test chains (`Params().IsTestChain()`). This is BTX's own derivation index, not a registered SLIP-44 coin type.
- `accounth`: hardened account (omnibus deposit vault is typically `0h`).
- `branch`: **0** = deposit, **1** = change (unhardened in the path encoding; still derived from the seed).
- `index`: sequential customer deposit (or change) index.

**Public children are unsupported.** ML-DSA-44 cannot do Bitcoin-style non-hardened BIP32 public-child derivation. A watch-only `btxd` must **not** be given an xpub and asked to mint `m/…/i` itself.

Watch-only deposit addresses therefore come from one of:

1. Signer `getp2mrpubkeys` (existing `-signer` command; `ExternalSigner::GetP2MRPubKeys`) — the signer derives from the seed and returns the P2MR pubkey(s) for that descriptor index.
2. A pre-generated address/pubkey pool imported with `importdepositpool`.

The **default monetary wallet tree** is two leaves, not a single ML-DSA key:

```text
mr(pqhd(seed/…), pk_slh(pqhd(seed/…)))
```

`importdepositpool` therefore accepts `{pubkey, pubkey_slh}` (ML-DSA-44 + SLH-DSA-128s) so the watch-only descriptor commits to the **same** P2MR merkle root as `getnewaddress(address_type=p2mr)`. A single-leaf `mr(ML-DSA-only)` is a different script and will not see those deposits.

`deriveexchangeaddress(index)` on a watch-only wallet uses the imported pool or signer-exported pubkeys. It never fakes a BIP32 xpub. The `pqhd(fingerprint/…)` descriptor form is derivation-incapable until the wallet injects the seed; fingerprint-only material cannot produce children.

### Can withdrawals be batched?

**Yes.** One transaction, many outputs, plus change: `createexchangebatch` (BCP/1) or existing `sendmany` / `createpsbt` with multiple outputs. The batch remains unsigned until the external signer returns ML-DSA-44 (or SLH-DSA-128s) signatures.

### Are mempool and confirmation events available?

**Yes.** BCP/1 names: `transaction.mempool`, `transaction.confirmed`, `deposit.detected`, `deposit.confirmations_changed`, plus block connect/disconnect and reorg. They map onto existing ZMQ (`hashtx`, `hashblock`, `rawtx`, `rawblock`, `sequence`, wallet topics) and wallet notify / `getdepositstatus`. See [bcp1.md](bcp1.md).

### Can deposits survive / reconcile reorgs?

**Yes, via the deposit-status interface.** `getdepositstatus(txid, vout)` returns `MEMPOOL | CONFIRMED | REORGED | CONFLICTED | SPENT | UNKNOWN` with confirmation depth and canonical block identity. ZMQ `sequence` publishes every block connect (`C`) and disconnect (`D`). A confirming block that leaves the active chain moves the deposit back toward mempool/`REORGED`. Pair this with wallet reorg hold flags (`-walletreorgsafetydepth`, `-walletreorgholdblocks`, `-walletreorgholdseconds`) so settlement reporting pauses after a disconnect without restarting the node. BCP/1 does **not** publish a maximum historical reorg depth or call any confirmation count irreversible — see [bcp1.md](bcp1.md).

### Is the Model Network needed?

**No.** Listing and custody use the monetary chain only.

### Is HCP needed?

**No.** HCP is a separate hosted/model control plane. BCP/1 does not depend on it.

### Does an exchange need a GPU?

**No.** A monetary node does not mine, does not run ExactReplay attestation, and does not need CUDA to accept deposits or broadcast withdrawals.

### Can a monetary-only node run without CUDA / model dependencies?

**Yes.** Build with `-DWITH_MODELNET=OFF`. That tree is money only: `btxd`, `btx-cli`, wallet, external signer, ZMQ. No `btx-modeld`, no model discovery, no inference, no Cognitive Reserve, no GUI requirement. A local certification image tag is conceptually `btx:exchange-local` ([contrib/bcp1/Dockerfile](../../contrib/bcp1/Dockerfile)); this repository does not publish container registries.

### Can a deposit `txid` change? Is there transaction malleability?

**Deposit keys are `txid` + `vout`, not `wtxid`.** On the normal P2MR path, ML-DSA-44 / SLH-DSA-128s signatures sit in the **witness**. Changing the witness changes **`wtxid`** but not **`txid`** (witness is excluded from the txid hash). P2MR spends use an empty `scriptSig`, so classic scriptSig malleation of the txid does not apply. BCP/1 does not claim ML-DSA signatures are unique. Shielded bundles would affect both hashes; BCP/1 monetary withdrawals should not include one. Details: [bcp1.md — Confirmation and reorg](bcp1.md#confirmation-and-reorg).

### How does the node expose disconnected blocks?

**ZMQ `sequence`** publishes every connect (`C`) and disconnect (`D`) with the block hash (little-endian on the wire). BCP/1 maps disconnects to `block.disconnected`. `hashblock` / `rawblock` fire on **tip** updates only; after a reorg you may see only the new tip there — subscribers must walk from the last known block or rely on `sequence`. Pair with `getdepositstatus` and wallet reorg hold flags. See [bcp1.md — Events](bcp1.md#events).

### Does ASERT change confirmation counting or deposit state?

**No.** ASERT retargets MatMul proof-of-work difficulty; it does not rewrite `confirmations`, txids, or `getdepositstatus`. Depth is still “how many active-chain blocks sit above the block that included this output.” Block intervals may change around retargets; counting rules do not. See [bcp1.md — Confirmation and reorg](bcp1.md#confirmation-and-reorg).

### How deep a reorg has BTX historically experienced?

**BCP/1 does not publish a normative maximum historical reorg depth** for credit policy. Integrators must not hard-code a magic number from documentation. Implement policy with `getdepositstatus`, ZMQ `sequence`, and wallet reorg hold (`-walletreorgsafetydepth`, `-walletreorgholdblocks`, `-walletreorgholdseconds`). See [bcp1.md — Confirmation and reorg](bcp1.md#confirmation-and-reorg).

---

## Topology

```text
                    ┌─────────────────────────┐
                    │ External signer / HSM   │
                    │ (ML-DSA-44 keys)        │
                    └───────────┬─────────────┘
                                │ SignDigest only
                                ▼
┌───────────────────────────────────────────────┐
│ Exchange custody coordinator                  │
│ watch-only wallet · UTXO accounting           │
│ unsigned construction · policy / withdrawals  │
└───────────────────────┬───────────────────────┘
                        │ JSON-RPC / ZMQ
                        ▼
                     btxd
                        │
                   BTX network
```

`automatic_spend_atoms` is a Model Network gate and stays unused here. Wallet spends are explicit signed withdrawals.

---

## What BCP/1 does not answer

BCP/1 does not prescribe how many confirmations a venue should wait. That is the venue's risk policy. The node exposes depth, block hash/height, disconnects, and conflict status so any policy can be implemented.

Attaching ML-DSA-44 through a particular vendor's Key-Link / MPC / PKCS#11 product is an **open vendor question**, not a BCP/1 PASS. See [key-link.md](key-link.md) stage 1 vs stage 2.
