# BCP/1 external signing

**Release state.** This document describes the **0.34.8rc3** tree (`CLIENT_VERSION_RC=3`, `CLIENT_VERSION_IS_RELEASE=false`); the last shipping tag is **0.34.7**. It is a development contract under review, not a published vendor standard.

**Proven scope.** Isolated-regtest `feature_bcp1.py` proves a **software** ML-DSA-44 round trip: watch-only deposit pool → unsigned package → canonical digests → valid signature → `finalizeexternalsign complete=true` → `testmempoolaccept` → explicit `sendrawtransaction`. It does **not** prove a live vendor HSM, PKCS#11, KMIP, or HTTPS adapter (those classes fail closed with no client linked). `--stub-signature` remains a negative test only. See [../../contrib/bcp1/README.md](../../contrib/bcp1/README.md).

This extends [../external-signer.md](../external-signer.md). It does not replace the existing `-signer` command protocol (`enumerate`, `signtransaction` / `signtx`, `getdescriptors`, `displayaddress`, `getp2mrpubkeys`).

BCP/1 adds an explicit **digest** lifecycle so `btxd` can construct a P2MR withdrawal **without the private key**. Consensus contains no venue-specific code. Adapter names (PKCS#11, HTTPS, Key-Link, command) are transport. ML-DSA-44 support inside a particular vendor product is an **open vendor question**, not a BCP/1 PASS. Stage 1 vs Stage 2 (native-chain asset): [key-link.md](key-link.md).

---

## Lifecycle

```text
createpsbt
    → prepareexternalsign
    → getsigningdigests
    → external SignDigest(path, algorithm, digest)
    → finalizeexternalsign
    → testmempoolaccept
    → sendrawtransaction
```

| Step | Who | Notes |
|---|---|---|
| `createpsbt` (or `walletcreatefundedpsbt` / `createexchangebatch` / `createconsolidationtx`) | Coordinator | Unsigned BIP174 PSBT. Watch-only. |
| `prepareexternalsign` | Coordinator | Builds **BTXPSBT** JSON from the PSBT + prevouts. No broadcast. No secrets. |
| `getsigningdigests` | Coordinator | One canonical digest per input the signer must cover. |
| `SignDigest` | External signer | ML-DSA-44 (or SLH-DSA-128s) over the digest. Keys never enter `btxd`. |
| `finalizeexternalsign` | Coordinator | Inserts signatures; **validates** witness/digest binding locally; returns hex. **Does not send.** |
| `testmempoolaccept` | Coordinator | Second validation: policy + consensus before broadcast. |
| `sendrawtransaction` | Coordinator | Only after accept. |

Do not skip `testmempoolaccept`. A corrupt ML-DSA signature, wrong prevout, wrong network, or non-canonical witness must fail before send.

Existing `walletprocesspsbt` + `<cmd> signtransaction` remains valid for command adapters. BCP/1 prefers `SignDigest` so raw-signing venues can attach without parsing a full PSBT on day one.

---

## BTXPSBT JSON

BTXPSBT is a **JSON container**, not a new consensus type. It carries everything a signer needs to bind a digest to a P2MR spend. Field names below are the BCP/1 contract; they align with `decodepsbt` P2MR keys (`p2mr_merkle_root`, `p2mr_leaf_script`, `p2mr_bip32_derivs`, …) in `src/rpc/rawtransaction.cpp`.

```json
{
  "format": "BTXPSBT",
  "version": 1,
  "network": "main",
  "chain": "BTX",
  "unsigned_tx_hex": "…",
  "txid": "…",
  "inputs": [
    {
      "index": 0,
      "txid": "…",
      "vout": 0,
      "amount_atoms": 125000000,
      "script_pubkey": "…",
      "sequence": 4294967295,
      "p2mr": {
        "merkle_root": "…",
        "leaf_script": "…",
        "leaf_version": 194,
        "leaf_hash": "…",
        "control_block": "…"
      },
      "path": "m/87h/0h/0h/1/0",
      "pubkeys": [
        {
          "algo": "ML-DSA-44",
          "pubkey": "…",
          "master_fingerprint": "…"
        }
      ],
      "sighash": "DEFAULT",
      "digest": "…",
      "signatures": [
        {
          "algo": "ML-DSA-44",
          "pubkey": "…",
          "signature": "…"
        }
      ]
    }
  ],
  "outputs": [
    {
      "index": 0,
      "address": "btx1z…",
      "amount_atoms": 50000000,
      "script_pubkey": "…",
      "role": "withdrawal"
    },
    {
      "index": 1,
      "address": "btx1z…",
      "amount_atoms": 74900000,
      "script_pubkey": "…",
      "role": "change",
      "path": "m/87h/0h/0h/1/3"
    }
  ],
  "fee_atoms": 100000,
  "weight": 0,
  "locktime": 0
}
```

| Field | Meaning |
|---|---|
| `network` | `main` / `test` / `testnet4` / `signet` / `regtest` (ChainType strings) |
| `unsigned_tx_hex` | Witness-empty (or not-yet-signed) serialization |
| `txid` | `TX_NO_WITNESS_WITH_SHIELDED` hash — stable once vin/vout/locktime/version/shielded are fixed |
| `inputs[].amount_atoms` | Prevout value; required for the P2MR digest |
| `inputs[].p2mr` | Merkle root, selected leaf, control block. `leaf_version` is `P2MR_LEAF_VERSION` (`0xc2`) |
| `inputs[].path` | Signer derivation path (seed-side). Informational for watch-only. |
| `inputs[].pubkeys[].algo` | `ML-DSA-44` or `SLH-DSA-128s` |
| `inputs[].sighash` | P2MR uses `SignatureHashSchnorr` with `SigVersion::P2MR`. Default is `SIGHASH_DEFAULT` (0), equivalent to ALL |
| `inputs[].digest` | 32-byte hex; this is what `SignDigest` signs |
| `inputs[].signatures` | Filled by the signer / `finalizeexternalsign` |
| `outputs[].role` | `withdrawal` or `change` |

`prepareexternalsign` must fail if prevouts, amounts, or P2MR leaf data are missing. `finalizeexternalsign` must fail closed on a corrupt signature, pubkey mismatch, digest mismatch, or modified unsigned tx (same rule as `ExternalSigner::SignTransaction`: signer must not rewrite the transaction).

---

## `SignerProvider`

Vendor-neutral interface (`src/wallet/signer_provider.*` in the BCP/1 implementation). No venue-named classes.

| Method | Behavior |
|---|---|
| `GetPublicKey` | Return the P2MR / PQ pubkey for a stored identity |
| `DerivePublicKey(path)` | **Returns `PUBLIC_CHILD_UNSUPPORTED`.** Public-child derivation is not available for ML-DSA-44. Signers that only hold a seed derive **privately** and export the pubkey (same as `getp2mrpubkeys`). Watch-only coordinators must not call this expecting BIP32 xpub children. |
| `SignDigest(path, algorithm, digest)` | Produce ML-DSA-44 or SLH-DSA-128s over the canonical digest |
| `Health` | Reachable, algorithm list, whether P2MR is declared |

`algorithm` strings: `ML-DSA-44`, `SLH-DSA-128s` (wire may also use `ml_dsa_44` / `slh_dsa_128s` as in `test/functional/mocks/signer.py`).

---

## Adapters

| Adapter | Use | Fail-closed rules |
|---|---|---|
| **command** | Wraps existing `-signer=<cmd>` | **The only live adapter wired to wallet RPC.** Same argv protocol as [../external-signer.md](../external-signer.md), including `health`, `getpubkey`, `getp2mrpubkeys`, and `signtx`. |
| **software** | Regtest / certification mock only | Keys in-process only if **`-bcp1software=1` AND `regtest`**. Never on mainnet. Not reachable from wallet RPC. |
| **https** | Loopback URL check only | **No TLS/HTTP client is linked.** `GetPublicKey` / `SignDigest` always return `HTTPS_UNAVAILABLE`. Compose `--http` is for an external coordinator, not `btxd`. |
| **pkcs11** | Type reserved for a PKCS#11 module | **No PKCS#11 client is linked.** Always `PKCS11_LIB_MISSING` / `PKCS11_UNAVAILABLE`, even if a `.so` path exists. |
| **kmip** | Type reserved for a KMIP server | **No KMIP client is linked.** Always `KMIP_LIB_MISSING` / `KMIP_UNAVAILABLE`. |

Key-Link and other custody-product transports plug in **behind the command adapter** (or a future real PKCS#11/KMIP/HTTPS client). They are not consensus types. Do not treat the stub classes as working HSM I/O.

Existing `ExternalSigner` already declares `m_supports_p2mr` and `m_pq_algorithms`, and calls `getp2mrpubkeys --desc … --index …`. BCP/1 `command` reuses that.

---

## Two stages of venue support

Stage 1 (raw/PQ `SignDigest` via Key-Link / customer HSM; BTX coordinator does addresses, watch-only, deposits, construction, broadcast) is the BCP/1 target. Stage 2 (native-chain vault / address / tx APIs) is a **vendor product** question, not a BCP/1 PASS. Self-service token registration on already-supported chains is **not** native UTXO support. ML-DSA-44 custody (MPC vs KEY_LINK / customer HSM) is an open vendor question.

Full write-up: [key-link.md](key-link.md).

---

## Watch-only and pubkeys

Because `DerivePublicKey` returns `PUBLIC_CHILD_UNSUPPORTED` for public children:

1. The signer derives `m/87h/coin_typeh/accounth/branch/index` from the master seed (HKDF in `pq::DerivePQKeyFromBIP39`).
2. The coordinator imports the resulting pubkeys via `getp2mrpubkeys` or `importdepositpool`.
3. The coordinator later sends `SignDigest` with the **same path** so the signer reconstructs the key from seed.

Do not ship an “xpub” that pretends to mint ML-DSA children. See [exchange-custody.md](exchange-custody.md).
