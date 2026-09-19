# BCP/1 Key-Link / raw-signing

This is the vendor-neutral **Key-Link / raw-signing** integration note for **BTX Custody Profile 1 (BCP/1)** (`BTX_EXCHANGE_PROFILE_V1`).

Venue, HSM, and Key-Link product names appear **only as examples of adapters**. They are not consensus, not a listing requirement, and not a BCP/1 PASS. Consensus contains no venue-specific code. Do not add venue-named C++ types.

Digest lifecycle, BTXPSBT fields, and fail-closed `finalizeexternalsign` rules live in [external-sign.md](external-sign.md). This document is the **stage 1 / stage 2** contract and the adapter map. Do not treat a self-service “register a token on an already-supported chain” API as native BTX UTXO support.

Related:

- FAQ: [exchange-custody.md](exchange-custody.md)
- Profile contract: [bcp1.md](bcp1.md)
- Digest lifecycle / BTXPSBT: [external-sign.md](external-sign.md)
- Existing `-signer` command protocol: [../external-signer.md](../external-signer.md)
- Incident / recovery: [incident-recovery.md](incident-recovery.md)

`automatic_spend_atoms` is unused here. Wallet spends are explicit signed withdrawals.

---

## Two stages

### STAGE 1 — raw / PQ `SignDigest` (BCP/1 target)

The custody product (or a **customer HSM** attached behind it) can **sign a digest** with ML-DSA-44 (or SLH-DSA-128s) at a derivation path. BTX software does the rest. Keys never enter `btxd`.

```text
Key-Link / customer HSM / PKCS#11 / HTTPS / `-signer`
        │
        └── raw/PQ SignDigest(path, algorithm, digest)
                     ▲
                     │ signatures only
┌────────────────────┴───────────────────────────────┐
│ BTX coordinator (watch-only)                       │
│   addresses · watch-only · deposits                │
│   unsigned construction · BTXPSBT · broadcast      │
└────────────────────┬───────────────────────────────┘
                     │ JSON-RPC / ZMQ
                     ▼
                  btxd
                     │
                BTX network
```

| Role | Who | What |
|---|---|---|
| Addresses | Coordinator | `deriveexchangeaddress` from `importdepositpool` or signer-exported pubkeys (`GetPublicKey` / `getp2mrpubkeys`). Never a fake BIP32 xpub. |
| Watch-only | Coordinator | Descriptor wallet, `disable_private_keys`, `-exchange-watchonly`. |
| Deposits | Coordinator | ZMQ / wallet notify + `getdepositstatus`. |
| Construction | Coordinator | `createpsbt` / `createexchangebatch` / `createconsolidationtx` → `prepareexternalsign` → `getsigningdigests`. |
| Sign | External | `SignDigest(path, algorithm, digest)`. |
| Insert / validate | Coordinator | `finalizeexternalsign` (no broadcast) → `testmempoolaccept` → `sendrawtransaction`. |

Result: an exchange can deploy BTX **without hot ML-DSA-44 keys in `btxd`**. Stage 1 is enough for a listing that already runs a BTX watch-only coordinator.

**Self-service token registration is not native UTXO chain support.** Public “add a token” endpoints on already-supported *account* chains (for example EVM, Stellar, Algorand, TRON, NEAR, Solana, Sui, TON) do **not** make BTX a first-class UTXO asset. Stage 1 does not require that. BTX still needs its own address construction, P2MR serialization, and a signer that can invoke ML-DSA-44.

### STAGE 2 — native-chain asset (vendor product, not a BCP/1 PASS)

The venue adds BTX as a first-class chain so customers use that product's normal vault / address / transaction APIs instead of orchestrating raw `SignDigest` themselves:

```text
Venue vault account
  └── BTX wallet
        ├── create deposit address
        ├── receive BTX
        ├── send BTX
        ├── MPC / Key-Link / HSM custody
        ├── policy engine
        ├── webhooks
        └── transaction history
```

Stage 2 is a **vendor product** milestone. It is outside BTX consensus and **outside a BCP/1 certification PASS**. Native vault semantics are not something `btxd` can declare complete.

---

## ML-DSA-44: MPC vs KEY_LINK / customer HSM

BTX's normal P2MR monetary path uses **ML-DSA-44** (leaves may also use SLH-DSA-128s), not the ECDSA/EdDSA families most institutional custody stacks historically built around.

Whether a given vendor can **custody and invoke ML-DSA-44** is an **open vendor question**, not a BCP/1 PASS. Ask explicitly, in two forms:

| Path | Question |
|---|---|
| **MPC** | Does the vendor's MPC stack implement ML-DSA-44 (and the `m/87h/…` seed derivation) so a vault can sign a BCP/1 digest? |
| **KEY_LINK / customer HSM** | Can a customer-supplied HSM or remote signer that already holds ML-DSA-44 attach while the vendor keeps policy / orchestration? |

A product that exposes both **MPC** and **KEY_LINK** (or equivalent “external key”) vault types should be examined on **both** paths. If ML-DSA-44 attaches cleanly through Key-Link / PKCS#11 / HTTPS / a customer HSM, Stage 1 can be operational **without** waiting for that vendor's MPC stack to implement PQ signatures.

ECDSA/EdDSA-only raw signing is **not** sufficient for a normal P2MR withdrawal. BCP/1:

- documents the digest and path ([external-sign.md](external-sign.md));
- ships PKCS#11 / KMIP / HTTPS / command adapters;
- does **not** mark Key-Link + ML-DSA-44, or any named venue, as PASS.

Example adapter attachments (not a listing list, not consensus): a Key-Link / MPC venue (for example Fireblocks), a Copper- or BitGo-class custody API, a Thales PKCS#11 module, an AWS CloudHSM partition, or an exchange-proprietary HSM. BTX does not care which, as long as `SignDigest` returns ML-DSA-44 over the canonical digest.

---

## `SignerProvider`

Vendor-neutral interface (`src/wallet/signer_provider.*`). Conceptual names below; C++ uses the PascalCase forms. No venue-named classes.

| Method | C++ | Behavior |
|---|---|---|
| `get_public_key` | `GetPublicKey(path, algorithm)` | Return the P2MR / PQ pubkey for a stored identity. The signer derives from seed or HSM; this is **not** public-child derivation. |
| `derive_public_key` | `DerivePublicKey(parent, path, algorithm)` | **Always returns `PUBLIC_CHILD_UNSUPPORTED`** for ML-DSA-44 (and the BCP/1 SLH-DSA path). There is no Bitcoin-style non-hardened BIP32 public child. Watch-only coordinators must not call this expecting an xpub. Use `get_public_key` or `importdepositpool`. |
| `sign_digest` | `SignDigest(path, algorithm, digest)` | Produce ML-DSA-44 or SLH-DSA-128s over the 32-byte canonical digest from `getsigningdigests`. |
| `health` | `Health()` | Reachable, `p2mr` declared, `pq_algorithms` list. Fail-closed if the backend cannot advertise ML-DSA-44 for a P2MR spend. |

`algorithm` strings: `ML-DSA-44`, `SLH-DSA-128s` (wire may also use `ml_dsa_44` / `slh_dsa_128s` as in `test/functional/mocks/signer.py`).

Canonical path (hardened **seed** on the signer, HKDF in `pq::DerivePQKeyFromBIP39`, not BIP32 CKD):

```text
m/87h / coin_typeh / accounth / branch / index
branch 0 = deposit, 1 = change
```

`coin_typeh` is **0h** on mainnet, **1h** on test chains. Watch-only `btxd` never mints children from an xpub. See [exchange-custody.md](exchange-custody.md).

---

## Adapters

Key-Link and other custody-product transports plug in **behind** these adapters. They are not consensus types.

| Adapter | Use | Fail-closed rules |
|---|---|---|
| **command** | Wraps existing `-signer=<cmd>` | **The only live adapter wired to wallet RPC.** Same argv protocol as [../external-signer.md](../external-signer.md), including `health`, `getpubkey`, `getp2mrpubkeys`, and `signtx` / `signtransaction`. |
| **software** | Regtest / certification mock only | Keys in-process only if **`-bcp1software=1` AND `regtest`**. Never on mainnet. Error `SOFTWARE_SIGNER_REGTEST_ONLY` / `SOFTWARE_SIGNER_DISABLED` otherwise. Not reachable from wallet RPC. |
| **pkcs11** | Type reserved for a PKCS#11 module | **No PKCS#11 client is linked.** Always `PKCS11_LIB_MISSING` / `PKCS11_UNAVAILABLE`, even if the module path exists. No silent ECDSA fallback. |
| **kmip** | Type reserved for a KMIP server | **No KMIP client is linked.** Always `KMIP_LIB_MISSING` / `KMIP_UNAVAILABLE`. |
| **https** | Loopback URL check only | **No TLS/HTTP client is linked.** `GetPublicKey` / `SignDigest` always `HTTPS_UNAVAILABLE`. Loopback check only (`HTTPS_NOT_LOOPBACK` for non-loopback URLs). |

Existing `ExternalSigner` already declares `m_supports_p2mr` and `m_pq_algorithms`. The **command** adapter reuses that.

Do not skip `testmempoolaccept` after `finalizeexternalsign`. A corrupt ML-DSA signature, wrong prevout, wrong network, or non-canonical witness must fail before send.

---

## What Stage 1 does not include

- Native venue deposit-address / history / policy APIs (Stage 2).
- Claiming any vendor's MPC or Key-Link product supports ML-DSA-44.
- Model Network, HCP, CUDA, mining, or `automatic_spend_atoms`.
- In-process keys on mainnet.
