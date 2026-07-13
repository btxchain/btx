# Post-Quantum Asset Custody Guide for Exchanges

**Integrating BTX when you have no prior post-quantum assets**

> Audience: exchange integration, custody, treasury-ops, and compliance teams onboarding
> BTX for the first time. This guide answers the practical question raised by most
> integrating venues: *"Your cryptographic algorithm differs from BTC/ETH/SOL and is not
> compatible with our existing MPC cluster — do you have a multisig implementation and docs
> for it?"* The answer is yes: BTX ships a native, consensus-enforced post-quantum multisig
> inside `btxd`. This document explains what it is, why your existing MPC/ECDSA stack cannot
> sign for it, and exactly how to custody BTX without it.
>
> Companion normative docs in the BTX tree: `doc/btx-key-management-guide.md` (custody
> source-of-truth), `doc/btx-pq-multisig-spec.md`, `doc/btx-pq-multisig-tutorial.md`,
> `doc/btx-pqc-spec.md`, `doc/offline-signing-tutorial.md`, `doc/external-signer.md`.

---

## 0. TL;DR for the integration lead

1. **BTX is post-quantum-only.** Ordinary transfers are authorized by NIST **ML-DSA-44**
   (FIPS 204, primary) and **SLH-DSA-SHAKE-128s** (FIPS 205, backup) signatures — *not*
   secp256k1 ECDSA/Schnorr. Legacy signatures are **rejected at consensus**.
2. **Your MPC/TSS cluster will not work for BTX.** Standard MPC clusters do threshold
   *ECDSA/EdDSA/Schnorr* over elliptic curves. BTX keys are lattice/hash-based; there is no
   drop-in threshold-signing protocol for them in your existing cluster.
3. **You do not need MPC.** BTX has **native on-chain k-of-n multisig** (`P2MR` +
   `OP_CHECKSIGADD_MLDSA/SLHDSA`). Each co-signer holds an independent PQ key; the quorum is
   enforced by the script and by consensus. Coordinate partial signatures with **PSBT**.
4. **Everything is descriptor-based.** One receive address type — **P2MR** (bech32m witness
   v2, `btx1…`). Descriptor wallets only. The supported exchange pattern is a **watch-only
   coordinator + air-gapped/offline PQ signers** exchanging PSBTs.
5. **PQ signatures are large** (ML-DSA-44 signature ≈ 2.4 KB). Budget for it in fee-rate,
   UTXO consolidation, and block-space planning.
6. **Regulatory framing:** BTX is the **ACP-Q3 reference profile** in the *BTX Reference
   Asset Framework for Post-Quantum Digital Commodities*. Onboarding it cleanly means
   producing a custody **CBOM**, running the operational test suite, and mapping listing /
   collateral / halt controls to the framework's obligations (Sections 9–12 below).

---

## 1. Why your existing MPC cluster is incompatible

Most exchanges custody BTC/ETH/SOL with a Multi-Party Computation (MPC/TSS) cluster that
produces a single **threshold ECDSA** (secp256k1) or **threshold EdDSA/Schnorr** (Ed25519 /
BIP340) signature. That works because all three chains authorize transfers with the *same
family* of elliptic-curve signatures.

BTX breaks that assumption at three layers:

| Layer | BTC / ETH / SOL | BTX |
|---|---|---|
| Signature family | secp256k1 ECDSA / BIP340 Schnorr / Ed25519 | **ML-DSA-44** (lattice, FIPS 204) + **SLH-DSA-SHAKE-128s** (hash, FIPS 205) |
| Threshold signing | Mature MPC/TSS (GG20, CMP, FROST, …) | **No production TSS** for ML-DSA/SLH-DSA that fits a standard cluster |
| On-chain auth | ECDSA/Schnorr opcodes | `OP_CHECKSIG_MLDSA` / `OP_CHECKSIG_SLHDSA` / `OP_CHECKSIGADD_*` — **PQ-only** |

Two consequences:

- **Your MPC nodes cannot generate or co-sign a BTX key.** They operate on elliptic-curve
  scalars/points; ML-DSA is module-lattice math and SLH-DSA is hash-based. There is no shared
  secret your cluster can turn into a valid BTX signature.
- **Even a "legacy fallback" address is unspendable.** BTX enforces
  `fEnforceP2MROnlyOutputs = true` on mainnet and all production testnets: every non-`OP_RETURN`
  output must be a witness-v2 P2MR program, and a second consensus flag
  (`SCRIPT_VERIFY_REJECT_LEGACY_SIGS`) rejects any inherited ECDSA/Schnorr operation. You cannot
  route BTX value through an ECDSA path even if you wanted to.
  (Source: `src/kernel/chainparams.cpp`, `src/validation.cpp`, `src/script/interpreter.cpp`.)

**The supported answer is not "make MPC do PQ." It is native PQ multisig with independent
signers coordinated over PSBT** — described in the rest of this guide. This gives you the same
security property an MPC quorum gives you (no single key can move funds) using primitives that
are enforced by the BTX network itself.

> If your risk framework *requires* MPC/TSS specifically, treat that as a residual-exposure
> item in your custody CBOM (Section 9) and plan around native multisig for launch. A
> threshold-ML-DSA scheme is an open research area and is **not** available in `btxd` today.

---

## 2. BTX cryptographic profile (the CBOM starting point)

### 2.1 Signature algorithms

| Algorithm | Standard | Role | Public key | Secret key | Signature |
|---|---|---|---:|---:|---:|
| **ML-DSA-44** (CRYSTALS-Dilithium, Level I) | **FIPS 204** | Primary transfer authority | 1312 B | 2560 B | 2420 B |
| **SLH-DSA-SHAKE-128s** (SPHINCS+) | **FIPS 205** | Backup / diversity | 32 B | 64 B | 7856 B |
| ML-KEM-768 | FIPS 203 | Shielded-pool / transport KEM **only** | — | — | — |
| Falcon-512 | FIPS 206 (draft) | **Reserved, not active** | — | — | — |

- ML-DSA-44 is the default; SLH-DSA is available for algorithm diversity and can be mixed
  **per key** inside a single multisig.
- ML-KEM is a key-encapsulation mechanism used by the shielded pool / transport — it is **not**
  an ownership signature. Do not represent ML-KEM as your transfer-authority algorithm.
- Sources: `src/pqkey.h` (sizes, `enum class PQAlgorithm`), `src/libbitcoinpqc/` (backend),
  `src/script/interpreter.cpp` (verification).

### 2.2 Address & script model — "P2MR"

- **P2MR = "Pay to Merkle Root"** — a Taproot/BIP341-analogous, **post-quantum** script tree.
  The output is a **witness version 2** program committing to a 32-byte Merkle root over PQ
  script leaves.
- Output script: `OP_2 <32-byte merkle root>` → `TxoutType::WITNESS_V2_P2MR`.
- **Address encoding: bech32m, witness v2, 32-byte program.** Mainnet HRP is `btx`, so mainnet
  addresses render as **`btx1z…`** (the `z` bech32 character encodes witness version 2).
  Test networks: `tbtx` (testnet/signet), `tbtx4` (testnet4), `btxrt` (regtest).
- A single P2MR address can commit to **multiple leaves** (e.g. a primary multisig leaf plus a
  timelocked recovery leaf) — only the spent leaf is revealed, with a Merkle control block.
- Sources: `src/script/pqm.h`, `src/script/solver.cpp`, `src/key_io.cpp`,
  `src/kernel/chainparams.cpp`.

### 2.3 PQ opcodes used by multisig

| Opcode | Value | Meaning |
|---|---|---|
| `OP_CHECKSIG_MLDSA` | `0xbb` | Verify one ML-DSA signature |
| `OP_CHECKSIG_SLHDSA` | `0xbc` | Verify one SLH-DSA signature |
| `OP_CHECKSIGADD_MLDSA` | `0xbe` | Accumulate ML-DSA signatures (k-of-n) |
| `OP_CHECKSIGADD_SLHDSA` | `0xbf` | Accumulate SLH-DSA signatures (k-of-n) |
| `OP_CHECKSIGFROMSTACK` | `0xbd` | CSFS (oracle / delegation leaves) |
| `OP_CHECKTEMPLATEVERIFY` | `0xb3` | CTV covenant leaves |

All PQ opcodes are valid **only** under `SigVersion::P2MR`; used anywhere else they fail with
`SCRIPT_ERR_BAD_OPCODE`. Legacy `OP_CHECKMULTISIG` is **disabled** for P2MR — there is no
secp256k1 multisig on BTX. (Source: `src/script/script.h`, `src/script/interpreter.cpp`.)

---

## 3. How BTX multisig actually works

BTX multisig is an **on-chain script multisig**, structurally similar to Bitcoin's
Tapscript `CHECKSIGADD` multisig but with PQ signatures. It is *not* MPC and *not* a single
aggregated signature — each co-signer contributes an independent signature and the script
counts them.

**Leaf script (m-of-n):**

```
<pk1> OP_CHECKSIG_MLDSA <pk2> OP_CHECKSIGADD_MLDSA … <pkn> OP_CHECKSIGADD_MLDSA <m> OP_NUMEQUAL
```

- Each key may independently be ML-DSA or SLH-DSA (mix as you like).
- `CHECKSIGADD` semantics `(sig n pubkey -- n+success)`; an empty signature slot is skipped and
  charges no weight; `NULLFAIL` is enforced (a non-empty-but-invalid signature aborts).
- **Quorum cap: `MAX_PQ_PUBKEYS_PER_MULTISIG = 8`.** In practice ~7 ML-DSA keys fit under the
  10 KB per-leaf limit.
- Timelocked and covenant variants exist for recovery/governance leaves:
  `cltv_multi_pq` (absolute timelock), `csv_multi_pq` (relative timelock), `ctv_multi_pq`
  (CheckTemplateVerify).

**What this gives an exchange:** the same "no single key moves funds" guarantee as an MPC
quorum, but enforced by the BTX consensus rules rather than by an off-chain protocol, and with
each signer fully isolated (ideal for air-gapping). Sources:
`src/script/pqm.h` (`BuildP2MRMultisigScript`, timelock variants), `doc/btx-pq-multisig-spec.md`.

---

## 4. Descriptors — how you express a BTX wallet/vault

BTX uses **output descriptors** (descriptor wallets are mandatory; legacy wallets are
disabled). The post-quantum script function is **`mr(...)`**.

**Key expression forms inside `mr(...)`:**

| Form | Meaning |
|---|---|
| `<hex>` (bare) | ML-DSA-44 public key (1312-byte hex) |
| `pk_slh(<hex>)` | SLH-DSA-SHAKE-128s public key (32-byte hex) |
| `pqhd(<fingerprint or seed>/87h/<coin>h/<account>h/<chg>/*)` | PQ-native HD key provider (xpub-analog, HKDF-derived) |

**Leaf expressions inside `mr(...)`:**

| Descriptor leaf | Produces |
|---|---|
| `multi_pq(m, key1, key2, …)` | m-of-n PQ multisig (unsorted) |
| `sortedmulti_pq(m, …)` | m-of-n PQ multisig (BIP67-style sorted keys) |
| `cltv_multi_pq(locktime, m, …)` | absolute-timelocked multisig (recovery) |
| `csv_multi_pq(sequence, m, …)` | relative-timelocked multisig (recovery) |
| `ctv_multi_pq(hash, m, …)` | CTV-covenant multisig |
| `ctv(hash)` / `ctv_pk(hash, key)` | covenant / single-key covenant |
| `htlc(…)` / `csfs(…)` / `csfs_pk(…)` | HTLC / oracle / delegation leaves |
| `<key>` (bare in `mr`) | single-key P2MR |

**Example — a 2-of-3 ML-DSA multisig vault descriptor:**

```
mr(multi_pq(2,<mldsa_pk_A>,<mldsa_pk_B>,<mldsa_pk_C>))
```

**Example — 2-of-3 hot quorum with a 3-month single-key cold recovery leaf:**

```
mr({multi_pq(2,<pk_A>,<pk_B>,<pk_C>),cltv_multi_pq(<locktime>,1,<recovery_pk>)})
```

The `{…}` groups leaves into the Merkle tree; either quorum can spend, and only the used leaf
is revealed on-chain. HD (`pqhd`) keys let you derive ranged receive/change addresses exactly
as with `xpub` descriptors on Bitcoin. Sources: `src/script/descriptor.cpp` (`MRDescriptor`,
`ParsePQHD`), `doc/btx-pq-multisig-spec.md §5–6`.

---

## 5. RPC & PSBT integration surface

BTX inherits the Bitcoin Core RPC/PSBT model and extends it for PQ. The commands your
integration will use:

**Build the vault**
- `createmultisig <m> <keys> "p2mr"` — utility RPC, returns the P2MR **address + descriptor**
  (PQ-only; `address_type` must be `p2mr`). Accepts ML-DSA hex, SLH-DSA hex, or `pk_slh(hex)`.
- `addpqmultisigaddress` — BTX-specific; imports a PQ multisig into a descriptor wallet.
- `exportpqkey` — BTX-specific; deterministically export a multisig-ready PQ pubkey from a
  wallet address (use this to collect co-signer keys).
- `getdescriptorinfo` → adds a checksum; `deriveaddresses` → materialize addresses;
  `importdescriptors` → load into a wallet. `importdescriptors` on BTX accepts an optional PQ
  master-seed array for PQ-native descriptors.

**Wallets & addresses**
- `createwallet` — `descriptors=true` is required (legacy throws `LEGACY_WALLET_DISABLED_ERROR`);
  supports `disable_private_keys` + `blank` for **watch-only coordinators** and
  `external_signer=true` for hardware signers.
- `getnewaddress` / `getrawchangeaddress` — **`p2mr` only**.
- `getaddressinfo`, `listdescriptors`, `gethdkeys`.

**Sign & broadcast (PSBT flow)**
- `walletcreatefundedpsbt` — build + fund a spend (set an explicit high `fee_rate`, see §6).
- `walletprocesspsbt` — each signer adds its partial PQ signature.
- `combinepsbt` — merge partial signatures from all signers.
- `finalizepsbt` → `sendrawtransaction` — assemble and broadcast.
- Utilities: `createpsbt`, `joinpsbts`, `analyzepsbt`, `decodepsbt`, `converttopsbt`,
  `utxoupdatepsbt`, `signrawtransactionwithkey`.
- `decodescript` returns a `pq_multisig` object (`threshold`, `keys`, `algorithms`) for a P2MR
  multisig leaf — useful for deposit/withdrawal verification.

**PSBT PQ fields** (for anyone building a custom coordinator/signer):
- `PSBT_IN_P2MR_LEAF_SCRIPT = 0x19` — the selected leaf script + control block.
- `PSBT_IN_P2MR_PQ_SIG = 0x1B` — a partial PQ signature, keyed by `(leaf_hash || pubkey)`.
- Combine unions partial sigs by key; conflicting selected leaves are rejected; the updater
  normalizes `nLockTime`/`nSequence`/version to satisfy CLTV/CSV leaves.
- A signing/finalization flag **`slhdsa_fips205`** is threaded through the stack and is derived
  per-block by the wallet (`SlhdsaFips205ForNextBlock()`). It matters only if you sign with
  **SLH-DSA** keys near the FIPS-205 activation boundary; ML-DSA-only flows are unaffected.

Sources: `src/rpc/output_script.cpp`, `src/wallet/rpc/*`, `src/psbt.h`,
`src/external_signer.cpp`, `doc/btx-pq-multisig-tutorial.md`.

---

## 6. Capacity, fees & block-space planning

PQ signatures are **1–2 orders of magnitude larger** than ECDSA/Schnorr. This is the single
biggest operational surprise for a first-time integrator.

| Item | secp256k1 (BTC) | BTX ML-DSA-44 | BTX SLH-DSA-128s |
|---|---:|---:|---:|
| Public key | 33 B | 1312 B | 32 B |
| Single signature | ~64–72 B | 2420 B | 7856 B |
| 2-of-3 spend witness (approx) | ~0.2 KB | **~8.8 KB** | much larger |

Planning implications:

- **Set explicit, generous `fee_rate`** on every `walletcreatefundedpsbt` — automatic
  estimation can under-fund large PQ witnesses.
- **Consolidate UTXOs deliberately.** Many small deposits become expensive to sweep; run
  scheduled consolidation during low-fee windows (`sweeptoself` / `sendall`).
- **Prefer ML-DSA-44 for routine spends** (smaller than SLH-DSA); reserve SLH-DSA for keys
  where hash-based diversity is a deliberate requirement.
- **Validation-weight budget** (DoS accounting, not fees): ML-DSA checksig = 50, SLH-DSA
  checksig = 500, ML-DSA multisig-sigop = 500, SLH-DSA multisig-sigop = 5000. Very large
  quorums of SLH-DSA keys can hit these limits — model your worst-case spend.
- Limits: `MAX_PQ_PUBKEYS_PER_MULTISIG = 8`; per-leaf element/script caps in the ~10–11 KB
  range; stack byte cap 1,000,000. (One doc/code discrepancy to verify when you write your own
  spec: `MAX_P2MR_ELEMENT_SIZE = 10000` vs `MAX_P2MR_SCRIPT_SIZE = 11000` — the 10,000 value is
  the element cap.) Source: `src/script/script.h`, `doc/pq-benchmark-results.md`.

---

## 7. Reference integration: cold-vault 2-of-3, watch-only + air-gapped signers

This is the recommended launch topology for an exchange with no prior PQ tooling. It maps
directly to the role-separation model in `doc/btx-key-management-guide.md`.

**Roles (never colocate all on one host):**

| Role | Wallet | Holds keys? |
|---|---|---|
| Coordinator | watch-only (`disable_private_keys`, `blank`) | No — public descriptors only |
| Signer A / B / C | offline / air-gapped or external-signer wallets | Yes — one PQ key each |
| Recovery holder | offline cold backup of recovery leaf key | Yes — recovery only |
| Auditor | view-only | No |

**One-time setup**

1. On each **offline signer**, create a descriptor wallet and export its multisig pubkey:
   ```
   btx-cli -named createwallet wallet_name=signerA descriptors=true
   btx-cli -rpcwallet=signerA getnewaddress "" p2mr
   btx-cli -rpcwallet=signerA exportpqkey "<address>"      # -> ML-DSA pubkey hex
   ```
2. Collect the three pubkeys and build the vault descriptor on the coordinator:
   ```
   btx-cli createmultisig 2 '["<pkA>","<pkB>","<pkC>"]' p2mr
   # returns { "address": "btx1z…", "descriptor": "mr(multi_pq(2,…))#checksum" }
   ```
3. Import the **public** descriptor into the watch-only coordinator:
   ```
   btx-cli -rpcwallet=coordinator importdescriptors \
     '[{"desc":"mr(multi_pq(2,…))#cs","active":true,"timestamp":"now","internal":false},
       {"desc":"…change…","active":true,"timestamp":"now","internal":true}]'
   ```
4. Generate deposit addresses on the coordinator with `getnewaddress "" p2mr`.

**Withdrawal (spend) flow**

1. Coordinator: `walletcreatefundedpsbt … {"fee_rate": <high>}` → base PSBT.
2. Move PSBT to **Signer A** (air-gap/QR/file): `walletprocesspsbt` → partially signed PSBT.
3. Repeat for **Signer B** (2-of-3 quorum reached).
4. Coordinator: `combinepsbt` → `finalizepsbt` → `sendrawtransaction`.

A full worked 2-of-3 example, including native timelocked-recovery descriptor imports, is in
`doc/btx-pq-multisig-tutorial.md`. Air-gap specifics are in `doc/offline-signing-tutorial.md`
(note its banner: use P2MR descriptor wallets + watch-only coordinator, not the upstream
`wpkh` examples).

---

## 8. Key management, backups & recovery

- **HD derivation path:** `m/87h/<coin_type>h/<account>h/<change>/<index>` (purpose `87h`). PQ
  seeds are 32 bytes; keys are HKDF-derived. Secret keys live in secure/zeroizing allocators.
- **Two backup formats — treat them very differently:**
  - **`.bundle.btx`** — the *preferred* native backup: an **encrypted** archive with an
    integrity manifest (`backupwalletbundlearchive` / `restorewalletbundlearchive`, supports
    `-stdinbundlepassphrase`).
  - **`.btxwallet`** — a **plaintext** JSON bundle containing the raw 32-byte PQ master seed
    plus public descriptors (`exportwalletbundle` / `importwalletbundle` /
    `restorewalletbundle`). It exists for browser↔node interop. **Handle it exactly like a
    private key** — plaintext seed = full spend authority.
- **Recovery leaves:** encode a timelocked recovery quorum (`cltv_multi_pq` / `csv_multi_pq`)
  in the same P2MR address so funds are recoverable if a hot signer is lost, without weakening
  the primary quorum.
- **External/hardware signers:** compile with `ENABLE_EXTERNAL_SIGNER`; use `enumeratesigners`
  and `walletdisplayaddress`. Note most third-party HSMs do **not** yet expose ML-DSA/SLH-DSA —
  confirm PQ support with your vendor before assuming HSM custody, and record any gap as
  residual exposure.
- Source of truth: `doc/btx-key-management-guide.md`, `doc/btxwallet-browser-node-interop.md`.

---

## 9. Custody CBOM & operational readiness (regulatory framework §9–§10)

Under the *BTX Reference Asset Framework*, BTX is the **ACP-Q3 reference profile** — the
"Bitcoin-equivalent post-quantum digital commodity" whose ordinary transfer authority is
NIST-standard PQC. To onboard it as a regulated custodian/exchange you produce a **custody
CBOM** and pass an **operational test suite**. Neither is optional in a supervised context.

**Custody CBOM (machine-readable) must inventory, at minimum:**

| Category | For BTX, record… |
|---|---|
| Cryptographic algorithms | ML-DSA-44 (FIPS 204), SLH-DSA-SHAKE-128s (FIPS 205); parameter sets; claimed evidence level (spec-conformance vs ACVP/CAVP vs CMVP) |
| Keys & signatures | HD path `m/87h/…`, generation, public-key exposure state, rotation, backup, destruction |
| Consensus/protocol | P2MR (witness v2), `fEnforceP2MROnlyOutputs`, `SCRIPT_VERIFY_REJECT_LEGACY_SIGS`, address format, replay/downgrade controls |
| Custody systems | signer wallets, external signers, quorum/approval policy, recovery + wind-down workflow |
| Libraries & modules | `libbitcoinpqc` version/commit, build options, validation certificate **where claimed** |
| Transport & APIs | node RPC auth, coordinator↔signer channel, monitoring |
| Residual exposure | any ECDSA/EdDSA/MPC dependency still able to move value; unsupported wallets; bridge/wrapper keys |

**Required operational tests (execution evidence, not policy text):**
`withdrawal` · `sweep` · `recovery` (lost signer / unavailable participant / disaster) ·
`wind-down` (transfer all customer assets to customers or a successor) · `freeze-release` ·
`customer-notice`. Each must reconcile the customer sub-ledger, on-chain balances, and approval
logs.

**Customer-asset segregation** must be both legal *and* cryptographic: separate key material,
quorums, and approval roles for customer vs house vs test assets; a single key path that can
move both customer and proprietary value is a **critical finding**.

**Evidence-level discipline (important for disclosures):** distinguish (a) *specification
conformance* — "implements FIPS 204/205"; (b) *algorithm validation* — ACVP/CAVP evidence for
the exact build; and (c) *module validation* — CMVP / FIPS 140-3 certificate for a defined
module boundary. Do **not** market "quantum-safe" or "NIST-certified" beyond the evidence you
actually hold.

---

## 10. Exchange / market-operator obligations (framework §11)

Listing and trading BTX (or any covered asset) triggers a **market-operator control file** and
an **admission review** before spot listing, collateral acceptance, or product exposure:

- **Market-operator control file:** ACP record + claim boundary, transfer-authority map, custody
  & settlement test results, fork/replay playbook, oracle/index dependency map, margin &
  collateral treatment, halt/delisting triggers, quarterly reporting.
- **Admission gates:** ACP classification, transfer-authority (no unmitigated quantum-vulnerable
  path), custody readiness (deposit/withdrawal/sweep/recovery/wind-down proven), market quality,
  fork & replay controls, oracle/index integrity, margin/collateral policy, disclosure accuracy.
- **Halt / suspension / delisting triggers** must be objective and pre-written, including: ACP
  downgrade, credible CRQC or signature-forgery event, discovery of a legacy/nonconforming
  transfer path, custodian transfer failure, fork/replay instability, oracle disruption.
- **Fork & replay controls** for BTX-style assets center on: does the active chain preserve
  production P2MR (post-quantum) transfer authority and reject nonconforming paths? Quarantine
  deposits and test replay before resuming after any migration/fork.
- **Margin/collateral by ACP:** an ACP-Q3 asset (BTX with passing custody/oracle/liquidation
  controls) is eligible for base-haircut collateral treatment; lower ACP classes carry add-ons,
  concentration caps, or ineligibility.

---

## 11. Test vectors to request/produce (framework §9.4)

For your own certification file and for any regulator/auditor, assemble signed vector manifests
covering at least:

- **V1 ML-DSA / V2 SLH-DSA:** KeyGen, sigGen, sigVer, malformed signature, malformed pubkey,
  wrong message, wrong context, boundary-size vectors (FIPS-205 activation behavior for SLH-DSA).
- **V4 Address & commitment:** P2MR address encoding, Merkle commitment, wrong-commitment
  rejection.
- **V5 Transaction & custody workflow:** sighash preimage, PSBT fields, multi-input/multi-output,
  fee/size boundaries.
- **V6 Block & consensus:** valid P2MR block, **rejected** non-P2MR standard-transfer output,
  **rejected** legacy-signature path, activation/reorg boundaries.
- **V7 Negative & downgrade:** replay, cross-network replay, wrong chain id, unsupported
  algorithm, legacy-signature fallback, parser-confusion.
- **V8 Wallet & custody:** address generation, deposit, withdrawal, sweep, recovery, rotation,
  external-signer signing, wind-down.
- **V9 Interoperability:** explorer, exchange, custodian, indexer, node-RPC parsing/verification
  consistency.

BTX ships functional tests you can lean on directly: `test/functional/feature_p2mr_end_to_end.py`,
`feature_pq_multisig.py`, `rpc_pq_multisig.py`, `rpc_createmultisig.py`,
`feature_btx_pq_wallet_enforcement.py`.

---

## 12. Integration checklist

**Engineering**
- [ ] Build/run `btxd` + `btx-cli`; confirm you can reach a synced node (mainnet HRP `btx`).
- [ ] Confirm your indexer/deposit-detector parses **witness-v2 P2MR** addresses and `mr(...)`
      descriptors; verify `decodescript` `pq_multisig` output.
- [ ] Stand up a **watch-only coordinator** and ≥2 **offline PQ signers**; complete a 2-of-3
      PSBT withdrawal on testnet (`tbtx`).
- [ ] Set explicit high `fee_rate` in withdrawal construction; validate against ~8.8 KB witness
      sizing; implement UTXO consolidation.
- [ ] Implement backups: encrypted `.bundle.btx` for native custody; treat `.btxwallet` as key
      material; test `restorewalletbundlearchive`.
- [ ] Add a timelocked recovery leaf and rehearse recovery + wind-down.

**Compliance / custody**
- [ ] Produce the custody **CBOM** (Section 9) and fix the claim boundary.
- [ ] Run and log the operational test suite (withdrawal/sweep/recovery/wind-down/freeze-release/
      customer-notice).
- [ ] Document customer-asset segregation (legal + cryptographic).
- [ ] Record **residual exposure** — including the fact that ML-DSA/SLH-DSA are **not**
      MPC/TSS-signable today, and any HSM PQ gaps.
- [ ] Classify BTX as **ACP-Q3** with claim boundary + evidence date; align ETP/collateral/
      listing disclosures to the evidence level actually held.
- [ ] Stand up the market-operator control file, halt/delisting triggers, and fork/replay
      playbook before listing.

---

## 13. Document map (BTX repo)

| Need | Read |
|---|---|
| Custody source-of-truth (roles, boundaries, backups) | `doc/btx-key-management-guide.md` |
| Multisig normative spec (opcodes, leaves, PSBT fields, limits) | `doc/btx-pq-multisig-spec.md` |
| Multisig worked example (`btx-cli` commands) | `doc/btx-pq-multisig-tutorial.md` |
| PQ script/crypto profile | `doc/btx-pqc-spec.md` |
| Air-gapped signing | `doc/offline-signing-tutorial.md` |
| Wallet management | `doc/managing-wallets.md` |
| Hardware/external signers | `doc/external-signer.md` |
| PSBT roles/workflow | `doc/psbt.md` |
| Descriptor reference | `doc/descriptors.md` |
| Browser↔node bundle interop | `doc/btxwallet-browser-node-interop.md` |
| PQ performance/size benchmarks | `doc/pq-benchmark-results.md` |

---

*Prepared as an onboarding reference for exchanges integrating BTX post-quantum custody. This
guide is technical and operational; it is not legal advice and does not constitute a regulatory
approval. Classify against the BTX Reference Asset Framework using your own evidence record and
counsel.*
