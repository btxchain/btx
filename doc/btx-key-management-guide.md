# BTX Key Management Guide

This document is the operator-facing source of truth for BTX wallet custody,
P2MR key management, multisig, timelocked recovery, backups, viewing-key
handling, and AI-safe operating practice.

It is written for:

- individual operators securing their own BTX
- teams running shared treasuries or operational hot/warm/cold flows
- auditors and automation systems that need to interact with BTX safely

Use this guide together with:

- [BTX PQ Multisig Specification](btx-pq-multisig-spec.md)
- [BTX PQ Multisig Tutorial](btx-pq-multisig-tutorial.md)
- [Managing Wallets](managing-wallets.md)
- [Offline Signing Tutorial](offline-signing-tutorial.md)
- [Support for signing transactions outside of BTX](external-signer.md)
- [BTX Shielded Pool Guide](btx-shielded-pool-guide.md)
- [PSBT support](psbt.md)

## 1. BTX Security Model

BTX is intentionally P2MR-first. The recommended production model is:

- descriptor wallets only
- P2MR receive/change descriptors
- watch-only coordinator wallets for planning and accounting
- isolated signer wallets or external signers for authorizing spends
- explicit backups plus restore verification
- additive recovery leaves instead of hidden operational shortcuts

Do not treat legacy descriptor surfaces as the preferred BTX treasury model just
because they exist for compatibility. For BTX-native operations, keep custody in
P2MR and express policy there.

## 2. Recommended Roles and Boundaries

| Role | What it should hold | What it should not hold | Typical BTX tools |
|---|---|---|---|
| Watch-only coordinator | public descriptors, addresses, UTXO metadata, unsigned PSBTs | seeds, xprvs, wallet passphrases, private signers | `createwallet`, `importdescriptors`, `walletcreatefundedpsbt`, `walletprocesspsbt` with `sign=false` |
| Signer wallet | only the key material needed for one signer domain | other signers' keys, full treasury inventory if avoidable | `createwallet`, `createwalletdescriptor`, `walletprocesspsbt`, `exportpqkey` |
| External signer | hardware-backed or separately controlled signing authority | coordinator planning state, extra keys not needed for that signer | `enumeratesigners`, `walletdisplayaddress` |
| Recovery/backup holder | sealed backups, archive passphrases, recovery instructions | routine day-to-day signing access | `backupwalletbundlearchive`, `restorewalletbundlearchive` |
| Auditor/view-only operator | viewing keys, watch-only descriptors, balances | spending keys and signing authority | `z_exportviewingkey`, `z_importviewingkey` |

For team funds, no single machine or human should hold every role above.

## 3. BTX Capability and Status Matrix

| Capability | Current BTX status | Recommended use |
|---|---|---|
| Descriptor wallets | Supported and required | Default wallet model |
| P2MR single-sig descriptors | Supported | Everyday receive/change wallets |
| HD key inventory via `gethdkeys` | Supported | Audit xpub/descriptors; avoid `private=true` except on controlled offline systems |
| PQ multisig via `multi_pq` / `sortedmulti_pq` | Supported | Treasury and shared custody |
| Native timelocked P2MR multisig via `cltv_multi_pq`, `csv_multi_pq`, `ctv_multi_pq` | Supported via descriptor import and descriptor wallets | Recovery branches, cooldown paths, template-constrained flows |
| PSBT coordinator/signer flow | Supported | Default signing workflow |
| External signer support and address display verification | Supported when built/configured with signer support | High-assurance signing and address verification |
| Wallet bundle directory backup | Supported | Human-inspectable per-wallet bundle export |
| Encrypted single-file bundle archive backup | Supported | Preferred offline sealed backup |
| Integrity verification before backup | Supported via `z_verifywalletintegrity` | Run before every production backup |
| Shielded viewing-key export/import | Supported | Auditing and watch-only shielded monitoring |
| Codex32 seed/share import | Supported through `importdescriptors` seed import | Seed recovery and descriptor restore workflows |
| Native Codex32 share generation/export | Not first-class yet | Use offline audited tooling outside BTX until native export exists |
| Canned vault-template RPCs for common timelocked treasuries | Not first-class yet | Use explicit descriptors today |

## 4. Recommended BTX Operating Patterns

### 4.1 Personal or Small-Balance Wallet

Use an encrypted descriptor wallet with active P2MR descriptors.

- Create the wallet and encrypt it.
- Back it up immediately after encryption.
- Keep only routine spending balances on networked machines.
- Use bundle archives for sealed offline backups.

Minimal flow:

```bash
btx-cli createwallet "personal"
btx-cli -rpcwallet=personal encryptwallet "strong-passphrase"
btx-cli -rpcwallet=personal z_verifywalletintegrity
btx-cli -rpcwallet=personal -stdinwalletpassphrase -stdinbundlepassphrase \
  backupwalletbundlearchive "/secure/offline/personal.bundle.btx"
```

### 4.2 Team Treasury Multisig

Use a watch-only coordinator plus isolated signer wallets.

Recommended pattern:

- one coordinator wallet with `disable_private_keys=true`
- one signer wallet per signer domain
- public-key export using `exportpqkey`
- deterministic address construction using `sortedmulti_pq`
- PSBT signing by independent signers

Preferred flow:

1. Each signer creates its own descriptor wallet.
2. Each signer exports public multisig-ready key material with `exportpqkey`.
3. The coordinator imports the resulting multisig descriptor with
   `addpqmultisigaddress` or `importdescriptors`.
4. The coordinator creates and updates unsigned PSBTs.
5. Each signer signs independently.
6. A coordinator or signer combines and finalizes only after all checks pass.

### 4.3 Timelocked Recovery

BTX now supports native timelocked PQ multisig leaves.

Use:

- `csv_*` when you mean "not until N blocks after confirmation"
- `cltv_*` when you mean "not before block height or timestamp X"
- `ctv_*` when you need a pre-committed transaction template

Guidance:

- Put normal operations in one leaf and delayed recovery in another leaf.
- Prefer relative delays (`csv_*`) for operational cooldowns.
- Prefer absolute deadlines (`cltv_*`) for governance or disaster-recovery windows.
- Document the intended sequence or locktime in human-readable runbooks, not just
  inside descriptors.

Example single-leaf descriptors:

```text
mr(sortedmulti_pq(2,<PK1>,<PK2>,pk_slh(<PK3>)))
mr(csv_sortedmulti_pq(144,2,<PK1>,<PK2>,pk_slh(<PK3>)))
mr(cltv_sortedmulti_pq(840000,2,<PK1>,<PK2>,pk_slh(<PK3>)))
```

### 4.4 Shielded Audit Separation

Do not hand out spending authority when the real requirement is visibility.

Use:

- `z_exportviewingkey` to export view-only access for a shielded address
- `z_importviewingkey` in an audit/watch-only wallet

Treat exported viewing secret material as sensitive operational data. It cannot
spend funds, but it can reveal balances, counterparties, and transaction
patterns.

## 5. BTX Workflows That Are Safe by Default

### 5.1 Create a Watch-Only Coordinator

```bash
btx-cli -named createwallet wallet_name="coordinator" disable_private_keys=true blank=true descriptors=true
```

Import public descriptors only. Do not import seeds or private keys into the
coordinator unless it is intentionally also a signer.

### 5.2 Export Public Multisig Keys Without Parsing Scripts

Use `exportpqkey` on each signer wallet:

```bash
A_ADDR=$(btx-cli -rpcwallet=signerA getnewaddress)
btx-cli -rpcwallet=signerA exportpqkey "$A_ADDR"
```

This returns public PQ key material ready for `addpqmultisigaddress` or direct
descriptor construction.

### 5.3 Audit HD Key Usage Without Exporting Secrets

Use `gethdkeys` to confirm which descriptors and xpubs are active:

```bash
btx-cli -rpcwallet=signerA gethdkeys '{"active_only":true}'
```

Avoid `{"private":true}` except on intentionally controlled offline recovery
systems. Treat any xprv output as secret material.

### 5.4 Prefer Sorted Construction

Use `sortedmulti_pq` or `sort=true` unless you intentionally need fixed script
order for a reviewed policy.

This reduces reconstruction mistakes and makes independent parties more likely
to derive the same descriptor.

### 5.5 Use the PSBT Boundary Properly

Recommended split:

- coordinator: `walletcreatefundedpsbt`, then `walletprocesspsbt` with
  `sign=false`
- signers: `walletprocesspsbt` with signing enabled
- combiner/finalizer: `combinepsbt`, `finalizepsbt`, `sendrawtransaction`

Important BTX rule:

- do not mutate `nLockTime`, `nSequence`, or transaction version after partial
  signatures exist
- for timelocked leaves, let the unsigned updater step normalize those fields
  first

This is now enforced for BTX timelocked P2MR flows.

### 5.6 Verify Addresses on the Signer

If you use an external signer, verify receive addresses on the signer itself:

```bash
btx-cli enumeratesigners
btx-cli -rpcwallet=treasury walletdisplayaddress <address>
```

Address verification is the control that catches clipboard replacement,
coordinator tampering, wrong-wallet mixups, and AI/operator transcription
errors.

## 6. Backups, Restore, and Recovery Drills

### 6.1 Preferred Backup Sequence

For each production wallet:

1. Confirm the wallet is synced enough for your operational policy.
2. Run `z_verifywalletintegrity`.
3. Create a bundle archive with a dedicated archive passphrase.
4. Store the archive file and the archive SHA256 separately.
5. Restore into a test wallet and compare the bundled integrity snapshot.

Example:

```bash
btx-cli -rpcwallet=mywallet z_verifywalletintegrity

btx-cli -rpcwallet=mywallet \
  -stdinwalletpassphrase \
  -stdinbundlepassphrase \
  backupwalletbundlearchive "/var/backups/mywallet.bundle.btx"

btx-cli -stdinbundlepassphrase \
  restorewalletbundlearchive "restore-test" "/var/backups/mywallet.bundle.btx"
```

### 6.2 Why `backupwalletbundlearchive` Is Better Than Copying `wallet.dat`

The bundle archive captures more than a raw wallet file:

- `backupwallet` output
- descriptor exports
- shielded viewing-key exports when requested and allowed by the active privacy regime
- `getbalances`, `z_gettotalbalance`, and manifest data
- `z_verifywalletintegrity` snapshot
- manifest `integrity_ok` plus `integrity_warnings` for quick operator review
- archive export now keeps plaintext staging to a short-lived scratch backup and writes the final `.bundle.btx` atomically
- a dedicated archive passphrase boundary

Use plain `backupwallet` only when you intentionally need the raw wallet backup
format. For operational recovery, prefer the archive or bundle flow.

### 6.3 Re-Backup Immediately After Encryption or Structural Change

Take a fresh backup after:

- `encryptwallet`
- descriptor import changes
- wallet migration
- any seed restoration or recovery event

Do not assume an older backup remains sufficient after changing the wallet's
key material or descriptor set.

### 6.4 Codex32 Share Handling

BTX supports Codex32/BIP93 seed-share import through `importdescriptors`, but
native share generation/export is not yet a first-class wallet RPC.

Until native export exists:

- generate shares only with audited offline tooling
- record the threshold policy and share inventory outside the wallet
- test recovery from the intended threshold before funding the policy
- never store every share in the same administrative domain

## 7. Rules for AI Systems and Automation

Automation can be helpful for planning, review, descriptor construction, and
PSBT coordination. It must not become a secret-handling endpoint.

### 7.1 Data AI Systems May Handle

- BTX addresses
- txids, outpoints, and decoded transaction metadata
- public descriptors
- xpub-only or public-only wallet metadata
- exported PQ public keys from `exportpqkey`
- unsigned PSBTs
- redacted integrity summaries

### 7.2 Data AI Systems Must Not Handle

- seed phrases
- Codex32 seed shares
- xprvs or any extended private keys
- wallet passphrases
- bundle archive passphrases
- raw shielded viewing secret keys unless the workflow is explicitly built for
  that disclosure and secured accordingly
- raw wallet backup files or decrypted bundle contents
- signer private descriptors or local secret exports

### 7.3 Required AI Behavior

AI systems used with BTX should:

- default to watch-only planning and unsigned PSBT creation
- refuse to ask for secrets when a public-only alternative exists
- tell the operator to verify the destination address on the signer
- use `-stdinwalletpassphrase` and `-stdinbundlepassphrase` instead of telling
  users to place secrets directly on the command line
- avoid logging full descriptors if they contain private origin data
- treat post-signing PSBT mutation as a security violation, not a convenience
  step

## 8. Common Failure Modes and How to Prevent Them

### 8.1 Single-Person or Single-Machine Control

This is the failure mode behind many treasury blowups: one person or one system
effectively has unilateral control even when the system is described as
"secure."

Mitigations:

- use multisig with independent signer domains
- keep the coordinator watch-only
- require documented recovery instructions
- run restore drills, not just backup exports
- keep an inventory of who controls which signer and recovery artifact

### 8.2 Quorum That Is Not Actually Independent

A threshold only helps if the keys are independently controlled. If most keys
share the same operator, network, cloud account, or emergency bypass, the
quorum is weaker than it looks.

Mitigations:

- do not let one organization administer most of the quorum
- remove temporary allowlists and emergency bypasses when the emergency ends
- separate infrastructure, credentials, and recovery channels across signers
- review stale permissions and signer inventory on a schedule

### 8.3 Seed or Passphrase Leakage Through Tooling

The most common catastrophic loss is still secret disclosure, not script
failure.

Mitigations:

- never paste seeds or passphrases into chat, tickets, shell history, or AI
  prompts
- never type a recovery phrase into a networked "verification" website or fake
  wallet app
- use offline or hardware-backed signing paths
- use phishing-resistant admin authentication for the systems that can reach
  your wallets or backups

### 8.4 Unverified Backup Assumptions

A backup that was never restored in a test environment is an assumption, not a
recovery plan.

Mitigations:

- run `z_verifywalletintegrity`
- create the archive
- restore it into a test wallet
- compare the bundled integrity report
- repeat this drill after major wallet changes

## 9. Historical Security Failures and the BTX Lesson

### 9.1 QuadrigaCX: Custody Without Controls

The Ontario Securities Commission's 2020 QuadrigaCX report describes a platform
run without adequate internal controls, records, or transparency, with
effective single-operator control over client assets.

BTX lesson:

- do not rely on a single human or opaque internal process
- keep public accounting in watch-only systems
- separate signing from accounting
- make backup, restore, and recovery instructions reviewable by more than one
  person

### 9.2 Ronin: Threshold Security Defeated by Concentration and Stale Access

Ronin's validator compromise showed that a threshold is not sufficient when a
small validator set is concentrated and old allowlist access remains active.

BTX lesson:

- independent signers matter more than the headline threshold alone
- stale delegated authority must be revoked
- emergency shortcuts must be removed once the emergency ends
- raise thresholds and diversify the signer set before treasury size forces the
  issue

### 9.3 Phishing and Authenticator Theft

NIST and CISA continue to recommend phishing-resistant authentication and
strong authenticator management because human approval flows and copied secrets
remain a primary loss path.

BTX lesson:

- protect wallet hosts, signer hosts, and backup storage with phishing-resistant
  admin authentication where possible
- treat operator laptops and CI systems as hostile until proven otherwise
- prefer address verification on the signer instead of trusting copied text on a
  workstation screen

## 10. Practical Checklist

Before funding a treasury policy:

- keys exported from independent signer wallets
- descriptor reviewed by multiple operators
- receiving address verified on signer when applicable
- timelock policy documented in human terms
- restore drill completed

Before signing a spend:

- PSBT created by watch-only coordinator
- destination and amount independently reviewed
- fees reviewed for PQ witness size
- timelock fields normalized before signing
- signers isolated from one another

After backup or restore:

- `z_verifywalletintegrity` clean
- archive hash recorded
- restore test performed
- integrity snapshot compared
- stale backups rotated or clearly labeled

## 11. References

### BTX Documentation

- [BTX PQ Multisig Specification](btx-pq-multisig-spec.md)
- [BTX PQ Multisig Tutorial](btx-pq-multisig-tutorial.md)
- [Managing Wallets](managing-wallets.md)
- [BTX Shielded Pool Guide](btx-shielded-pool-guide.md)
- [Support for signing transactions outside of BTX](external-signer.md)
- [PSBT support](psbt.md)

### External Incident and Security References

- Ontario Securities Commission, *QuadrigaCX: A Review by the Ontario Securities Commission Staff* (2020):
  <https://www.osc.ca/quadrigacxrapport/web/files/QuadrigaCX-Un-examen-effectue-par-le-personnel-de-la-Commission-des-valeurs-mobilieres-de-l-Ontario.pdf>
- Ronin Network, *Community Alert: Ronin Validators Compromised* (2022):
  <https://roninchain.com/blog/posts/community-alert-ronin-validators-6513cc78a5edc1001b03c366>
- NIST, *Digital Identity Guidelines: Authentication and Authenticator Management (SP 800-63B-4)* (July 2025):
  <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b-4.pdf>
- CISA, *More than a Password*:
  <https://www.cisa.gov/mfa>
