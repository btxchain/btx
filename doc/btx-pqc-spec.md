# BTX Post-Quantum Script Profile

This document defines the BTX post-quantum script profile used by witness v2
P2MR outputs.

## 1. Algorithms

- Active primary signature algorithm: ML-DSA-44
  - Public key: 1312 bytes
  - Secret key: 2560 bytes
  - Signature: 2420 bytes
- Active backup signature algorithm: SLH-DSA-SHAKE-128s
  - Public key: 32 bytes
  - Secret key: 64 bytes
  - Signature: 7856 bytes
- Reserved future path: Falcon-512
  - Not consensus-enabled, relay-standard, wallet-exposed, or signer-exposed yet
  - P2MR soft-fork opcode slots are reserved now so Falcon activation can be
    added later without another hard fork

## 2. Output and Address Format

- Output script type: `witness_v2_p2mr`
- Script form: `OP_2 <32-byte-merkle-root>`
- Mainnet address prefix: `btx1z...` (Bech32m witness v2)

## 3. Leaf Scripts

- ML-DSA leaf:
  - `<1312-byte-pubkey> OP_CHECKSIG_MLDSA`
- SLH-DSA leaf:
  - `<32-byte-pubkey> OP_CHECKSIG_SLHDSA`
- Multisig leaf (m-of-n):
  - `<pk1> OP_CHECKSIG_{algo1} <pk2> OP_CHECKSIGADD_{algo2} ... <pkn> OP_CHECKSIGADD_{algon} <m> OP_NUMEQUAL`
  - `algo` is per-key and may mix ML-DSA and SLH-DSA.
- CLTV multisig leaf:
  - `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <multisig-leaf>`
- CSV multisig leaf:
  - `<sequence> OP_CHECKSEQUENCEVERIFY OP_DROP <multisig-leaf>`
- CTV multisig leaf:
  - `<32-byte-template-hash> OP_CHECKTEMPLATEVERIFY OP_DROP <multisig-leaf>`

Control blocks carry:
- 1-byte leaf version (`0xc2` masked with `0xfe`)
- Zero or more 32-byte sibling hashes

## 4. Merkle Commitments

- Leaf hash: `P2MRLeaf(leaf_version || script)`
- Branch hash: `P2MRBranch(sort(h1, h2))`
- Witness program is the 32-byte Merkle root.

## 5. Sighash

- P2MR uses the BIP341-style digest structure with a distinct epoch byte
  for witness v2 script execution.
- The signed message is a 32-byte digest over transaction context and leaf
  commitment context.

## 6. Opcode Semantics

- `OP_CHECKSIG_MLDSA`:
  - Pops signature and ML-DSA-44 public key.
  - Verifies against P2MR sighash digest.
- `OP_CHECKSIG_SLHDSA`:
  - Pops signature and SLH-DSA public key.
  - Verifies against P2MR sighash digest.
- `OP_CHECKSIGADD_MLDSA`:
  - Stack: `(sig n pubkey -- n+success)` for ML-DSA keys.
  - Empty signature keeps `n` unchanged and does not charge validation weight.
- `OP_CHECKSIGADD_SLHDSA`:
  - Stack: `(sig n pubkey -- n+success)` for SLH-DSA keys.
  - Empty signature keeps `n` unchanged and does not charge validation weight.
- Reserved future Falcon opcodes:
  - `OP_CHECKSIG_FALCON`
  - `OP_CHECKSIGADD_FALCON`
  - `OP_CHECKSIGFROMSTACK_FALCON`
  - These remain P2MR `OP_SUCCESS` slots today and are intentionally
    non-standard under policy until a later activation defines real Falcon
    semantics.

Invalid signatures and malformed pubkey sizes map to dedicated script errors.

## 7. Descriptor and HD Profile

- Descriptor root: `mr(...)`
- Optional backup leaf: `pk_slh(...)`
- Multisig leaves:
  - `mr(multi_pq(m,key1,key2,...))`
  - `mr(sortedmulti_pq(m,key1,key2,...))`
  - `mr(ctv_multi_pq(ctv_hash,m,key1,key2,...))`
  - `mr(ctv_sortedmulti_pq(ctv_hash,m,key1,key2,...))`
  - `mr(cltv_multi_pq(locktime,m,key1,key2,...))`
  - `mr(cltv_sortedmulti_pq(locktime,m,key1,key2,...))`
  - `mr(csv_multi_pq(sequence,m,key1,key2,...))`
  - `mr(csv_sortedmulti_pq(sequence,m,key1,key2,...))`
- BTX wallet derivation path uses purpose `87h` for P2MR descriptors.

## 8. PSBT Profile

- Selected P2MR leaf script and control block are carried in input metadata.
- Partial PQ script signatures are keyed by `(leaf_hash, pubkey)`.
- Combine/finalize merges signer-contributed partial signatures and finalizes only
  when threshold is met for the selected multisig leaf.
- Descriptor-wallet updater/signer flows normalize `nLockTime`, `nSequence`, and
  transaction version for selected CLTV/CSV leaves before signing unsigned PSBTs.
- Finalization rejects selected CLTV/CSV leaves when the transaction fields do not
  actually satisfy the committed timelock.

## 9. Policy and Limits

- `MAX_PQ_PUBKEYS_PER_MULTISIG = 8`.
- Multisig leaves may use up to `MAX_P2MR_SCRIPT_SIZE` (11,000 bytes).
- Validation weight costs:
  - ML-DSA checksig: 50
  - SLH-DSA checksig: 500
  - ML-DSA checksigadd: 500
  - SLH-DSA checksigadd: 5000
- Standardness requires valid threshold, key count, and witness stack shape.

## 10. Constant-Time Requirements

- Secret key buffers must be zeroized on clear/destruction.
- Sensitive comparisons use constant-time primitives.
- Signature and verification timing should not depend on secret key material.


## 11. Miniscript Profile (P2MR Context)

- `MiniscriptContext::P2MR` is supported for PQ leaves.
- PQ fragments include:
  - `pk_mldsa(KEY)`
  - `pk_slhdsa(KEY)`
  - `multi_mldsa(k, KEY, KEY, ...)`
  - `multi_slhdsa(k, KEY, KEY, ...)`
- Context gating rejects these PQ fragments in non-P2MR contexts.

## 12. Forward-Compatibility Rules

- P2MR supports `OP_SUCCESS`-style upgrade behavior through P2MR-specific checks.
- Defined PQ opcodes are explicitly excluded from unconditional success handling.
- Reserved Falcon slots are intentionally *not* excluded from `OP_SUCCESS`
  handling yet, preserving a clean soft-fork activation surface.
- P2MR annex data is parsed at consensus and remains non-standard under relay
  policy by default.

## 13. External Signer and Hardware Integration

- External signer capability signaling includes P2MR/PQ support metadata.
- P2MR PSBT metadata (leaf script, control data, derivation info, merkle root,
  and PQ signatures) is validated before signing.
- Returned signatures are validated against expected algorithm-specific sizes.
- Deterministic PQ derivation is available for signer workflows under purpose
  path family `m/87h/...`.

## 14. HTLC and Atomic-Swap Templates

- P2MR template builders support two-leaf HTLC/refund flows and CTV-assisted
  atomic-swap leaf construction.
- HTLC construction uses separate Merkle leaves for success-path and refund-path
  semantics instead of `OP_IF/OP_ELSE` branching.
- Descriptor integration supports assembling these leaves into `mr(...)` trees.

## 15. Operational References

- Detailed multisig semantics: `doc/btx-pq-multisig-spec.md`
- End-to-end operator flow: `doc/btx-pq-multisig-tutorial.md`
- Validation/test evidence tracker: `doc/pq-multisig-full-implementation-tracker.md`
- Falcon readiness and activation roadmap: `doc/falcon-softfork-readiness-analysis-2026-03-29.md`
