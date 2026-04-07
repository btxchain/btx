# BTX PQ Multisig Specification

This document specifies post-quantum multisignature spending for witness v2 P2MR
outputs in BTX.

For operator guidance on signer isolation, watch-only coordinators, timelocked
recovery patterns, backups, restore drills, and AI-safe handling of BTX
artifacts, see the [BTX Key Management Guide](btx-key-management-guide.md).

## 1. Scope

This spec defines:
- New P2MR-only opcodes for signature accumulation.
- Multisig leaf script templates.
- Descriptor grammar for multisig leaves.
- PSBT fields and finalization behavior.
- Standardness and sizing limits.

Legacy `OP_CHECKMULTISIG` remains disabled for P2MR.

## 2. New Opcodes

| Opcode | Value | Meaning | SigVersion |
|---|---|---|---|
| `OP_CHECKSIGADD_MLDSA` | `0xbe` | Accumulate one ML-DSA verification result | `P2MR` only |
| `OP_CHECKSIGADD_SLHDSA` | `0xbf` | Accumulate one SLH-DSA verification result | `P2MR` only |

Associated constants:
- `VALIDATION_WEIGHT_PER_MLDSA_MULTISIG_SIGOP = 500`
- `VALIDATION_WEIGHT_PER_SLHDSA_MULTISIG_SIGOP = 5000`
- `MAX_PQ_PUBKEYS_PER_MULTISIG = 8`

## 3. Opcode Semantics

Both new opcodes follow this stack contract:

`(sig n pubkey -- n+success)`

Rules:
- Only valid under `SigVersion::P2MR`; otherwise `SCRIPT_ERR_BAD_OPCODE`.
- `pubkey` size must match algorithm size:
  - ML-DSA-44: 1312 bytes
  - SLH-DSA-SHAKE-128s: 32 bytes
- Empty signature:
  - verification is skipped
  - no validation weight charged
  - `n` is pushed unchanged
- Non-empty signature:
  - validation weight is charged for the algorithm
  - if validation budget underflows: `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT`
  - `CheckPQSignature(...)` is executed with selected algorithm
  - if valid, `n+1` is pushed; else `n`
- `SCRIPT_VERIFY_NULLFAIL` is enforced for non-empty failing signatures.

## 4. Multisig Leaf Script Pattern

m-of-n PQ multisig leaves are encoded as:

```
<pk_1> OP_CHECKSIG_{algo1}
<pk_2> OP_CHECKSIGADD_{algo2}
...
<pk_n> OP_CHECKSIGADD_{algon}
<m> OP_NUMEQUAL
```

Properties:
- O(n) verification behavior.
- No dummy-element bug from legacy multisig.
- Mixed-algorithm leaves are supported.

Example 2-of-3 mixed:

```
<pk1_ml> OP_CHECKSIG_MLDSA
<pk2_ml> OP_CHECKSIGADD_MLDSA
<pk3_slh> OP_CHECKSIGADD_SLHDSA
OP_2 OP_NUMEQUAL
```

## 5. Builders

Builder APIs:
- `BuildP2MRMultisigScript(threshold, pubkeys)`
- `BuildP2MRMultisigCTVScript(ctv_hash, threshold, pubkeys)`
- `BuildP2MRCLTVMultisigScript(locktime, threshold, pubkeys)`
- `BuildP2MRCSVMultisigScript(sequence, threshold, pubkeys)`

Validation rules:
- `1 <= threshold <= key_count`
- `key_count >= 1`
- `key_count <= MAX_PQ_PUBKEYS_PER_MULTISIG`
- Every key must match declared PQ algorithm size.
- CLTV locktimes must fit the standard 32-bit transaction locktime field.
- CSV sequences must satisfy `1 <= sequence < 2^31` and must not set the BIP68 disable flag.

## 6. Descriptor Grammar

New `mr()` leaf expressions:
- `mr(multi_pq(m,key1,key2,...))`
- `mr(sortedmulti_pq(m,key1,key2,...))`
- `mr(ctv_multi_pq(ctv_hash,m,key1,key2,...))`
- `mr(ctv_sortedmulti_pq(ctv_hash,m,key1,key2,...))`
- `mr(cltv_multi_pq(locktime,m,key1,key2,...))`
- `mr(cltv_sortedmulti_pq(locktime,m,key1,key2,...))`
- `mr(csv_multi_pq(sequence,m,key1,key2,...))`
- `mr(csv_sortedmulti_pq(sequence,m,key1,key2,...))`

Key forms:
- bare hex: ML-DSA pubkey (1312 bytes)
- `pk_slh(hex)`: SLH-DSA pubkey (32 bytes)
- descriptor-derived keys are supported where existing PQ derivation is supported

`sortedmulti_pq` sorts keys by raw pubkey bytes before script construction.
The `*_sortedmulti_pq` timelocked variants apply the same bytewise sorting before
building the CLTV/CSV/CTV leaf suffix.

## 7. Signing and Witness Assembly

When signing a multisig leaf:
- signer scans leaf keys in script order
- signatures are produced for locally available private keys
- final witness stack layout is:

`[sig_n_or_empty] ... [sig_2_or_empty] [sig_1_or_empty] [leaf_script] [control_block]`

Completion condition:
- threshold count of valid non-empty signatures is required.

Transaction field requirements:
- CLTV multisig leaves require `tx.nLockTime >= locktime` in the same locktime domain
  (block height or timestamp) and a non-final sequence on the spending input.
- CSV multisig leaves require `tx.version >= 2` and `vin[i].nSequence` to satisfy the
  encoded BIP68 relative lock.

## 8. PSBT Fields

P2MR multisig relies on these input fields:
- `PSBT_IN_P2MR_LEAF_SCRIPT` (`0x19`): selected leaf script + leaf version, keyed by control block
- `PSBT_IN_P2MR_PQ_SIG` (`0x1B`): keyed by `(leaf_hash || pubkey)`, value is PQ signature
- existing P2MR derivation/root fields remain applicable

Merge behavior:
- partial PQ signatures are union-merged by key
- conflicting selected leaves are rejected

Finalize behavior:
- combine available PQ partial signatures
- finalize only when threshold requirement is satisfied for selected leaf
- for unsigned PSBTs, descriptor-wallet updater/signer flows normalize `nLockTime`,
  `nSequence`, and transaction version to satisfy the selected CLTV/CSV leaf
- emit final witness stack for transaction extraction.
- finalization rejects witness construction when selected CLTV/CSV requirements are
  not actually satisfied by the transaction.

## 9. RPC Surface

- `createmultisig` supports PQ keys and returns P2MR address + descriptor.
- `addpqmultisigaddress` creates/imports a PQ multisig descriptor in descriptor wallets.
- `decodescript` may return `pq_multisig` metadata for matching leaf scripts.
- Timelocked PQ multisig leaves are available through descriptor import and descriptor
  wallet flows using the expressions above.

Legacy secp256k1 multisig policy remains disabled.

## 10. Policy and Limits

Standardness checks enforce:
- valid multisig leaf shape
- key count and threshold bounds
- correct witness stack size (`key_count + 2`)
- exact threshold number of non-empty signatures
- valid signature sizes per algorithm

Script size policy:
- multisig leaves may use full `MAX_P2MR_SCRIPT_SIZE` (10,000 bytes)
- other non-multisig P2MR leaves use existing policy leaf-size limit

Practical bound:
- ML-DSA keys dominate script size; around 7 keys fits under 10 KB.

## 11. Weight Notes

Validation weight cost is additive per non-empty signature:
- ML-DSA multisig sigop: 500
- SLH-DSA multisig sigop: 5000

Example 2-of-3 ML-DSA spend:
- ~8.8 KB witness footprint
- 1000 validation weight (two signatures)

## 12. Security Notes

- Consensus safety depends on strict SigVersion gating and key-size checks.
- Policy caps (`MAX_PQ_PUBKEYS_PER_MULTISIG`) limit resource abuse.
- PSBT merge rejects conflicting selected leaves.
- Wallet signing and PSBT finalization reject timelocked multisig spends whose
  transaction fields do not satisfy the selected CLTV/CSV leaf.
- Empty signatures are allowed for non-participating keys and are non-charged.
