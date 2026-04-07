# BTX PQ Multisig Tutorial

This tutorial shows a 2-of-3 post-quantum multisig flow on BTX using P2MR,
`addpqmultisigaddress`, and PSBT.

Use this tutorial for mechanics. For the production custody model, signer
separation, timelocked recovery, backup/archive procedures, and AI/operator
safety rules, see the [BTX Key Management Guide](btx-key-management-guide.md).

## 1. Prerequisites

- Descriptor wallets enabled.
- Three signer wallets (`signerA`, `signerB`, `signerC`).
- One coordinator/watch-only wallet (`coordinator`).
- Three PQ public keys in script order (or sorted mode):
  - `<PK1>`
  - `<PK2>`
  - `<PK3>`

Key syntax:
- ML-DSA: raw hex (1312-byte pubkey)
- SLH-DSA: `pk_slh(<32-byte-hex>)`

### Deterministic Key Export (Recommended)

Use each signer wallet to export deterministic PQ key material directly from a
wallet-owned P2MR address. This avoids witness/script parsing.

```bash
A_ADDR=$(btx-cli -rpcwallet=signerA getnewaddress)
B_ADDR=$(btx-cli -rpcwallet=signerB getnewaddress)
C_ADDR=$(btx-cli -rpcwallet=signerC getnewaddress)

PK1=$(btx-cli -rpcwallet=signerA exportpqkey "$A_ADDR" | jq -r '.key')
PK2=$(btx-cli -rpcwallet=signerB exportpqkey "$B_ADDR" | jq -r '.key')
PK3=$(btx-cli -rpcwallet=signerC exportpqkey "$C_ADDR" | jq -r '.key')
```

Fresh BTX descriptor wallets currently export `ml-dsa-44` keys by default.
Pass an explicit algorithm only if that signer wallet has matching key material.

## 2. Create a PQ Multisig Address

### Option A: Utility RPC (no wallet import)

```bash
# Using shell variables (after deterministic key export):
btx-cli createmultisig 2 "[\"${PK1}\",\"${PK2}\",\"${PK3}\"]" '{"address_type":"p2mr","sort":true}'

# Using literal key placeholders (mixed ML-DSA + SLH-DSA example):
btx-cli createmultisig 2 '["<PK1>","<PK2>","pk_slh(<PK3>)"]' '{"address_type":"p2mr","sort":true}'
```

Returns:
- `address`
- `redeemScript` (P2MR leaf script)
- `descriptor` (`mr(sortedmulti_pq(...))`)

### Option B: Wallet RPC (create + import)

```bash
# Using shell variables (after deterministic key export):
btx-cli -rpcwallet=coordinator addpqmultisigaddress 2 "[\"${PK1}\",\"${PK2}\",\"${PK3}\"]" "team-safe" true

# Using literal key placeholders (mixed ML-DSA + SLH-DSA example):
btx-cli -rpcwallet=coordinator addpqmultisigaddress 2 '["<PK1>","<PK2>","pk_slh(<PK3>)"]' "team-safe" true
```

This imports the multisig descriptor into the descriptor wallet.

### Option C: Native Timelocked Multisig Descriptor

For vault, recovery, or staged-governance flows, import a timelocked descriptor
directly. Examples:

```bash
# Absolute timelock recovery branch
btx-cli getdescriptorinfo 'mr(cltv_multi_pq(700,2,<PK1>,<PK2>,pk_slh(<PK3>)))'

# Relative timelock recovery branch
btx-cli getdescriptorinfo 'mr(csv_sortedmulti_pq(144,2,<PK1>,<PK2>,pk_slh(<PK3>)))'
```

Take the returned descriptor with checksum and import it with `importdescriptors`
or store it in a descriptor wallet workflow.

## 3. Fund the Multisig Address

```bash
btx-cli -rpcwallet=funder sendtoaddress <MULTISIG_ADDRESS> 3.0
btx-cli -rpcwallet=funder generatetoaddress 1 <MINER_ADDRESS>
```

## 4. Create an Unsigned PSBT

Use a fee rate suitable for large PQ witnesses:

```bash
btx-cli -rpcwallet=coordinator walletcreatefundedpsbt \
  '[{"txid":"<TXID>","vout":<N>}]' \
  '[{"<DESTINATION>":1.0}]' \
  0 \
  '{"add_inputs":false,"changeAddress":"<MULTISIG_ADDRESS>","fee_rate":25}'
```

Take `.psbt` from the result.

## 5. Add Metadata (Updater Step)

```bash
btx-cli -rpcwallet=coordinator walletprocesspsbt <PSBT_BASE64> false "ALL" true false
```

Use returned `.psbt` as signer input.

For selected CLTV/CSV multisig leaves, this updater step also normalizes the
transaction fields on an unsigned PSBT:
- CLTV: raises `nLockTime` as needed and clears the input from final sequence.
- CSV: sets `tx.version >= 2` and applies the required relative sequence.

## 6. Sign on Two Independent Signers

Signer A:

```bash
btx-cli -rpcwallet=signerA walletprocesspsbt <PSBT_FROM_UPDATER>
```

Signer B:

```bash
btx-cli -rpcwallet=signerB walletprocesspsbt <PSBT_FROM_UPDATER>
```

Each response contains a partially signed PSBT.

## 7. Combine + Finalize + Broadcast

```bash
btx-cli combinepsbt '["<PSBT_A>","<PSBT_B>"]'
btx-cli finalizepsbt <COMBINED_PSBT>
btx-cli sendrawtransaction <FINAL_HEX>
```

Confirm spend:

```bash
btx-cli gettransaction <TXID>
```

## 8. Script/Descriptor Inspection

Decode script metadata:

```bash
btx-cli decodescript <REDEEM_SCRIPT_HEX>
```

For PQ multisig leaves, output includes:
- `pq_multisig.threshold`
- `pq_multisig.keys`
- `pq_multisig.algorithms`

## 9. Common Errors

- `Only address type 'p2mr' is supported for PQ multisig`
  - Use `{"address_type":"p2mr"}`.
- `nrequired cannot exceed number of keys`
  - Fix threshold/key count mismatch.
- `Unable to build PQ multisig leaf script`
  - Verify key sizes and `MAX_PQ_PUBKEYS_PER_MULTISIG` policy cap.
- relay fee rejection after finalize
  - Increase explicit `fee_rate` when creating funded PSBT.

## 10. Operational Guidance

- Use `sortedmulti_pq` (or `sort=true`) for deterministic descriptor construction.
- Back up descriptor strings and wallet metadata for recovery.
- For larger quorums, split policy across multiple P2MR leaves instead of a single oversized leaf.
- Use CLTV for absolute-height or absolute-time recovery paths and CSV for relative
  “cooldown after confirmation” paths.
- If a PSBT already has signatures on it, do not change `nLockTime` or input
  sequence fields afterward; recreate or update the unsigned PSBT first.
