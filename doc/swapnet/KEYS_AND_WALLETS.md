# Keys, wallets and signing boundary

Native BTX uses its existing PQ/P2MR wallet and key expressions. The internal `_swapnet_import_htlc` callback is never public RPC: it selects an owner-controlled spendable address, obtains its descriptor signing provider inside CWallet, verifies the local public key matches one of the exact agreed HTLC branches, and adds that private provider to the contract descriptor without exporting it. Normal wallet locking and signing rules still apply.

Bitcoin HTLC keys are independent secp256k1 keys generated for the foreign vault. The existing selected Bitcoin wallet funds transactions and receives final payouts; imported address descriptors watch HTLC outputs. EVM funding/claim/refund account roles also use independently generated secp256k1 keys and signed type-2 transactions. There is no PQ-to-ECDSA conversion, HD seed sharing, byte truncation, or reuse of the BTX wallet seed.

The local foreign vault is AES-GCM encrypted. Its random local wrapping key resides beside it under owner-only filesystem permissions. This guards accidental disclosure of the vault file alone; it is not a hardware-backed security claim and does not protect against an attacker who can read both files or control the node process. Use full-disk encryption, OS account separation and native wallet encryption as appropriate. Python cryptographic operations do not promise perfect in-memory secret erasure.

A secret preimage is encrypted before negotiation/funding can proceed and is never returned by generic status RPCs. The coordinator durably records exposure before broadcasting a revealing claim. Chain-visible preimages are public by design after claim, but that fact does not authorize arbitrary wallet calls.

Back up both authorities: the native wallet through its normal backup procedure, and SwapNet through encrypted recovery export. Neither backup alone replaces the other. Old backups can omit later HTLC descriptors, EVM keys, nonces, secrets and raw transactions.
