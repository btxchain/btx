P2MR HTLC fixes
---------------

- **Consensus (soft fork, scheduled separately).** The 32-byte preimage rule
  for transaction-bound HTLC claim leaves (`htlc_sha256`, the earlier SHA-256
  leaf and HASH160 `htlc_tx`) is now the script flag
  `SCRIPT_VERIFY_P2MR_HTLC_PREIMAGE32`. It is standard policy at once and a
  consensus rule only from `Consensus::Params::nP2MRHTLCPreimage32Height`.
  Below that height blocks validate exactly as in 0.34.12. 0.34.13 enforced
  the rule from genesis with no activation, so a block that 0.34.12 accepts
  could split 0.34.13 nodes from the rest of the network. Mainnet activates
  the rule at block 244000, about five days after header tip 239154 on
  2026-10-05. Regtest enforces from height 0; `-regtesthtlcpreimage32height=<n>`
  overrides.
- Correction to the 0.34.13 notes: the new `htlc_sha256` leaf's `OP_SIZE 32`
  check is ordinary script, not a consensus change. The consensus change was
  the unconditional pre-check described above.
- `htlc_sha256()` derives a different address from 0.34.13 on. Both sides of
  a swap must compare the funding **address**, not only the descriptor.
  Claims of 0.34.13-format locks are non-standard on 0.34.12 nodes: they do
  not relay through, and are not mined by, 0.34.12 nodes.
- New descriptor leaf `htlc_sha256_legacy(<sha256>,<key>)` names the claim
  leaf used before 0.34.13, so a wallet can import, watch and claim such a
  lock. It is recovery-only (no `deriveaddresses`, not active).
- `buildhtlcclaim` refuses, unless overridden in its new `options` argument,
  to reveal the preimage while the funding output is unconfirmed
  (`allow_unconfirmed_funding`) or once the refund path is already final
  (`allow_late_claim`). `buildhtlcclaim` and `buildhtlcrefund` refuse dust
  outputs and fees above `-maxtxfee`. A claim and refund descriptor whose
  expanded keys are the same is refused.
- Descriptor rules: every claim/refund leaf pair must use distinct keys, and
  a repeated key expression (for example the same `pqhd()`) is refused. These
  rules and `refund(0)` apply to new descriptors only; a wallet that imported
  such a descriptor with an older version loads again.
- `bridge_planin`, `bridge_planout` and the batch variants refuse a
  `refund_lock_height` of 500000000 or more. CLTV reads such a value as a Unix
  time, so the refund was spendable at once.
- `buildmodelhtlcclaim` requires a 32-byte preimage, and both modelnet
  templates signal replacement. `buildmodelhtlcrefund` takes its nLockTime from
  the descriptor and refuses one below it.
- `generateblock` (and `generatetoaddress`) now report a block that is stored
  but fails validation, instead of returning its hash.
