# BTX 0.34.15 — Followed tip and host formats

**Status:** release. `CLIENT_VERSION` is **0.34.15** with
`CLIENT_VERSION_RC=0` and `CLIENT_VERSION_IS_RELEASE=true`. `btxd -version`
prints `v0.34.15`. P2P subversion is `/BTX:0.34.15/`. Do not recut
`v0.34.14` or `v0.34.13`.

Miner work remains the only consensus. The checks that 0.34.14 scheduled
for mainnet block **244000** stay at that height. An unset `-reorgpolicy`
stays legacy.

A unique followed tip-child is ExactReplayed without waiting for a fresh
rcadmit ticket or for a retained body to expire. Competing siblings stay
header-only.

EXL3 weights can be hosted beside GGUF. The container is recognized from
its tensors, not from the filename alone. Generation uses `BTX_EXL3_CLI`.
llama.cpp is not given those weights. A missing CLI reports
`no_exl3_backend`. When both formats are present, GGUF is preferred.

## Wallet and HTLC

These do not move the 244000 activation:

- `buildhtlcclaim` takes a caller-chosen confirmation depth.
- A new address or active import whose refund time is already past is refused.
- A model-funding step that asks for a block height where a timestamp is
  required is refused.
- A bounty claim does not reveal a preimage before the claim is ready.
- Wallets created with older multi-leaf HTLC descriptors still load.

## What a node reports

- `help` lists open-ended results instead of printing an internal error.
- `btx-cli preparereorg` sends the disconnect limit as a number.
- `getfinalityinfo` documents `trusted_pq_signer_pubkeys`. Single-key and
  collocated-pin warnings count secp and ML-DSA-44 keys together.
- `exportmatmulattestations` and `importmatmulattestations` call the
  export and import RPCs.
- A consensus node whose only secp pin member is its own WIF can start.
  The attestation store still refuses a blocklisted seeded key.

## Trusted mirrors

A mirror does not retain a body for an attestation before attestation is
active. When its signer names a block the mirror has not seen, the mirror
requests headers immediately. Bodies are fetched from the mirror's own
outbound archive connection.

## Unchanged

Block subsidy, difficulty adjustment, ExactReplay arithmetic,
`automatic_spend_atoms`, and the 244000 activation height are unchanged.
Pay With Compute remains an off-consensus access ledger. The direct GEMM
probe names a declined call, a thrown call, or a byte mismatch. Admission
stays as it was.
