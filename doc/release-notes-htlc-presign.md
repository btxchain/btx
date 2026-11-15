Presigned HTLC claims
---------------------

- `walletprocesspsbt` has a new option `htlc_presign` (default `false`). With
  the `htlc_sha256` claim leaf selected through `p2mr_leaf`, the wallet signs
  that leaf before the preimage is known. The leaf signature does not commit
  to the preimage, so the PSBT stays incomplete and holds no preimage. Whoever
  later learns the preimage passes it to `finalizepsbt` (new argument
  `preimages`, see below) or adds it as `PSBT_IN_SHA256` itself; no wallet is
  needed for that step. This lets a swap party hand a presigned claim to a
  watchtower.
- `finalizepsbt` has a new optional third argument `preimages`, an array of
  32-byte hex strings. Each one is added as `PSBT_IN_SHA256` to every input
  whose selected `htlc_sha256` claim leaf locks its SHA256 hash, and then the
  PSBT is finalized as before. A preimage that is not 32 bytes, is not hex, or
  matches no such input is an error, and nothing is returned. The
  `htlc_sha256_legacy` leaf is not matched. An input that is already
  finalized no longer carries its selected leaf, so it is not matched either;
  call `finalizepsbt` without `preimages` for such a PSBT.
- The option needs `sign=true`, a selected leaf and `sighashtype` `DEFAULT` or
  `ALL`. Only the `htlc_sha256` claim leaf is presigned, not the
  recovery-only `htlc_sha256_legacy` leaf. Without the option nothing
  changes: the wallet still refuses to sign the claim leaf without the
  preimage, and a `PSBT_IN_SHA256` entry whose value does not hash to its key
  is still rejected when the PSBT is read.
- The presignature commits to the whole transaction. Anyone holding the
  presigned PSBT who learns the preimage can broadcast exactly that
  transaction, and no other.
- The claim leaf has no timeout, but its fee is fixed when it is presigned.
  It has to confirm before the refund height: after that, a refund with a
  higher fee can replace it (full RBF is the default). Presign only once the
  funding transaction is deeply confirmed.
