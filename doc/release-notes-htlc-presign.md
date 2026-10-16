Presigned HTLC claims
---------------------

- `walletprocesspsbt` has a new option `htlc_presign` (default `false`). With
  the `htlc_sha256` claim leaf selected through `p2mr_leaf`, the wallet signs
  that leaf before the preimage is known. The leaf signature does not commit
  to the preimage, so the PSBT stays incomplete and holds no preimage. Whoever
  later learns the preimage adds it as `PSBT_IN_SHA256` and calls
  `finalizepsbt`; no wallet is needed for that step. This lets a swap party
  hand a presigned claim to a watchtower.
- The option needs `sign=true`, a selected leaf and `sighashtype` `DEFAULT` or
  `ALL`. Only the claim leaf that pins a 32-byte preimage is presigned, not
  `htlc_sha256_legacy`. Without the option nothing changes: the wallet still
  refuses to sign the claim leaf without the preimage, and a `PSBT_IN_SHA256`
  entry whose value does not hash to its key is still rejected when the PSBT
  is read.
- The presignature commits to the whole transaction. Anyone holding the
  presigned PSBT who learns the preimage can broadcast exactly that
  transaction, and no other.
- The claim leaf has no timeout, but its fee is fixed when it is presigned.
  It has to confirm before the refund height: after that, a refund with a
  higher fee can replace it (full RBF is the default). Presign only once the
  funding transaction is deeply confirmed.
