# Recovery walkthrough (B0 DOC-03)

This is an operator walkthrough for **this tree**. It is not a packaged
`acceptance-matrix.csv` PASS and not a rewrite of B0.

Qt Models-first recovery copy is out of scope. Use `btx-modeld` + wallet
HTLC RPCs.

## 1. Helper process gone, monetary node still up

`btxd` and `btx-modeld` are separate processes. If the helper dies:

1. Monetary RPC, mempool, and ExactReplay keep running.
2. Model RPCs on `btxd` fail closed until the helper unix socket is back.
3. Restart **only** `btx-modeld` with the same `-modeldir`. Do not replace a
   live production `btxd.real`.

Catalog pieces that were committed under `modeldir/store/` survive. Leftover
`tmp/` files are ignored (STORE-07).

## 2. Campaign object without a spend

`createmodelrelease` stores SHA-256(`secret32`) only (`secret_retained=false`).
After a helper restart, `getmodelrelease` reloads `campaigns.json`.

Claim and refund use 0.34.6 SHA-256 HTLC:

- `buildmodelhtlcclaim` / `buildmodelhtlcrefund` (unsigned helper templates)
- `buildhtlcclaim` / `buildhtlcrefund` (wallet signs)
- HASH160 `htlc_tx` is recovery-only for old outputs, never a new campaign

Helper `preparemodelfunding` / `signmodelfunding` /
`submitmodelfunding` freeze the round. Helper sign is `complete=false`
without spending keys. Helper submit journals; `btxd` broadcasts.

## 3. Funding fingerprint mutated

If the round changed (amount, refund height, claimant, refund key),
`FundingUnchanged` fails. Run `preparemodelfunding` again. Do not reuse a
partially signed template.

## 4. Retrieve interrupted (STORE-01)

Keep the fetcher `-modeldir`. Re-run `getmodel` with the same URI. Verified
pieces stay; corrupt piece bytes are refused. Do not delete scratch on
failure if you intend to resume.

Granite-sized fixtures belong on **disk**, never on tmpfs `/tmp`.

## 5. OpenSSL / PQ1 fail-closed

Hostile `OPENSSL_CONF` must not weaken PQ1 (PQ-19). Second-process helpers
may set `LD_LIBRARY_PATH` to OpenSSL 3.5.8. Do not relink a live
`btxd.real`.

## 6. GPU qualification skipped

If a production `btxd.real` holds the GPU, `cuda-isolated-qual.sh` skips
kernels. `capabilities.cuda_qualification` stays **false**. That is
`NOT_RUN`, not a usefulness claim.
