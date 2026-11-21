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

## 7. Retain a complete model copy for catalog recovery

Cloud payload objects alone are not a catalog backup. If local catalog metadata
is lost, retain a complete original model directory or independent export to
re-import. A share URI or `.btx` card alone is not a complete model copy.

### Before local state is lost

Using the usual operator RPC connection, materialize a complete model:

```sh
btx-cli exportmodelpath '<model URI or model_id>'
```

The response includes `path`, `model_id`, `artifact_id`, and a `files` list with
relative paths, sizes and SHA-384 hashes. These paths belong to the helper's
machine, which may differ from the machine running `btx-cli`.

The returned path is a managed runtime checkout, not an independent backup.
It may hardlink files from the original input, and `removemodel` deletes the
checkout. Keep a separate copy:

1. Choose a backup directory outside the helper's modeldir, checkout and original
   input tree. Keep the source files stable while copying and verifying them.
2. Copy every listed file into `BACKUP/payload/`, preserving relative paths and
   bytes. Use independent file copies, not symlinks or hardlink-based copies.
   Check that the destination files do not share device/inode identities with
   the source or checkout files on filesystems that expose those identities.
3. Save the export response as `BACKUP/export-manifest.json`, **outside**
   `payload/`. Adding recognized sidecar files inside the model directory can
   change the content IDs when it is imported.
4. Verify the copied file set, sizes and SHA-384 hashes against the saved response.
   Keep originals and any previous backup until the new copy is verified.

A separate copy on the same device protects against removal of the managed
paths; it does not protect against loss of that device. Keep a verified copy
on separate storage when device-loss recovery is required.

### Restore through normal import

Make the complete copy accessible to the intended helper. With sufficient
storage quota and the usual operator permissions, import the payload directory:

```sh
btx-cli importmodel '/absolute/path/to/BACKUP/payload' '{"publish":false,"pin":true}'
```

Import `payload/`, not the enclosing directory containing the saved response.
Import recomputes the model and artifact identities and applies the existing
file-format, integrity and quota checks. `publish:false` suppresses search-card
publication for this import; it does not disable other configured helper
activity. The normal import may demand-seed the model.

Compare the returned `model_id` and `artifact_id` with the saved response.
Export again and compare its complete file set, sizes and hashes. After a normal
helper restart, repeat that export verification without importing again. Keep
the independent backup unchanged. The directory name may change the display
label even when the content IDs match.

This restores model content, not the entire helper state. It does not promise
restoration of aliases, publisher keys, trust, cloud credentials, jobs, history
or previous pin/seed settings, and is not a wallet backup. Do not edit catalog
flags or bypass admission checks to make a partial copy appear complete.

The independent-copy/CLI-restore/restart procedure was checked on macOS arm64
with a tiny two-file fixture. Earlier Linux recovery evidence covers re-import
from a surviving complete checkout. Neither qualifies large-model recovery,
other platforms, power-loss durability, inference or a release. With local
metadata and all complete copies gone, this candidate does not promise catalog
reconstruction from cloud objects alone.
