# Cloud seeding (0.34.8-dev)

**Status:** **0.34.8-dev** (`CLIENT_VERSION_IS_RELEASE=false`). Not a shipping
tag. Last shipping tag is **v0.34.7**. Helper RPCs `setcloudstorage` /
`testcloudstorage` / `getcloudstorageinfo` exist in this helper. FakeS3 is
**unit-tested**. Live HTTPS/R2 is **NOT_RUN**. The CLI wrapper still **fails
closed** if an older helper lacks the method. This page does **not** claim a
successful WAN or R2 bootstrap. No PASS.

CLI: `contrib/modelnet/btx-model cloud add|test|status --json`.
Recipes: [../../contrib/modelnet/recipes/cloud-status.json](../../contrib/modelnet/recipes/cloud-status.json).
Layout rules: [storage-backends.md](storage-backends.md).

## Architecture principle

> BTX pieces are the unit of verification and swarm exchange. They do not
> have to be the unit of cloud storage.
>
> A hyperscale origin should bootstrap decentralization, not impose its
> billing model on the swarm.

A large origin can **introduce** bytes so the first peers can verify them.
After that, the swarm should prefer verified P2P. Cloud stays optional. It
must not remain preferred merely because it is fast. It must not appear in
canonical model identity (`btx://`).

## R2 AUTO

Hostname `*.r2.cloudflarestorage.com` **or** explicit `CLOUDFLARE_R2` →

- `cloud_object_layout = SOURCE_FILES`
- `cloud_read_strategy = STREAM_FILE`

One origin GET (or long Range) of the **source file**, then split at
`PIECE_SIZE` on the node. Do **not** issue one GET per piece against R2
AUTO. `PIECE_OBJECTS` on R2 requires `--allow-request-heavy-cloud-layout`
(CLI) / `allow_request_heavy_cloud_layout` (RPC).

## Direct seed

Short-lived **presigned GET** of the **exact object** (the file object in
`SOURCE_FILES` mode). Constraints:

- GET only (no PUT/DELETE via the seed URL)
- exact key, not an operator-supplied arbitrary URL (no SSRF)
- never credentials on the wire to peers
- TTL 60s; per-peer / netgroup / concurrent limits on issuance
- logs redacted (`presigned_get` query stripped)
- fallback is the swarm

`getmodel` with `direct_seed: true` emits a redacted offer after those
limits. `direct_seed_fetch: true` lets **this helper** pull the same
allowlisted object via `FetchPresignedGet` (FakeS3 unit-tested). Live R2
WAN remains **NOT_RUN**.

Scheduler preference (when the delivery lane exists): verified P2P →
relay-assist P2P → direct cloud → provider-proxied origin.

## Configure (CLI; fail closed)

Secrets stay in the environment or a 0600 file. Examples use **refs**, not
key material:

```bash
export BTX_CLOUD_CREDENTIAL   # value never passed on argv, never committed
contrib/modelnet/btx-model --json cloud add \
  --endpoint "https://<accountid>.r2.cloudflarestorage.com" \
  --bucket "models" \
  --prefix "btx" \
  --region "auto" \
  --provider AUTO \
  --layout AUTO \
  --read-strategy AUTO \
  --credential-ref env:BTX_CLOUD_CREDENTIAL
contrib/modelnet/btx-model --json cloud test
contrib/modelnet/btx-model --json cloud status
```

`--secret-file /path/to/cloud.cred` (mode 0600) is the file form of the same
ref. The wrapper **refuses** `--secret` / `--password` on argv.

Unknown RPC → immediate error (`method not found (0.34.8-dev; fails closed
if helper lacks method)`). Do not wait.

## Dated vendor pricing (docs only)

**Not protocol.** Retrieved **2026-09-16** from Cloudflare’s public R2
docs: [https://developers.cloudflare.com/r2/pricing/](https://developers.cloudflare.com/r2/pricing/).
Cloudflare’s public calculator states that published fees in that tool are
limited to the public list **as of 2026-01-01**. Operators must re-read
the vendor page; BTX does not settle invoices.

Standard storage (public list, that retrieval):

| Component | Public list (retrieved 2026-09-16) |
|---|---|
| Storage | $0.015 / GB-month |
| Class A (writes / lists) | $4.50 / million requests |
| Class B (reads) | $0.36 / million requests |
| Egress (data transfer to Internet) | listed as free |
| Included monthly (Standard) | 10 GB-month, 1 million Class A, 10 million Class B |

Class A includes `PutObject`, `ListObjects`, multipart complete, etc.
Class B includes `GetObject` / `HeadObject`. A `PIECE_OBJECTS` layout on
R2 turns every piece into billable Class B (and often Class A on upload).
That is why AUTO is `SOURCE_FILES` + `STREAM_FILE`.

These figures are **not** in RPC, events, search records, or consensus.

## Honesty

- Do not count N CDN frontends as N independent origins.
- FakeS3 is unit-tested. OpenSSL HTTPS transport is compiled. Live HTTPS/R2
  WAN is **NOT_RUN** (not a PASS). SCALE huge / 400GiB body stream is
  **NOT_RUN**.
- R2 AUTO is `SOURCE_FILES` + `STREAM_FILE`. Pieces remain the swarm unit.
- `testcloudstorage` is a FakeS3 (or configured-backend) probe, not a
  production soak and not a PASS.
- This tree does not record a successful live R2 bootstrap in this session.
- `CLIENT_VERSION_IS_RELEASE=false`. Qt watches/cloud panels are 0.34.8-dev
  source (`BUILD_GUI=OFF`; do not claim `bitcoin-qt` was built).
