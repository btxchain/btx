# Storage backends (0.34.8-dev)

**Status:** **0.34.8-dev** (`CLIENT_VERSION_IS_RELEASE=false`). Not a
shipping tag (`IS_RELEASE=false` means this tree is not sealed, not that
the code is missing). Last shipping tag is **v0.34.7**. This page describes
the intended layout. Helper MinIO / cloud RPCs **exist** in this tree
(`setcloudstorage` / `testcloudstorage` / `getcloudstorageinfo`). FakeS3 is
**unit-tested**. Live R2 WAN is **HONEST_NOT_RUN**. CLI verbs still fail
closed if an older helper lacks the method. This document is **not** a PASS,
not WAN evidence, and not a claim that a live origin is attached.

People: [HUMANS.md](../../HUMANS.md) and [first-run.md](first-run.md).
Agents: [AGENTS.md](../../AGENTS.md) and [agent-recipes.md](agent-recipes.md).
CLI: [../../contrib/modelnet/btx-model](../../contrib/modelnet/btx-model)
(`cloud`, `profile`). RPC names: [rpc.md](rpc.md).

## Architecture principle

> BTX pieces are the unit of verification and swarm exchange. They do not
> have to be the unit of cloud storage.
>
> A hyperscale origin should bootstrap decentralization, not impose its
> billing model on the swarm.

The swarm still verifies **4 MiB pieces** (`PIECE_SIZE`) with ChunkLeaf /
`pieces_root` / file SHA-384. Cloud objects are an optional backing store.
Verification never lives inside an S3 ETag. Catalog identity does **not**
include bucket, URL, or layout.

## What ships today vs this page

| Surface | 0.34.7 / existing first-run | 0.34.8-dev (this page) |
|---|---|---|
| Local filesystem `ModelStore` | yes | still the swarm body |
| `hostmodel` / watch folder | yes | unchanged |
| S3 / R2 / MinIO backend | not in the 0.34.7 shipping tag | RPCs **exist**; FakeS3 **unit-tested**; live R2 WAN **HONEST_NOT_RUN**; wrapper fails closed if an older helper lacks the method |
| Cloud layout AUTO | n/a | R2 AUTO → `SOURCE_FILES` + `STREAM_FILE` |

FakeS3 (`use_fake=true`) is the tested transport. OpenSSL HTTPS client
transport is compiled (`S3HttpsTransportAvailable()`), but a live Cloudflare
R2 WAN round-trip is **HONEST_NOT_RUN** (not PASS). SCALE huge / 400GiB body
stream is **NOT_RUN**. R2 AUTO is `SOURCE_FILES` +
`STREAM_FILE`. Pieces remain the swarm unit. Qt Models page watches/cloud
panels are 0.34.8-dev **source**; this tree is `BUILD_GUI=OFF` (do not claim
`bitcoin-qt` was built). `CLIENT_VERSION_IS_RELEASE=false`.

Do not treat a capabilities bit, a CLI wrapper, or this file as evidence
that a live origin round-trip ran.

## Layouts

```
cloud_provider = AUTO | GENERIC_S3 | AWS_S3 | CLOUDFLARE_R2 | MINIO
cloud_object_layout = AUTO | SOURCE_FILES | PIECE_OBJECTS
allow_request_heavy_cloud_layout = false
cloud_read_strategy = AUTO | STREAM_FILE | PIECE_GET
```

| Layout | Cloud object | Swarm still |
|---|---|---|
| `SOURCE_FILES` (R2 AUTO default) | one object per `FileEntry`: `<prefix>/artifacts/<artifact_id>/files/<file_index>` (exact file bytes) | 4 MiB pieces after verify |
| `PIECE_OBJECTS` | `<prefix>/artifacts/<artifact_id>/<file_index>/<piece_index>.piece` | same pieces; **request-heavy** on R2 |

R2 AUTO (hostname `*.r2.cloudflarestorage.com` **or** explicit
`CLOUDFLARE_R2`) resolves to `SOURCE_FILES` + `STREAM_FILE`. Custom domains
are **not** inferred as Cloudflare. An explicit operator setting wins.

`PIECE_OBJECTS` on R2 is refused unless `allow_request_heavy_cloud_layout`
is true. Random piece GET against a `SOURCE_FILES` origin is not the R2
AUTO path: use local cache, P2P, or sequential file hydrate.

## Credentials

Credentials are **local secrets**:

- `--credential-ref env:BTX_CLOUD_CREDENTIAL` (env name; value never logged)
- `--secret-file` path, mode **0600** (path is the ref; bytes stay in the file)

Never put access keys in:

- `ModelSearchRecord` / search JSON
- feed / event journal
- GUI diagnostics
- CLI argv (the wrapper refuses `--secret` / `--password`)
- RPC **responses** (`getcloudstorageinfo` must not echo secrets)

`btx-model cloud add` sends endpoint, bucket, prefix, region, layout,
provider, and `credential_ref` only.

## Health JSON

`getcloudstorageinfo` / `testcloudstorage` exist in this helper. They report
reachability, auth, read/write, latency, error counts, bytes, and GET / PUT
/ HEAD / Range / multipart / presign counts, plus budget remaining (lifetime
and UTC day/month windows when configured). **No
secrets.** FakeS3 is unit-tested. `testcloudstorage` is a **local helper
probe**, not a live R2 WAN receipt and not a PASS. Live R2 WAN remains
**HONEST_NOT_RUN**.

## Dollar prices are not protocol

The protocol does not encode vendor prices. Dated public list prices belong
only in operator docs. See [cloud-seeding.md](cloud-seeding.md) for a
retrieved R2 table (source + date). Do not bake those numbers into RPC,
events, or consensus.

## Related

- [cloud-seeding.md](cloud-seeding.md) — origin as bootstrap, not billing model
- [mirroring.md](mirroring.md) — keep/follow policy, no auto-spend
- [events.md](events.md) / [watches.md](watches.md)
- [architecture.md](architecture.md) — process split
