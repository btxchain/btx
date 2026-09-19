# Mirroring (0.34.8-dev)

**Status:** **0.34.8-dev** (`CLIENT_VERSION_IS_RELEASE=false`). Not a shipping
tag. Last shipping tag is **v0.34.7**. `getmodelmirror` / `setmodelmirror` /
`setmodelprofile` exist in this helper (keep-N, `automatic_spend_atoms=0`).
The CLI wrapper **fails closed** if an older helper lacks the method. This
page is not a PASS and not evidence that a public mirror is running.

CLI: `contrib/modelnet/btx-model mirror --publisher … --keep-latest N --json`
and `profile set mirror`. Recipe for the infrastructure preset:
[../../contrib/modelnet/recipes/infra-profile.json](../../contrib/modelnet/recipes/infra-profile.json).
Profiles and cloud: [storage-backends.md](storage-backends.md).
Follow vs folder: [watches.md](watches.md).

## Architecture principle

> BTX pieces are the unit of verification and swarm exchange. They do not
> have to be the unit of cloud storage.
>
> A hyperscale origin should bootstrap decentralization, not impose its
> billing model on the swarm.

A mirror is a **node role** (large quota + declarative keep/follow), not a
consensus privilege and not a search ranking privilege. Relay on an
infrastructure node still must **not** cache payloads.

## Profiles are config presets

`PERSONAL` / `INFRASTRUCTURE` / `MIRROR` / `CUSTOM` expand to ordinary
args (storage cap, seed, follow, preserve, relay, index, `host=auto`,
upload cap). They are **not** protocol. They must not bypass the resource
governor (thermal / battery / congestion / disk still bind). They grant
**no** monetary, search, or consensus extra rights.

```bash
contrib/modelnet/btx-model --json profile show
contrib/modelnet/btx-model --json profile set personal
contrib/modelnet/btx-model --json profile set infrastructure
contrib/modelnet/btx-model --json profile set mirror
contrib/modelnet/btx-model --json profile set custom '{"storage_bytes":null}'
```

`INFRASTRUCTURE`: relay + index + host-auto as **independent** roles, larger
AUTO target. Host advertisement still requires proven reachability and at
least one verified seeded range (`-modelhost=auto` must not OR
`NODE_MODEL_HOST` at init merely because the arg is set).

`MIRROR`: large quota plus declarative keep/follow. Still `automatic_spend_atoms
= 0`.

## Mirror policy

```bash
contrib/modelnet/btx-model --json mirror
contrib/modelnet/btx-model --json mirror --publisher '<publisher_id>' --keep-latest 3
```

Keep-N is “keep the latest N verified artifacts matching the selector.”
It is not a paid pin and not an auto-`getmodel` of arbitrary advertisements.
Preserve-rare remains a separate explicit flag (`-modelpreserverare`).

## Cloud is optional

A mirror may use local disk only. Attaching R2/S3 is optional backing, not
required for the role. FakeS3 is unit-tested; live HTTPS/R2 is **NOT_RUN**
(OpenSSL HTTPS transport is compiled; live R2 WAN is not PASS). SCALE huge
is **NOT_RUN**. R2 AUTO is `SOURCE_FILES` + `STREAM_FILE`. Pieces remain the
swarm unit. See [cloud-seeding.md](cloud-seeding.md). Secrets never appear in
mirror JSON. GUI is 0.34.8-dev source (`BUILD_GUI=OFF`).
`CLIENT_VERSION_IS_RELEASE=false`.
