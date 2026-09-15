# Native model HTTP API (`/btx-model/2/`)

HTTP/1.1 is **framing only**. All of these paths are served on the helper’s
**PQ1 TLS** listener (`-modelbind`). There is no plaintext public model
endpoint, no classical HTTPS downgrade, and no inference URL.

`btx-cli` JSON-RPC is the operator-facing API (`rpc.md`). These paths are
the peer protocol. Both surfaces share the same catalog and capabilities
object (`getmodelnetworkinfo` → `capabilities.http`).

Automatic spend is **0**. A field named `price=0` supplied by a requester
cannot bypass verification of an accepted paid quote.

## B0 paths

| Method | Path | Bound | Role |
|---|---|---|---|
| `POST` | `/hello` | 16 KiB | Channel-bound protocol/suite identity |
| `POST` | `/query` | 512 B request; 32 IDs | Exact `root` or bounded `text` lookup; `coverage` is always incomplete |
| `POST` | `/records/get` | 16 IDs; 128 KiB aggregate | Fetch signed/local provider records |
| `POST` | `/records/announce` | 16 KiB | Introduce a record to an opted-in router cache |
| `GET` | `/manifests/{id}` | 1 MiB | Manifest + model-core references |
| `POST` | `/availability` | 64 KiB | Bounded local availability |
| `POST` | `/quotes` | 64 KiB | Buyer-bound prepaid quote (no spend) |
| `POST` | `/transfers/{id}/payment` | 64 KiB | Journal a txid; duplicate txid → 409; **no chain verify** |
| `GET` | `/transfers/{id}/pieces/{file}/{piece}` | 4 MiB + proof headers | Verified chunk as `application/octet-stream` + `X-BTX-*` |
| `POST` | `/releases/{id}/pledges` | 16 KiB | Nonbinding local pledge |
| `POST` | `/releases/{id}/rounds` | 512 KiB | Frozen funding-round map (coordination only) |
| `POST` | `/releases/{id}/signatures` | 512 KiB | Partial signatures; not globally gossiped |

Piece bodies are **not** hex JSON. Proof metadata lives in `X-BTX-Artifact-Id`,
`X-BTX-File-Index`, `X-BTX-Piece-Index`, `X-BTX-File-Size`, `X-BTX-Pieces-Root`,
`X-BTX-Proof`.

## v1.1 extension paths (`/btx-model/2/ext/`)

Require a completed PQ1 hello. Caps JSON is bounded to 1 KiB.

| Path | Contract |
|---|---|
| `caps` | `{"extension_version":257,"features":<u32>,"max_envelope_bytes":81920}` |
| `resolve` | Typed digest lookup; 32 result IDs; coverage incomplete |
| `objects/get` | 1–8 record IDs |
| `objects/announce` | One envelope (JSON or octet-stream, max 80 KiB) |
| `free/grant` | Existing **seeded** local artifact; not a paid-quote bypass |
| `receipts` | Local session observation; not globally broadcast |

Feature bits: `RESOURCE_RESOLVE=1`, `FREE_GRANT=2`, `SERVICE_RECEIPT=4`,
`RESEARCH_IDENTITY=8`, `COLLECTIONS_ALIAS=16`, `POLICY_BUNDLE=32`,
`PRESERVATION_CIRCLE=64`. This tree reports **127** (all seven). Unknown bits
confer no permissions.

A 404 on `/ext/caps` means the peer is base-protocol-only. Do not invent record
support or downgrade crypto.

## Not on this wire

- Inference, logits, or “run this prompt”
- Wallet cookies, spending keys, or unrestricted `btxd` RPC
- BanMan / AddrMan / ExactReplay / issuance
- Browser bridge (optional, capability `browser_bridge=false`)
