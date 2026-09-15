# Decentralized model search

Normative contract for **discovering** models on the model plane (`src/modelnet/search.h`,
`search.cpp`). This is not ExactReplay, not monetary AddrMan, and not a hosted search SaaS.

Every node, RPC response, and explorer page must treat results as a **current network view**:
locally indexed records, configured index peers, and bounded peer replies. Nothing here implies a
**global complete directory**.

**Release posture:** `CLIENT_VERSION_IS_RELEASE` remains `false` in this tree. Behavior may change;
treat wire shapes as implemented in helper `DispatchHelperRpc`, not as a frozen public API until
release.

## Four planes (do not conflate)

| Plane | Question it answers | Authority | Global? |
|---|---|---|---|
| **Search / directory metadata** | “What might this digest be called?” | `ModelSearchRecord` (+ optional ML-DSA-44 signature) | No — gossip and indexers are partial |
| **Identity** | “Who signed this metadata line?” | ML-DSA-44 research identity (`signer_id`, `publisher_identity`) | Yes for **signature math** only |
| **Availability** | “Who can serve bytes right now?” | Local provider observations + piece ranges | No — time-varying, observed |
| **Trust / policy** | “Should *I* show or fetch this?” | Local hides, mutes, ACL rules | Never a chain-wide score |

Content truth is always digest verification at retrieve time. A signed search record does not
prove usefulness, safety, alignment, or that the publisher controls a distinct replica.

There is **no central telemetry**, no operator email/account system, and **no monetary coupling**
(`SearchTouchesMonetaryConsensus()` is false; search RPCs report `automatic_spend_atoms: 0`).

Network search queries (`scope=NETWORK`) may be visible to consulted peers
and indexers. `scope=LOCAL` keeps the query on this node. Do not claim
anonymous search.

## ModelSearchRecord

Typed catalog metadata keyed by `model_id` (and optional `artifact_id`).

| Property | Value |
|---|---|
| JSON `type` | `btx-model-search-v1` (v2 signing still uses this type) |
| `schema_version` | **2** on the record; economy/feed cards use **3** |
| Signature domain | New records: `BTX/ModelSearchRecord/v2`. Historic `record_version=1` still verifies as `BTX/ModelSearchRecord/v1` |
| Algorithm | **ML-DSA-44** only (no Ed25519, no ECDSA) |

v2 preimage covers **all publisher-authored searchable fields** including
`short_description`, tags, languages, modalities, publisher display name,
parameter/file counts, timestamps, and static release terms (`release_id`,
target, SHA-256 `key_hash`, refund height). v1 signatures are not reinterpreted
as covering those extra fields. Description/use-case queries match
`short_description` over the live network path after remote records are ingested.

### Fields (wire JSON)

| Field | Type | Notes |
|---|---|---|
| `schema_version` | int | Always `2` |
| `type` | string | Always `btx-model-search-v1` |
| `record_version` | int | Record format revision (default `1`) |
| `model_id` | hex48 | Typed MODEL root |
| `artifact_id` | hex48 | Optional artifact root |
| `uri` | string | Canonical `btx://` when encodable |
| `canonical_name` | string | ≤ 160 bytes |
| `display_name` | string | ≤ 160 bytes |
| `aliases` | string[] | ≤ 32 entries, each ≤ 128 bytes |
| `publisher_identity` | hex48 | Research identity root |
| `publisher_display_name` | string | Display only |
| `family` | string | e.g. architecture family |
| `architecture` | string | |
| `parameter_count` | int64 | |
| `format` | string | e.g. `safetensors`, `gguf` |
| `quantization` | string | |
| `languages` | string[] | ≤ 64 |
| `modalities` | string[] | ≤ 16 |
| `tags` | string[] | ≤ 64 |
| `short_description` | string | ≤ 1024; no `<` (HTML rejected) |
| `size_bytes` | uint64 | |
| `file_count` | int | |
| `published_at` | int64 | Unix ms or seconds (operator convention) |
| `updated_at` | int64 | |
| `release_id` | string | Optional campaign id |
| `release_state` | string | Default `PUBLIC` when empty |
| `metadata_sequence` | int64 | Monotonic per `model_id`; rollback rejected |
| `expires_at` | int64 | `0` = no expiry check |
| `signer_id` | hex48 | Derived from `pubkey` |
| `pubkey` | hex | ML-DSA-44 public key |
| `signature` | hex | ML-DSA-44 over domain hash of preimage |
| `signed_metadata` | bool | True when signature present / verified |
| `tombstone` | bool | Logical delete marker |

Whole-record JSON must be ≤ **16384** bytes (`SEARCH_RECORD_MAX`).

### Preimage (signed fields)

Domain hash input covers: `model_id`, `artifact_id`, `metadata_sequence`, `canonical_name`,
`display_name`, `aliases`, `family`, `architecture`, `format`, `quantization`,
`short_description`, `size_bytes`, `expires_at`, `tombstone`.

### Unsigned vs signed

- **Unsigned** records may be stored locally (catalog ingest, import). Remote verification requires
  `pubkey` + `signature`; `VerifySearchRecord` rejects missing crypto.
- **Signed** records bind metadata to `signer_id`. Explorers agree on **signature validity**, not on
  which records they have cached.
- **Unsigned cannot override signed** (`Put` error: `unsigned cannot override signed`).
- **Sequence rollback rejected** for signed updates and tombstones.
- Wrong signer with non-increasing sequence → `wrong signer`.

### Index retention and abuse

| Limit | Value |
|---|---|
| Index capacity | 100 000 records (`index cap`) |
| Publisher burst | > 64 new records per publisher window → `publisher spam` |
| Query body | ≤ 4096 bytes JSON |
| Search terms | ≤ 16 tokens |
| Page size default / max | 50 / 100 |

Peer search forward uses TTL default **2**, max **4** hops (`ShouldForwardSearch`); fanout is
bounded (`SEARCH_FANOUT_MAX` = 8). These limits cap mesh amplification, not completeness.

## Query model (`searchmodels` / `SearchQuery`)

Default **`scope`:** `NETWORK`. Default **`sort`:** `RELEVANCE`.

### Scope

| Value | Meaning |
|---|---|
| `LOCAL` | Local index (+ catalog ingest) only |
| `PEERS` | Reserved for connected peer indexes (same merge path when extras bound) |
| `NETWORK` | Local + configured index peers (default) |
| `ALL` | Used internally for full directory listing |

For **sensitive text**, use `LOCAL` (or operator alias `local`); see [Query privacy](#query-privacy).

### Sort

`RELEVANCE` (default), `AVAILABILITY`, `NEWEST`, `OLDEST`, `SIZE_ASC`, `SIZE_DESC`, `PROVIDERS`,
`RARITY`, `PUBLISHER`, `NAME`. Aliases accepted in RPC: `available`, `popular`, `rare`.

### Filters (object `filters`)

| Field | Type |
|---|---|
| `publisher_id` | hex48 |
| `publisher_name` | substring on display name |
| `family`, `architecture`, `format`, `quantization` | exact normalized match |
| `min_size_bytes`, `max_size_bytes` | int64 |
| `language` | string[] (any match) |
| `tags` | string[] (any match) |
| `public_only`, `min_provider_count`, `pinned`, `seeded`, `locally_available` | bool / int (stored; not all applied in local index pass) |

Unsupported filter keys are listed in RPC `unsupported_filters` (often empty).

### Text tokenization

Text is normalized (lower-case, alnum + UTF-8, collapsed whitespace). Empty text matches all
records (subject to filters). Relevance scoring prefers exact name/alias matches, then substring
hits on name, family, architecture, tags, description, publisher name; +50 when signed.

## RPC response shape (`searchmodels`)

Implemented in helper `DispatchHelperRpc`. **Coverage is always incomplete** (`coverage.complete`
and `coverage.global_complete` are always `false`).

```json
{
  "schema_version": 2,
  "query_id": "16-hex-bytes",
  "text": "llama",
  "scope": "NETWORK",
  "coverage": {
    "local": true,
    "connected_peers_queried": 0,
    "index_peers_queried": 0,
    "routing_peers_queried": 0,
    "responses_received": 0,
    "timed_out": 0,
    "complete": false,
    "global_complete": false
  },
  "results": [],
  "results_returned": 0,
  "total_candidates_seen": 0,
  "applied_filters": ["family"],
  "unsupported_filters": [],
  "remote_count": 0,
  "note": "current network view; not a complete global directory"
}
```

Each element of `results` is a **result card** (`SearchResultCard`): `model_id`, `artifact_id`,
`uri`, `name`, `aliases`, `publisher`, `family`, `architecture`, `parameters`, `format`,
`quantization`, `languages`, `tags`, `description`, `size_bytes`, `file_count`, `published_at`,
`availability` (swarm class), `local` state, `release`, `search` (`score`, `metadata_verified`,
`provenance`), `sources`.

`remote_count` mirrors `coverage.responses_received` (peer/index replies merged), not a global census.

### Errors

| Code | When |
|---|---|
| `INVALID_PARAMETER` | Bad scope/sort, bad query object, oversize query |
| `NOT_FOUND` | `getmodelsearchrecord` miss |
| `REJECTED` | Publish/import: verify fail, sequence rollback, unsigned override, cap/spam |

## Peer wire (optional HTTP)

**Authoritative operator API:** JSON-RPC on the helper / `btxd` proxy ([rpc.md](rpc.md)).

**Optional peer HTTP:** `POST /btx-model/2/ext/search` — same bounded `SearchRequest` /
`SearchResponseJson` envelope (`schema_version` 2, `results[]`, `coverage_hint: incomplete`).
Requires PQ1 hello; see [http.md](http.md). Peers may omit this path.

**Browser convenience only:** GET `/api/v1/*` on optional web bridges is **not** authoritative;
use RPC or native PQ1 for normative behavior.

### SearchRequest (peer)

| Field | Default | Notes |
|---|---|---|
| `schema_version` | 2 | |
| `query_id` | required | Deduped per node (`QueryDedupe`) |
| `text` / `text_terms` | | ≤ 16 terms |
| `ttl` | 2 | Clamped to max 4 |
| `limit` | 25 | Local slice before merge |
| `filters`, `sort_hint` | | Same semantics as RPC |

### SearchResponse (peer)

`query_id`, `responder_id`, `results[]` (result cards), `truncated`, `coverage_hint: incomplete`.

## Query privacy

Search text and filters are **revealed to every peer or indexer consulted** when `scope` is not
`LOCAL`. There is no encrypted query layer in v1.

- Use **`scope: LOCAL`** for sensitive or unpublished catalog strings.
- `cancelmodelsearch` marks a job cancelled; fan-out is bounded by TTL/fanout caps.
- Responses do not include wallet addresses or monetary identifiers.
- Relay nodes should not operate a central query-log product; the protocol defines **no telemetry
  channel** to a vendor.

## Local policy

| RPC | Effect |
|---|---|
| `hidesearchmodel` / `unhidesearchmodel` | Omit model from search hits |
| `mutesearchpublisher` / `unmutesearchpublisher` | Omit publisher’s records from search |

Hides/mutes affect **local ranking and listing**, not signature verification or retrieve-by-id.

## Related docs

- Directory aggregation: [directory.md](directory.md)
- Index peers: [indexers.md](indexers.md)
- RPC catalogue: [rpc.md](rpc.md)
- Provider bytes: [provider-routing.md](provider-routing.md), [swarm.md](swarm.md)
