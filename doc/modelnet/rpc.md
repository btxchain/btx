# Model RPC catalogue

`btxd` (when `-DWITH_MODELNET=ON`) proxies these to `btx-modeld` via
`-modelrpcsocket`. If the helper is down, calls **fail closed**. The same
methods are available directly on the helper unix socket (researcher
profile, no `btxd`).

**Coverage rule:** Search and directory methods return `schema_version: 2` and a
`coverage` object with **`complete: false`** (and usually `global_complete: false`).
The `note` / `coverage_disclaimer` strings state **current network view; not a
complete global directory**. Low `remote_count` is normal. Never interpret results
as a global census.

**Release posture:** `CLIENT_VERSION_IS_RELEASE` is `false` in this tree.

**Privacy:** Network-scoped queries reveal text to consulted peers/indexers; use
`scope: LOCAL` for sensitive searches ([search.md](search.md)).

Conceptual background: [search.md](search.md), [directory.md](directory.md),
[indexers.md](indexers.md).

## Implemented in this tree (baseline)

| RPC | Role |
|---|---|
| `getmodelnetworkinfo` / `getmodelcryptoinfo` | Schema 2, OpenSSL identity, PQ1 flags, **capabilities**, `automatic_spend_atoms=0` |
| `decoderesource` / `encoderesource` / `decoderesourceuri` / `encoderesourceuri` | Compact URI; no network |
| `openbtxuri` | Preview-only; never inference / mining / wallet |
| `resolveresource` | Typed lookup; coverage incomplete |
| `importmodel` | Stream hash + 4 MiB pieces; optional pin. Never executes pickle/.pt |
| `listmodels` | Local catalog only |
| Search / directory / index (below) | Implemented in helper `DispatchHelperRpc` (`search.cpp`) |
| `getmodelmanifest` | Verified metadata |
| `exportmodelpath` | Verified local store paths; never starts a runtime |
| `seedmodel` / `unseedmodel` | Manual serve / stop. Default `seed=auto` already seeds after import/`getmodel` |
| `qualifymodel` | Structure only |
| `getmodel` | `FREE_ONLY` retrieve (URI or digest48); demand-seeds when `seed=auto` |
| `getmodelpolicy` / `setmodelpolicy` | Free-first + propagation (`seed`, `preserve_rare`); non-zero automatic spend and `auto_pay` are refused |
| `addmodelnode` / `getmodelpeers` | Model-plane contacts, not AddrMan |
| `exportmodelcontacts` / `importmodelcontacts` / `exportmodelpeers` / `importmodelpeers` / `importmodeltrust` | Public endpoints; download cannot modify trust |
| `getmodeljob` / `cancelmodeljob` | Job list with `status`, `bytes_committed`, `pieces_committed`, `file_index`, `piece_index`, `inflight`, `peer_retries`, `last_err`, catalog `used_bytes` |
| `listmodelidentities` / `createmodelidentity` | Identity-only ML-DSA keys; never wallet keys |
| `listmodelrules` / `setmodelrule` / `removemodelrule` | Model ACL; never BanMan |
| `joinmodelcircle` / `leavemodelcircle` / `subscribemodelcollection` / `subscribemodelpolicy` | Local community policy; no on-chain membership |
| `delegatemodelservice` / `revokemodelservice` | Typed service ops; never a money signature |
| `getmodelreciprocity` | Local useful-byte observations; not money |
| `createmodelrelease` / `pledgemodelrelease` / `getmodelrelease` | Local campaign objects; SHA-256 `key_hash` only |
| `claimmodelrelease` / `refundmodelrelease` | Demand-seed + pointer to `buildmodelhtlcclaim` / `buildmodelhtlcrefund` |
| `preparemodelfunding` / `signmodelfunding` / `submitmodelfunding` / `exportmodelrecovery` | Freeze exact `htlc_sha256` round. Helper never auto-spends; helper sign is complete=false without keys; helper submit journals (no chain verify). `btxd` wallet signs and broadcasts. |
| `buildmodelhtlcclaim` / `buildmodelhtlcrefund` | Unsigned 0.34.6 SHA-256 HTLC templates. SHA-256(preimage) must match `key_hash`. HASH160 `htlc_tx` is recovery-only. |

Search, directory, indexer, and browse RPCs below are implemented on the helper
unix socket (and proxied through `btxd` when `-modelrpcsocket` is set). Peer
HTTP (PQ1): [http.md](http.md). Optional bounded search:
`POST /btx-model/2/ext/search` ([search.md](search.md)). Browser
`GET /api/v1/*` is convenience only, not authoritative.

`getmodelnetworkinfo` → `capabilities.http` lists implemented PQ1 paths.
`capabilities.features` is `127` (v1.1 core profile bits).

POST `/btx-model/2/quotes` records a prepaid quote. POST `.../payment` journals a txid and **refuses duplicate txids**. The helper does not verify the chain and does not spend.

## Common errors

| Code | Meaning |
|---|---|
| `INVALID_PARAMETER` | Bad id, oversize string, unknown enum |
| `NOT_FOUND` | Unknown model, record, job, or indexer |
| `REJECTED` | Record verify/import failed, sequence rollback, unsigned override, index cap, publisher spam |
| `NOT_ENABLED` | Build or capability off (monetary proxy paths) |
| `HELPER_DOWN` | Proxy socket missing (`btxd` only) |
| `IMPORT_FAILED` | Index import parse/verify failure |

Monetary RPC errors (`RPC_WALLET_*`, etc.) never apply on the helper unix
socket researcher profile.

## Global limits (search / records)

| Limit | Value |
|---|---|
| Query JSON | ≤ 4096 bytes |
| Search terms | ≤ 16 |
| Default / max `limit` | 50 / 100 |
| Record JSON | ≤ 16384 bytes |
| Index capacity | 100000 records |
| Search forward TTL default / max | 2 / 4 |
| Search fanout max | 8 peers |

Record field bounds: see [search.md](search.md).

---

## Search and records

All methods below are dispatched by `DispatchHelperRpc` in `helper.cpp`.

### searchmodels

Bounded merge of local index (+ catalog ingest) and optional index peers when
`scope` ≠ `LOCAL`. Default **`scope`:** `NETWORK`. Default **`sort`:** `RELEVANCE`.

**Request** — string shorthand or object:

| Field | Type | Notes |
|---|---|---|
| `text` / `query` | string | Tokenized relevance search |
| `scope` | string | `LOCAL`, `PEERS`, `NETWORK` (default), `ALL` |
| `sort` | string | See [search.md](search.md#sort) |
| `limit` | int | Default 50, max 100 |
| `offset` | int | Slice after sort |
| `cursor` | string | Reserved |
| `filters` | object | See [search.md](search.md#filters-object-filters) |

**Response** (required keys):

| Field | Notes |
|---|---|
| `query_id` | 16-byte hex job id |
| `text`, `scope` | Echo |
| `coverage` | Object; **`complete` always false** |
| `results` | Array of result cards |
| `results_returned`, `total_candidates_seen` | Counts |
| `applied_filters`, `unsupported_filters` | Arrays |
| `note` | `current network view; not a complete global directory` |
| `remote_count` | Same as `coverage.responses_received` |

**Example**

```bash
btx-cli searchmodels '{"text":"llama","scope":"NETWORK","limit":10}'
```

**Errors:** `INVALID_PARAMETER` (bad scope/sort/query).

---

### getmodelsearchrecord

**Request:** `model_id` — `btx://` URI or hex48.

**Response:** Full `ModelSearchRecord` (`type: btx-model-search-v1`) + `locally_cached: true`.

**Errors:** `NOT_FOUND`, `INVALID_PARAMETER`.

---

### publishmodelsearchrecord

**Request:** `(model_id, record)` — id string + record object ([search.md](search.md)).
Signing uses ML-DSA-44 domain `BTX/ModelSearchRecord/v1` when `pubkey`/`signature` supplied.

**Response:** `schema_version`, `model_id`, `sequence` (`metadata_sequence`),
`automatic_spend_atoms: 0`, `wallet_key: false`.

**Errors:** `INVALID_PARAMETER`, `REJECTED` (verify, cap, spam).

---

### updatemodelsearchrecord

**Request:** same arity as publish. Bumps `metadata_sequence` from stored record.

**Errors:** `REJECTED` on sequence rollback or unsigned override.

---

### removemodelsearchrecord

**Request:** `model_id`.

**Response:** `tombstone: true`, `guaranteed_global_delete: false`.

**Errors:** `REJECTED`, `INVALID_PARAMETER`.

---

### listmodelsearchrecords

**Request:** optional `{ "limit" (max 100), "updated_after" }`.

**Response:** `schema_version`, `sequence`, `records[]`, `updated_after`, `next_cursor`.

---

## Directory and availability

### getmodeldirectoryentry

**Request:** `model_id` (URI or hex48).

**Response:** [Directory entry](directory.md#directory-entry) (`DirectoryEntryJson`).

Stub entry when no record: id only, `UNKNOWN` availability class.

---

### getmodeldirectory

**Request:** optional search query object (filters/text/limit/offset).

**Response:** `{ "schema_version": 2, "results": [ … entries … ], "global_complete": false }`.

---

### getmodelproviders

**Request:** `model_id`.

**Response:** `providers[]` with `provider_id`, `reachability`, `complete`, `last_seen`,
`direct`, `relayed`. **Observed list only.**

---

### getmodelavailability

**Request:** `model_id`.

**Response:** [Availability object](directory.md#availability-classes) +
`model_id`, `global_complete: false`.

Classes: `EXCELLENT`, `HIGH`, `MEDIUM`, `FRAGILE`, `DEGRADED`, `UNKNOWN`.

---

### getmodelpeercount

**Request:** `model_id`.

**Response:** Provider observation totals + `note` (network view, not global census).

---

### getnetworkmodelstats

**Response:** `models_known`, `models_local`, `search_records_known`, `searches_running`,
`searches_completed`, `index_records`, `coverage_disclaimer`, `global_complete: false`,
`automatic_spend_atoms: 0`.

---

## Publishers and collections (search views)

### getmodelaliases

**Request:** `model_id`.

**Response:** `aliases[]` with `{ alias, provenance }` (`publisher_metadata` vs `unsigned`).

---

### searchpublishers

**Request:** string or query object.

**Response:** `publishers[]` with `id`, `model_count_observed`.

---

### getpublisher

**Request:** publisher id hex48.

**Response:** `id`, `display_name`, `model_count_observed`.

---

### searchcollections / getcollection

**Response:** `collections: []` + note when none cached (signed collections remain first-class).

---

## Explorer-style browse (partial views)

All return `results[]`, `global_complete: false`, and a `metric` string.

| RPC | Default sort / metric |
|---|---|
| `browsemodels`, `getnewmodels` | `NEWEST` |
| `gettrendingmodels` | `PROVIDERS` / `observed_provider_growth_local` |
| `getsimilarmodels` | `RELEVANCE` + optional `filters.family` |
| `getrecentreleases` | `RELEVANCE` |

---

## In-flight search control

### getsearchstatus

**Request:** `query_id`.

**Response:** `state` (`RUNNING|COMPLETE|CANCELLED`), `results_returned`, `complete: false`.

**Errors:** `NOT_FOUND`.

---

### cancelmodelsearch

**Request:** `query_id`.

**Response:** `{ "ok": true|false }`.

---

### getsearchpeers

**Response:** `peers[]` with `endpoint`, `capability: NODE_MODEL_INDEX`, `monetary_service_bit: false`.

---

## Indexer configuration

See [indexers.md](indexers.md).

### addmodelindex

**Request:** `endpoint` string.

**Response:** `schema_version`, `index_peers`, `addrman: false`.

---

### removemodelindex

**Request:** `endpoint` string.

**Response:** same shape as add.

---

### exportmodelindex

Same as `listmodelsearchrecords` (optional limit object).

---

### importmodelindex

**Request:** `{ "records": [ … ] }`.

**Response:** `imported`, `rejected`, `reverified`.

---

## Local policy (search UI)

### hidesearchmodel / unhidesearchmodel

**Request:** `model_id`.

**Response:** `{ "hidden": true|false }`.

---

### mutesearchpublisher / unmutesearchpublisher

**Request:** publisher id hex string.

**Response:** `{ "muted": true|false }`.

---

## Economy, feed, and release discovery (schema 3)

Preferred third-party / agent APIs. Coverage is always incomplete. Helper
observations are not wallet authority. `automatic_spend_atoms` is 0.

| RPC | Role |
|---|---|
| `getmodeleconomyentry` | Full `ModelEconomyEntry` (search + swarm + local + release + actions) |
| `getmodelfeed` | Network feed (`NEWEST`, `NEARLY_FUNDED`, `JUST_UNLOCKED`, …) |
| `getmodelfeedstatus` / `getmodelfeedsequence` | `feed_sequence`, counts, coverage disclaimer |
| `getfundablemodels` | Still-fundable campaigns (`NEARLY_FUNDED` default) |
| `getmodelreleaseeconomics` | pledged vs confirmed funded, hashlock, refund, ciphertext |
| `getrecentlyunlockedmodels` | Secret recently disclosed |
| `getreleasefeed` | Wrapper over `getmodelfeed` for campaigns |
| `preparefundmodelrelease` | Unsigned plan; never spends |

See [model-economy.md](model-economy.md), [feed.md](feed.md),
[explorers.md](explorers.md).

## Model bounties (proposed 0.34.7 contract)

Demand-side bounty RPCs (draft terms through refund recovery and agent
mandates) are documented separately — they extend the model plane but use
wallet boundaries for money:

- Overview: [../bounties.md](../bounties.md)
- Full method reference: [../bounty-rpc.md](../bounty-rpc.md)
- Machine inventory: [../../contrib/modelnet/bounty/schemas/rpc-catalog.json](../../contrib/modelnet/bounty/schemas/rpc-catalog.json)

Example:

```bash
btx-cli searchmodels '{"text":"coding agent","scope":"NETWORK"}'
btx-cli getmodelfeed '{"scope":"NETWORK","mode":"NEWEST","limit":50}'
btx-cli getmodeleconomyentry '<model_id>'
```

---

## Isolation

`addmodelnode` is not monetary `addnode`. Model RPCs never sit on the
validation hot path. Search/indexer traffic never uses BanMan or wallet keys.
See [isolation.md](isolation.md).
