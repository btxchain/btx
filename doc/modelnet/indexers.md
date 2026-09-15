# Model indexers (optional explorers)

Indexers are **optional** model-plane peers that cache and serve `ModelSearchRecord` metadata.
They are not consensus nodes, not monetary validators, and not required once a `btx://` digest is
known.

Anyone can run an indexer: a helper with index peers configured, periodic `exportmodelindex` /
`importmodelindex`, or a read-only site fed by exports. Multiple indexers **agree on ML-DSA-44
signature math** (`BTX/ModelSearchRecord/v1`) and **disagree on coverage**.

There is **no central telemetry**, no account/email gate, and no monetary coupling for indexing.

## NODE_MODEL_INDEX (model plane only)

`NODE_MODEL_INDEX` is advertised on index-capable peers (`getsearchpeers` → `capability`:
`NODE_MODEL_INDEX`, `monetary_service_bit: false`). It is **not** a Bitcoin P2P `NODE_*` bit and
must never appear in monetary `SeedsServiceFlags()` or AddrMan.

| Property | Rule |
|---|---|
| Purpose | Serve bounded search/index metadata to opted-in helpers |
| Payload | Metadata (`btx-model-search-v1` records); no automatic piece storage |
| Trust | Signature verification only; no global reputation score |
| Default | Off until operator adds index peers |

Monetary `btxd` may proxy client queries without running an index itself.

## Configuring index peers (helper)

| RPC | Behavior |
|---|---|
| `addmodelindex` | Parameter: `endpoint` string (host:port or forwarder). Adds to local index peer list. Response: `index_peers` count, `addrman: false`. |
| `removemodelindex` | Parameter: `endpoint` string. Removes peer. |
| `getsearchpeers` | Lists configured index peers with `NODE_MODEL_INDEX` capability. |

During `searchmodels` with `scope` ≠ `LOCAL`, the runtime merges hits from the local index and
**extras** bound to configured index stores (when connected). Coverage remains incomplete.

## Export / import

### `exportmodelindex`

Same handler as `listmodelsearchrecords`. Optional object argument:

| Field | Default | Max |
|---|---|---|
| `limit` | 100 | 100 |
| `updated_after` | 0 | filter hint (exported with response) |

Response:

```json
{
  "schema_version": 2,
  "sequence": 123,
  "records": [ "… ModelSearchRecord objects …" ],
  "updated_after": 0,
  "next_cursor": ""
}
```

Never includes wallet paths, monetary addresses, or query logs.

### `importmodelindex`

Request object:

```json
{ "records": [ "… ModelSearchRecord JSON …" ] }
```

Response:

```json
{
  "schema_version": 2,
  "imported": 0,
  "rejected": 0,
  "reverified": true
}
```

Each record passes `SearchRecordFromJson` + `SearchIndex::Put` (signature verify when signed;
unsigned cannot override signed; sequence rules apply).

## Client browse RPCs

Convenience views over the **local index** (and merged search runtime when scope allows):

| RPC | Sort / metric |
|---|---|
| `browsemodels`, `getnewmodels` | `NEWEST` |
| `gettrendingmodels` | `PROVIDERS` (`metric: observed_provider_growth_local`) |
| `getsimilarmodels` | Same family filter when `family` set |
| `getrecentreleases` | Default relevance/newest pipeline |

All responses include `global_complete: false`. UI must say **incomplete coverage**, not “all models
on BTX.”

## Search fan-out limits (peer protocol)

When indexers or routers forward `SearchRequest`:

| Parameter | Value |
|---|---|
| TTL default / max | 2 / 4 |
| Max fanout | 8 peers (`SEARCH_FANOUT_MAX`) |
| Dedup | `query_id` per node |

Unsigned gossip cannot override signed records on ingest.

## Privacy and abuse

- Indexers learn **query text** when participating in network scope searches; operators should use
  `scope: LOCAL` for sensitive strings ([search.md](search.md)).
- Rate limiting is local policy (`REJECTED` / `publisher spam` on index store).
- No protocol-level email signup or centralized query archive.

## Isolation

Indexer RPCs touch only the model metadata index (`SearchIndex`). They do not modify BanMan,
cs_main, or wallet keys.

## Optional HTTP

Normative peer search (when implemented on a peer): `POST /btx-model/2/ext/search`. Browser
`GET /api/v1/*` mirrors are convenience only — see [search.md](search.md).
