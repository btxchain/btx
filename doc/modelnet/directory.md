# Model directory (observed view)

The **directory** is the helper’s merged view of each `model_id`: search metadata, **observed**
provider piece ranges, swarm health, and local catalog flags. It is not a centralized database and
never globally complete.

Language rule: use **observed providers** and **current network view**. Never claim global
completeness.

Implementation reference: `DirectoryEntryJson`, `SearchResultCard`, `ComputeSwarmHealth` in
`src/modelnet/search.cpp`; RPC handlers in `DispatchHelperRpc`.

## Directory entry

Returned by `getmodeldirectoryentry`, listed by `getmodeldirectory`, and embedded in search
`results[]`.

A directory entry is a **result card** plus:

| Extra field | Content |
|---|---|
| `metadata` | Full `ModelSearchRecord` JSON (`type: btx-model-search-v1`) |
| `swarm` | Same object as `availability` on the card (swarm health summary) |

Core card fields:

| Field | Meaning |
|---|---|
| `schema_version` | `2` |
| `model_id`, `artifact_id`, `uri` | Typed roots |
| `name` | `display_name` or `canonical_name` |
| `publisher` | `{ id, display_name }` |
| `availability` | Observed swarm metrics (below) |
| `local` | `{ known, downloaded, partial, seeded, pinned, qualification }` |
| `release` | `{ id, state }` |
| `search` | `{ score, metadata_verified, provenance }` |
| `sources` | Count of merged index sources for this hit |

Entries combine:

1. Local search index (records, catalog ingest)
2. `g_search_obs` provider observations (from seeded catalog entries and future PEX)
3. Local catalog admission/seed/pin flags

No single field means “the network definitely has this model.”

## Observed providers vs global census

| Concept | Definition |
|---|---|
| **Observed provider** | An entry in this node’s provider observation list for the model (id, endpoint, piece ranges, complete flag, direct/relay) |
| **Global census** | **Not available** — use `getmodelpeercount` for contact/dial stats, not replica counts |

`getmodelproviders` returns the **observed** list for one `model_id`:

```json
{
  "schema_version": 2,
  "providers": [
    {
      "provider_id": "hex48-or-label",
      "reachability": "direct|relay",
      "complete": false,
      "last_seen": 0,
      "direct": true,
      "relayed": false
    }
  ]
}
```

`getmodelpeercount` returns aggregate **provider observation** counts for the model’s swarm snapshot:

```json
{
  "schema_version": 2,
  "total": 0,
  "complete": 0,
  "partial": 0,
  "reachable_direct": 0,
  "reachable_relay": 0,
  "observed_provider_count": 0,
  "note": "this node's current network view; not a global census"
}
```

Provider records mean “this identity offered these ranges recently,” not “globally online forever.”

## Reconstructable

**Reconstructable** is computed from the **union of observed piece ranges** across providers
(`UnionCoversAll`): every piece index must appear in at least one provider range. When
`pieces_total` is unknown (0), health falls back to “providers exist → HIGH, else UNKNOWN.”

Reconstructable is not a promise of speed, free supply, or permanent availability.

## Availability classes

Enum (`AvailabilityClassName`): **`EXCELLENT`**, **`HIGH`**, **`MEDIUM`**, **`FRAGILE`**,
**`DEGRADED`**, **`UNKNOWN`**.

When `pieces_total > 0` and observations exist:

| Class | Condition (simplified) |
|---|---|
| `UNKNOWN` | No observations |
| `DEGRADED` | Union of ranges does not cover all pieces |
| `FRAGILE` | Reconstructable but at least one piece has exactly one source |
| `EXCELLENT` | Reconstructable, ≥3 complete providers, `min_piece_sources` ≥ 3 |
| `HIGH` | Reconstructable, ≥1 complete provider, not EXCELLENT |
| `MEDIUM` | Reconstructable, partial providers only |

When `pieces_total == 0`: `UNKNOWN` if no obs, else `HIGH` (reconstructable flag set from obs).

`getmodelavailability` returns `AvailabilityJson` plus `model_id`:

```json
{
  "schema_version": 2,
  "model_id": "…",
  "providers_total": 0,
  "providers_complete": 0,
  "providers_partial": 0,
  "min_piece_sources": 0,
  "pieces_with_0_sources": 0,
  "pieces_with_1_source": 0,
  "pieces_with_2_sources": 0,
  "reconstructable": false,
  "reconstructable_known": false,
  "missing_piece_count": 0,
  "fragile": false,
  "class": "UNKNOWN",
  "observed_provider_count": 0,
  "global_complete": false
}
```

`global_complete` is **always false** on the wire.

## `getmodeldirectory`

Optional query object (same parser as `searchmodels`). Forces internal scope `ALL`, returns:

```json
{
  "schema_version": 2,
  "results": [ "… directory entries …" ],
  "global_complete": false
}
```

Pagination uses `limit` (default 50, max 100) and `offset` on the search query, not a separate
cursor field in the current helper.

## `getnetworkmodelstats`

Local counters only:

- `models_known`, `search_records_known`, `index_records` — search index size
- `models_local` — from catalog list
- `searches_running`, `searches_completed`
- `coverage_disclaimer`: `this node's observations only`
- `global_complete`: false
- `automatic_spend_atoms`: 0

## Policy overlays (local only)

- **Hidden** models: excluded from `SearchIndex::Search` hits; still fetchable by exact id RPCs.
- **Muted publishers**: excluded from search hits; signatures still verify if fetched directly.

See `hidesearchmodel`, `mutesearchpublisher` in [rpc.md](rpc.md).

## RPC and HTTP

- JSON-RPC: [rpc.md](rpc.md)
- Peer HTTP availability: `POST /btx-model/2/availability` ([http.md](http.md))
- Optional federated search: `POST /btx-model/2/ext/search` ([search.md](search.md))

## Isolation

Directory and search RPCs do not touch BanMan, monetary AddrMan, cs_main, or wallet spend paths.
`NODE_MODEL_INDEX` is a **model-plane capability**, not a Bitcoin `NODE_*` service bit.
