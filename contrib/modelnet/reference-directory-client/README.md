# Reference directory client

Tiny third-party explorer that talks to **only** `btx-modeld` over its unix
JSON-RPC socket (one JSON object per line: `jsonrpc`, `id`, `method`, `params`).
No wallet, no `btx-cli`, no HTTP bridge, no catalog files on disk.

Contract: [doc/modelnet/rpc.md](../../../doc/modelnet/rpc.md) (search + directory
section). Responses use `schema_version: 2`; coverage is always incomplete.

## Prerequisites

- A running `btx-modeld` with `-modelrpcsocket=/path/to/modeld.sock`
- Python 3.10+ (stdlib only)

Default socket when launched under `btxd` is under the model data directory;
researcher-only runs pass `-modelrpcsocket` explicitly (see
[contrib/modelnet/e2e-local-helper.sh](../e2e-local-helper.sh)).

## Run

```bash
export MODELD_SOCK=/path/to/modeld.sock

# Tab-separated cards: name, providers_total, availability_class, reconstructable, publisher, uri
python3 directory_client.py browse
python3 directory_client.py new
python3 directory_client.py search "qwen coder"
python3 directory_client.py detail 'btx://MODEL/…'
python3 directory_client.py availability 'btx://MODEL/…'
python3 directory_client.py peercount 'btx://MODEL/…'
python3 directory_client.py providers 'btx://MODEL/…'
python3 directory_client.py publishers "lab"
python3 directory_client.py collections "vision"
python3 directory_client.py stats

./demo.sh
```

Or import from another script:

```python
from directory_client import search, browse, model_detail, network_stats
```

Paged RPCs (`browsemodels`, `getnewmodels`, `searchmodels`, `searchpublishers`,
`searchcollections`, `getmodeldirectory`) follow an opaque `cursor` until exhausted.
List pages expose `results[]` (the client also accepts legacy `models[]`).

Directory cards use helper fields: `name`, `uri`, `availability.class`,
`availability.providers_total`, `availability.reconstructable`, and
`publisher.display_name`. `getmodelavailability` returns `class` and `providers_*`
at the top level (`AvailabilityJson`). `getmodelpeercount` returns
`total`, `complete`, and `partial`. Publisher rows use `id`, `display_name`, and
`model_count_observed`.

## RPC methods used

| Python helper      | JSON-RPC method           |
|--------------------|---------------------------|
| `search(text)`     | `searchmodels`            |
| `browse()`         | `browsemodels`            |
| `new_models()`     | `getnewmodels`            |
| `model_detail(id)` | `getmodeldirectoryentry`  |
| `availability(id)` | `getmodelavailability`    |
| `peercount(id)`    | `getmodelpeercount`       |
| `providers(id)`    | `getmodelproviders`       |
| `publishers(text)` | `searchpublishers`        |
| `collections(text)`| `searchcollections`       |
| `network_stats()`  | `getnetworkmodelstats`    |

Methods not yet implemented in a given build may return `NOT_ENABLED`; the
client surfaces the RPC error on stderr.

## Notes

- Observed provider counts are a **local network view**, not a global census.
- No secrets or keys are read or stored.
- For a quick sanity check against a live helper, use `./demo.sh` with
  `MODELD_SOCK` set.
