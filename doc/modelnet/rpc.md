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

**Release posture:** last shipping tag is **v0.34.7**. This tree is
**0.34.8-dev** (`CLIENT_VERSION_IS_RELEASE=false`). 0.34.8 is **not** a
shipping tag. First-run walkthrough: [first-run.md](first-run.md). CLI:
[../../contrib/modelnet/btx-model](../../contrib/modelnet/btx-model).

**User id:** `IdFromUser` / `ResolveUserId` accept a canonical `btx://`, a
hex digest, `share.copy_text` (first `btx://` token), or a local **alias**.
The URI has no query string.

**Privacy:** Network-scoped queries reveal text to consulted peers/indexers; use
`scope: LOCAL` for sensitive searches ([search.md](search.md)). Empty
`searchmodels` params are `LOCAL`.

Conceptual background: [search.md](search.md), [directory.md](directory.md),
[indexers.md](indexers.md).

## Implemented in this tree (baseline)

| RPC | Role |
|---|---|
| `getmodelnetworkinfo` / `getmodelcryptoinfo` | Schema 2, OpenSSL identity, PQ1 flags, **capabilities**, `automatic_spend_atoms=0` |
| `decoderesource` / `encoderesource` / `decoderesourceuri` / `encoderesourceuri` | Compact URI; no network |
| `openbtxuri` | Preview-only; never inference / mining / wallet |
| `resolveresource` | Typed lookup; coverage incomplete |
| `importmodel` | Stream hash + 4 MiB pieces; pin + signed search card by default (`publish:true`). Never executes pickle/.pt |
| `hostmodel` | Alias of `importmodel` (pin + signed search card + demand-seed). Returns `share` + `next_actions`. A `.btx` / copy_text path is **not** hashed as weights |
| `checkmodelsetup` | First-run doctor: `identity_ready`, `quota`/`pq1`, `remaining_bytes`, `ready_to_host`, `watch_dir`, `one_liner`, `next_actions`. Never spends |
| `previewmodelimport` | Size vs quota, `would_fit`, inferred family/format/quant; **no hash** |
| `getmodelsharecard` | `share.{uri,copy_text,family,format,quantization,signed}` for a local or search id, alias, or copy_text |
| `showmodel` | Ollama-show analog: `share`, local catalog, `aliases`, `bytes`, `next_actions` |
| `exportmodellink` | Write/return a `.btx` JSON magnet analog (canonical `uri` + `copy_text`) |
| `openmodelshare` | Preview-only parse of copy_text / `.btx` file / `btx://` (same contract as `openbtxuri`) |
| `unhostmodel` | Unpin + unseed in one call (does not delete catalog bytes) |
| `getmodeltransfers` | Torrent-style list: `state`, ratio, served/received, `share`; live job `percent`, `bytes_per_sec`, `eta_s`, `job_id` |
| `setmodelalias` / `getmodelaliases` / `removemodelalias` | Ollama-style alias; omit id on get to list all |
| `scanmodelwatch` | Host new GGUF/SafeTensors from `-modelwatch=` or an explicit path; skip when `would_fit` is false; `.btx` cards are **opened**, not imported as weights |
| `getmodelwatchstatus` | Side-effect-free watch-folder doctor: `watch_dir`, `configured`, `one_liner`. Never spends |
| `getsetupstatus` | `btxd` doctor: ExactReplay mining + helper `checkmodelsetup` when connected. Top-level `one_liner`. `money.headers` / `money.verificationprogress` when chainman is in scope |
| `getmininginfo.first_run` | `ready_to_mine`, `ibd`, `blocks`, `peer_count`, `headers`, `verificationprogress`, `one_liner`, `recommended_action`, `next_actions`, `min_peers`, `connections_total`, `uptime_s`, `version`. Not a hash lottery |
| `createbountydraft` / `listbountydrafts` / `getbountydraft` / `updatebountydraft` / `deletebountydraft` | Title-only drafts allowed (`recipe_complete=false`, `missing_fields`, `one_liner`). Incomplete stays unpublished. Patch/delete stay local. `automatic_spend_atoms=0` |
| `listmodels` | Local catalog; 0.34.8 adds `state`, `ratio`, `share`, `name`, `aliases`, `imported_at`; live retrieve `percent` / `bytes_per_sec` / `eta_s` / `job_id` |
| Search / directory / index (below) | Implemented in helper `DispatchHelperRpc` (`search.cpp`) |
| `getmodelmanifest` | Verified metadata |
| `exportmodelpath` | Verified local store root + source path + file list (`btx-model path`; `hf download --local-dir` analog); never starts a runtime |
| `seedmodel` / `unseedmodel` | Manual serve / stop. Default `seed=auto` already seeds after import/`getmodel`. Prefer `unhostmodel` to unpin+unseed together |
| `qualifymodel` | Structure only |
| `getmodel` | `FREE_ONLY` retrieve (URI, digest48, **alias**, or `copy_text`); demand-seeds when `seed=auto` |
| `getmodelpolicy` / `setmodelpolicy` | Free-first + propagation (`seed`, `preserve_rare`); non-zero automatic spend and `auto_pay` are refused |
| `addmodelnode` / `getmodelpeers` | Model-plane contacts, not AddrMan |
| `exportmodelcontacts` / `importmodelcontacts` / `exportmodelpeers` / `importmodelpeers` / `importmodeltrust` | Public endpoints; download cannot modify trust |
| `getmodeljob` / `cancelmodeljob` | Job list with `status`, `bytes_committed`, `pieces_committed`, `file_index`, `piece_index`, `inflight`, `peer_retries`, `last_err`, catalog `used_bytes` |
| `listmodelidentities` / `createmodelidentity` | Identity-only ML-DSA keys; never wallet keys. Helper creates a default identity on first start |
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

## First-run conveniences (0.34.8-dev)

People: [first-run.md](first-run.md). Agents: [agent-recipes.md](agent-recipes.md).
Copy-paste bodies: [../../contrib/modelnet/recipes/](../../contrib/modelnet/recipes/).
CLI: [../../contrib/modelnet/btx-model](../../contrib/modelnet/btx-model)
(`init`, `ls`, `show`, `pull`, `unhost`, `link`, `rm-alias`, `pause` /
`resume`, `bounty-draft --update` / `--delete`, plus round-1 verbs).
**0.34.8-dev** wrapper verbs `cloud`, `follow`, `events`, `mirror`,
`profile` fail closed if the helper lacks the method (`--json` agent door).
`automatic_spend_atoms` stays **0**. No auto-spend. No inference.
Pickle / `.pt` are refused. User ids parse `share.copy_text` (first `btx://`
token) and **aliases**. The URI has no query string (`dn=` stays on
`copy_text`). These methods exist in this development tree; they are **not**
a claim that 0.34.8 is released. Last shipping tag remains **v0.34.7**.

### checkmodelsetup

Helper doctor. No arguments.

**Response:** `identity_ready`, `quota` / `quota_bytes`, `remaining_bytes`
(quota minus used; `0` when quota is `0`), `pq1` / `pq1_ready`,
`ready_to_host`, `watch_dir`, **`one_liner`**, `next_actions[]`,
`automatic_spend_atoms: 0`.
`getmodelnetworkinfo` repeats the same doctor fields (`identity_id`,
`ready_to_host`, `next_actions`).

```bash
btx-cli checkmodelsetup
contrib/modelnet/btx-model init
contrib/modelnet/btx-model doctor
```

### hostmodel

Alias of `importmodel`: pin + signed search card + demand-seed by default.
Never spends. Never starts a runtime.

**Request:** filesystem `path`, optional `{ "pin", "publish" }`.

**Response:** catalog import object plus `share` (`uri`, `copy_text`, `family`,
`format`, `quantization`, `signed`) and `next_actions`. Pass `{"publish":false}`
to skip the signed card.

If `path` is a `.btx` link file or a text file whose contents are
`copy_text` / a `btx://` token, the helper does **not** hash it as weights.
It returns the share card and `next_actions` including `getmodel FREE_ONLY`
(same preview-then-retrieve path as `openmodelshare`).

```bash
btx-cli hostmodel /path/to/dir
btx-cli hostmodel /path/to/qwen3.btx
contrib/modelnet/btx-model host /path/to/dir
```

### previewmodelimport

Size versus quota. Inferred `family` / `format` / `quantization`. **Does not
hash** and does not write the catalog.

**Request:** filesystem `path`.

**Response:** `bytes`, `quota_bytes`, `would_fit`, inferred labels,
`hashes: false`, `automatic_spend_atoms: 0`.

### getmodelsharecard

Magnet analog for a local catalog id, search hit, alias, or `copy_text`.

**Request:** `model_id` (`btx://` URI, hex48, alias, or `share.copy_text`).

**Response:** `share` object as on import (`uri`, `copy_text`, family/format/quant,
`signed`). `automatic_spend_atoms: 0`.

### showmodel

Ollama `show` analog. Combines share card, local catalog row, aliases, and
size so agents do not need three RPCs.

**Request:** `model_id` (`btx://`, hex48, alias, or `copy_text`).

**Response:** `share`, `local` (known / downloaded / seeded / pinned),
`aliases[]`, `bytes`, `name`, `next_actions`, `automatic_spend_atoms: 0`.
Does not retrieve. Does not start a runtime.

```bash
btx-cli showmodel qwen3-local
contrib/modelnet/btx-model show qwen3-local
```

### exportmodellink

qBittorrent-style magnet **file**. Writes and/or returns a `.btx` JSON
object with the canonical URI and `copy_text`.

**Request:** `model_id` (URI / hex / alias / copy_text), optional filesystem
`path` (`.btx` destination).

**Response:** `link` (`uri`, `copy_text`, family/format/quant when known),
`path` when a file was written, `automatic_spend_atoms: 0`. Display names
stay on `copy_text`; the `btx://` URI has no query string.

```bash
btx-cli exportmodellink qwen3-local
btx-cli exportmodellink qwen3-local /path/to/qwen3.btx
contrib/modelnet/btx-model link qwen3-local /path/to/qwen3.btx
```

### openmodelshare

Preview-only open of a pasted card or `.btx` file. Same contract as
`openbtxuri`: never inference, never mining, never wallet.

**Request:** `copy_text`, a `btx://` token, or a filesystem path to a `.btx`
/ text file.

**Response:** decoded resource + `share` + `next_actions` (`getmodel
FREE_ONLY`, `getmodelsharecard`, …), `network: false`, `inference: false`,
`wallet: false`, `automatic_spend_atoms: 0`.

```bash
btx-cli openmodelshare /path/to/qwen3.btx
```

### unhostmodel

Stop seed + drop Keep in one call (`unpinmodel` + `unseedmodel`). Does
**not** delete catalog bytes.

**Request:** `model_id` (URI / hex / alias / copy_text).

**Response:** `pinned: false`, `seeded: false`, `next_actions`,
`automatic_spend_atoms: 0`.

```bash
btx-cli unhostmodel qwen3-local
contrib/modelnet/btx-model unhost qwen3-local
```

### getmodeltransfers

Torrent-style local list. No arguments.

**Response:** `transfers[]` with `uri`, `name`, `aliases`, `imported_at`,
`state`, `seeded`, `pinned`, `bytes`, `complete`, `served` / `received`
(useful bytes), `ratio`. When a retrieve job is live also `percent` (0–100
of payload), `bytes_per_sec`, `eta_s`, `job_id`.
`automatic_spend_atoms: 0`.

```bash
btx-cli getmodeltransfers
contrib/modelnet/btx-model transfers
contrib/modelnet/btx-model ls
contrib/modelnet/btx-model pause '<job_id>'   # cancelmodeljob; pieces stay
contrib/modelnet/btx-model resume qwen3-local # getmodel FREE_ONLY (same as pull)
```

`listmodels` rows carry the same `name` / `aliases` / `imported_at` columns
and the same live-job rate fields. `pause` does not invent a retrieve
scheduler: it is `cancelmodeljob`. `resume` is `getmodel` again.

### setmodelalias

Add an Ollama-style alias, re-sign the search record, bump `metadata_sequence`.
Not a wallet label.

**Request:** `(model_id, alias)`. `model_id` may be URI, hex, alias, or
copy_text.

**Response:** `model_id`, `alias`, `signed_metadata`, `automatic_spend_atoms: 0`.

`getmodelaliases` takes an **optional** id: omit it to list all local aliases.

### removemodelalias

Drop one Ollama-style name, re-sign, bump `metadata_sequence`.

**Request:** `(model_id, alias)`. If `model_id` is omitted / empty, `alias`
must uniquely identify a local record.

**Response:** `model_id`, `alias`, `removed: true`, `signed_metadata`,
`automatic_spend_atoms: 0`.

```bash
btx-cli removemodelalias '<model_id>' qwen3-local
contrib/modelnet/btx-model rm-alias qwen3-local
```

### scanmodelwatch

Scan `-modelwatch=<dir>` and host new GGUF / SafeTensors like `hostmodel`.
Idempotent via `watch-imported.json`. Empty watch dir is off. No arguments
required. Candidates with `would_fit: false` are **skipped** (not imported,
not hashed). A `.btx` / share file in the watch dir is **opened** as a card
(same preview as `openmodelshare`); it is not hashed as weights.

```bash
btx-cli scanmodelwatch
contrib/modelnet/btx-model watch-scan
```

### getmodelwatchstatus

Syncthing-style folder status. Reports the configured `-modelwatch=` path
without scanning or importing. No arguments.

**Response:** `watch_dir`, `configured` (false when the path is empty),
`one_liner`, `next_actions` (`scanmodelwatch`, `hostmodel <path>`),
`automatic_spend_atoms: 0`.

```bash
btx-cli getmodelwatchstatus
```

**Not the same as publisher watch.** `scanmodelwatch` / `getmodelwatchstatus`
are the filesystem drop folder (`-modelwatch=`). Publisher / collection
watches are the separate 0.34.8-dev names below. See [watches.md](watches.md).

### getsetupstatus

**`btxd` only** (not helper-only). Combines chain/mining first-run with helper
`checkmodelsetup` when the helper is connected. Never spends. Never starts
inference. Agents should read **`one_liner`** before walking nested objects.

**Response:** `one_liner`, `money` (ExactReplay readiness, including
`blocks` / `peer_count` / `headers` / `verificationprogress` /
`ready_to_mine` / `min_peers` when the mining chain guard is in scope),
`models` (helper doctor or fail-closed), `next_actions`,
`automatic_spend_atoms: 0`.

### getmininginfo.first_run

Additive JSON on **`btxd`** `getmininginfo`. Mining here is header-bound
**ExactReplay**, not a hash lottery. Hosting models does not require mining.

| Field | Meaning |
|---|---|
| `ready_to_mine` | Tip is not IBD and the chain guard is healthy |
| `ibd` / `initialblockdownload` | Still catching up |
| `blocks` | Local tip height |
| `peer_count` | Outbound peers the mining chain guard counts |
| `min_peers` | Configured minimum for a healthy guard decision |
| `headers` | Best header height (`getblockchaininfo.headers`) |
| `verificationprogress` | Estimate toward network tip, `0..1` |
| `connections_total` / `connections_out` | Live P2P counts (`null` if connman is unavailable) |
| `network_active` | Whether P2P is enabled |
| `uptime_s` / `version` | Process uptime and `btxd` version |
| `tip_age_s` | Seconds since the local tip's block time |
| `one_liner` | Single sentence for a status bar or agent |
| `recommended_action` | Chain-guard string |
| `next_actions` | Including `getsetupstatus` |
| `automatic_spend_atoms` | Always `0` |

### listbountydrafts / getbountydraft / updatebountydraft / deletebountydraft

Local incomplete drafts. Title-only `createbountydraft` stays unpublished
(`recipe_complete=false`, `missing_fields`, Gitcoin-style `checklist`,
**`one_liner`** naming the first *user* missing field — `terms_version` /
`network_id` / `requester_identity` are stamped at publish). Drafts also
return `copy_text: "draft_id=<hex>"` (not a `btx://` pay URI) and
`terms_id_preview` (canonical digest of the stored terms). CLI file form:
`btx-model bounty-draft @file.json` (JSON object as `params[0]`).
`--validate ID|@FILE|JSON` is `validatebountyterms` (same checklist; never
publishes). Do **not** invent a council. Every bounty mutation returns
`next_actions` and `automatic_spend_atoms=0`.

**Request:** `listbountydrafts` — none. `getbountydraft` — `draft_id`.
`updatebountydraft` — `(draft_id, patch)` or a single object with `draft_id`
plus fields to overlay (Gitcoin save-in-place). Never publishes.
`deletebountydraft` — `draft_id`; response `deleted: true`, `local_only`,
`one_liner`, `next_actions`.

```bash
btx-cli updatebountydraft '<draft_id>' '{"summary":"local save-in-place"}'
btx-cli deletebountydraft '<draft_id>'
contrib/modelnet/btx-model bounty-draft --validate '<draft_id>'
contrib/modelnet/btx-model bounty-draft --update '<draft_id>' '{"summary":"…"}'
contrib/modelnet/btx-model bounty-draft --delete '<draft_id>'
```

Full bounty catalogue: [../bounty-rpc.md](../bounty-rpc.md).

---

## Search and records

All methods below are dispatched by `DispatchHelperRpc` in `helper.cpp`.

### searchmodels

Bounded merge of local index (+ catalog ingest) and optional index peers when
`scope` ≠ `LOCAL`. **Empty params** (`[]` / no arguments) default **`scope`:**
`LOCAL` (this node's catalog). An explicit query object still defaults
`scope` to `NETWORK` unless you set it. Default **`sort`:** `RELEVANCE`.
`btx-model search` defaults `LOCAL`.

**Request** — string shorthand or object:

| Field | Type | Notes |
|---|---|---|
| `text` / `query` | string | Tokenized relevance search |
| `scope` | string | `LOCAL`, `PEERS`, `NETWORK`, `ALL`. Empty params → `LOCAL`. Query object default: `NETWORK` |
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
| `results` | Array of result cards (`share.copy_text` and `next_actions`, including `getmodel FREE_ONLY`) |
| `results_returned`, `total_candidates_seen` | Counts |
| `applied_filters`, `unsupported_filters` | Arrays |
| `note` | `current network view; not a complete global directory` |
| `remote_count` | Same as `coverage.responses_received` |

**Example**

```bash
btx-cli searchmodels
btx-cli searchmodels '{"text":"llama","scope":"NETWORK","limit":10}'
contrib/modelnet/btx-model search llama
contrib/modelnet/btx-model search --format gguf --max-size-bytes 8000000000 --sort size_asc
contrib/modelnet/btx-model search --fits
```

`btx-model search` names the object fields above (`--scope`, `--format`,
`--quantization`, `--family`, `--architecture`, `--publisher`, `--state`,
`--min-size-bytes`, `--max-size-bytes`, `--min-providers`, `--sort`,
`--limit`). `--fits` is **client-side** and local: it compares each card's
signed `size_bytes` against `checkmodelsetup.remaining_bytes` on this node and
drops what does not fit, reporting `fits.remaining_bytes` /
`dropped_too_large` / `dropped_size_unknown` (unknown stays dropped, never
guessed). It is a **storage** comparison, not a RAM/VRAM or inference claim.

**Errors:** `INVALID_PARAMETER` (bad scope/sort/query).

---

### getmodelsearchrecord

**Request:** `model_id` — `btx://` URI or hex48.

**Response:** Full `ModelSearchRecord` (`type: btx-model-search-v1`) + `locally_cached: true`.

**Errors:** `NOT_FOUND`, `INVALID_PARAMETER`.

---

### publishmodelsearchrecord

**Request:** `(model_id, record)` — id string + record object ([search.md](search.md)).
Creates a local research identity if none exists and always signs with
`BTX/ModelSearchRecord/v2`. Not a wallet spend. Re-publish of an existing id
bumps `metadata_sequence`.

**Response:** `schema_version`, `model_id`, `sequence` (`metadata_sequence`),
`automatic_spend_atoms: 0`, `wallet_key: false`, `signed_metadata`.

**Errors:** `INVALID_PARAMETER`, `REJECTED` (verify, cap, spam), `CRYPTO`.

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

**Request:** optional `model_id` (`btx://` URI, hex48, alias, or
`copy_text`). Omit the id (empty params) to list **all local** aliases.

**Response:** `aliases[]` with `{ alias, provenance }` (`publisher_metadata` vs
`unsigned`), plus `model_id` / `uri` when listing. `automatic_spend_atoms: 0`.
Use `setmodelalias` to add a name and re-sign; `removemodelalias` to drop
one. `getmodel` / `showmodel` / `btx-model pull` resolve these names.

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

0.34.8-dev local drafts (`automatic_spend_atoms` stays **0**; not a shipping
tag): `createbountydraft` accepts title-only incomplete drafts
(`recipe_complete=false`, `missing_fields`, `one_liner`, unpublished) and a
JSON object from `btx-model bounty-draft @file.json`. `listbountydrafts` /
`getbountydraft` inspect. `updatebountydraft` patches in place.
`deletebountydraft` drops a local draft. Do not invent a publishable council.
Do not collapse prepare/sign/submit.

---

## 0.34.8-dev cloud / events / watches / profile (not a shipping tag)

These helper RPCs **exist** in this 0.34.8-dev tree
(`CLIENT_VERSION_IS_RELEASE=false`). **`btx-model` still fails closed** if an
older helper is missing the method. This is **not** a shipping catalogue.
No PASS. Live HTTPS/R2 WAN is **NOT_RUN** (OpenSSL HTTPS transport is
compiled; no live origin round-trip). SCALE huge / 400GiB body stream is
**NOT_RUN**. GUI is source-only (`BUILD_GUI=OFF`; `bitcoin-qt` was not built
here). Secrets never appear in responses. `automatic_spend_atoms` is always
**0**. SubscriptionMandate `wallet_signed=false` is intentional. Dual door:
people [first-run.md](first-run.md); agents `--json` +
[agent-recipes.md](agent-recipes.md).

Layout and R2 AUTO: [storage-backends.md](storage-backends.md),
[cloud-seeding.md](cloud-seeding.md). Events: [events.md](events.md).
Watches: [watches.md](watches.md). Profiles/mirror: [mirroring.md](mirroring.md).

| RPC | Role | Status |
|---|---|---|
| `getcloudstorageinfo` | Health/config **without secrets** | 0.34.8-dev; fail closed if missing |
| `testcloudstorage` | Local probe (not a WAN receipt) | same |
| `setcloudstorage` | Local origin config; secrets **in** via `credential_ref` only, never out | same |
| `getmodelprofile` / `setmodelprofile` | Config presets PERSONAL / INFRASTRUCTURE / MIRROR / CUSTOM | same |
| `watchmodelpublisher` / `watchmodelcollection` / `watchmodelquery` / `watchmodel` | Follow; default action NOTIFY | same |
| `listmodelwatches` / `getmodelwatch` / `unwatchmodel` | Not `getmodelwatchstatus` (folder) | same |
| `getmodelevents` / `getmodeleventsequence` / `waitformodelevent` | Local journal; `--wait` must not hang on unknown RPC | same |
| `getmodelmirror` / `setmodelmirror` | Declarative keep/follow; no auto-spend | same |
| `executemodelimport` / `getmodelimport` | ImportPlan staging until VerifiedManifest. HF/torrent integrity ≠ authorship. **No live HF HTTP** | same |
| `createbtxpackage` / `inspectbtxpackage` / `exportbtxbundle` | Core v2 unsigned REGTEST/TESTNET `.btx` (BTX-PJSON1). `exportmodellink` stays the JSON magnet analog. MAINNET unsigned create is rejected. | same |
| `verifybtxpackage` | Fail-closed: UNSIGNED_PACKAGE / SIGNATURE_FAIL. Inspect remains available without a signature. | same |
| `getbtxpackagedocument` | Inert escaped virtual document (`document` / `document_path`). Never writes project or home `AGENTS.md`. | same |
| `getbtxpackagecapabilities` | `BTXPKG_CORE_V2`, `AGENT_HANDOFF_V1`, `wallet_sign=false`, `automatic_spend_atoms=0`, `writes_project_agents_md=false`, `remote_inference=false`. GUI DEFERRED. | same |
| `planbtxacquisition` / `executebtxacquisition` / `getbtxacquisition` / `cancelbtxacquisition` | FREE_ONLY + NATIVE_ONLY plan. Execute does not forge `manifest_verified`. No auto-spend. | same |
| `planbtxclientinstall` | InstallPlan only. TRUST_REQUIRED without an independently trusted catalogue. Does not install. | same |
| `planbtxruntime` | RuntimePlan only. Does not execute. Missing receipt → MODEL_BYTES_UNVERIFIED. | same |
| `preparemodelerasure` / `getmodelerasurehealth` | Per-stripe reconstructability. Global `n` is **not** sufficiency | same |
| `gettorrentsourcestatus` | Packaged torrent bridge. `btx-torrentd` is **not** a process | same |
| `getmodeloriginoffer` | Native PQ1 proxy default. Presigned GET is **not** a meter | same |
| `querymodelsummary` / `reconcilemodelindex` | Sample cap 32 / want cap 256. Digests do not authorize insert | same |
| `getmodelobjectlayout` | WHOLE_FILE / LARGE_EXTENTS / PIECE_OBJECTS arithmetic. Does **not** replace R2 `SOURCE_FILES` | same |
| `validatesubpiece` | SUBPIECE_V1 256 KiB. Overlap/overflow rejected. Partial pieces are not advertised | same |
| `getevaluatedtransport` | uTP **NONSHIPPING**, `quic=false`, live R2 WAN **NOT_RUN** | same |
| `addmodelstorage` / `listmodelstorage` / `inspectmodelstorage` | **Aliases** of `setcloudstorage` / `getcloudstorageinfo` / `testcloudstorage` | same |
| `removemodelstorage` | Detach local handle. **Does not** delete remote objects | same |
| `getmodelcapabilities` | Alias of `getmodelnetworkinfo` | same |
| `getmodelresidency` / `getmodeldedupinfo` / `getmodelfileselection` / `getmultipartjournal` / `getmodellandiscovery` / `getsourcepolicy` | Residency, physical-byte reuse (CDC NONSHIPPING), SELECTIVE_FILES, MPU journal (ETag ≠ identity), LAN, SSRF | same |
| `setbootstrapdistributor` / `getbootstrapstatus` / `setmodeluploadpolicy` / `getmodelroutingstatus` | Truthful bootstrap, finite upload slots, LAN/delegated routing diagnostics | same |

Libraries for HF/Xet/torrent/erasure/DRR exist and are unit-tested. Live Hugging Face HTTP, `btx-torrentd` as a helper process, live R2 WAN, SCALE huge, GUI (`BUILD_GUI=OFF`), and wallet-signed SubscriptionMandate remain **NOT_RUN** / operator-gated. `automatic_spend_atoms` stays **0**.

Credentials: `credential_ref` = `env:BTX_CLOUD_CREDENTIAL` or a 0600 file
path. Never argv `--secret`. R2 AUTO → `SOURCE_FILES` + `STREAM_FILE`.
`PIECE_OBJECTS` on R2 requires `allow_request_heavy_cloud_layout`.

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
