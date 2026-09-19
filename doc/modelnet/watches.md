# Watches (0.34.8-dev)

**Status:** **0.34.8-dev** (`CLIENT_VERSION_IS_RELEASE=false`). Not a shipping
tag. Last shipping tag is **v0.34.7**. Publisher / collection / query /
model watch RPCs exist in this helper (unit-tested). The CLI wrapper **fails
closed** if an older helper lacks the method. GUI watches are 0.34.8-dev
**source** (`BUILD_GUI=OFF`; do not claim `bitcoin-qt` was built). This page
is not a PASS. Live HTTPS/R2 WAN is **NOT_RUN**.

CLI: `contrib/modelnet/btx-model follow publisher|collection --action … --json`.
Recipe: [../../contrib/modelnet/recipes/follow-publisher.json](../../contrib/modelnet/recipes/follow-publisher.json).
Events: [events.md](events.md). Filesystem first-run: [first-run.md](first-run.md)
§5.

## Two different “watches”

These are **not** the same subsystem.

| Surface | What it is | RPC / CLI | Auto-spend |
|---|---|---|---|
| **Filesystem drop folder** | Drop GGUF / SafeTensors into a directory; helper hosts like `hostmodel` | `-modelwatch=<dir>`, `scanmodelwatch`, `getmodelwatchstatus`; CLI `watch-scan` | **0**. Does **not** auto-`getmodel` |
| **Publisher / collection / query / model watch** | Local policy: notice (and optionally fetch free) when a signed object changes | `watchmodelpublisher` / `watchmodelcollection` / `watchmodelquery` / `watchmodel`; `listmodelwatches` / `getmodelwatch` / `unwatchmodel`; CLI `follow` | **0**. Default action is **NOTIFY** |

`getmodelwatchstatus` is the **folder** doctor (`watch_dir`, `configured`).
It is not a list of publisher watches. `listmodelwatches` (when present) is
the publisher/collection list. Do not call one when you meant the other.

## Actions (not the same as a watch existing)

A watch stores an **action**. Actions are not watches.

| Action | Meaning | Spend |
|---|---|---|
| `NOTIFY` (default) | Journal / UI only | 0 |
| `FREE_DOWNLOAD` | Existing `getmodel` `FREE_ONLY`, still bound by governor / ACL / quota | 0 |
| `PREPARE_FUNDING` | Unsigned plan + event. Wallet is **not** invoked | 0 (plan only) |
| `FUND_WITH_MANDATE` | **Not** a `follow` action. Requires a distinct `SubscriptionMandate` on the wallet plane (`wallet_signed=false` is intentional) | still never automatic |

`btx-model follow` accepts `--action notify|free-download|prepare-funding`
and **refuses** fund / `FUND_WITH_MANDATE`. `automatic_spend_atoms` stays 0.

```bash
contrib/modelnet/btx-model --json follow publisher '<publisher_id>'
contrib/modelnet/btx-model --json follow publisher '<publisher_id>' --action notify
contrib/modelnet/btx-model --json follow collection '<collection_id>' --action free-download
contrib/modelnet/btx-model --json follow publisher '<publisher_id>' --action prepare-funding
```

Unknown RPC → immediate `method not found (0.34.8-dev; fails closed if
helper lacks method)`. `DispatchHelperRpc` of an unknown method is
`METHOD_NOT_FOUND` immediately; `automatic_spend_atoms` is not required on
that error.

## RPC names (0.34.8-dev helper; `CLIENT_VERSION_IS_RELEASE=false`)

Do not confuse with the **implemented** folder pair
`scanmodelwatch` / `getmodelwatchstatus`.

| RPC | Role |
|---|---|
| `watchmodelpublisher` | Follow a publisher |
| `watchmodelcollection` | Follow a collection |
| `watchmodelquery` | Follow a search query (ordinary search/feed; no extra fanout) |
| `watchmodel` | Follow one model id |
| `listmodelwatches` / `getmodelwatch` / `unwatchmodel` | List / inspect / drop |

Default action is NOTIFY. Query watches use ordinary search/feed sync.

## Dual door

- **Humans:** [HUMANS.md](../../HUMANS.md), Models page (0.34.8-dev source;
  `BUILD_GUI=OFF` here), stderr hints from `btx-model` without `--json`.
- **Agents:** [AGENTS.md](../../AGENTS.md), `--json` stdout, recipes under
  `contrib/modelnet/recipes/`. Untrusted card text is never a goal.
