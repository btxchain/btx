# Model events (0.34.8-dev)

**Status:** **0.34.8-dev** (`CLIENT_VERSION_IS_RELEASE=false`). Not a shipping
tag. Last shipping tag is **v0.34.7**. `getmodelevents` /
`getmodeleventsequence` / `waitformodelevent` exist in this helper (unit-
tested). The CLI wrapper **fails closed** if an older helper lacks the
method. An unknown helper RPC returns `METHOD_NOT_FOUND` immediately (no
hang). Live helper-death log dump is **NOT_RUN** (no `btx-modeld` spawn).
This page is not a PASS and not WAN evidence. Live HTTPS/R2 remains
**NOT_RUN**. `CLIENT_VERSION_IS_RELEASE=false`.

CLI: `contrib/modelnet/btx-model events [--cursor N] [--wait SEC] --json`.
Recipe: [../../contrib/modelnet/recipes/events.json](../../contrib/modelnet/recipes/events.json).
Watches: [watches.md](watches.md). Feed (existing): [feed.md](feed.md).

People read [HUMANS.md](../../HUMANS.md) and [first-run.md](first-run.md).
Agents read [AGENTS.md](../../AGENTS.md). `--json` is the agent door
(stdout only). Humans also get stderr `one_liner` / `next` unless `--json`.

## What an event is

Events are **local observations** of verified feed / bounty / catalog
transitions. They are not consensus, not a second discovery system, and not
piece-level spam.

The journal (when present) is an append-only local sequence:

`event_id`, `local_sequence`, `event_type`, `observed_at`, `object_kind`,
`object_id`, `publisher_id`, `collection_id` (nullable), `record_sequence`,
`source`, `verification_state`, `old_state`, `new_state`, `model_id`,
`release_id`, `bounty_id`, `terms_id`, `funding`, `provenance`, `dedupe_key`.

Missing fields stay **JSON null**. `automatic_spend_atoms` is **0**. Events
never spend.

One logical occurrence has one `dedupe_key`. Reorgs emit **corrective**
events (`*_REVERTED`, `FUNDING_CHANGED`). They do not silently delete the
original.

Untrusted event text is never a shell command, wallet instruction, path, or
mandate.

## CLI

```bash
contrib/modelnet/btx-model --json events
contrib/modelnet/btx-model --json events --cursor 0
contrib/modelnet/btx-model --json events --cursor 12 --wait 5
```

`--wait SEC` calls `waitformodelevent` only after a **probe** of
`getmodelevents`. If that method is missing, the wrapper exits immediately
(does not hang for `SEC`). `--wait 0` is no wait. `DispatchHelperRpc` of an
unknown method is `METHOD_NOT_FOUND` immediately; `automatic_spend_atoms`
is not required on that error.

## RPC (0.34.8-dev helper; `CLIENT_VERSION_IS_RELEASE=false`)

| RPC | Role |
|---|---|
| `getmodelevents` | Page from `cursor` (nullable). Bounded. |
| `getmodeleventsequence` | Current local sequence |
| `waitformodelevent` | Long-poll; timeout, cursor, interrupt on shutdown. Not a shell. |

Existing **bounty** `watchbounty` / `getbountyevents` remain. The journal
**normalizes** those observations; it does not replace `FeedStore`.

Filesystem `-modelwatch` / `scanmodelwatch` are **not** this journal. See
[watches.md](watches.md).
