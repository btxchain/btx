# Model events (0.34.8 surface)

**Candidate and evidence:** this source tree is **0.35.0rc1** (`CLIENT_VERSION_IS_RELEASE=true`, `CLIENT_VERSION_RC=1`); the last shipping tag recorded here is **v0.34.15**. A release-build flag is not native qualification. See [native participation and release evidence](swarm/16_NATIVE_EXECUTION_AND_RELEASE_EVIDENCE.md) for the current defaults, RPC observations, complete helper build, and remaining hardware/deployment gates. Older version-labelled sections below describe their historical surface introduction.

**Status:** this tree is **0.35.0rc1**. The last shipping tag remains
**v0.34.15**. `getmodelevents` /
`getmodeleventsequence` / `waitformodelevent` exist in this helper (unit-
tested). The CLI wrapper **fails closed** if an older helper lacks the
method. An unknown helper RPC returns `METHOD_NOT_FOUND` immediately (no
hang). Live helper-death log dump is **NOT_RUN** (no `btx-modeld` spawn).
This page is not a PASS and not WAN evidence. Live HTTPS/R2 remains
**NOT_RUN**.

CLI: `contrib/modelnet/btx-model --json events [--cursor N] [--wait SEC]`.
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

The CLI accepts finite seconds in `0..86400` and converts a positive wait
to integer `timeout_ms` for the native helper. Direct Unix RPC uses
milliseconds, not `wait_s` or `timeout_s`:

```json
{"jsonrpc":"1.0","id":1,"method":"waitformodelevent","params":[{"cursor":"12","timeout_ms":5000}]}
```

The native response contains `events`, a decimal-string `cursor`, `timeout`
and `interrupted`. `getmodeleventsequence` returns numeric `sequence`.
The CLI exposes the returned native cursor as `next_cursor`; use that value
for the next page or wait instead of repeating the requested cursor.

## RPC (this 0.35.0rc1 helper; build flag `CLIENT_VERSION_IS_RELEASE=true`, native qualification separate)

| RPC | Role |
|---|---|
| `getmodelevents` | Page from `cursor` (nullable). Bounded. |
| `getmodeleventsequence` | Current local sequence |
| `waitformodelevent` | Long-poll; timeout, cursor, interrupt on shutdown. Not a shell. |

Existing **bounty** `watchbounty` / `getbountyevents` remain. The journal
**normalizes** those observations; it does not replace `FeedStore`.

Filesystem `-modelwatch` / `scanmodelwatch` are **not** this journal. See
[watches.md](watches.md).
