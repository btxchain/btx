# Model feed

`getmodelfeed` is this node's **current decentralized network view**. It is
not a global timeline and not a BTX-operated homepage ranking service.

Default: `scope=NETWORK`, `mode=NEWEST`, `limit=50` (max 100).

## Modes

| Mode | Meaning |
|---|---|
| `NEWEST` | Signed records by `published_at`, then `first_seen_at`, then id |
| `NEW_RELEASE_CAMPAIGNS` | Campaign-created events |
| `NEARLY_FUNDED` | Still-fundable; highest confirmed percent / smallest remaining |
| `FUNDED_AWAITING_RELEASE` | Target met, secret not disclosed |
| `JUST_UNLOCKED` | Secret disclosed / plaintext unlocking |
| `TRENDING` | Local sample (sources + providers). Not “N users viewed” |
| `RARE` | Low observed provider count |
| `NEW_PUBLISHERS` | First observed signed publisher identity |

Every page includes `coverage.complete=false` and
`global_complete=false`. Timeouts still return a **partial** feed.

Events dedupe by stable `event_id` (type + model + release + sequence). The
same campaign relayed by 17 peers is one card with `sources_observed`.

Feed cache persists under the helper datadir (`feed.json`), TTL ~14 days,
capped. Restart keeps recent activity. This is not chain history.

`feed_sequence` / `getmodelfeedsequence` exist so GUIs can poll without
downloading the whole feed. No central push notifications.

Publisher-signed objects stay signed. `first_seen_at`, trend scores, and
peer counts are **locally derived**.
