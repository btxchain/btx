# Third-party explorers

Anyone can build a model-economy explorer from supported RPCs only.
No permission, no email, no internal files, no log parsing.

## Minimum surface

| Job | RPC |
|---|---|
| Search (name / use case) | `searchmodels` |
| Economy card | `getmodeleconomyentry` |
| Feed | `getmodelfeed` |
| Fundable | `getfundablemodels` |
| Unlocked | `getrecentlyunlockedmodels` |
| Campaign math | `getmodelreleaseeconomics` |
| Unsigned fund plan | `preparefundmodelrelease` then wallet sign/submit |
| Availability | `getmodelavailability` / `getmodelproviders` |

Browser `GET /api/v1/feed` is a disclosed-weaker decode stub. Native PQ
unix RPC / `btxd` proxy is authoritative. **No unauthenticated funding writes.**

Reference client: `contrib/modelnet/reference-economy-client/`.

Bounty list/detail (read-only `GET /api/v1/bounties` only):
`contrib/modelnet/explorer-bounties/`. See [../bounties.md](../bounties.md).

Example:

```
btx-cli searchmodels '{"text":"coding agent","scope":"NETWORK"}'
btx-cli getmodelfeed '{"scope":"NETWORK","mode":"NEARLY_FUNDED"}'
btx-cli getmodeleconomyentry <model_id>
```

Network search queries may be visible to consulted peers. Use
`scope=LOCAL` when that matters. Funding is on-chain and observable.
Peer counts are **providers observed**, not global copies.

`automatic_spend_atoms` remains 0. Agents must not spend without explicit
wallet authorization.
