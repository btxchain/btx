# Collections, aliases, policy bundles, circles

Normative: root addendum §9 (D08). Qt collection pages are **out of scope**.

v1.1 D08: signed community objects. They organize **which models to keep
and introduce**, not what the chain considers valid.

| Object | Purpose |
|---|---|
| Collection | Signed set of model/artifact roots |
| Alias | Human label bound to a resource URI; not a DNS hijack of `btx://` |
| Policy bundle | Local free-first / quota / give-back preferences |
| Preservation circle | Who agrees to retain which roots, with caps |

None of these objects:

- change ExactReplay or issuance
- create a global reputation token
- replace content verification (SHA-384 still wins)

Wire layouts and schemas live under `contrib/modelnet/schemas/` and
`contrib/modelnet/reference/`. Live router persistency is incomplete;
`listmodels` reports `coverage: incomplete` until that store exists.
