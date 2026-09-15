# Propagation — demand default, bounded preserve-rare

v1.1 **D11**. Unsolicited fetch of arbitrary advertised models stays off.
Packaged installs allocate a **bounded AUTO** cache (`-modelstorage=auto`)
on the model-store filesystem. `-modelstorage=0` is the explicit no-payload
setting. Explicit numeric quotas remain FIXED.

Once a user **intentionally** retrieves or imports a qualified
redistributable public model, the default policy **retains and
re-advertises** it inside that budget. Nodes with catalog contacts
(`-modelpeer`, `addmodelnode`, and PEX-learned endpoints) **also follow**
those peers' FREE seeded catalogs into spare quota. That is how a new
participant learns models without calling `getmodel`, the same shape as
Tor needing at least one bootstrap contact then learning more relays.
Arbitrary advertised models from unknown gossip are still not fetched
unless preserve-rare is on.

This is not IPFS “addressable therefore everywhere”. Somebody has to
retain a replica. BTX combines real demand, automatic reseeding, observed
rarity, local budgets, and native money when voluntary supply is not enough.

## Behaviors

```
download / import M
    → verify chunks
    → retain according to local storage budget
    → automatically advertise what you have     (seed=auto)
    → serve it to other peers
    → network gains another replica
```

| Kind | Trigger | Default |
|---|---|---|
| **Demand** | Intentional `importmodel` / `getmodel` | On when storage > 0 and `-modelseed=auto` |
| **Peer follow** | A catalog contact announces a FREE seeded model that fits spare quota | On (`-modelfollowpeers=1`) |
| **Preservation** | Spare quota + observed sources ≤ 2 | Off unless `-modelpreserverare` |
| **Release** | Local decrypt of a qualified public artifact after key reveal | Demand-seed the **plaintext** identity |

## Flags (`btx-modeld`)

| Flag | Default | Meaning |
|---|---|---|
| `-modelstorage=` / `-modelcache=` | `auto` | AUTO budget, `0` (no payload), or `80GiB` (FIXED) |
| `-modelseed=auto\|manual\|off` | `auto` | Auto = seed on intentional download. `manual` = only `seedmodel`. `off` = never auto-advertise |
| `-modelseedupondownload=0\|1` | B0 alias | `1` → auto, `0` → off. **Not** a second opt-in; ignored when `-modelseed` is set |
| `-modelpreserverare` | off | Unsolicited fetch of under-replicated **qualified** public models into spare space. At most one fetch per 5s tick |
| `-modelfollowpeers` | on | Follow FREE models announced by catalog contacts (`-modelpeer`, `addmodelnode`, PEX) into spare quota. Disable with `=0` |
| `-modeluploadlimit=` | 0 | Serving cap (bytes/s). 0 = existing connection ceilings only |
| `-modelallowencrypted` | off | Permit preserve-rare and peer-follow of `ENCRYPTED_UNQUALIFIED` ciphertext |

`getmodelpolicy` / `setmodelpolicy` expose the same fields. `auto_pay` and
non-zero automatic spend remain refused.

`getmodelnetworkinfo.propagation` reports `demand_propagation`,
`peer_follow_propagation`, `preservation_propagation`, and
`release_propagation`. The helper polls catalog contacts every **5s**.
Governor `preservation_allowed=false` pauses preserve-rare only; catalog
follow still runs. Seeders advertise their local seeded catalogs over PEX
so a third peer can learn the seeder from an intermediate contact.

## What is served on PQ1

`/availability`, `/query`, `/manifests/{id}` and piece GET serve **seeded**
artifacts only. A local-only download (`-modelseed=off`) is not advertised.
`listmodels` over unix RPC still shows local unseeded entries to the operator.

## Eviction

When the working budget is exceeded, unpinned **common** replicas (many
observed sources) go first. Rare seeded copies rank higher. Pinned copies
are never deleted by this path. The store garbage collector also removes
aged temporary files and empty unpinned artifact directories, then recounts
usage; it does not delete a non-empty artifact behind the catalog's quota
and admission policy.

## GUI copy (first-run)

The Qt Models page and first-run resource controls expose the same policy
without requiring a terminal when a GUI build is used. Headless and
standalone helper deployments set the same fields with the CLI flags above.

```
Model Network Storage
Use up to:                       [ 500 GB ]
Help preserve downloaded models: [✓]
Help preserve rare models:       [✓]
Upload bandwidth:                 [ 20 MB/s ]
Only while idle:                  [✓]
```
