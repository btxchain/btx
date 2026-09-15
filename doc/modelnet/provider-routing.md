# Provider routing

Distributed provider discovery for `btx://` resources. Not a generic DHT.
Not IPFS. Not monetary AddrMan.

## Record

Typed `btx-provider-v1` only. Fields: resource id, service identity,
candidate endpoints, reachability kind, complete flag or compact piece
ranges (capped), sequence, expiry, ML-DSA-44 pubkey + signature.

Domain: `BTX/ModelProviderRecord/v1`. The service id must be
`ProviderId(pubkey)`. Routers cache and forward; they do not author
records. Sequence rollback and expiry are rejected.

Records mean “I can provide these model bytes.” They do **not** mean
“send me prompts.”

TTL is on the order of an hour. Renew while the provider is active.
Disappearance is expiry, not a global delete.

Announce on initial availability, material range changes, completion,
reachability/relay changes, and periodic renewal — not every piece
mutation.

## Routing table

Separate from monetary AddrMan. 48 buckets, k=8, netgroup cap 2 per
bucket. Routing id is a stable hash of the model service identity.

`PUBLIC_DIRECT` / `PUBLIC_MAPPED` nodes may answer queries (server role).
Private / relay-reachable nodes query and publish through reachable peers
and do not accept arbitrary inbound routing traffic.

Lookups: local cache → closest contacts → bounded iterative queries
(16 queries, parallelism 3, 8s). No unbounded recursion.

## Persistence

A bounded subset of recently healthy contacts may be stored across
restart and revalidated asynchronously. Stale contacts are not a
permanent dependency. Fresh connectivity overrides cache.
