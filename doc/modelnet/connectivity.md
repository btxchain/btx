# Model-plane connectivity

BTX 0.34.7 borrows **ideas** from libp2p/IPFS (AutoNAT, Circuit v2-style
reservations, DCUtR-style hole punch, Kademlia-inspired provider records)
and reimplements them natively. It does not embed libp2p, depend on IPFS,
or weaken PQ1.

See [libp2p-ipfs-parts-bin-audit.md](libp2p-ipfs-parts-bin-audit.md) for
upstream files and BTX-specific differences.

## Endpoint security (non-negotiable)

```
peer A  ↔  strict PQ1 mutually authenticated session  ↔  peer B
```

A relay, rendezvous, or discovery peer may change **routing**. It is not a
TLS/PQ terminator, not an identity authority, and not a model authority.

No X25519, classical TLS, hybrid-only, or WebPKI fallback on the native
model transport.

## Fallback order

1. Proven direct global IPv6
2. Proven direct / mapped IPv4
3. Synchronized hole-punch candidate
4. Relay reservation

First fully ready path wins: TCP + PQ1 + expected service identity.
`ConnectionFullyReady` rejects a bare TCP connect.

## Discovery layering

local connected peers → provider cache → PEX → distributed provider
routing → configured bootstrap → wait/retry.

No layer is mandatory after providers are already known.

## Failure domain

NAT mapping, AutoNAT, relay, hole punch, and provider routing failures
leave monetary `btxd` running. Known direct peers and in-flight verified
pieces should continue.

## Privacy

This is not anonymity. Relays and routing peers can see addresses, timing,
and encrypted byte counts. Provider interest is visible to queried peers.

## Status

`getmodelnetworkinfo` exposes `reachability_state`, mapped/relay
endpoints, routing table size, provider cache size,
`bootstrap_dependency`, hole-punch counters, and bytes by path. It does
not expose secrets.

Related: [reachability.md](reachability.md), [relay.md](relay.md),
[hole-punching.md](hole-punching.md), [provider-routing.md](provider-routing.md),
[bootstrap.md](bootstrap.md), [network-roaming.md](network-roaming.md).
